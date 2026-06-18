import { describe, it, expect } from "vitest";
import {
  createGuard as createGuardRaw,
  inferToolCall,
  canonicalizeAction,
  GuardBlockedError,
} from "../src/index.js";
import type { GuardConfig } from "../src/index.js";

// Guard defaults to advisory ("warn"); these integration tests assert enforcement,
// so default them to enforce (ADR-0006/0007).
const createGuard = (config?: GuardConfig) => createGuardRaw({ mode: "enforce", ...config });

describe("canonicalizeAction", () => {
  it("maps synonyms, casing, and composite names to a canonical class", () => {
    expect(canonicalizeAction("update_row")).toBe("write");
    expect(canonicalizeAction("deleteUser")).toBe("write");
    expect(canonicalizeAction("Exfiltrate")).toBe("exfiltrate");
    expect(canonicalizeAction("export_all")).toBe("exfiltrate");
    expect(canonicalizeAction("drop_table")).toBe("destroy");
    expect(canonicalizeAction("delete_all")).toBe("destroy");
    expect(canonicalizeAction("listCustomers")).toBe("read");
    expect(canonicalizeAction("admin_access")).toBe("admin");
    expect(canonicalizeAction("grantRole")).toBe("admin");
    expect(canonicalizeAction("rmdir")).toBe("destroy");
    expect(canonicalizeAction("frobnicate")).toBe("other");
  });

  it("does NOT over-match benign verbs (send / upload / format / flush)", () => {
    // These were removed from the danger sets — they must not canonicalize to
    // exfiltrate/destroy, which would quarantine common email/upload/format agents.
    expect(canonicalizeAction("send_email")).toBe("other");
    expect(canonicalizeAction("sendNotification")).toBe("other");
    expect(canonicalizeAction("upload")).toBe("other");
    expect(canonicalizeAction("format_date")).toBe("other");
    expect(canonicalizeAction("formatCurrency")).toBe("other");
    expect(canonicalizeAction("flush_cache")).toBe("other");
  });
});

describe("inferToolCall", () => {
  it("derives action from the tool name and target from arguments", () => {
    const tc = inferToolCall({
      name: "update_user",
      arguments: { table: "user_db.sensitive_table", id: 7 },
    });
    expect(tc.action).toBe("update_user");
    expect(tc.target).toBe("user_db.sensitive_table");
  });

  it("parses a JSON-string arguments payload (OpenAI function-calling shape)", () => {
    const tc = inferToolCall({ name: "sql_delete", arguments: JSON.stringify({ table: "orders" }) });
    expect(tc.target).toBe("orders");
  });

  it("falls back to the tool name when no target-like argument is present", () => {
    const tc = inferToolCall({ name: "healthcheck", arguments: {} });
    expect(tc.target).toBe("healthcheck");
  });

  it("honours explicit overrides", () => {
    const tc = inferToolCall({ name: "x", arguments: {} }, { action: "read", target: "t", hour: 9 });
    expect(tc.action).toBe("read");
    expect(tc.target).toBe("t");
    expect(tc.hour).toBe(9);
  });

  it("flows through the guard to catch a sensitive mutation on inferred fields", () => {
    const g = createGuard();
    for (let i = 0; i < 5; i++) {
      g.evaluate(inferToolCall({ name: "list_customers", arguments: { table: "customers" } }, { hour: 14 }));
    }
    const r = g.evaluate(
      inferToolCall({ name: "update_record", arguments: { table: "user_db.sensitive_table" } }, { hour: 14 }),
    );
    expect(r.pattern).toBe("credential-creep");
    expect(r.blocked).toBe(true);
  });
});

describe("wrapTool", () => {
  it("runs the tool when allowed and blocks a risky call", () => {
    const g = createGuard();
    const calls: string[] = [];

    const readTool = g.wrapTool(
      (id: number) => {
        calls.push(`read:${id}`);
        return id * 2;
      },
      { action: "read", target: "customers", agentId: "a" },
    );
    for (let i = 0; i < 5; i++) expect(readTool(i)).toBe(i * 2);
    expect(calls).toHaveLength(5);

    const exfilTool = g.wrapTool(
      (t: string) => {
        calls.push(`exfil:${t}`);
        return "done";
      },
      { action: "exfiltrate", target: (t: string) => t, agentId: "a" },
    );
    expect(() => exfilTool("user_db.credentials")).toThrow(GuardBlockedError);
    expect(calls).not.toContain("exfil:user_db.credentials"); // the tool never ran
  });

  it("calls onBlocked instead of throwing when provided", () => {
    const g = createGuard();
    const tool = g.wrapTool((_t: string) => "ran", {
      action: "exfiltrate",
      target: (t: string) => t,
      onBlocked: () => "refused",
    });
    expect(tool("user_db.credentials")).toBe("refused");
  });
});
