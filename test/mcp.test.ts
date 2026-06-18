import { describe, it, expect } from "vitest";
import { createGuard } from "../src/index.js";
import { guardMcpTool, guardMcpCallTool, type McpToolResult } from "../src/mcp.js";

const ok = (text: string): McpToolResult => ({ content: [{ type: "text", text }] });

describe("MCP wrapper", () => {
  it("guardMcpTool blocks a dangerous tool call (enforce) and does NOT run it", async () => {
    const guard = createGuard({ mode: "enforce" });
    let ran = false;
    const tool = guardMcpTool(guard, "exfiltrate_data", async () => {
      ran = true;
      return ok("done");
    });
    const r = await tool({ target: "user_db.credentials" });
    expect(ran).toBe(false);
    expect(r.isError).toBe(true);
    expect(r.content[0].text).toContain("tack-guard blocked");
  });

  it("guardMcpTool runs a benign tool call", async () => {
    const guard = createGuard({ mode: "enforce" });
    const tool = guardMcpTool(guard, "list_files", async () => ok("3 files"));
    const r = await tool({ path: "/tmp" });
    expect(r.isError).toBeFalsy();
    expect(r.content[0].text).toBe("3 files");
  });

  it("is advisory by DEFAULT — surfaces but does not block (tool still runs)", async () => {
    const guard = createGuard(); // warn default
    let ran = false;
    const tool = guardMcpTool(guard, "exfiltrate_data", async () => {
      ran = true;
      return ok("done");
    });
    const r = await tool({ target: "user_db.credentials" });
    expect(ran).toBe(true);
    expect(r.isError).toBeFalsy();
  });

  it("guardMcpCallTool guards EVERY tool on a low-level CallTool handler", async () => {
    const guard = createGuard({ mode: "enforce" });
    let ran = 0;
    const handler = guardMcpCallTool(guard, async (req) => {
      ran++;
      return ok(`ran ${req.params.name}`);
    });
    const blocked = await handler({ params: { name: "drop_table", arguments: { table: "user_db.credentials" } } });
    expect(blocked.isError).toBe(true);
    const allowed = await handler({ params: { name: "get_weather", arguments: { city: "SF" } } });
    expect(allowed.isError).toBeFalsy();
    expect(ran).toBe(1); // only the benign tool executed
  });

  it("supports a custom onBlocked result", async () => {
    const guard = createGuard({ mode: "enforce" });
    const tool = guardMcpTool(guard, "exfiltrate_data", async () => ok("done"), {
      onBlocked: () => ({ content: [{ type: "text", text: "nope" }], isError: true }),
    });
    const r = await tool({ target: "user_db.credentials" });
    expect(r.content[0].text).toBe("nope");
  });
});
