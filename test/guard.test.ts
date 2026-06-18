import { describe, it, expect, beforeEach } from "vitest";
import { createGuard as createGuardRaw, inferToolCall } from "../src/index.js";
import type { Guard, GuardConfig, MemoryClient, StoredEvent } from "../src/index.js";

// The guard defaults to ADVISORY ("warn") mode (ADR-0006/0007): it detects + warns
// but does not auto-block. Most tests below assert ENFORCEMENT, so default them to
// enforce; the advisory default is asserted explicitly in "default mode (advisory)".
const createGuard = (config?: GuardConfig) => createGuardRaw({ mode: "enforce", ...config });

describe("tack-guard", () => {
  let guard: Guard;

  beforeEach(() => {
    guard = createGuard();
  });

  describe("default mode (advisory)", () => {
    it("detects credential-creep but does NOT block by default (warn)", () => {
      const g = createGuardRaw(); // real default mode
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers" });
      const r = g.evaluate({ action: "write", target: "user_db.credentials" });
      expect(r.pattern).toBe("credential-creep"); // still detected
      expect(r.verdict).toBe("warn"); // surfaced
      expect(r.blocked).toBe(false); // but not blocked
    });

    it("surfaces a CRITICAL exfil signature as advisory, not a block, by default", () => {
      const g = createGuardRaw();
      const r = g.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(r.severity).toBe("CRITICAL");
      expect(r.verdict).toBe("warn");
      expect(r.blocked).toBe(false);
    });

    it("mode:'enforce' blocks the same exfil", () => {
      const g = createGuardRaw({ mode: "enforce" });
      const r = g.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(r.blocked).toBe(true);
      expect(r.verdict).toBe("quarantine");
    });
  });

  describe("baseline establishment", () => {
    it("should report 'establishing baseline' for the first few calls", () => {
      const result = guard.evaluate({ action: "read", target: "customers" });
      expect(result.verdict).toBe("allow");
      expect(result.score).toBe(0);
      expect(result.summary).toContain("establishing baseline");
      expect(result.blocked).toBe(false);
    });

    it("should not detect threats during baseline", () => {
      for (let i = 0; i < 4; i++) {
        const result = guard.evaluate({ action: "read", target: "customers" });
        // GuardResult has no `detected` field — assert on the real public surface.
        expect(result.verdict).toBe("allow");
        expect(result.pattern).toBe("none");
        expect(result.score).toBe(0);
        expect(result.summary).toContain("establishing baseline");
        expect(result.blocked).toBe(false);
      }
    });
  });

  describe("credential-creep detection", () => {
    it("should detect read-only -> write -> sensitive escalation", () => {
      // Establish read-only baseline (5 reads)
      for (let i = 0; i < 5; i++) {
        guard.evaluate({ action: "read", target: "customers", hour: 14 });
      }

      // Now escalate: write to sensitive target
      const result = guard.evaluate({
        action: "write",
        target: "user_db.sensitive_table",
        hour: 14,
      });

      expect(result.pattern).toBe("credential-creep");
      expect(result.severity).toBe("CRITICAL");
      // Graded score, no constant floor: escalation .25 + sensitive .22 + new_write .10
      expect(result.score).toBeCloseTo(0.57, 2);
      expect(result.quarantined).toBe(true);
      expect(result.blocked).toBe(true);
      expect(result.verdict).toBe("quarantine");
    });

    it("should block risky calls after quarantine", () => {
      // Baseline
      for (let i = 0; i < 5; i++) {
        guard.evaluate({ action: "read", target: "customers" });
      }
      // Trigger quarantine
      guard.evaluate({ action: "write", target: "user_db.sensitive_table" });

      // Subsequent risky call should be blocked
      const result = guard.evaluate({ action: "write", target: "orders" });
      expect(result.blocked).toBe(true);
      expect(result.quarantined).toBe(true);
    });

    it("should still allow reads of non-sensitive targets when quarantined", () => {
      // Baseline
      for (let i = 0; i < 5; i++) {
        guard.evaluate({ action: "read", target: "customers" });
      }
      // Trigger quarantine
      guard.evaluate({ action: "write", target: "user_db.sensitive_table" });

      // Non-risky read should pass
      const result = guard.evaluate({ action: "read", target: "products" });
      expect(result.blocked).toBe(false);
    });
  });

  describe("smash-and-grab detection (stateless)", () => {
    it("should block blatant exfiltration on first call", () => {
      const result = guard.evaluate({
        action: "exfiltrate",
        target: "user_db.credentials",
      });

      expect(result.pattern).toBe("smash-and-grab");
      expect(result.severity).toBe("CRITICAL");
      expect(result.score).toBe(0.95);
      expect(result.blocked).toBe(true);
      expect(result.quarantined).toBe(true);
    });

    it("should block destructive actions on sensitive targets", () => {
      const result = guard.evaluate({
        action: "delete_all",
        target: "user_db.sensitive_table",
      });

      expect(result.blocked).toBe(true);
      expect(result.pattern).toBe("smash-and-grab");
    });

    it("should not block delete_all on non-sensitive targets", () => {
      const result = guard.evaluate({
        action: "delete_all",
        target: "temp_cache",
      });

      expect(result.blocked).toBe(false);
    });
  });

  describe("volume spike (behavioral)", () => {
    it("surfaces a volume spike in signals but does NOT block on volume alone (default threshold)", () => {
      // Calls are spaced 1s apart (explicit `at`) so the rapid_burst signal does
      // NOT fire — we isolate the slow volume_spike + after_hours contribution.
      let t = 1_000_000;
      for (let i = 0; i < 5; i++) {
        guard.evaluate({ action: "read", target: "customers", hour: 14, at: (t += 1000) });
      }
      let result = guard.evaluate({ action: "read", target: "products", hour: 3, at: (t += 1000) });
      for (let i = 0; i < 9; i++) {
        result = guard.evaluate({ action: "read", target: "products", hour: 3, at: (t += 1000) });
      }

      expect(guard.getAgentState("default").events).toBe(15);
      expect(result.signals.volume_spike).toBe(true);
      expect(result.signals.after_hours).toBe(true);
      expect(result.signals.rapid_burst).toBe(false);
      // volume_spike (0.15) + after_hours (0.08) = 0.23, below the 0.5 default
      // threshold -> no detection, no block. Pinned so a future weight change
      // is intentional. (A fast burst would add rapid_burst — see below.)
      expect(result.score).toBeCloseTo(0.23, 2);
      expect(result.verdict).toBe("allow");
      expect(result.pattern).toBe("none");
      expect(result.blocked).toBe(false);
    });

    it("classifies a slow volume spike as smash-and-grab once the threshold is lowered", () => {
      const g = createGuard({ detectionThreshold: 0.2 });
      let t = 1_000_000;
      for (let i = 0; i < 5; i++) {
        g.evaluate({ action: "read", target: "customers", hour: 14, at: (t += 1000) });
      }
      let result = g.evaluate({ action: "read", target: "products", hour: 3, at: (t += 1000) });
      for (let i = 0; i < 9; i++) {
        result = g.evaluate({ action: "read", target: "products", hour: 3, at: (t += 1000) });
      }
      // 0.23 >= 0.2 -> detected; volume_spike && !escalation_trajectory => smash-and-grab.
      expect(result.score).toBeCloseTo(0.23, 2);
      expect(result.pattern).toBe("smash-and-grab");
      expect(result.severity).toBe("MEDIUM");
      // reads of a non-sensitive target are not "risky" -> warn, not blocked.
      expect(result.verdict).toBe("warn");
      expect(result.blocked).toBe(false);
    });
  });

  describe("multi-agent support", () => {
    it("should track agents independently", () => {
      // Agent A: normal reads
      for (let i = 0; i < 5; i++) {
        guard.evaluate({ action: "read", target: "customers", agentId: "agent-a" });
      }

      // Agent B: blatant attack
      const resultB = guard.evaluate({
        action: "exfiltrate",
        target: "user_db.credentials",
        agentId: "agent-b",
      });

      expect(resultB.blocked).toBe(true);

      // Agent A should still be fine
      const resultA = guard.evaluate({
        action: "read",
        target: "customers",
        agentId: "agent-a",
      });
      expect(resultA.blocked).toBe(false);
      expect(resultA.quarantined).toBe(false);
    });
  });

  describe("score-only mode", () => {
    it("should never block in score-only mode", () => {
      const softGuard = createGuard({ mode: "score-only" });

      const result = softGuard.evaluate({
        action: "exfiltrate",
        target: "user_db.credentials",
      });

      expect(result.blocked).toBe(false);
      expect(result.verdict).toBe("allow");
      expect(result.score).toBe(0.95); // still scores
    });
  });

  describe("warn mode", () => {
    it("should warn but not block", () => {
      const warnGuard = createGuard({ mode: "warn" });

      // Baseline
      for (let i = 0; i < 5; i++) {
        warnGuard.evaluate({ action: "read", target: "customers", hour: 14 });
      }

      const result = warnGuard.evaluate({
        action: "write",
        target: "user_db.sensitive_table",
        hour: 14,
      });

      expect(result.verdict).toBe("warn");
      expect(result.blocked).toBe(false);
      expect(result.score).toBeGreaterThanOrEqual(0.5);
    });
  });

  describe("custom config", () => {
    it("should respect custom sensitive targets", () => {
      const customGuard = createGuard({
        sensitiveTargets: ["payments", "api_keys"],
      });

      for (let i = 0; i < 5; i++) {
        customGuard.evaluate({ action: "read", target: "products" });
      }

      const result = customGuard.evaluate({
        action: "write",
        target: "payments",
      });

      expect(result.pattern).toBe("credential-creep");
      expect(result.severity).toBe("CRITICAL");
    });

    it("should respect custom business hours", () => {
      const nightGuard = createGuard({
        businessHours: [22, 6], // night shift
      });

      for (let i = 0; i < 5; i++) {
        nightGuard.evaluate({ action: "read", target: "orders", hour: 23 });
      }

      // Hour 23 is within [22, 6) so NOT after hours
      const result = nightGuard.evaluate({ action: "read", target: "orders", hour: 23 });
      expect(result.signals.after_hours).toBe(false);
    });
  });

  describe("reset", () => {
    it("should clear agent state on reset", () => {
      // Build up state
      guard.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(guard.getAgentState("default").quarantined).toBe(true);

      // Reset
      guard.reset("default");
      expect(guard.getAgentState("default").quarantined).toBe(false);
      expect(guard.getAgentState("default").events).toBe(0);
    });

    it("should clear all agents on reset()", () => {
      guard.evaluate({ action: "read", target: "a", agentId: "x" });
      guard.evaluate({ action: "read", target: "b", agentId: "y" });

      guard.reset();

      expect(guard.getAgentState("x").events).toBe(0);
      expect(guard.getAgentState("y").events).toBe(0);
    });
  });

  describe("config overrides", () => {
    it("respects a custom detectionThreshold", () => {
      const g = createGuard({ detectionThreshold: 0.05 });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "orders", hour: 14 });
      const result = g.evaluate({ action: "read", target: "orders", hour: 3 });
      expect(result.signals.after_hours).toBe(true);
      expect(result.score).toBeCloseTo(0.08, 2); // after_hours alone clears 0.05
      expect(result.verdict).toBe("warn");
    });

    it("respects custom signal weights", () => {
      const g = createGuard({ weights: { after_hours: 0.6 } });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "orders", hour: 14 });
      const result = g.evaluate({ action: "read", target: "orders", hour: 3 });
      // after_hours now worth 0.6 on its own -> detected, HIGH, behavioral-drift.
      expect(result.score).toBeCloseTo(0.6, 2);
      expect(result.severity).toBe("HIGH");
      expect(result.pattern).toBe("behavioral-drift");
    });

    it("respects a custom baselineMin", () => {
      const g = createGuard({ baselineMin: 2 });
      const first = g.evaluate({ action: "read", target: "customers" });
      expect(first.summary).toContain("establishing baseline (1/2");
      g.evaluate({ action: "read", target: "customers" }); // completes the 2-call baseline window
      const result = g.evaluate({ action: "write", target: "user_db.sensitive_table" });
      expect(result.pattern).toBe("credential-creep");
      expect(result.severity).toBe("CRITICAL");
    });
  });

  describe("sensitiveTargets as a predicate", () => {
    it("treats targets matched by the predicate as sensitive", () => {
      const g = createGuard({ sensitiveTargets: (t) => t.startsWith("vault_") });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers" });
      const result = g.evaluate({ action: "write", target: "vault_keys" });
      expect(result.pattern).toBe("credential-creep");
      expect(result.severity).toBe("CRITICAL");
    });
  });

  describe("non-read-only baseline (documented limitation)", () => {
    it("does NOT flag escalation when the agent wrote from the start", () => {
      const g = createGuard();
      // The baseline already contains writes -> there is no read-only norm to
      // deviate from, so escalation_trajectory / new_write_access stay gated off.
      for (let i = 0; i < 5; i++) g.evaluate({ action: "write", target: "orders", hour: 14 });
      g.evaluate({ action: "write", target: "user_db.sensitive_table", hour: 3 });
      const result = g.evaluate({ action: "admin_access", target: "admin_panel", hour: 3 });

      expect(result.signals.escalation_trajectory).toBe(false);
      expect(result.signals.new_write_access).toBe(false);
      expect(result.signals.sensitive_write).toBe(true);
      expect(result.signals.admin_attempt).toBe(true);
      // sensitive(0.22)+admin(0.07)+after_hours(0.08) = 0.37, under the 0.5 default.
      // Pinned so any future re-tune of this gap is a deliberate change.
      expect(result.score).toBeCloseTo(0.37, 2);
      expect(result.verdict).toBe("allow");
      expect(result.pattern).toBe("none");
    });
  });

  describe("quarantine output consistency", () => {
    it("a call blocked by a latched signature reports the quarantine reason, not baseline state", () => {
      const g = createGuard();
      // Blatant exfil on call 1 -> latched quarantine while still pre-baseline.
      const first = g.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(first.blocked).toBe(true);

      // A later risky call: the behavioral layer is still in baseline (2/5), but
      // the blocked result must NOT leak "LOW / establishing baseline".
      const next = g.evaluate({ action: "write", target: "orders" });
      expect(next.blocked).toBe(true);
      expect(next.quarantined).toBe(true);
      expect(next.severity).toBe("CRITICAL");
      expect(next.score).toBe(0.95);
      expect(next.summary).toMatch(/quarantined/i);
      expect(next.summary).not.toContain("establishing baseline");
    });
  });

  describe("after-hours boundary", () => {
    it("treats 18:00 as after-hours and 09:00 as in-hours (default [9,18))", () => {
      const late = createGuard();
      for (let i = 0; i < 5; i++) late.evaluate({ action: "read", target: "orders", hour: 18 });
      const lateResult = late.evaluate({ action: "read", target: "orders", hour: 18 });
      expect(lateResult.signals.after_hours).toBe(true);

      const early = createGuard();
      for (let i = 0; i < 5; i++) early.evaluate({ action: "read", target: "orders", hour: 9 });
      const earlyResult = early.evaluate({ action: "read", target: "orders", hour: 9 });
      expect(earlyResult.signals.after_hours).toBe(false);
    });
  });

  describe("custom memory (sync)", () => {
    it("works through a custom synchronous MemoryClient", () => {
      const store = new Map<string, StoredEvent[]>();
      const custom: MemoryClient = {
        push(agentId, event) {
          const e = store.get(agentId) ?? [];
          e.push(event);
          store.set(agentId, e);
        },
        getEvents(agentId) {
          return store.get(agentId) ?? [];
        },
        clear(agentId) {
          store.delete(agentId);
        },
        clearAll() {
          store.clear();
        },
      };

      const g = createGuard();
      g.setMemory(custom);
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers" });
      const result = g.evaluate({ action: "write", target: "user_db.sensitive_table" });

      expect(result.pattern).toBe("credential-creep");
      expect(g.getAgentState("default").events).toBe(6);
      expect(store.get("default")?.length).toBe(6);
    });
  });

  describe("async memory (evaluateAsync)", () => {
    function asyncClient(): MemoryClient {
      const store = new Map<string, StoredEvent[]>();
      return {
        async push(agentId, event) {
          const e = store.get(agentId) ?? [];
          e.push(event);
          store.set(agentId, e);
        },
        async getEvents(agentId) {
          return store.get(agentId) ?? [];
        },
        async clear(agentId) {
          store.delete(agentId);
        },
        async clearAll() {
          store.clear();
        },
      };
    }

    it("scores through an async MemoryClient via evaluateAsync()", async () => {
      const g = createGuard();
      g.setMemory(asyncClient());
      for (let i = 0; i < 5; i++) {
        await g.evaluateAsync({ action: "read", target: "customers" });
      }
      const result = await g.evaluateAsync({
        action: "write",
        target: "user_db.sensitive_table",
      });
      expect(result.pattern).toBe("credential-creep");
      expect(result.blocked).toBe(true);
    });

    it("sync evaluate() throws on an async MemoryClient", () => {
      const g = createGuard();
      g.setMemory(asyncClient());
      expect(() => g.evaluate({ action: "read", target: "customers" })).toThrow(
        /evaluateAsync/,
      );
    });

    it("stateless signatures fire through evaluateAsync() too", async () => {
      const g = createGuard();
      g.setMemory(asyncClient());
      const result = await g.evaluateAsync({
        action: "exfiltrate",
        target: "user_db.credentials",
      });
      expect(result.blocked).toBe(true);
      expect(result.pattern).toBe("smash-and-grab");
    });
  });

  describe("connect()", () => {
    it("throws a 'not implemented' error (persistence is bring-your-own via setMemory)", () => {
      expect(() => guard.connect("tk_live_xxx")).toThrow(/not implemented/i);
    });
  });

  describe("action canonicalization (evasion resistance)", () => {
    it("catches a sensitive mutation regardless of the verb synonym", () => {
      for (const verb of ["update", "delete", "patch", "UPSERT", "modifyRow"]) {
        const g = createGuard();
        for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
        const r = g.evaluate({ action: verb, target: "user_db.sensitive_table", hour: 14 });
        expect(r.pattern, verb).toBe("credential-creep");
        expect(r.blocked, verb).toBe(true);
      }
    });

    it("blocks blatant exfil regardless of casing or synonym", () => {
      for (const verb of ["exfiltrate", "Exfiltrate", "EXPORT_ALL", "bulkExport", "dump"]) {
        const g = createGuard();
        const r = g.evaluate({ action: verb, target: "user_db.credentials" });
        expect(r.blocked, verb).toBe(true);
        expect(r.pattern, verb).toBe("smash-and-grab");
      }
    });

    it("does not flag benign read synonyms", () => {
      const g = createGuard();
      for (let i = 0; i < 5; i++) g.evaluate({ action: "list", target: "products", hour: 14 });
      const r = g.evaluate({ action: "get", target: "products", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).toBe("none");
    });
  });

  describe("temporal signals", () => {
    it("rapid_burst fires on a fast burst and stays off when calls are paced", () => {
      // Paced: 12 calls 1s apart -> no burst.
      const slow = createGuard();
      let t = 1_000_000;
      let rSlow = slow.evaluate({ action: "read", target: "events", hour: 14, at: t });
      for (let i = 0; i < 11; i++) rSlow = slow.evaluate({ action: "read", target: "events", hour: 14, at: (t += 1000) });
      expect(rSlow.signals.rapid_burst).toBe(false);

      // Fast: 12 calls within ~60ms -> burst.
      const fast = createGuard();
      let rFast = fast.evaluate({ action: "read", target: "events", hour: 14, at: 2_000_000 });
      for (let i = 1; i < 12; i++) rFast = fast.evaluate({ action: "read", target: "events", hour: 14, at: 2_000_000 + i * 5 });
      expect(rFast.signals.rapid_burst).toBe(true);
    });

    it("a rapid burst of sensitive access is flagged as smash-and-grab", () => {
      const g = createGuard();
      const base = 3_000_000;
      // Non-read-only baseline (writes) so this is NOT escalation/creep.
      for (let i = 0; i < 5; i++) g.evaluate({ action: "write", target: "orders", hour: 14, at: base + i * 5 });
      let r = g.evaluate({ action: "read", target: "user_db.sensitive_table", hour: 3, at: base + 25 });
      for (let i = 6; i < 15; i++) r = g.evaluate({ action: "read", target: "user_db.sensitive_table", hour: 3, at: base + i * 5 });

      expect(r.signals.rapid_burst).toBe(true);
      expect(r.signals.sensitive_write).toBe(true);
      expect(r.pattern).toBe("smash-and-grab");
      expect(r.score).toBeGreaterThanOrEqual(0.5);
      expect(r.verdict).toBe("warn");
    });

    it("reports the escalation time-span in evidence (uses real timestamps)", () => {
      const g = createGuard();
      const day = 24 * 60 * 60 * 1000;
      const base = 1_700_000_000_000;
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 10, at: base + i * 1000 });
      const r = g.evaluate({ action: "write", target: "user_db.sensitive_table", hour: 3, at: base + 3 * day });

      expect(r.pattern).toBe("credential-creep");
      expect(r.evidence.some((e) => /over\s+\d+\s*[dh]/.test(e))).toBe(true);
    });
  });

  describe("false-positive balance & robustness", () => {
    // Foot-gun regression (ADR-0006/0007): a bare "user_db" prefix used to mark every
    // table sensitive, so a legit first write to user_db.preferences fired CRITICAL
    // credential-creep (which bypasses the threshold) and blocked benign work.
    it("does NOT flag a legit first write to a non-sensitive user_db.* table", () => {
      const g = createGuard();
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      const r = g.evaluate({ action: "write", target: "user_db.preferences", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).not.toBe("credential-creep");
    });

    it("STILL flags read-baseline escalation to user_db.credentials (real credential-creep)", () => {
      const g = createGuard();
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      const r = g.evaluate({ action: "write", target: "user_db.credentials", hour: 14 });
      expect(r.pattern).toBe("credential-creep");
    });

    it("does NOT quarantine a benign send/upload to a sensitive-named target", () => {
      for (const action of ["send_email", "upload", "sendNotification"]) {
        const g = createGuard();
        const r = g.evaluate({ action, target: "user_db.profile", hour: 14 });
        expect(r.blocked, action).toBe(false);
        expect(r.quarantined, action).toBe(false);
      }
    });

    it("does NOT quarantine a formatting verb on a sensitive-named target", () => {
      const g = createGuard();
      const r = g.evaluate({ action: "format_date", target: "user_db.report", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.quarantined).toBe(false);
    });

    it("catches destructive aliases (rmdir) on a sensitive target", () => {
      const g = createGuard();
      const r = g.evaluate({ action: "rmdir", target: "user_db.sensitive_table", hour: 3 });
      expect(r.pattern).toBe("smash-and-grab");
      expect(r.blocked).toBe(true);
    });

    it("still detects credential-creep even with a high detectionThreshold", () => {
      // The flagship pattern must not be demotable by a config knob (no floor now).
      const g = createGuard({ detectionThreshold: 0.9 });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      const r = g.evaluate({ action: "write", target: "user_db.sensitive_table", hour: 14 });
      expect(r.pattern).toBe("credential-creep");
      expect(r.severity).toBe("CRITICAL");
      expect(r.blocked).toBe(true);
    });

    it("does not invent a read-only baseline when baselineMin is 0", () => {
      const g = createGuard({ baselineMin: 0 });
      const r = g.evaluate({ action: "write", target: "user_db.sensitive_table", hour: 14 });
      // No prior reads -> not credential-creep, not blocked.
      expect(r.pattern).not.toBe("credential-creep");
      expect(r.blocked).toBe(false);
    });
  });

  describe("egress / data-exfiltration", () => {
    // FP-FIRST: these MUST NOT fire. The egress signal is opt-in and must never
    // flag legitimate traffic — false positives are the existential risk.
    it("is dormant with no egressTargets (read sensitive -> send external)", () => {
      const g = createGuard(); // egress monitoring not configured
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      const r = g.evaluate({ action: "send", target: "attacker@evil.com", hour: 14 });
      expect(r.pattern).not.toBe("data-exfiltration");
      expect(r.blocked).toBe(false);
    });

    it("does not fire on egress to an ALLOWLISTED destination", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      const r = g.evaluate({ action: "send", target: "ops@mycorp.com", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).not.toBe("data-exfiltration");
    });

    it("does not fire on egress of NON-sensitive data", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      for (let i = 0; i < 6; i++) g.evaluate({ action: "read", target: "products", hour: 14 });
      const r = g.evaluate({ action: "send", target: "newsletter@external.com", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).not.toBe("data-exfiltration");
    });

    it("does not fire when egress happens BEFORE any sensitive access", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      g.evaluate({ action: "send", target: "external@elsewhere.com", hour: 14 });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "products", hour: 14 });
      const r = g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      expect(r.pattern).not.toBe("data-exfiltration");
      expect(r.blocked).toBe(false);
    });

    // DETECTION: the canonical exfil flow MUST fire and block.
    it("catches sensitive read -> egress to an untrusted destination", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      const r = g.evaluate({ action: "send", target: "attacker@evil.com", hour: 14 });
      expect(r.pattern).toBe("data-exfiltration");
      expect(r.severity).toBe("CRITICAL");
      expect(r.blocked).toBe(true);
      expect(r.quarantined).toBe(true);
    });

    it("works via inferToolCall (real provider shape) + a predicate allowlist", () => {
      const g = createGuard({ egressTargets: (dest) => dest.endsWith("@mycorp.com") });
      for (let i = 0; i < 5; i++) g.evaluate({ action: "read", target: "customers", hour: 14 });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      // GmailSendEmail({ to }) -> action "GmailSendEmail" (egress), target = recipient
      const r = g.evaluate(
        inferToolCall({ name: "GmailSendEmail", arguments: { to: "thief@evil.com" } }, { hour: 14 }),
      );
      expect(r.pattern).toBe("data-exfiltration");
      expect(r.blocked).toBe(true);
    });

    // The AgentDojo finding: a SHORT exfil (sensitive read -> send, 2 calls) must
    // fire even below the baseline window — data-exfiltration is an intrinsic flow,
    // not a learned-baseline deviation. Earlier this slipped through.
    it("catches a short exfil below the baseline window (2 calls)", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      const r = g.evaluate({ action: "send", target: "attacker@evil.com", hour: 14 });
      expect(r.pattern).toBe("data-exfiltration");
      expect(r.blocked).toBe(true);
    });

    it("a short read -> internal egress (allowlisted) stays clean (no FP)", () => {
      const g = createGuard({ egressTargets: ["mycorp.com"] });
      g.evaluate({ action: "read", target: "user_db.credentials", hour: 14 });
      const r = g.evaluate({ action: "send", target: "ops@mycorp.com", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).not.toBe("data-exfiltration");
    });

    // AgentDojo FP regression: "email"/"mail" are also a NOUN. Mailbox ops on an
    // email object (delete/read/archive/get/move) must NOT read as an egress just
    // because the tool name ends in "_email". Only the verb form is an egress.
    it("does not fire on mailbox object-ops after a sensitive read (email is a noun)", () => {
      for (const action of ["delete_email", "read_email", "archive_email", "get_email", "move_email"]) {
        const g = createGuard({ egressTargets: ["mycorp.com"], sensitiveTargets: ["inbox"] });
        g.evaluate({ action: "read_email", target: "inbox", hour: 14 });
        const r = g.evaluate({ action, target: "13", hour: 14 });
        expect(r.pattern, `${action} should not be exfil`).not.toBe("data-exfiltration");
        expect(r.blocked, `${action} should not block`).toBe(false);
      }
    });

    it("still fires when email/mail LEAD the action (verb slot) to an untrusted dest", () => {
      for (const action of ["email_to", "email", "mail_report", "mail"]) {
        const g = createGuard({ egressTargets: ["mycorp.com"], sensitiveTargets: ["inbox"] });
        g.evaluate({ action: "read", target: "inbox", hour: 14 });
        const r = g.evaluate({ action, target: "thief@evil.com", hour: 14 });
        expect(r.pattern, `${action} should be exfil`).toBe("data-exfiltration");
        expect(r.blocked, `${action} should block`).toBe(true);
      }
    });

    // Money movement is egress too — financial exfil (sensitive read -> transfer to a
    // non-allowlisted IBAN). egressTargets allowlist works on IBANs, not just domains.
    it("catches money-movement egress (transfer/wire/remit) to an untrusted destination", () => {
      for (const action of ["transfer_money", "wire_transfer", "remit_funds"]) {
        const g = createGuard({ egressTargets: ["DE89370400440532013000"], sensitiveTargets: ["account", "iban"] });
        g.evaluate({ action: "read", target: "account_balance", hour: 14 });
        const r = g.evaluate({ action, target: "GB00EVIL99999999999999", hour: 14 });
        expect(r.pattern, `${action} should be exfil`).toBe("data-exfiltration");
        expect(r.blocked, `${action} should block`).toBe(true);
      }
    });

    it("does not fire money-movement to an ALLOWLISTED destination (no FP)", () => {
      const g = createGuard({ egressTargets: ["DE89370400440532013000"], sensitiveTargets: ["account", "iban"] });
      g.evaluate({ action: "read", target: "account_balance", hour: 14 });
      const r = g.evaluate({ action: "transfer_money", target: "DE89370400440532013000", hour: 14 });
      expect(r.blocked).toBe(false);
      expect(r.pattern).not.toBe("data-exfiltration");
    });
  });
});
