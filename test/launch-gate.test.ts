/**
 * Launch-gate tests — the "Bloquant" scenarios from the OSS launch criteria.
 *
 * These exercise the headline claims end to end: the kill-switch (behavioral
 * detection needs memory; stateless signatures don't), no false positives on
 * normal traffic, cold-start safety, the two flagship attack patterns, raw
 * performance on a large history, and multi-agent isolation.
 */
import { describe, it, expect } from "vitest";
import { createGuard as createGuardRaw } from "../src/index.js";
import type { GuardConfig, MemoryClient } from "../src/index.js";

// These gate the BLOCKING headline claims; the guard now defaults to advisory
// ("warn", ADR-0006/0007), so run them in enforce mode.
const createGuard = (config?: GuardConfig) => createGuardRaw({ mode: "enforce", ...config });

/** A client that remembers nothing — simulates the "memory off" kill-switch. */
const noMemory: MemoryClient = {
  push() {},
  getEvents() {
    return [];
  },
  clear() {},
  clearAll() {},
};

describe("launch gate", () => {
  describe("kill-switch (the headline)", () => {
    it("behavioral detection requires memory", () => {
      // Memory ON: a read-only baseline then a sensitive write is caught.
      const on = createGuard();
      for (let i = 0; i < 5; i++) on.evaluate({ action: "read", target: "customers" });
      const caught = on.evaluate({ action: "write", target: "user_db.sensitive_table" });
      expect(caught.pattern).toBe("credential-creep");
      expect(caught.blocked).toBe(true);

      // Memory OFF: the exact same sequence sails through — no baseline to
      // deviate from. This is the kill-switch demo.
      const off = createGuard();
      off.setMemory(noMemory);
      for (let i = 0; i < 5; i++) off.evaluate({ action: "read", target: "customers" });
      const missed = off.evaluate({ action: "write", target: "user_db.sensitive_table" });
      expect(missed.pattern).toBe("none");
      expect(missed.blocked).toBe(false);
    });

    it("does NOT disable stateless signatures", () => {
      // Even with memory off, a blatant exfil is blocked on the first call.
      const off = createGuard();
      off.setMemory(noMemory);
      const result = off.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(result.blocked).toBe(true);
      expect(result.pattern).toBe("smash-and-grab");
    });
  });

  describe("false positives", () => {
    it("100 normal read-only calls never block or quarantine", () => {
      const g = createGuard();
      for (let i = 0; i < 100; i++) {
        const r = g.evaluate({
          action: "read",
          target: `table_${i % 5}`,
          hour: 10 + (i % 6), // 10..15, always in business hours
          at: 1_000_000 + i * 1000, // 1s apart -> deterministic, no rapid_burst
        });
        expect(r.blocked).toBe(false);
        expect(r.quarantined).toBe(false);
      }
    });
  });

  describe("cold start", () => {
    it("does not behaviorally score before the baseline is established", () => {
      const g = createGuard(); // baselineMin = 5
      for (let i = 0; i < 4; i++) {
        const r = g.evaluate({ action: "write", target: "user_db.sensitive_table", hour: 3 });
        expect(r.summary).toContain("establishing baseline");
        expect(r.blocked).toBe(false);
      }
    });

    it("is still covered by stateless signatures from call 1", () => {
      const g = createGuard();
      const r = g.evaluate({ action: "exfiltrate", target: "user_db.credentials" });
      expect(r.blocked).toBe(true);
    });
  });

  describe("end-to-end attack patterns", () => {
    it("catches a slow, multi-day credential-creep", () => {
      const g = createGuard();
      // Days 1-2: pure read-only during business hours.
      for (let i = 0; i < 8; i++) g.evaluate({ action: "read", target: "customers", hour: 10 });
      // Day 3: a first write, then reaching into sensitive data after hours.
      g.evaluate({ action: "write", target: "orders", hour: 9 });
      const result = g.evaluate({ action: "read", target: "user_db.sensitive_table", hour: 2 });

      expect(result.pattern).toBe("credential-creep");
      expect(result.severity).toBe("CRITICAL");
      // Graded score (no constant floor); escalation + sensitive + after-hours + burst.
      expect(result.score).toBeGreaterThanOrEqual(0.5);
      expect(result.blocked).toBe(true);
    });

    it("blocks a smash-and-grab burst on the first call", () => {
      const g = createGuard();
      const result = g.evaluate({ action: "bulk_export", target: "user_db.credentials" });
      expect(result.pattern).toBe("smash-and-grab");
      expect(result.severity).toBe("CRITICAL");
      expect(result.blocked).toBe(true);
    });
  });

  describe("performance", () => {
    it("evaluate stays fast even with a large accumulated history", () => {
      const g = createGuard();
      for (let i = 0; i < 5_000; i++) g.evaluate({ action: "read", target: "customers", hour: 10 });

      const iterations = 200;
      const start = Date.now();
      for (let i = 0; i < iterations; i++) g.evaluate({ action: "read", target: "customers", hour: 10 });
      const avgMs = (Date.now() - start) / iterations;

      // Inline target is < 1ms. Assert a generous ceiling to avoid CI flakiness.
      // NOTE: scoring is O(history); bounding/windowing very long-running
      // sessions is a custom MemoryClient's job. See architecture.md "Scaling".
      expect(avgMs).toBeLessThan(5);
    });
  });

  describe("multi-agent isolation", () => {
    it("isolates three simultaneous agents", () => {
      const g = createGuard();
      for (let i = 0; i < 5; i++) {
        g.evaluate({ action: "read", target: "customers", agentId: "agent-a" });
        g.evaluate({ action: "read", target: "customers", agentId: "agent-c" });
      }

      // agent-b goes rogue.
      const b = g.evaluate({ action: "exfiltrate", target: "user_db.credentials", agentId: "agent-b" });
      expect(b.blocked).toBe(true);

      // a and c are untouched.
      const a = g.evaluate({ action: "read", target: "customers", agentId: "agent-a" });
      const c = g.evaluate({ action: "read", target: "customers", agentId: "agent-c" });
      expect(a.blocked).toBe(false);
      expect(a.quarantined).toBe(false);
      expect(c.blocked).toBe(false);
      expect(c.quarantined).toBe(false);
    });
  });
});
