/**
 * The canonical tack-guard demo: a CRM agent that is read-only for days, then
 * slowly escalates to writes and finally reaches into credentials.
 *
 * No single call is damning — it's the *trajectory* (read-only baseline → write
 * → sensitive access) that tack-guard catches and blocks. The timestamps below
 * are real and day-spaced, so the reported escalation span ("over 3d") is
 * computed, not decoration.
 *
 * Run from repo root:  npx tsx examples/crm-bot-credential-creep.ts
 */
import { createGuard, type ToolCall } from "../src/index.js";

const guard = createGuard();
const agentId = "crm-bot";
const DAY = 24 * 60 * 60 * 1000;
const start = Date.parse("2026-06-01T10:00:00Z");

function step(call: ToolCall, at: number): void {
  const r = guard.evaluate({ ...call, agentId, at });
  const tag = r.blocked ? "BLOCKED" : r.verdict === "warn" ? "WARN   " : "allow  ";
  console.log(
    `[${tag}] ${call.action.padEnd(8)} ${call.target.padEnd(26)} ` +
      `score=${r.score.toFixed(2)} pattern=${r.pattern}`,
  );
  if (r.evidence.length) console.log(`           evidence: ${r.evidence.join("; ")}`);
}

console.log("\nDay 1-2 — normal read-only CRM work (establishing baseline):");
for (let i = 0; i < 5; i++) {
  step({ action: "read", target: "customers", hour: 10 }, start + i * (DAY / 4));
}

console.log("\nDay 3 — the agent drifts off course:");
step({ action: "write", target: "orders", hour: 11 }, start + 2 * DAY);
step({ action: "read", target: "user_db.sensitive_table", hour: 3 }, start + 3 * DAY);
console.log("");
