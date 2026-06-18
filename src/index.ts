/**
 * tack-guard — Runtime risk scoring for AI agent tool calls.
 *
 * Detect behavioral drift, privilege escalation, and data exfiltration
 * inline — under 1ms, zero dependencies.
 *
 * @example
 * ```ts
 * import { createGuard } from '@tacksec/guard'
 *
 * const guard = createGuard()
 *
 * // In your agent's tool execution pipeline:
 * const result = guard.evaluate({
 *   action: 'write',
 *   target: 'user_db.sensitive_table',
 *   agentId: 'sales-bot',
 * })
 *
 * if (result.blocked) {
 *   console.log(`Blocked: ${result.summary}`)
 *   // deny the tool call
 * }
 * ```
 *
 * @packageDocumentation
 */

// ── Public API ──────────────────────────────────────────────────────────────

export { createGuard, GuardBlockedError } from "./guard.js";
export type { Guard, WrapToolOptions } from "./guard.js";

// ── Framework adapters (map a real tool call to a ToolCall) ──────────────────

export { inferToolCall } from "./integrations.js";
export type { RawToolCall } from "./integrations.js";
export { canonicalizeAction } from "./actions.js";
export type { CanonicalAction } from "./actions.js";

// ── Types ───────────────────────────────────────────────────────────────────

export type {
  ToolCall,
  GuardResult,
  GuardConfig,
  StoredEvent,
  Severity,
  Verdict,
  Pattern,
} from "./types.js";

// ── Memory (for custom implementations) ─────────────────────────────────────

export type { MemoryClient } from "./memory/types.js";
export { InMemoryClient } from "./memory/in-memory.js";

// ── Constants (for advanced usage) ──────────────────────────────────────────

export {
  WEIGHTS,
  BASELINE_MIN,
  DETECTION_THRESHOLD,
  type SignalName,
} from "./constants.js";
