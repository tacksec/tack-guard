import type { SignalName } from "./constants.js";
import type { CanonicalAction } from "./actions.js";

// ── Severity & Verdict ──────────────────────────────────────────────────────

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * - `allow`   — let the call through.
 * - `warn`    — let it through but flag it (the only non-blocking detection verdict).
 * - `deny`    — block this single call without quarantining the agent. Reserved:
 *               currently unreachable because every block path also quarantines.
 * - `quarantine` — the agent is contained; this and future risky calls are blocked.
 */
export type Verdict = "allow" | "warn" | "deny" | "quarantine";

export type Pattern =
  | "credential-creep"
  | "smash-and-grab"
  | "behavioral-drift"
  | "data-exfiltration"
  | "none";

// ── Input: what the developer passes to guard.evaluate() ────────────────────

export interface ToolCall {
  /**
   * What the agent is doing. Any string — it is canonicalized internally, so
   * "update_row", "deleteUser", "Exfiltrate", "export_all" all map to the right
   * risk class (you are NOT limited to a fixed vocabulary). See
   * `canonicalizeAction`.
   */
  action: string;
  /** What the agent is touching: "users", "user_db.sensitive_table", etc. */
  target: string;
  /** Agent identifier (for multi-agent setups). Defaults to "default". */
  agentId?: string;
  /** Hour of day (0-23). Defaults to current hour. Used for after-hours detection. */
  hour?: number;
  /**
   * Event time as epoch milliseconds. Defaults to `Date.now()`. Used by the
   * temporal signals (rapid_burst, escalation span). Pass it explicitly to
   * replay historical traffic or for deterministic tests.
   */
  at?: number;
  /** Arbitrary metadata attached to the event. */
  metadata?: Record<string, unknown>;
}

// ── Output: what guard.evaluate() returns ───────────────────────────────────

export interface GuardResult {
  /** Final verdict: allow the call, warn, deny it, or quarantine the agent. */
  verdict: Verdict;
  /** Threat confidence score, 0-1. Higher = more dangerous. */
  score: number;
  /** Severity classification. */
  severity: Severity;
  /** Detected attack pattern, if any. */
  pattern: Pattern;
  /**
   * Which behavioral signals fired. Always reflects the behavioral layer, so
   * these may all be `false` even on a CRITICAL result driven by a stateless
   * signature — in that case `score`/`severity`/`pattern` describe the signature,
   * not the signals.
   */
  signals: Record<SignalName, boolean>;
  /** Human-readable evidence lines explaining why signals fired. */
  evidence: string[];
  /** One-line summary of the verdict. */
  summary: string;
  /** Whether the agent is currently quarantined (persists across calls). */
  quarantined: boolean;
  /** Whether this specific call was blocked. */
  blocked: boolean;
}

// ── Stored event (internal, but exposed for MemoryClient implementors) ──────

export interface StoredEvent {
  timestamp: string;
  /** Epoch milliseconds (the numeric form of `timestamp`, used by temporal signals). */
  at: number;
  agentId: string;
  action: string;
  /** Canonical action class, precomputed at ingest. Falls back to canonicalizeAction(action) if absent. */
  canonical?: CanonicalAction;
  target: string;
  hour: number;
  metadata?: Record<string, unknown>;
}

// ── Guard configuration ─────────────────────────────────────────────────────

export interface GuardConfig {
  /**
   * Custom sensitivity targets. Calls touching these targets trigger the
   * `sensitive_write` signal. Defaults to targets whose name contains any of:
   * credential, secret, password, api_key, apikey, private_key, token, ssn,
   * sensitive.
   */
  sensitiveTargets?: string[] | ((target: string) => boolean);

  /**
   * Trusted egress destinations — an ALLOWLIST. When set, tack-guard scores the
   * data-exfiltration trajectory: a sensitive target is accessed, then an egress
   * action (send / upload / post / …) targets a destination NOT in this list.
   *
   * Opt-in: if unset, the egress signal is dormant — tack-guard never guesses
   * whether a destination is "external", so there are no egress false positives
   * by default. Mirrors `sensitiveTargets`: a string array (substring match) or
   * a predicate over the destination.
   *
   * Note: a destination here is the egress call's `target` (e.g. the recipient/
   * URL). Agents that legitimately send sensitive data to non-enumerable
   * destinations (e.g. emailing customers their own data) can't be covered by a
   * simple allowlist — use `mode: 'warn'` for those.
   */
  egressTargets?: string[] | ((destination: string) => boolean);

  /**
   * Business hours range [start, end). Calls outside this range trigger
   * `after_hours`. Default: [9, 18].
   */
  businessHours?: [start: number, end: number];

  /**
   * Custom signal weights. Partial override — unspecified signals keep
   * their default weight.
   */
  weights?: Partial<Record<SignalName, number>>;

  /**
   * Minimum calls before baseline is established. Default: 5.
   */
  baselineMin?: number;

  /**
   * Detection threshold (0-1). Confidence below this = no detection.
   * Default: 0.5.
   */
  detectionThreshold?: number;

  /**
   * Verdict policy: what to do when detection fires.
   * - "warn" (default): return "warn" on detection, never "deny"/"quarantine".
   * - "enforce": deny risky calls when quarantined, quarantine on CRITICAL.
   * - "score-only": always return "allow", just report the score.
   */
  mode?: "score-only" | "warn" | "enforce";
}
