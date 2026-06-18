/**
 * tack-guard — Runtime risk scoring for AI agent tool calls.
 *
 * Usage:
 *   import { createGuard } from '@tacksec/guard'
 *
 *   const guard = createGuard()                  // advisory by default: detects + warns
 *   const result = guard.evaluate({ action: 'write', target: 'users' })
 *   if (result.verdict !== 'allow') console.log(result.severity, result.summary)
 *
 *   // opt into inline blocking once you trust the false-positive rate:
 *   const enforcing = createGuard({ mode: 'enforce' })
 */

import { score, type ScoreResult } from "./score.js";
import { checkSignature, type SignatureMatch } from "./signatures.js";
import { canonicalizeAction, isMutating, isEgressAction } from "./actions.js";
import { InMemoryClient } from "./memory/in-memory.js";
import type { MemoryClient } from "./memory/types.js";
import type {
  ToolCall,
  GuardResult,
  GuardConfig,
  StoredEvent,
  Verdict,
} from "./types.js";
import type { SignalName } from "./constants.js";

const ASYNC_CLIENT_ERROR =
  "tack-guard: your MemoryClient is async. Use evaluateAsync() or provide a synchronous MemoryClient.";

// ── Guard state (per agent) ─────────────────────────────────────────────────

interface AgentState {
  quarantined: boolean;
  /** Latched by a stateless signature — survives regardless of memory. */
  signatureTripped: boolean;
  /** The signature that latched this agent, so later calls can explain the quarantine. */
  signatureMatch: SignatureMatch | null;
}

// ── Sensitivity check builder ───────────────────────────────────────────────

// Conservative default sensitive surface — genuinely-sensitive resources only, NOT a
// whole-database prefix (a bare "user_db" quarantined benign first writes to
// user_db.preferences etc.). Kept in sync with score.ts's DEFAULT_SENSITIVE.
const DEFAULT_SENSITIVE = [
  "credential", "secret", "password", "api_key", "apikey", "private_key", "token", "ssn", "sensitive",
];

function buildSensitivityCheck(config?: GuardConfig): (target: string) => boolean {
  if (!config?.sensitiveTargets) {
    return (t) => {
      const lower = t.toLowerCase();
      return DEFAULT_SENSITIVE.some((s) => lower.includes(s));
    };
  }
  if (typeof config.sensitiveTargets === "function") {
    return config.sensitiveTargets;
  }
  const set = new Set(config.sensitiveTargets.map((s) => s.toLowerCase()));
  return (t) => {
    const lower = t.toLowerCase();
    for (const s of set) {
      if (lower.includes(s)) return true;
    }
    return false;
  };
}

type EgressCheck = { active: boolean; isTrusted: (destination: string) => boolean };

// Egress allowlist (opt-in via egressTargets). Mirrors buildSensitivityCheck.
// When inactive, no destination is treated as external — egress risk is dormant,
// so there are no egress false positives by default.
function buildEgressCheck(config?: GuardConfig): EgressCheck {
  const t = config?.egressTargets;
  if (!t) return { active: false, isTrusted: () => true };
  if (typeof t === "function") return { active: true, isTrusted: t };
  const set = new Set(t.map((s) => s.toLowerCase()));
  return {
    active: true,
    isTrusted: (destination) => {
      const lower = destination.toLowerCase();
      for (const s of set) if (lower.includes(s)) return true;
      return false;
    },
  };
}

// ── Risky call detection ────────────────────────────────────────────────────

function isRisky(
  action: string,
  target: string,
  isSensitive: (t: string) => boolean,
  egress: EgressCheck,
): boolean {
  return (
    isMutating(canonicalizeAction(action)) ||
    isSensitive(target) ||
    target.includes("admin") ||
    // An egress to a destination outside the allowlist is risky, so a quarantined
    // agent's exfiltration attempt is actually blocked, not merely detected.
    (egress.active && isEgressAction(action) && !egress.isTrusted(target))
  );
}

/** Thrown by a wrapped tool when the guard blocks the call (unless onBlocked is set). */
export class GuardBlockedError extends Error {
  readonly result: GuardResult;
  constructor(result: GuardResult) {
    super(`tack-guard blocked a tool call: ${result.summary}`);
    this.name = "GuardBlockedError";
    this.result = result;
  }
}

/** Options for {@link Guard.wrapTool}. `action`/`target` may be static or derived from the call args. */
export interface WrapToolOptions<A extends unknown[], R> {
  action: string | ((...args: A) => string);
  target: string | ((...args: A) => string);
  agentId?: string;
  /** Called instead of the wrapped tool when the call is blocked. Default: throw GuardBlockedError. */
  onBlocked?: (result: GuardResult, ...args: A) => R;
}

/**
 * Project a stateless signature match onto the ScoreResult shape so the guard
 * can return a single, consistent result regardless of which layer fired.
 *
 * When `latched` is true, the signature fired on an *earlier* call (the agent
 * is still quarantined). We surface the original quarantine reason instead of
 * the current — possibly still-in-baseline — behavioral state, so a blocked
 * call never reports a self-contradictory "LOW / establishing baseline".
 */
function signatureToScore(
  sig: SignatureMatch,
  signals: Record<SignalName, boolean>,
  latched = false,
): ScoreResult {
  return {
    score: sig.confidence,
    severity: sig.severity,
    pattern: sig.pattern,
    signals,
    evidence: latched
      ? ["agent quarantined by an earlier signature match", ...sig.evidence]
      : sig.evidence,
    summary: latched ? `Agent quarantined: ${sig.summary}` : sig.summary,
    detected: true,
  };
}

// ── Guard instance ──────────────────────────────────────────────────────────

export interface Guard {
  /**
   * Evaluate a tool call. Returns a verdict (allow/warn/deny/quarantine),
   * a confidence score (0-1), and evidence explaining why.
   *
   * < 1ms. Synchronous. Zero network calls.
   *
   * Requires a synchronous MemoryClient (the default InMemoryClient is sync).
   * If you plug in an async client (Redis, SQLite via a network driver, cloud),
   * call {@link Guard.evaluateAsync} instead — `evaluate()` throws on an async
   * client rather than silently skipping the behavioral layer.
   */
  evaluate(call: ToolCall): GuardResult;

  /**
   * Async counterpart of {@link Guard.evaluate}, for use with an asynchronous
   * MemoryClient (Redis, SQLite, cloud, …). Awaits `push`/`getEvents`, then
   * runs the exact same scoring and verdict logic. The scoring itself is still
   * synchronous and local — only the memory I/O is awaited.
   */
  evaluateAsync(call: ToolCall): Promise<GuardResult>;

  /**
   * Reserved hook for connecting to a hosted persistence backend behind a
   * single API key. NOT IMPLEMENTED — it throws.
   *
   * For persistent or cross-session baselines today, implement
   * {@link MemoryClient} and pass it to {@link Guard.setMemory} (use
   * {@link Guard.evaluateAsync} for an async backend). The signature is kept
   * stable so a future hosted backend is a drop-in, non-breaking addition.
   *
   * @param apiKey - API key for the hosted backend.
   */
  connect(apiKey: string): void;

  /**
   * Replace the memory client (e.g., for custom persistence).
   */
  setMemory(client: MemoryClient): void;

  /**
   * Reset all state for a specific agent, or all agents if no ID given.
   */
  reset(agentId?: string): void;

  /**
   * Get the current state for an agent: events count, quarantine status, etc.
   * `events` is -1 if the memory client is async (use evaluateAsync()).
   */
  getAgentState(agentId: string): {
    events: number;
    quarantined: boolean;
    signatureTripped: boolean;
  };

  /**
   * Wrap a tool's function so every call is evaluated first. If the guard
   * blocks the call, the wrapped tool is NOT executed — `onBlocked` runs, or a
   * {@link GuardBlockedError} is thrown. This removes the boilerplate of calling
   * `evaluate()` by hand around each tool.
   *
   * `action`/`target` can be static strings or functions of the call args
   * (e.g. derive the target from the SQL or the file path). Synchronous; for an
   * async memory client, guard the call yourself with `evaluateAsync()`.
   *
   * @example
   * const safeQuery = guard.wrapTool(db.query, {
   *   action: 'read',
   *   target: (sql: string) => sql.includes('credentials') ? 'user_db.credentials' : 'db',
   * })
   */
  wrapTool<A extends unknown[], R>(
    fn: (...args: A) => R,
    opts: WrapToolOptions<A, R>,
  ): (...args: A) => R;
}

/**
 * Create a new tack-guard instance.
 *
 * @param config - Optional configuration (sensitivity, business hours, mode, etc.)
 * @returns A Guard instance with evaluate(), connect(), reset().
 */
export function createGuard(config?: GuardConfig): Guard {
  let memory: MemoryClient = new InMemoryClient();
  const agentStates = new Map<string, AgentState>();
  // Advisory by default (ADR-0006/0007): detect + warn, never auto-block, until
  // enforce-mode benign false-positives are proven < 3%. Opt into blocking with
  // `mode: "enforce"`. "warn" still surfaces detections (verdict "warn" + score),
  // unlike "score-only" which reports verdict "allow" and leaves it to the score.
  const mode = config?.mode ?? "warn";
  const isSensitive = buildSensitivityCheck(config);
  const egress = buildEgressCheck(config);

  function getOrCreateState(agentId: string): AgentState {
    let state = agentStates.get(agentId);
    if (!state) {
      state = { quarantined: false, signatureTripped: false, signatureMatch: null };
      agentStates.set(agentId, state);
    }
    return state;
  }

  function buildEvent(agentId: string, call: ToolCall): StoredEvent {
    const now = new Date();
    return {
      timestamp: now.toISOString(),
      at: call.at ?? now.getTime(),
      agentId,
      action: call.action,
      canonical: canonicalizeAction(call.action),
      target: call.target,
      hour: call.hour ?? now.getHours(),
      metadata: call.metadata,
    };
  }

  /**
   * The shared core: given the freshly stored event and the full event history,
   * run both detection layers and produce the verdict. Identical for the sync
   * and async paths — only how `events` is obtained differs.
   */
  function finalize(
    call: ToolCall,
    event: StoredEvent,
    events: StoredEvent[],
    state: AgentState,
  ): GuardResult {
    // 1. Stateless signature check (memory-independent)
    const signature = checkSignature(event, isSensitive);
    if (signature) {
      state.signatureTripped = true;
      state.signatureMatch = signature;
    }

    // 2. Behavioral scoring (memory-dependent)
    const behavioral = score(events, config);

    // 3. Quarantine decision (recomputed every call; signature latch is permanent)
    const memoryQuarantine = behavioral.severity === "CRITICAL";
    state.quarantined = state.signatureTripped || memoryQuarantine;

    // 4. Pick the result to surface.
    //    - current-call signature wins,
    //    - else a latched signature surfaces its quarantine reason. The
    //      max-by-score tie-break would prefer behavioral if it ever out-scored
    //      the signature; with signature confidence 0.95 > the behavioral ceiling
    //      (0.90), that branch is currently latent — kept as defense against
    //      future constant changes.
    //    - else behavioral.
    let activeResult: ScoreResult;
    if (signature) {
      activeResult = signatureToScore(signature, behavioral.signals);
    } else if (state.signatureTripped && state.signatureMatch) {
      const latched = signatureToScore(state.signatureMatch, behavioral.signals, true);
      activeResult = latched.score >= behavioral.score ? latched : behavioral;
    } else {
      activeResult = behavioral;
    }

    // 5. Verdict based on mode
    const risky = isRisky(call.action, call.target, isSensitive, egress);
    const blockedBySignature = signature !== null;
    let verdict: Verdict;
    let blocked: boolean;

    if (mode === "score-only") {
      verdict = "allow";
      blocked = false;
    } else if (mode === "warn") {
      verdict = activeResult.detected ? "warn" : "allow";
      blocked = false;
    } else {
      // enforce mode
      blocked = blockedBySignature || (state.quarantined && risky);
      if (blocked) {
        // Quarantine is the active containment verdict. A plain "deny" (block a
        // single call without quarantining the agent) is reserved in the Verdict
        // type but currently unreachable: every block path also quarantines.
        verdict = state.quarantined ? "quarantine" : "deny";
      } else if (activeResult.detected) {
        verdict = "warn";
      } else {
        verdict = "allow";
      }
    }

    return {
      verdict,
      score: activeResult.score,
      severity: activeResult.severity,
      pattern: activeResult.pattern,
      signals: activeResult.signals,
      evidence: activeResult.evidence,
      summary: activeResult.summary,
      quarantined: state.quarantined,
      blocked,
    };
  }

  function evaluate(call: ToolCall): GuardResult {
    const agentId = call.agentId ?? "default";
    const state = getOrCreateState(agentId);
    const event = buildEvent(agentId, call);

    const pushed = memory.push(agentId, event);
    if (pushed instanceof Promise) {
      // The async push already fired; swallow its rejection so a backend error
      // doesn't surface as an unhandledRejection alongside the throw below.
      pushed.catch(() => {});
      throw new Error(ASYNC_CLIENT_ERROR);
    }

    const events = memory.getEvents(agentId);
    if (events instanceof Promise) {
      events.catch(() => {});
      throw new Error(ASYNC_CLIENT_ERROR);
    }

    return finalize(call, event, events, state);
  }

  async function evaluateAsync(call: ToolCall): Promise<GuardResult> {
    const agentId = call.agentId ?? "default";
    const state = getOrCreateState(agentId);
    const event = buildEvent(agentId, call);

    await memory.push(agentId, event);
    const events = await memory.getEvents(agentId);

    return finalize(call, event, events, state);
  }

  function connect(_apiKey: string): void {
    // Reserved for a future hosted persistence backend. Until then persistence
    // is bring-your-own: implement MemoryClient and pass it to setMemory()
    // (use evaluateAsync() for an async backend).
    throw new Error(
      "tack-guard: connect() is not implemented. " +
      "tack-guard runs fully offline with in-memory baselines. " +
      "For persistent or cross-session baselines, implement a MemoryClient and call setMemory().",
    );
  }

  function setMemory(client: MemoryClient): void {
    memory = client;
  }

  function reset(agentId?: string): void {
    if (agentId) {
      memory.clear(agentId);
      agentStates.delete(agentId);
    } else {
      memory.clearAll();
      agentStates.clear();
    }
  }

  function getAgentState(agentId: string) {
    const state = agentStates.get(agentId);
    const events = memory.getEvents(agentId);
    const count = events instanceof Promise ? -1 : events.length;
    return {
      events: count,
      quarantined: state?.quarantined ?? false,
      signatureTripped: state?.signatureTripped ?? false,
    };
  }

  function wrapTool<A extends unknown[], R>(
    fn: (...args: A) => R,
    opts: WrapToolOptions<A, R>,
  ): (...args: A) => R {
    return (...args: A): R => {
      const action = typeof opts.action === "function" ? opts.action(...args) : opts.action;
      const target = typeof opts.target === "function" ? opts.target(...args) : opts.target;
      const result = evaluate({ action, target, agentId: opts.agentId });
      if (result.blocked) {
        if (opts.onBlocked) return opts.onBlocked(result, ...args);
        throw new GuardBlockedError(result);
      }
      return fn(...args);
    };
  }

  return { evaluate, evaluateAsync, connect, setMemory, reset, getAgentState, wrapTool };
}
