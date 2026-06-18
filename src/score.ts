/**
 * Behavioral scoring engine.
 *
 * Scores a stream of tool calls against a per-agent baseline built from observed calls. Memory-dependent:
 * without history there is no baseline to deviate from, so the score stays at 0.
 * The behavioral layer is what catches slow, subtle attacks (credential-creep)
 * that have no single damning call.
 *
 * The confidence score is the weighted sum of fired signals (clamped to 0-1) —
 * it GRADES with evidence strength, it is not a hardcoded constant. Actions are
 * canonicalized, so detection survives synonyms ("update", "Exfiltrate", …),
 * and two temporal signals (rapid_burst, plus the escalation time-span surfaced
 * in evidence) use the event timestamps.
 */

import {
  WEIGHTS,
  BASELINE_MIN,
  DETECTION_THRESHOLD,
  RAPID_BURST_WINDOW_MS,
  RAPID_BURST_MIN,
  type SignalName,
} from "./constants.js";
import { canonicalizeAction, isMutating, isEgressAction, type CanonicalAction } from "./actions.js";
import type {
  StoredEvent,
  Severity,
  Pattern,
  GuardConfig,
} from "./types.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

const round2 = (n: number): number => Math.round(n * 100) / 100;
const clamp01 = (n: number): number => Math.max(0, Math.min(1, n));

type SensitivityCheck = (target: string) => boolean;

// Conservative default surface: genuinely-sensitive RESOURCES, not a whole-database
// prefix. Matching a bare "user_db" quarantined benign first writes to user_db.preferences
// / user_db.metrics etc. — a documented foot-gun where credential-creep (which bypasses
// the detection threshold) blocked legitimate work. Real credential-creep targets
// credentials/secrets/tokens, which these still match; callers with a different sensitive
// surface pass an explicit `sensitiveTargets`.
const DEFAULT_SENSITIVE = [
  "credential", "secret", "password", "api_key", "apikey", "private_key", "token", "ssn", "sensitive",
];

function buildSensitivityCheck(config?: GuardConfig): SensitivityCheck {
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

// Egress allowlist. Opt-in: with no egressTargets, `active` is false and the
// data-exfiltration signal stays dormant (no destination is ever judged
// "external"), so there are zero egress false positives by default.
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

const canon = (e: StoredEvent): CanonicalAction =>
  e.canonical ?? canonicalizeAction(e.action);

function isAdmin(event: StoredEvent): boolean {
  return canon(event) === "admin" || event.target.includes("admin");
}

function isAfterHours(hour: number, config?: GuardConfig): boolean {
  const [start, end] = config?.businessHours ?? [9, 18];
  if (start <= end) {
    // Normal range, e.g. [9, 18): after-hours is before 9 or at/after 18.
    return hour < start || hour >= end;
  }
  // Wrapped range, e.g. [22, 6): business hours span midnight.
  return hour >= end && hour < start;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.max(0, Math.round(ms))}ms`;
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

/** Count events whose timestamp falls within the burst window ending at `latest`. */
function burstCount(events: StoredEvent[], windowMs: number): number {
  const latest = events[events.length - 1].at;
  let n = 0;
  for (const e of events) if (e.at >= latest - windowMs) n++;
  return n;
}

// ── Scoring ─────────────────────────────────────────────────────────────────

export interface ScoreResult {
  score: number;
  severity: Severity;
  pattern: Pattern;
  signals: Record<SignalName, boolean>;
  evidence: string[];
  summary: string;
  detected: boolean;
}

const NO_SIGNALS: Record<SignalName, boolean> = {
  escalation_trajectory: false,
  sensitive_write: false,
  sensitive_egress: false,
  volume_spike: false,
  rapid_burst: false,
  new_write_access: false,
  after_hours: false,
  admin_attempt: false,
};

/**
 * Score a stream of events for a single agent.
 *
 * @param events - All events for this agent, oldest first.
 * @param config - Optional guard configuration overrides.
 */
export function score(events: StoredEvent[], config?: GuardConfig): ScoreResult {
  const baselineMin = config?.baselineMin ?? BASELINE_MIN;
  const threshold = config?.detectionThreshold ?? DETECTION_THRESHOLD;
  const weights = { ...WEIGHTS, ...config?.weights };
  const isSensitive = buildSensitivityCheck(config);
  const egress = buildEgressCheck(config);

  // Data-exfiltration is an intrinsic malicious flow — a sensitive access, then an
  // egress to an untrusted destination — NOT a learned-baseline deviation. So,
  // like the stateless signatures, it must fire even BEFORE the baseline window
  // fills; otherwise a 2-call read->exfil sails through as "establishing baseline".
  if (egress.active) {
    const firstSensitive = events.findIndex((e) => isSensitive(e.target));
    if (firstSensitive !== -1) {
      for (let i = firstSensitive; i < events.length; i++) {
        const e = events[i];
        if (isEgressAction(e.action) && !egress.isTrusted(e.target)) {
          return {
            score: clamp01(round2(weights.sensitive_write + weights.sensitive_egress)),
            severity: "CRITICAL",
            pattern: "data-exfiltration",
            signals: { ...NO_SIGNALS, sensitive_write: true, sensitive_egress: true },
            evidence: [
              `access to sensitive target: ${events[firstSensitive].target}`,
              `sensitive data sent to an untrusted destination: ${e.target}`,
            ],
            summary:
              "Sensitive data accessed, then sent to an untrusted destination. Data-exfiltration detected.",
            detected: true,
          };
        }
      }
    }
  }

  // Not enough data to establish a baseline.
  if (events.length < baselineMin) {
    return {
      score: 0,
      severity: "LOW",
      pattern: "none",
      signals: { ...NO_SIGNALS },
      evidence: [],
      summary: `establishing baseline (${events.length}/${baselineMin} calls)`,
      detected: false,
    };
  }

  // Categorize events
  const mutations = events.filter((e) => isMutating(canon(e)));
  const sensitive = events.filter((e) => isSensitive(e.target));
  const admin = events.filter(isAdmin);
  const after = events.filter((e) => isAfterHours(e.hour, config));
  const burst = burstCount(events, RAPID_BURST_WINDOW_MS);

  // Was the baseline read-only? Escalation only means something if the agent
  // established a pattern of reads first. (baselineMin === 0 has no read-only
  // norm, so these signals must not fire on the very first call.)
  const baselineReadOnly =
    baselineMin > 0 && events.slice(0, baselineMin).every((e) => canon(e) === "read");

  const signals: Record<SignalName, boolean> = {
    escalation_trajectory:
      baselineReadOnly && mutations.length > 0 && (sensitive.length > 0 || admin.length > 0),
    sensitive_write: sensitive.length > 0,
    // data-exfiltration fired (if at all) in the pre-baseline early return above.
    sensitive_egress: false,
    volume_spike: events.length >= Math.max(baselineMin, 1) * 3,
    rapid_burst: burst >= RAPID_BURST_MIN,
    new_write_access: baselineReadOnly && mutations.length > 0,
    after_hours: after.length > 0,
    admin_attempt: admin.length > 0,
  };

  // Weighted sum of fired signals, clamped to [0, 1]. No constant floors — the
  // score grades with how much evidence stacked up.
  const confidence = clamp01(
    round2(
      (Object.entries(signals) as [SignalName, boolean][])
        .filter(([, fired]) => fired)
        .reduce((sum, [name]) => sum + weights[name], 0),
    ),
  );

  // Credential-creep (read-only -> sensitive escalation) is ALWAYS a detection,
  // regardless of the tunable threshold or weights — enforcement of the flagship
  // pattern must not be demotable by a config knob. Everything else is gated by
  // the threshold.
  const credentialCreep = signals.escalation_trajectory && signals.sensitive_write;

  if (confidence < threshold && !credentialCreep) {
    return {
      score: confidence,
      severity: "LOW",
      pattern: "none",
      signals,
      evidence: [],
      summary: "activity within baseline",
      detected: false,
    };
  }

  // Severity: CRITICAL reserved for credential-creep (exfiltration in progress).
  // Other anomaly combinations grade HIGH/MEDIUM by confidence.
  const severity: Severity = credentialCreep
    ? "CRITICAL"
    : confidence >= 0.6
      ? "HIGH"
      : "MEDIUM";

  const pattern: Pattern = credentialCreep
    ? "credential-creep"
    : (signals.rapid_burst || signals.volume_spike) && !signals.escalation_trajectory
      ? "smash-and-grab"
      : "behavioral-drift";

  // Human-readable evidence
  const span = events[events.length - 1].at - events[0].at;
  const evidence: string[] = [];
  if (signals.new_write_access)
    evidence.push(`${mutations.length} mutation(s) after a read-only baseline`);
  if (signals.sensitive_write)
    evidence.push(`access to sensitive target: ${sensitive[0].target}`);
  if (signals.admin_attempt) evidence.push("admin access attempt");
  if (signals.after_hours) evidence.push(`${after.length} after-hours call(s)`);
  if (signals.volume_spike)
    evidence.push(`call volume ${events.length} (>= 3x baseline)`);
  if (signals.rapid_burst)
    evidence.push(`rapid burst: ${burst} calls within ${RAPID_BURST_WINDOW_MS / 1000}s`);
  if (signals.escalation_trajectory)
    evidence.push(`trajectory: read-only -> mutate -> sensitive/admin over ${formatDuration(span)}`);

  const summary =
    pattern === "credential-creep"
      ? "Agent escalated from read-only to sensitive/admin access. Credential-creep detected."
      : `Anomalous behavior detected (${pattern}).`;

  return {
    score: confidence,
    severity,
    pattern,
    signals,
    evidence,
    summary,
    detected: true,
  };
}
