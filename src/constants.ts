/**
 * Signal weights for the behavioral scoring model.
 *
 * Each weight is the contribution of one signal to the threat confidence score
 * (0-1, clamped). No single signal alone clears the detection threshold (0.5) —
 * detection always takes a combination. Scores are the weighted sum of fired
 * signals, so confidence GRADES with the strength of evidence (it is not a
 * hardcoded constant): a bare read→write→sensitive escalation scores ~0.57,
 * and each additional signal (admin probe, after-hours, a rapid burst) pushes
 * it higher.
 *
 * Starting weights were hand-set against credential-creep / smash-and-grab /
 * drift scenarios. They are not claimed to be empirically optimal — see the
 * eval harness (`npm run eval`) for the precision/recall they actually produce.
 */
export const WEIGHTS = {
  /** Read-only baseline violated + scope grew to sensitive/admin. */
  escalation_trajectory: 0.25,
  /** Any access (read or mutate) to a sensitive target. */
  sensitive_write: 0.22,
  /** Sensitive data accessed, then sent to a destination outside the egress allowlist. Opt-in via `egressTargets`. */
  sensitive_egress: 0.3,
  /** Call volume >= 3x the baseline window. */
  volume_spike: 0.15,
  /** Many calls within a short wall-clock window (automated burst). Temporal. */
  rapid_burst: 0.15,
  /** First mutation after an established read-only baseline. */
  new_write_access: 0.1,
  /** Activity outside business hours (default half-open [9, 18)). */
  after_hours: 0.08,
  /** Admin access or admin target touched. */
  admin_attempt: 0.07,
} as const;

export type SignalName = keyof typeof WEIGHTS;

/**
 * Minimum number of tool calls before a behavioral baseline is considered
 * established. Until this threshold, the guard returns "establishing baseline".
 */
export const BASELINE_MIN = 5;

/**
 * Confidence threshold below which the guard reports "within baseline".
 * Signals that fire but stay under this produce no detection.
 */
export const DETECTION_THRESHOLD = 0.5;

/**
 * Window (ms) for the `rapid_burst` signal. >= RAPID_BURST_MIN calls landing
 * within this wall-clock window looks automated rather than human-paced.
 */
export const RAPID_BURST_WINDOW_MS = 5_000;

/** Minimum calls within RAPID_BURST_WINDOW_MS to trip `rapid_burst`. */
export const RAPID_BURST_MIN = 10;
