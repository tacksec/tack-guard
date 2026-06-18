/**
 * Stateless signature layer — memory-INDEPENDENT detection.
 *
 * Flat, per-call rules that need no baseline or history. They catch blatant,
 * self-evidently malicious single-shot actions: a wholesale credential dump, a
 * destructive wipe. This is the deliberate foil to the behavioral scorer:
 * signatures fire even without memory, catching the loud attacks; the slow
 * credential-creep, which has no single damning call, needs the behavioral layer.
 *
 * Actions are matched via `canonicalizeAction`, so synonyms and casing
 * ("Exfiltrate", "export_all", "drop_table") don't slip past.
 */

import type { StoredEvent, Pattern, Severity } from "./types.js";
import { canonicalizeAction } from "./actions.js";

export interface SignatureMatch {
  detected: true;
  pattern: Pattern;
  confidence: number;
  severity: Severity;
  evidence: string[];
  summary: string;
}

/**
 * Check a single tool call against stateless attack signatures.
 *
 * @returns A SignatureMatch if the call is blatantly malicious, null otherwise.
 */
export function checkSignature(
  event: StoredEvent,
  isSensitive: (target: string) => boolean,
): SignatureMatch | null {
  const canonical = event.canonical ?? canonicalizeAction(event.action);
  const { target } = event;
  const sensitive = isSensitive(target);

  const exfil = canonical === "exfiltrate" && sensitive;
  const destroy = canonical === "destroy" && sensitive;

  if (!exfil && !destroy) return null;

  return {
    detected: true,
    pattern: "smash-and-grab",
    confidence: 0.95,
    severity: "CRITICAL",
    evidence: [
      exfil
        ? `single-shot bulk export of ${target}`
        : `destructive mass operation on ${target}`,
      "matches a known attack signature — no behavioral history required",
    ],
    summary: exfil
      ? "Blatant exfiltration: bulk export of sensitive data. Blocked by stateless signature."
      : "Blatant destructive action on sensitive target. Blocked by stateless signature.",
  };
}
