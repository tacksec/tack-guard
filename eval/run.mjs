/**
 * Evaluation runner — replays the labeled corpus and reports precision/recall.
 *
 *   npm run eval          # builds, then runs this
 *   node eval/run.mjs     # if dist/ is already built
 *
 * A scenario counts as "flagged" if ANY call returns a non-allow verdict
 * (warn / deny / quarantine). Timestamps are assigned deterministically so the
 * result does not depend on machine speed: 5ms apart for `burst` scenarios
 * (trips rapid_burst), 1500ms apart otherwise (does not).
 */
import { createGuard } from "../dist/index.js";
import { corpus } from "./corpus.mjs";

let tp = 0, fp = 0, tn = 0, fn = 0;
const rows = [];

for (const s of corpus) {
  const guard = createGuard(s.config);
  const step = s.burst ? 5 : 1500;
  let flagged = false;
  let pattern = "none";

  s.calls.forEach((c, i) => {
    const r = guard.evaluate({ ...c, at: 1_000_000 + i * step });
    if (r.verdict !== "allow") flagged = true;
    if (r.pattern !== "none") pattern = r.pattern;
  });

  const actualPositive = s.label === "attack";
  let outcome;
  if (actualPositive && flagged) { tp++; outcome = "TP"; }
  else if (actualPositive && !flagged) { fn++; outcome = "FN"; }
  else if (!actualPositive && flagged) { fp++; outcome = "FP"; }
  else { tn++; outcome = "TN"; }

  rows.push({ name: s.name, label: s.label, outcome, pattern, hard: !!s.hard });
}

const precision = tp / (tp + fp || 1);
const recall = tp / (tp + fn || 1);
const f1 = (2 * precision * recall) / (precision + recall || 1);
const accuracy = (tp + tn) / corpus.length;
const pct = (n) => `${(n * 100).toFixed(1)}%`;

const mark = { TP: "OK", TN: "OK", FN: "MISS", FP: "FALSE+" };
console.log("\ntack-guard — evaluation\n");
for (const r of rows) {
  const flag = r.outcome === "FN" || r.outcome === "FP" ? ` <-- ${mark[r.outcome]}` : "";
  console.log(
    `  ${r.outcome.padEnd(2)} ${(r.hard ? "* " : "  ")}${r.name.padEnd(42)} ${r.pattern}${flag}`,
  );
}
console.log("\n  (* = deliberately hard case)\n");
console.log(`  scenarios : ${corpus.length}  (TP ${tp} / FP ${fp} / TN ${tn} / FN ${fn})`);
console.log(`  precision : ${pct(precision)}   recall: ${pct(recall)}   f1: ${pct(f1)}   accuracy: ${pct(accuracy)}\n`);

// Non-zero exit if detection collapses, so CI/eval catches regressions.
if (recall < 0.6 || precision < 0.6) {
  console.error("Detection quality regressed below the 0.6 floor.");
  process.exit(1);
}
