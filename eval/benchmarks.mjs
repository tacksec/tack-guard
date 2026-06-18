/**
 * Benchmark runner — emits the normalized results.json the scorecard renders.
 *
 *   npm run benchmarks        # builds, then runs this
 *   node eval/benchmarks.mjs  # if dist/ is already built
 *
 * Every benchmark (the internal corpus + InjecAgent today; AgentDojo next) is
 * reduced to the SAME result record, so any renderer can display any of them
 * without special-casing. That shape is the stable result contract.
 *
 * Unlike run.mjs (the CI regression gate, which fails the build below 0.6),
 * this one only REPORTS: it never exits non-zero. Scores per scenario are the
 * max non-allow confidence over its calls; timestamps are deterministic so the
 * result does not depend on machine speed (mirrors run.mjs).
 */
import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createGuard } from "../dist/index.js";
import { corpus } from "./corpus.mjs";
import { injecAgentScenarios } from "./injecagent.mjs";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const pkg = JSON.parse(readFileSync(here("../package.json"), "utf8"));
const round = (n, d = 3) => Math.round(n * 10 ** d) / 10 ** d;

/** AUC via Mann-Whitney: P(score(attack) > score(benign)); ties count half. */
function auc(pos, neg) {
  if (!pos.length || !neg.length) return null;
  let wins = 0, ties = 0;
  for (const p of pos) for (const n of neg) {
    if (p > n) wins++;
    else if (p === n) ties++;
  }
  return round((wins + 0.5 * ties) / (pos.length * neg.length));
}

/**
 * Replay one labeled corpus through a fresh guard per scenario and reduce it to
 * a single normalized result record (the dashboard contract).
 *
 * @param scenarios - [{ name, label: "attack"|"benign", category?, calls, config?, burst? }]
 * @param meta - fields the runner can't infer (mapper_version, model, …).
 */
function runBenchmark(name, version, scenarios, meta = {}) {
  let tp = 0, fp = 0, tn = 0, fn = 0, benignBlocked = 0;
  const attackScores = [], benignScores = [];
  const cat = {}; // category -> { tp, fn }

  for (const s of scenarios) {
    // Enforce mode so we can measure benign-task utility — what an inline BLOCKER
    // would actually break. Detection (flagging via verdict !== "allow") is
    // mode-independent, so recall/precision/fpr are unaffected by forcing enforce.
    const guard = createGuard({ ...s.config, mode: "enforce" });
    const step = s.burst ? 5 : 1500; // burst spacing trips rapid_burst; see run.mjs
    let flagged = false, blocked = false, maxScore = 0;

    s.calls.forEach((c, i) => {
      const r = guard.evaluate({ ...c, at: 1_000_000 + i * step });
      if (r.verdict !== "allow") flagged = true;
      if (r.blocked) blocked = true;
      if (r.score > maxScore) maxScore = r.score;
    });

    const positive = s.label === "attack";
    (positive ? attackScores : benignScores).push(maxScore);
    if (positive) {
      const c = (cat[s.category ?? "_all"] ??= { tp: 0, fn: 0 });
      if (flagged) { tp++; c.tp++; } else { fn++; c.fn++; }
    } else {
      if (flagged) fp++; else tn++;
      if (blocked) benignBlocked++; // a blocked benign scenario = lost utility
    }
  }

  const recall = round(tp / (tp + fn || 1));
  const precision = round(tp / (tp + fp || 1));
  const fpr = round(fp / (fp + tn || 1)); // the existential metric
  const f1 = round((2 * precision * recall) / (precision + recall || 1));
  // Benign-task utility in ENFORCE mode: the share of legitimate scenarios the guard
  // does NOT block. no_defense_baseline is 1.0 (without a guard, nothing is blocked),
  // so the utility COST an inline blocker imposes is (1 - benign_utility).
  const benignTotal = tn + fp;
  const benign_utility = benignTotal ? round((benignTotal - benignBlocked) / benignTotal) : null;
  const no_defense_baseline = benignTotal ? 1 : null;
  const by_category = Object.keys(cat).length > 1
    ? Object.fromEntries(Object.entries(cat).map(([k, v]) => [k, round(v.tp / (v.tp + v.fn || 1))]))
    : null;

  return {
    benchmark: name,
    benchmark_version: version,
    tackguard_version: pkg.version,
    // Provenance is first-class: a score is meaningless without it.
    mapper_version: meta.mapper_version ?? null,
    model: meta.model ?? null,
    mode: meta.mode ?? "enforce",
    detection: { recall, precision, f1, by_category },
    false_pos: {
      fpr,
      benign_utility: meta.benign_utility ?? benign_utility,
      no_defense_baseline: meta.no_defense_baseline ?? no_defense_baseline,
    },
    separation: { auc: auc(attackScores, benignScores) },
    // The runner can't see which layer (signature vs behavioral) fired without
    // guard internals; left null until the result surfaces it. No fabrication.
    layer_split: meta.layer_split ?? null,
    n_cases: { attack: tp + fn, benign: tn + fp },
    date: new Date().toISOString(),
  };
}

const records = [
  // Internal corpus: actions/targets are passed explicitly (hand-written), so
  // there is no inference mapper under test here.
  runBenchmark("internal-corpus", "v1", corpus, { mapper_version: "explicit" }),

  // InjecAgent (third-party, MIT). Two configurations, side by side.
  runBenchmark("injecagent · default", "base", injecAgentScenarios("default"), {
    mapper_version: "inferToolCall (defaults)",
  }),
  runBenchmark("injecagent · tuned", "base", injecAgentScenarios("tuned"), {
    mapper_version: "inferToolCall + domain-sensitivity + seeded read baseline",
  }),
];

writeFileSync(here("results.json"), JSON.stringify({ results: records }, null, 2) + "\n");

// ── Human-readable tracker view — the "dashboard" until the public scorecard ──
const pct = (n) => (n == null ? "n/a" : `${(n * 100).toFixed(1)}%`);
const byCat = (r) =>
  r.detection.by_category
    ? Object.entries(r.detection.by_category).map(([k, v]) => `${k} ${pct(v)}`).join(", ")
    : "";

const mdRows = records
  .map(
    (r) =>
      `| ${r.benchmark} | ${r.benchmark_version} | ${r.tackguard_version} | ` +
      `${pct(r.detection.recall)} | ${pct(r.detection.precision)} | ${pct(r.false_pos.fpr)} | ` +
      `${r.separation.auc ?? "n/a"} | ${r.n_cases.attack} / ${r.n_cases.benign} |`,
  )
  .join("\n");
const mdCats = records
  .filter((r) => r.detection.by_category)
  .map((r) => `- **${r.benchmark}** — by category: ${byCat(r)}  ·  mapper: \`${r.mapper_version}\``)
  .join("\n");
const md = `# tack-guard — benchmark results

> Generated by \`npm run benchmarks\`. Do not edit by hand — the source of truth is \`eval/results.json\`.
> One row per benchmark configuration. **FPR** (false-positive rate) is the metric that matters most
> for an inline guard; **AUC** is the benign-vs-attack score separation (1.0 = perfect).

| Benchmark | Ver. | tack-guard | Recall | Precision | FPR | AUC | Cases (atk / ben) |
|---|---|---|---|---|---|---|---|
${mdRows}

${mdCats ? `### Detection by category\n\n${mdCats}\n` : ""}
_Last run: ${records[0]?.date ?? "n/a"}_
`;
writeFileSync(here("RESULTS.md"), md);

console.log("\ntack-guard — benchmarks\n");
for (const r of records) {
  console.log(`  ${r.benchmark} (${r.benchmark_version}, tack-guard ${r.tackguard_version})`);
  console.log(`    cases     : ${r.n_cases.attack} attack / ${r.n_cases.benign} benign`);
  console.log(`    recall    : ${pct(r.detection.recall)}   precision: ${pct(r.detection.precision)}   f1: ${pct(r.detection.f1)}`);
  if (r.detection.by_category) console.log(`    by category: ${byCat(r)}`);
  console.log(`    fpr       : ${pct(r.false_pos.fpr)}   (false positives — the metric that kills)`);
  {
    const bu = r.false_pos.benign_utility, base = r.false_pos.no_defense_baseline;
    const cost = bu != null && base != null ? base - bu : null;
    console.log(`    benign util: ${pct(bu)} in enforce mode (baseline ${pct(base)}, utility cost ${pct(cost)})`);
  }
  console.log(`    auc (sep) : ${r.separation.auc}\n`);
}
console.log(`  wrote eval/results.json + eval/RESULTS.md (${records.length} record(s))\n`);
