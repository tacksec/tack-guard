/**
 * Vendor the InjecAgent dataset for offline replay. Run once:
 *
 *   node eval/data/injecagent/fetch.mjs
 *
 * Source: https://github.com/uiuc-kang-lab/InjecAgent (MIT). We only need the
 * materialized test cases (tool names + order) and the benign user cases — the
 * injected text and attacker-tool arguments are not used (tack-guard scores tool
 * calls, not message text). The fetched files are committed so `npm run
 * benchmarks` stays fully offline and deterministic. See ATTRIBUTION.md.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RAW = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/";
const FILES = ["test_cases_dh_base.json", "test_cases_ds_base.json", "user_cases.jsonl"];
const here = (p) => fileURLToPath(new URL(p, import.meta.url));

mkdirSync(here("."), { recursive: true });
for (const f of FILES) {
  const res = await fetch(RAW + f);
  if (!res.ok) throw new Error(`${f}: HTTP ${res.status}`);
  const body = await res.text();
  writeFileSync(here(f), body);
  console.log(`fetched ${f} (${(body.length / 1024).toFixed(0)} KB)`);
}
console.log("done — InjecAgent data vendored into eval/data/injecagent/");
