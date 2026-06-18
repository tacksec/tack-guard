/**
 * InjecAgent → corpus scenarios (offline replay through the SHIPPED adapter).
 *
 * Each InjecAgent test case is reduced to a sequence of {action, target} calls
 * via `inferToolCall()` — the same adapter a developer uses — so we benchmark
 * the real artifact, not a bespoke mapper. We use only the tool NAMES and their
 * ORDER; the injected text and attacker-tool arguments are not used (tack-guard
 * scores tool calls, not message content). See data/injecagent/ATTRIBUTION.md.
 *
 * Two configurations are reported side by side:
 *  - "default": inferToolCall + default config, attacker sequence only. What a
 *    developer gets at zero config. A behavioral guard has nothing to work with
 *    on a 1-2 call injection, so detection is expected to be ~0 — that is honest,
 *    not a bug.
 *  - "tuned": seed a read-only baseline from the benign User Tool (so escalation
 *    can register) and mark InjecAgent's sensitive domains. The fair test of the
 *    behavioral thesis. NOTE: targets here are tool NAMES (offline data has no
 *    attacker-tool args), so sensitivity is matched on the tool name as a proxy.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inferToolCall } from "../dist/index.js";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const loadJson = (f) => JSON.parse(readFileSync(here(`data/injecagent/${f}`), "utf8"));
const loadJsonl = (f) =>
  readFileSync(here(`data/injecagent/${f}`), "utf8").trim().split("\n").map((l) => JSON.parse(l));

// Domain words that name a sensitive resource in InjecAgent's tool names.
// Used ONLY in the "tuned" configuration. Frozen + documented as part of the
// reported number (the mapper/config IS under test alongside the guard).
export const SENSITIVE_DOMAINS = [
  "address", "payment", "card", "account", "balance", "bank", "fund", "deposit",
  "withdraw", "credential", "password", "secret", "token", "ssn", "social",
  "health", "patient", "medical", "genetic", "dna", "lock", "door", "policy",
  "contact", "history",
];

const HOUR = 14; // neutral business-hour stamp — deterministic, no after-hours bonus (stay fair)

// One guard-input call per tool name, via the shipped adapter (empty args →
// target falls back to the tool name).
const toCalls = (toolNames) =>
  toolNames.map((name) => ({ ...inferToolCall({ name, arguments: {} }), hour: HOUR }));

/**
 * Build the labeled scenarios for one configuration.
 * @param mode - "default" | "tuned"
 */
export function injecAgentScenarios(mode) {
  const tuned = mode === "tuned";
  const config = tuned ? { sensitiveTargets: SENSITIVE_DOMAINS } : undefined;
  const dh = loadJson("test_cases_dh_base.json");
  const ds = loadJson("test_cases_ds_base.json");
  const users = loadJsonl("user_cases.jsonl");

  // In tuned mode, seed a 5-call read-only baseline from the benign user tool so
  // an escalation has something to deviate from. In default mode, no seeding.
  const seed = (userTool) =>
    tuned ? toCalls(Array.from({ length: 5 }, () => userTool)) : [];

  const scenarios = [];

  dh.forEach((r, i) =>
    scenarios.push({
      name: `dh#${i}:${r["Attacker Tools"][0]}`,
      label: "attack", category: "dh", config,
      calls: [...seed(r["User Tool"]), ...toCalls(r["Attacker Tools"])],
    }),
  );
  ds.forEach((r, i) =>
    scenarios.push({
      name: `ds#${i}:${r["Attacker Tools"].join(">")}`,
      label: "attack", category: "ds", config,
      calls: [...seed(r["User Tool"]), ...toCalls(r["Attacker Tools"])],
    }),
  );
  // Benign corpus: each user tool used legitimately (6 reads, past the baseline
  // window so it is actually scored). A guard that flags these is false-positive.
  users.forEach((u, i) =>
    scenarios.push({
      name: `benign#${i}:${u["User Tool"]}`,
      label: "benign", category: "benign", config,
      calls: toCalls(Array.from({ length: 6 }, () => u["User Tool"])),
    }),
  );

  return scenarios;
}
