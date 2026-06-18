# Vendored dataset — InjecAgent

These files are the **InjecAgent** benchmark dataset, vendored here for offline replay.

- **Source:** https://github.com/uiuc-kang-lab/InjecAgent (the `data/` directory)
- **Paper:** "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents", Zhan et al., ACL 2024 (arXiv:2403.02691)
- **License:** MIT — redistribution permitted with this notice.
- **Fetched by:** [`fetch.mjs`](fetch.mjs)

## Files

| File | What |
|---|---|
| `test_cases_dh_base.json` | Direct-harm attacks — a single malicious tool call. |
| `test_cases_ds_base.json` | Data-stealing attacks — two stages: extract → `GmailSendEmail`. |
| `user_cases.jsonl` | Benign user-tool cases — used for the benign/false-positive corpus and baseline seeding. |

## How we use it

We use only the tool **names** and their **order** (an offline action/target replay
through `inferToolCall()` → `guard.evaluate()`). The injected text and the
attacker-tool arguments are **not** used: tack-guard scores tool calls, not
message content. This measures "would the guard have blocked the malicious tool
call", which is a different quantity from InjecAgent's own attack-success rate.
See [`../../injecagent.mjs`](../../injecagent.mjs).
