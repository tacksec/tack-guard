# AgentDojo integration

Third-party efficacy harness: runs tack-guard as a defense element inside
[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zürich) and measures
how much it reduces a hijacked agent's **targeted attack-success rate (ASR)**.

This is the source behind the headline number in the root README — kept here so
the claim is reproducible, not just asserted.

## Result (gpt-4o-mini)

| Metric | No guard | tack-guard (`enforce`) |
|---|---|---|
| Targeted attack-success rate | 47% | **27%** |
| Inbox-exfiltration reaching the attacker | 4 of 4 runs | **0 of 4 runs** |

Blocked inline in ~3µs, before the tool call (e.g. the email send) executes. A
capable model (Claude) largely self-resists, so the value concentrates on
susceptible models. Live, per-suite breakdown: **[tacksec.com/benchmarks](https://tacksec.com/benchmarks)**.

> Numbers are model- and version-sensitive. Re-run on the version you ship before
> quoting them — see below.

## How it works

tack-guard scores tool calls in TypeScript; AgentDojo is in Python. They talk
over a tiny HTTP shim:

| File | Role |
|---|---|
| `server.mjs` | tack-guard HTTP shim — exposes `POST /evaluate` (default `http://127.0.0.1:3737/evaluate`) |
| `tack_guard_element.py` | tack-guard wired in as an AgentDojo defense element (calls the shim) |
| `run.py` | the runner — picks model/suite/attack, guard on/off, writes per-task results |
| `cost.py` | token/cost metering for a run |
| `progress_json.py`, `progress.sh`, `watch.sh` | live progress of a long sweep (read `runs/costs.jsonl`) |
| `breadth.sh`, `breadth_on.sh`, `claude_finish.sh` | orchestration for the full multi-suite / multi-model sweep |

Per-task JSON logs are written under `runs/`, which is **gitignored** to keep the
repo lean (the data can be large; regenerate it with the commands below).

## Reproduce

Requires Python with [`agentdojo`](https://github.com/ethz-spylab/agentdojo)
installed and a provider API key (e.g. `OPENAI_API_KEY` for `gpt-4o-mini`).

```bash
# 1. Start the tack-guard scoring shim (Node, from the repo root):
npm run build && node eval/agentdojo/server.mjs

# 2. Baseline — guard OFF:
python eval/agentdojo/run.py --model gpt-4o-mini --suite banking --no-defense

# 3. With the guard — ON, enforcing:
python eval/agentdojo/run.py --model gpt-4o-mini --suite banking --security --mode enforce
```

Compare the targeted-ASR between the two runs. `--suite` also accepts
`travel` / `slack` / `workspace`; `--shim` overrides the endpoint.
