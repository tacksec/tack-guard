#!/usr/bin/env bash
# Live progress of the breadth sweep. Reads runs/costs.jsonl (one line per
# completed sub-run) against the planned 16-step sequence. Re-run anytime.
cd "$(dirname "$0")"
/tmp/adojo-venv/bin/python - <<'PY'
import json, os, datetime

# planned sequence: 2 models x 4 suites x [OFF, ON] = 16 steps
MODELS = [("openai", "gpt-4o-mini"), ("anthropic", "claude-haiku-4-5")]
SUITES = ["workspace", "banking", "travel", "slack"]
PAIRS = {"workspace": 70, "banking": 45, "travel": 35, "slack": 25}  # 5 user tasks x injections
plan = [(p, m, s, g) for p, m in MODELS for s in SUITES for g in (False, True)]
TOTAL_STEPS = len(plan)
TOTAL_RUNS = sum(PAIRS[s] for _, _, s, _ in plan)

rows = []
path = "runs/costs.jsonl"
if os.path.exists(path):
    for line in open(path):
        line = line.strip()
        if line:
            try: rows.append(json.loads(line))
            except: pass

# a row is a BREADTH step only if its run count matches the full suite pair count
# (excludes the small 6-run cost-measurement runs already in the log).
breadth = [d for d in rows if d.get("runs") == PAIRS.get(d.get("suite"))]
spent_total = sum(d.get("cost_usd") or 0 for d in rows)

done_steps = len(breadth)
done_runs = sum(d.get("runs", 0) for d in breadth)
spent = sum(d.get("cost_usd") or 0 for d in breadth)
wall = sum(d.get("wall_s") or 0 for d in breadth)
per_run = (wall / done_runs) if done_runs else 12.0  # seconds; seed before first step lands
eta_s = (TOTAL_RUNS - done_runs) * per_run

# wall-clock elapsed since the first breadth step finished (approx)
elapsed_min = None
if breadth:
    try:
        t0 = min(datetime.datetime.fromisoformat(d["ts"]) for d in breadth if d.get("ts"))
        elapsed_min = (datetime.datetime.now() - t0).total_seconds() / 60
    except Exception:
        pass

bar_n = int(28 * done_steps / TOTAL_STEPS)
bar = "█" * bar_n + "·" * (28 - bar_n)

print(f"\n  BREADTH SWEEP  [{bar}]  {done_steps}/{TOTAL_STEPS} steps")
print(f"  runs   : {done_runs}/{TOTAL_RUNS}")
print(f"  spent  : ${spent:.4f}   (total logged incl. measurements: ${spent_total:.4f})")
if elapsed_min is not None:
    print(f"  clock  : {elapsed_min:.0f} min since first step done   ETA ~{eta_s/60:.0f} min left")
else:
    print(f"  clock  : first step still running (~{PAIRS['workspace']} runs)   ETA ~{eta_s/60:.0f} min")

if done_steps < TOTAL_STEPS:
    p, m, s, g = plan[done_steps]
    print(f"  NOW    : [{p}:{m}] {s}  GUARD {'ON' if g else 'OFF'}  (~{PAIRS[s]} runs)")
else:
    print("  ✅ DONE")

print("\n  completed breadth steps:")
if not breadth:
    print("    (none yet — first step in progress)")
for d in breadth:
    g = "ON " if d.get("guard") else "OFF"
    print(f"    {d['provider']:9} {d['model']:18} {d['suite']:10} {g}  {d.get('runs',0):>3} runs  ${d.get('cost_usd') or 0:.4f}  {d.get('wall_s',0)/60:.1f}m")
print()
PY
