"""Compute breadth-sweep progress as a JSON blob (consumed by a progress dashboard).

Fine-grained: counts the individual per-(user_task x injection_task) run files written
under runs/ since the sweep started (marker file .sweep_start), so the bar moves
continuously rather than only when a whole 70-run step finishes. Cost/steps come from
costs.jsonl (one line per completed invocation).
"""
import datetime
import glob
import json
import os

MODELS = [("openai", "gpt-4o-mini"), ("anthropic", "claude-haiku-4-5")]
SUITES = ["workspace", "banking", "travel", "slack"]
PAIRS = {"workspace": 70, "banking": 45, "travel": 35, "slack": 25}  # 5 user tasks x injections
PLAN = [(p, m, s, g) for p, m in MODELS for s in SUITES for g in (False, True)]
TOTAL_STEPS = len(PLAN)
TOTAL_RUNS = sum(PAIRS[s] for _, _, s, _ in PLAN)


def _model_from_pipeline(pipeline):
    if "gpt" in pipeline:
        return "openai", "gpt-4o-mini"
    if "claude" in pipeline:
        return "anthropic", "claude-haiku-4-5"
    return "?", pipeline


def compute(costs="runs/costs.jsonl", marker="runs/.sweep_start"):
    start = os.path.getmtime(marker) if os.path.exists(marker) else 0

    # fine count: security run files written by THIS sweep (mtime >= start)
    fresh = []
    for f in glob.glob("runs/**/*.json", recursive=True):
        b = os.path.basename(f)
        if b == "none.json" or "important_instructions" not in f:
            continue
        try:
            if os.path.getmtime(f) >= start - 5:
                fresh.append(f)
        except OSError:
            pass
    done_runs = len(fresh)

    # steps + spend from the per-invocation cost log
    rows = []
    if os.path.exists(costs):
        for line in open(costs):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    breadth = [d for d in rows if d.get("runs") == PAIRS.get(d.get("suite"))]
    done_steps = len(breadth)
    spent = sum(d.get("cost_usd") or 0 for d in breadth)
    spent_total = sum(d.get("cost_usd") or 0 for d in rows)

    # live clock + ETA from the fine run count
    now_dt = datetime.datetime.now()
    elapsed_s = (now_dt.timestamp() - start) if start else 0
    per_run = (elapsed_s / done_runs) if done_runs else 12.0
    eta_min = round(max(0, TOTAL_RUNS - done_runs) * per_run / 60)

    # current step: from the most-recently-written run file
    now = None
    if fresh and done_runs < TOTAL_RUNS:
        newest = max(fresh, key=os.path.getmtime)
        parts = newest.split(os.sep)
        # runs/<pipeline>/<suite>/<user_task>/important_instructions/<inj>.json
        pipeline = parts[1] if len(parts) > 1 else ""
        suite = parts[2] if len(parts) > 2 else "?"
        provider, model = _model_from_pipeline(pipeline)
        now = {"provider": provider, "model": model, "suite": suite,
               "guard": pipeline.startswith("tack-guard")}

    return {
        "status": "done" if done_runs >= TOTAL_RUNS else "running",
        "done_steps": done_steps,
        "total_steps": TOTAL_STEPS,
        "done_runs": done_runs,
        "total_runs": TOTAL_RUNS,
        "spent": round(spent, 4),
        "spent_total": round(spent_total, 4),
        "eta_min": eta_min,
        "elapsed_min": round(elapsed_s / 60) if start else None,
        "now": now,
        "updated": now_dt.isoformat(timespec="seconds"),
    }


if __name__ == "__main__":
    print(json.dumps(compute()))
