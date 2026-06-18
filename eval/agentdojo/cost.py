"""
Cost metering for AgentDojo runs.

AgentDojo calls a module-level ``chat_completion_request`` for both providers,
and the returned object carries token ``usage``. We monkeypatch that one function
per provider to tally tokens, then price them. Works for OpenAI, Anthropic, and
OpenAI-compatible gateways like OpenRouter (which additionally returns an exact
``usage.cost`` we prefer when present).

Each run appends one line to ``runs/costs.jsonl`` so spend can be monitored over
time, and prints a human summary.
"""
import datetime
import functools
import json
from pathlib import Path

# USD per 1M tokens: (input, output). Substring-matched against the model id, so
# "claude-haiku-4-5" matches "claude-haiku". Add OpenRouter ids (e.g.
# "openai/gpt-4o-mini") as needed — or rely on OpenRouter's reported cost.
PRICING = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.00, 8.00),
    "o4-mini": (1.10, 4.40),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-haiku": (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-opus-4": (5.00, 25.00),
}


def price_for(model):
    m = (model or "").lower()
    for key, p in PRICING.items():
        if key in m:
            return p
    return None


class CostMeter:
    def __init__(self, model, provider):
        self.model = model
        self.provider = provider
        self.calls = 0
        self.input = 0
        self.output = 0
        self.cache_read = 0
        self.cache_write = 0
        self.reported_cost = 0.0  # exact cost from the gateway (OpenRouter), if any
        self.price = price_for(model)

    def add(self, input_t, output_t, cache_read=0, cache_write=0, reported_cost=None):
        self.calls += 1
        self.input += input_t or 0
        self.output += output_t or 0
        self.cache_read += cache_read or 0
        self.cache_write += cache_write or 0
        if reported_cost:
            self.reported_cost += reported_cost

    def cost(self):
        """USD. Prefer the gateway's exact figure; else price tokens. None if unknown."""
        if self.reported_cost:
            return self.reported_cost
        if not self.price:
            return None
        pin, pout = self.price
        # No prompt caching in AgentDojo's calls, so cache_* are ~0; price them
        # defensively anyway (write 1.25x, read 0.1x — Anthropic's schedule).
        return (
            (self.input / 1e6) * pin
            + (self.output / 1e6) * pout
            + (self.cache_write / 1e6) * pin * 1.25
            + (self.cache_read / 1e6) * pin * 0.1
        )


def install(provider, model):
    """Monkeypatch the provider's chat_completion_request to tally usage. Returns the meter."""
    meter = CostMeter(model, provider)

    if provider == "anthropic":
        import agentdojo.agent_pipeline.llms.anthropic_llm as mod

        orig = mod.chat_completion_request

        @functools.wraps(orig)
        async def wrapped(*a, **k):
            msg = await orig(*a, **k)
            u = getattr(msg, "usage", None)
            if u is not None:
                meter.add(
                    getattr(u, "input_tokens", 0),
                    getattr(u, "output_tokens", 0),
                    getattr(u, "cache_read_input_tokens", 0) or 0,
                    getattr(u, "cache_creation_input_tokens", 0) or 0,
                )
            return msg

        mod.chat_completion_request = wrapped
    else:  # openai / openai-compatible (incl. OpenRouter)
        import agentdojo.agent_pipeline.llms.openai_llm as mod

        orig = mod.chat_completion_request

        @functools.wraps(orig)
        def wrapped(*a, **k):
            r = orig(*a, **k)
            u = getattr(r, "usage", None)
            if u is not None:
                # OpenRouter exposes an exact `cost` on usage when asked.
                rc = getattr(u, "cost", None)
                if rc is None and isinstance(u, dict):
                    rc = u.get("cost")
                meter.add(
                    getattr(u, "prompt_tokens", 0),
                    getattr(u, "completion_tokens", 0),
                    reported_cost=rc,
                )
            return r

        mod.chat_completion_request = wrapped

    return meter


def _fmt_usd(c):
    if c is None:
        return "unknown (add model to PRICING)"
    return f"${c:,.4f}"


def report(meter, *, suite, attack, security, guard, runs, wall_s, logdir="./runs"):
    """Print a summary and append a JSONL record to runs/costs.jsonl."""
    c = meter.cost()
    per_run = (c / runs) if (c is not None and runs) else None
    src = "OpenRouter reported" if meter.reported_cost else ("priced" if meter.price else "no price")

    print(f"\n=== COST ({src}) ===")
    print(f"  model        : {meter.model} ({meter.provider})")
    print(f"  LLM calls    : {meter.calls}   over {runs} run(s)")
    print(f"  tokens       : input {meter.input:,}  output {meter.output:,}")
    print(f"  cost         : {_fmt_usd(c)}" + (f"   (~{_fmt_usd(per_run)} / run)" if per_run is not None else ""))
    print(f"  wall time    : {wall_s:.1f}s   (~{wall_s / runs:.1f}s / run)" if runs else f"  wall time    : {wall_s:.1f}s")

    rec = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "provider": meter.provider,
        "model": meter.model,
        "suite": suite,
        "attack": attack if security else None,
        "security": security,
        "guard": guard,
        "runs": runs,
        "llm_calls": meter.calls,
        "input_tokens": meter.input,
        "output_tokens": meter.output,
        "cost_usd": round(c, 6) if c is not None else None,
        "cost_per_run_usd": round(per_run, 6) if per_run is not None else None,
        "wall_s": round(wall_s, 1),
    }
    path = Path(logdir) / "costs.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"  logged       : {path}")
    return rec
