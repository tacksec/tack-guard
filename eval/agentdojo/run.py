"""
Run AgentDojo with tack-guard as an inline tool-call defense.

Prereqs:
  1. tack-guard built:        npm run build            (from repo root)
  2. The Node shim running:   node eval/agentdojo/server.mjs
  3. An LLM:
       - Anthropic (default): put ANTHROPIC_API_KEY in tack-guard/.env.local
       - OpenAI / local:      --provider openai (+ --base-url for LM Studio)

Examples (run from eval/agentdojo/, with the throwaway venv's python):
  # benign smoke on Claude Haiku (fast, cheap)
  python run.py --suite banking --user-tasks user_task_0

  # the exfil-detection showcase (with the guard)
  python run.py --suite workspace --user-tasks user_task_0 --injection-tasks injection_task_6 \
                --security --attack important_instructions \
                --sensitive-targets email inbox file document drive mail \
                --egress-targets bluesparrowtech.com

  # local model via LM Studio instead of the API
  python run.py --provider openai --model <lm-studio-id> --base-url http://127.0.0.1:1234/v1 ...
"""
import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv  # noqa: E402

# Load ANTHROPIC_API_KEY / OPENAI_API_KEY from the repo root's .env.local
load_dotenv(Path(__file__).resolve().parents[2] / ".env.local")

import anthropic  # noqa: E402
import openai  # noqa: E402

from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline, AnthropicLLM, InitQuery, OpenAILLM, SystemMessage,
    ToolsExecutionLoop, ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.attacks import load_attack  # noqa: E402
from agentdojo.benchmark import (  # noqa: E402
    benchmark_suite_with_injections, benchmark_suite_without_injections,
)
from agentdojo.logging import OutputLogger  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

import cost  # noqa: E402
from tack_guard_element import TackGuardElement  # noqa: E402


def _model_tag(model):
    # AgentDojo's important_instructions attack reads the model name from the
    # pipeline name by matching a KEY of MODEL_NAMES as a substring. Embed a
    # valid key; "local" -> "Local model". (Avoid keys with slashes — they break
    # the log path.)
    m = model.lower()
    if "claude" in m:
        return "claude-3-5-sonnet-20241022"
    if "gpt-3.5" in m:
        return "gpt-3.5-turbo-0125"
    if "gpt-4" in m or "gpt-5" in m:
        return "gpt-4o-2024-05-13"
    if "gemini" in m or "google" in m:
        return "gemini-1.5-pro-002"
    return "local"


# OpenAI-COMPATIBLE providers: pick which credits to spend per run via --provider.
# base_url is env-overridable (defaults may drift — verify Nebius at wiring time).
PROVIDERS = {
    "openai": {"base_url": None, "key_env": "OPENAI_API_KEY"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY"},
    "nebius": {"base_url": "https://api.studio.nebius.com/v1", "key_env": "NEBIUS_API_KEY"},
    # "local" / LM Studio: pass --base-url + --api-key explicitly.
    "local": {"base_url": "http://127.0.0.1:1234/v1", "key_env": None},
}


def build_llm(args):
    if args.provider == "anthropic":
        # key from ANTHROPIC_API_KEY (loaded from .env.local)
        return AnthropicLLM(anthropic.Anthropic(), args.model, max_tokens=4096)
    # OpenAI-compatible (OpenAI / OpenRouter / Nebius / local). CLI flags override
    # the registry; otherwise base_url + key come from the provider's env vars.
    cfg = PROVIDERS.get(args.provider, PROVIDERS["openai"])
    base_url = args.base_url or os.environ.get(f"{args.provider.upper()}_BASE_URL") or cfg["base_url"]
    api_key = args.api_key or (os.environ.get(cfg["key_env"]) if cfg["key_env"] else "x")
    client = openai.OpenAI(
        base_url=base_url, api_key=api_key, timeout=1200.0, max_retries=1
    )
    return OpenAILLM(client, args.model)


# Per-model provider preference for `--provider auto`: cheapest / your-own credits
# first, OpenRouter as the universal catch-all (it hosts ~everything). On a credit /
# quota / model-not-available error we fall to the next candidate.
# ⚠️ SLUGS ARE BEST-EFFORT (June 2026) — verify exact provider IDs + availability at
# wiring time (esp. which open models Nebius actually hosts).
MODEL_ROUTES = {
    "claude-haiku-4-5": [
        {"provider": "anthropic", "model": "claude-haiku-4-5"},
        {"provider": "openrouter", "model": "anthropic/claude-haiku-4.5"},
    ],
    "gpt-4o-mini": [
        {"provider": "openai", "model": "gpt-4o-mini"},
        {"provider": "openrouter", "model": "openai/gpt-4o-mini"},
    ],
    "gpt-5-mini": [
        {"provider": "openai", "model": "gpt-5-mini"},
        {"provider": "openrouter", "model": "openai/gpt-5-mini"},
    ],
    "gemini-2.5-flash": [
        {"provider": "openrouter", "model": "google/gemini-2.5-flash"},
    ],
    "kimi-k2.5": [
        {"provider": "openrouter", "model": "moonshotai/kimi-k2.5"},
    ],
    "qwen3.5": [
        {"provider": "nebius", "model": "Qwen/Qwen3.5-Instruct"},
        {"provider": "openrouter", "model": "qwen/qwen3.5-instruct"},
    ],
    "deepseek-v4": [
        {"provider": "nebius", "model": "deepseek-ai/DeepSeek-V4"},
        {"provider": "openrouter", "model": "deepseek/deepseek-v4"},
    ],
    "glm-5.1": [
        {"provider": "openrouter", "model": "z-ai/glm-5.1"},
    ],
}


class _NoCredit(Exception):
    """Provider is out of credit / quota, or doesn't host the model — fall back."""


def _should_fallback(e):
    s = str(e).lower()
    return any(
        k in s
        for k in (
            "credit", "insufficient", "quota", "payment required", "402",
            "not found", "no endpoints", "no such model", "does not exist", "404",
        )
    )


def _probe(provider, model):
    """Tiny 1-token call to check the provider is usable for this model."""
    try:
        if provider == "anthropic":
            anthropic.Anthropic().messages.create(
                model=model, max_tokens=1, messages=[{"role": "user", "content": "ping"}]
            )
        else:
            cfg = PROVIDERS[provider]
            base = os.environ.get(f"{provider.upper()}_BASE_URL") or cfg["base_url"]
            key = os.environ.get(cfg["key_env"]) if cfg["key_env"] else "x"
            if cfg["key_env"] and not key:
                raise _NoCredit(f"{cfg['key_env']} not set")
            openai.OpenAI(base_url=base, api_key=key, max_retries=0).chat.completions.create(
                model=model, max_tokens=1, messages=[{"role": "user", "content": "ping"}]
            )
    except _NoCredit:
        raise
    except Exception as e:  # noqa: BLE001 — classify: credit/availability → fall back, else surface
        if _should_fallback(e):
            raise _NoCredit(str(e)[:140])
        raise


def pick_provider(logical):
    """Resolve a logical model name to (provider, slug), probing in preference order."""
    route = MODEL_ROUTES.get(logical)
    if not route:
        raise SystemExit(
            f"--provider auto: no route for '{logical}'. Known: {', '.join(MODEL_ROUTES)}"
        )
    last = None
    for cand in route:
        prov, slug = cand["provider"], cand["model"]
        try:
            _probe(prov, slug)
            print(f"[auto] {logical} -> {prov} ({slug})")
            return prov, slug
        except _NoCredit as e:
            print(f"[auto] {prov} unavailable for {logical} ({e}); trying next…")
            last = e
    raise SystemExit(f"--provider auto: all providers exhausted for {logical} (last: {last}).")


def build_pipeline(args, guard):
    llm = build_llm(args)
    sys_msg = SystemMessage(load_system_message(None))
    init = InitQuery()
    config = {}
    # The guard now defaults to advisory ("warn"); the benchmark wants the enforcement
    # path, so pass the mode through to the shim's guard explicitly (matches the element).
    config["mode"] = args.mode
    if args.egress_targets:
        config["egressTargets"] = args.egress_targets
    if args.sensitive_targets:
        config["sensitiveTargets"] = args.sensitive_targets
    loop = []
    if guard:
        loop.append(TackGuardElement(mode=args.mode, config=config, shim=args.shim))
    loop += [ToolsExecutor(), llm]
    pipeline = AgentPipeline([sys_msg, init, llm, ToolsExecutionLoop(loop)])
    # `_model_tag` puts a valid MODEL_NAMES substring in the name (the attack template
    # needs it); the [label] suffix makes the run dir UNIQUE per model so distinct
    # models (e.g. several that map to "local") don't collide. Label is slash-free.
    label = (args.label or str(args.model)).replace("/", "-")
    pipeline.name = f"{'tack-guard' if guard else 'no-defense'} {_model_tag(args.model)} [{label}]"
    return pipeline


def mean(d):
    vals = list(d.values())
    return round(sum(vals) / len(vals), 3) if vals else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--provider", default="anthropic",
        choices=["anthropic", "openai", "openrouter", "nebius", "local", "auto"],
        help="'auto' = resolve via MODEL_ROUTES (cheapest credits first, OpenRouter fallback)",
    )
    p.add_argument("--model", default=None, help="provider model id, or logical name when --provider auto")
    p.add_argument("--label", default=None, help="unique run-dir label (defaults to the model name)")
    p.add_argument("--suite", default="banking")
    p.add_argument("--version", default="v1.2")
    # base-url/api-key default to None → the real OpenAI API (key from OPENAI_API_KEY).
    # For a local LM Studio model: --base-url http://127.0.0.1:1234/v1 --api-key lm-studio
    p.add_argument("--base-url", default=None)
    p.add_argument("--api-key", default=None)
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--user-tasks", nargs="*", default=None)
    p.add_argument("--injection-tasks", nargs="*", default=None)
    p.add_argument("--no-defense", action="store_true")
    p.add_argument("--security", action="store_true")
    p.add_argument("--mode", default="enforce")
    p.add_argument("--shim", default="http://127.0.0.1:3737/evaluate")
    p.add_argument("--egress-targets", nargs="*", default=None)
    p.add_argument("--sensitive-targets", nargs="*", default=None)
    args = p.parse_args()

    # --provider auto: resolve a logical model to (provider, slug), cheapest credits first.
    if args.provider == "auto":
        if not args.model:
            raise SystemExit("--provider auto needs --model <logical name> (see MODEL_ROUTES).")
        logical = args.model
        args.provider, args.model = pick_provider(logical)
        if not args.label:
            args.label = logical

    if args.model is None:
        args.model = "claude-haiku-4-5" if args.provider == "anthropic" else "local-model"
    if not args.label:
        args.label = str(args.model).replace("/", "-")

    suite = get_suite(args.version, args.suite)
    logdir = Path("./runs")
    guard = not args.no_defense
    pipeline = build_pipeline(args, guard)
    tag = f"[{pipeline.name}] {args.suite} ({args.provider}:{args.model})"

    meter = cost.install(args.provider, args.model)
    t0 = time.time()

    with OutputLogger(str(logdir)):
        if args.security:
            attack = load_attack(args.attack, suite, pipeline)
            res = benchmark_suite_with_injections(
                pipeline, suite, attack, logdir, force_rerun=True,
                user_tasks=args.user_tasks, injection_tasks=args.injection_tasks,
                verbose=True, benchmark_version=args.version,
            )
            n_runs = len(res["security_results"])
            print(f"\n=== {tag} — SECURITY (attack={args.attack}) ===")
            print("  utility under attack :", mean(res["utility_results"]))
            print("  ASR (attack success) :", mean(res["security_results"]))
        else:
            res = benchmark_suite_without_injections(
                pipeline, suite, logdir, force_rerun=True,
                user_tasks=args.user_tasks, benchmark_version=args.version,
            )
            n_runs = len(res["utility_results"])
            print(f"\n=== {tag} — UTILITY (no injection) ===")
            print("  benign utility :", mean(res["utility_results"]))

    cost.report(
        meter, suite=args.suite, attack=args.attack, security=args.security,
        guard=guard, runs=n_runs, wall_s=time.time() - t0, logdir=str(logdir),
    )


if __name__ == "__main__":
    main()
