"""
tack-guard as an AgentDojo defense element.

A ``BasePipelineElement`` that sits IMMEDIATELY BEFORE ``ToolsExecutor`` inside the
``ToolsExecutionLoop``. At that point it sees the tool calls the LLM just proposed
(``messages[-1]["tool_calls"]``) and scores each with the real tack-guard artifact
(via the Node shim) before the tools run. If the guard blocks a call, we raise
``AbortAgentError`` — exactly the hard-block path AgentDojo's own PI detector uses.

We map each AgentDojo ``FunctionCall`` -> tack-guard ``{action, target}``:
  - ``action`` = the tool name (tack-guard canonicalizes it: send/get/delete/... ).
  - ``target`` = the salient argument (recipient / url / iban / path / ...), which is
    the egress DESTINATION the data-exfiltration signal needs (offline replays lack it).

agentId is derived from the task's user query, so each task gets an isolated baseline
without AgentDojo having to thread a task id through ``extra_args``.
"""

import hashlib
import json
import urllib.request

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.functions_runtime import EmptyEnv

# Argument keys, in priority order, that name the destination/resource being touched.
_TARGET_KEYS = [
    "to", "recipient", "recipients", "url", "endpoint", "address", "email",
    "recipient_iban", "iban", "account", "account_id", "channel", "path", "file",
    "blog", "page", "user", "query",
]


def _target_from_args(args):
    if isinstance(args, dict):
        for k in _TARGET_KEYS:
            v = args.get(k)
            if isinstance(v, str) and v:
                return v
            if isinstance(v, (list, tuple)) and v and isinstance(v[0], str):
                return v[0]
        for v in args.values():
            if isinstance(v, str) and v:
                return v
    return None


def _text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                parts.append(b.get("content") or b.get("text") or "")
        return " ".join(parts)
    return ""


class TackGuardElement(BasePipelineElement):
    def __init__(self, mode="enforce", config=None, shim="http://127.0.0.1:3737/evaluate"):
        self.name = "tack_guard"
        self.mode = mode
        self.config = config or {}
        self.shim = shim
        # Per-(user query) episode tracking. AgentDojo reuses ONE element instance
        # across every (user_task x injection_task) episode; episodes that share a
        # user task share the same query hash. Without this, the guard's behavioral
        # state would leak across episodes (a block in one poisons the next). We give
        # each episode a fresh agentId so the shim allocates a fresh guard per run.
        self._episodes = {}  # base_id -> (episode_index, last_message_count)

    def _agent_id(self, messages):
        for m in messages:
            if m.get("role") == "user":
                h = hashlib.sha1(_text(m.get("content")).encode()).hexdigest()[:12]
                return f"task-{h}"
        return "default"

    def _post(self, payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.shim, data=data, headers={"content-type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        if not messages or messages[-1].get("role") != "assistant":
            return query, runtime, env, messages, extra_args
        calls = messages[-1].get("tool_calls") or []
        if not calls:
            return query, runtime, env, messages, extra_args

        # Episode-scoped agentId: within one episode the message history only grows;
        # a new episode reusing the same user query starts with a shorter history, so
        # a shrink signals "new run" -> bump the episode index -> fresh guard.
        base = self._agent_id(messages)
        n = len(messages)
        ep, last_n = self._episodes.get(base, (0, 0))
        if n < last_n:
            ep += 1
        self._episodes[base] = (ep, n)
        agent_id = f"{base}-e{ep}"

        for tc in calls:
            target = _target_from_args(getattr(tc, "args", None)) or tc.function
            result = self._post({
                "agentId": agent_id,
                "action": tc.function,
                "target": target,
                "config": self.config,
                "metadata": {"fn": tc.function},
            })
            if self.mode != "score-only" and result.get("blocked"):
                raise AbortAgentError(
                    f"tack-guard blocked tool '{tc.function}' "
                    f"({result.get('pattern')}): {result.get('summary')}",
                    list(messages),
                    env,
                )
        return query, runtime, env, messages, extra_args
