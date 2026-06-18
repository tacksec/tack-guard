/**
 * tack-guard HTTP shim for the AgentDojo (Python) integration.
 *
 *   node eval/agentdojo/server.mjs           # listens on :3737
 *
 * AgentDojo is Python; tack-guard is the real TS/JS artifact. The Python defense
 * element (tack_guard_element.py) POSTs each proposed tool call here; we score it
 * with the SHIPPED guard and return the GuardResult. One guard per agentId so the
 * behavioral baseline accumulates within a task (the element keys agentId by the
 * task's user query → automatic per-task isolation).
 */
import { createServer } from "node:http";
import { createGuard } from "../../dist/index.js";

const PORT = Number(process.env.TACK_SHIM_PORT ?? 3737);
const guards = new Map(); // agentId -> { guard, configKey }

function guardFor(agentId, config) {
  const key = JSON.stringify(config ?? {});
  const existing = guards.get(agentId);
  if (existing && existing.configKey === key) return existing.guard;
  // egressTargets may arrive as an array (a predicate can't cross the JSON
  // boundary — use a string-array allowlist on the Python side).
  const guard = createGuard(config && Object.keys(config).length ? config : undefined);
  guards.set(agentId, { guard, configKey: key });
  return guard;
}

const server = createServer((req, res) => {
  const json = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (req.method === "POST" && req.url === "/evaluate") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const { agentId = "default", config, ...call } = JSON.parse(body);
        const result = guardFor(agentId, config).evaluate(call);
        const tag = result.pattern !== "none" ? ` (${result.pattern})` : "";
        console.log(`[${result.verdict}] ${call.action} -> ${call.target}${tag}`);
        json(200, result);
      } catch (e) {
        json(400, { error: String(e) });
      }
    });
  } else if (req.method === "POST" && req.url === "/reset") {
    guards.clear();
    json(200, { ok: true });
  } else {
    json(404, { error: "not found" });
  }
});

server.listen(PORT, "127.0.0.1", () => console.log(`tack-guard shim listening on http://127.0.0.1:${PORT}`));
