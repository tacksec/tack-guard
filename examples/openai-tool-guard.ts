/**
 * Guarding an OpenAI / Anthropic function-calling loop — without hand-mapping.
 *
 * The model emits tool calls as { name, arguments }. `inferToolCall()` turns
 * that into a tack-guard ToolCall (action from the tool name, target from the
 * args), so you DON'T hand-write a taxonomy. Each call is evaluated before your
 * code runs it. Swap `modelToolCalls` for the real `response.tool_calls`.
 *
 * No API key needed — the model's calls are mocked to show the wiring.
 *
 * Run from repo root:  npx tsx examples/openai-tool-guard.ts
 */
import { createGuard, inferToolCall, type RawToolCall } from "../src/index.js";

const guard = createGuard();

// Your real tool implementations.
const tools: Record<string, () => string> = {
  list_customers: () => "[ …rows… ]",
  get_order: () => "{ …order… }",
  update_record: () => "ok",
  export_table: () => "<dumped rows>",
};

// A session of tool calls the model emits (mocked). It starts normal, then drifts.
const modelToolCalls: RawToolCall[] = [
  { name: "list_customers", arguments: "{}" },
  { name: "get_order", arguments: JSON.stringify({ id: 42 }) },
  { name: "list_customers", arguments: "{}" },
  { name: "get_order", arguments: JSON.stringify({ id: 7 }) },
  { name: "list_customers", arguments: "{}" },
  // …prompt-injected drift:
  { name: "update_record", arguments: JSON.stringify({ table: "user_db.sensitive_table" }) },
  { name: "export_table", arguments: JSON.stringify({ table: "user_db.credentials" }) },
];

for (const call of modelToolCalls) {
  const verdict = guard.evaluate(inferToolCall(call, { hour: 3 }));

  if (verdict.blocked) {
    console.log(`[BLOCKED] ${call.name.padEnd(15)} -> ${verdict.pattern}: ${verdict.summary}`);
    continue; // do NOT run the tool — return the refusal to the model instead
  }

  const out = tools[call.name]?.() ?? "(unknown tool)";
  const tag = verdict.verdict === "warn" ? "[WARN]   " : "[allow]  ";
  console.log(`${tag} ${call.name.padEnd(15)} -> ${out}`);
}
