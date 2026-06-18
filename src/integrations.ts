/**
 * Framework adapters — turn a real tool call into a {@link ToolCall}.
 *
 * The whole security value of tack-guard lives in WHAT `action`/`target` you
 * feed it. Hand-mapping every tool by hand is the #1 adoption tax, so
 * `inferToolCall()` derives them from the common provider shape (a tool name +
 * arguments) used by OpenAI/Anthropic function-calling, the Vercel AI SDK, and
 * MCP. The action is canonicalized downstream (so "update_row" → write,
 * "exportAll" → exfiltrate), and the target is pulled from the arguments.
 *
 * Zero dependencies: this works against a structural shape, it does NOT import
 * any provider SDK. You can always override the inference per call.
 */
import type { ToolCall } from "./types.js";

/** The lowest-common-denominator tool-call shape across providers. */
export interface RawToolCall {
  /** The tool / function name, e.g. "delete_user", "sql_query", "exportAll". */
  name: string;
  /** The call arguments — a parsed object or a JSON string (OpenAI sends a string). */
  arguments?: Record<string, unknown> | string;
}

// Argument keys, in priority order, that typically name the thing being touched.
// Note: "query" is intentionally excluded — a SQL/search string is rarely the
// *resource*, and matching it by substring over-flags (pass an explicit target).
const TARGET_KEYS = [
  "target", "table", "resource", "path", "url", "endpoint", "collection",
  "bucket", "key", "file", "to", "database", "db", "dataset", "object", "entity",
];

/** Parse arguments to a plain object, or null if absent/malformed/array. */
function parseArgs(a: RawToolCall["arguments"]): Record<string, unknown> | null {
  if (a == null) return {};
  if (typeof a === "string") {
    try {
      const parsed: unknown = JSON.parse(a);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null; // malformed payload — preserved raw in metadata by the caller
    }
  }
  return Array.isArray(a) ? null : a;
}

function inferTarget(args: Record<string, unknown>, fallback: string): string {
  for (const k of TARGET_KEYS) {
    const v = args[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const v of Object.values(args)) {
    if (typeof v === "string" && v.length > 0) return v;
  }
  return fallback;
}

/**
 * Build a {@link ToolCall} from a provider tool call. The tool name becomes the
 * action (canonicalized internally) and the target is inferred from the args.
 * Pass `overrides` to pin either explicitly.
 *
 * @example
 * // OpenAI / Anthropic tool-use:
 * const result = guard.evaluate(inferToolCall(toolCall))
 * // MCP request params: inferToolCall({ name: req.params.name, arguments: req.params.arguments })
 */
export function inferToolCall(
  raw: RawToolCall,
  overrides: Partial<ToolCall> = {},
): ToolCall {
  const parsed = parseArgs(raw.arguments);
  const args = parsed ?? {};
  // Preserve provenance for audit. On a malformed payload, keep the raw bytes
  // (a garbled-but-suspicious tool call should still be inspectable). Caller
  // overrides augment — never erase — this provenance.
  const base: Record<string, unknown> =
    parsed === null
      ? { tool: raw.name, rawArguments: raw.arguments, parseError: true }
      : { tool: raw.name, args };
  return {
    action: overrides.action ?? raw.name,
    target: overrides.target ?? inferTarget(args, raw.name),
    agentId: overrides.agentId,
    hour: overrides.hour,
    at: overrides.at,
    metadata: overrides.metadata ? { ...base, ...overrides.metadata } : base,
  };
}
