/**
 * MCP integration — guard every tool call flowing through a Model Context Protocol
 * server. tack-guard scores the (tool name + arguments) of each CallTool request
 * BEFORE the tool runs; in enforce mode a risky call is blocked and an MCP error
 * result is returned instead of executing it. Advisory by default (see createGuard).
 *
 *   import { createGuard } from "@tacksec/guard";
 *   import { guardMcpCallTool } from "@tacksec/guard/mcp";
 *
 *   const guard = createGuard({ mode: "enforce" });
 *
 *   // Low-level SDK: wrap the CallTool handler — one wrap guards EVERY tool.
 *   server.setRequestHandler(CallToolRequestSchema, guardMcpCallTool(guard, async (req) =>
 *     dispatch(req),               // your existing tool dispatch
 *   ));
 *
 *   // High-level McpServer.tool: wrap a single tool's handler.
 *   mcp.tool("delete_record", schema, guardMcpTool(guard, "delete_record", async (args) => ({
 *     content: [{ type: "text", text: await del(args) }],
 *   })));
 *
 * Zero-dependency + SDK-version-agnostic: works against MCP's structural shapes,
 * it does NOT import @modelcontextprotocol/sdk.
 */
import type { Guard } from "./guard.js";
import type { GuardResult, ToolCall } from "./types.js";
import { inferToolCall } from "./integrations.js";

type Args = Record<string, unknown>;

/** Minimal structural shape of an MCP CallTool result (matches @modelcontextprotocol/sdk). */
export interface McpToolResult {
  content: Array<{ type: string; text?: string; [k: string]: unknown }>;
  isError?: boolean;
  [k: string]: unknown;
}

/** Minimal structural shape of an MCP CallTool request. */
export interface McpCallToolRequest {
  params: { name: string; arguments?: Args };
  [k: string]: unknown;
}

export interface GuardMcpOptions {
  /** Agent/session id for per-agent baselines (default "default"). */
  agentId?: string;
  /** Map an MCP tool call → a tack-guard action/target. Default: inferToolCall(). */
  map?: (name: string, args: Args) => Pick<ToolCall, "action" | "target">;
  /** Result returned when a call is blocked. Default: an isError text result. */
  onBlocked?: (result: GuardResult, name: string, args: Args) => McpToolResult;
}

function resolve(name: string, args: Args, options: GuardMcpOptions): ToolCall {
  const mapped = options.map?.(name, args);
  const call = mapped
    ? { action: mapped.action, target: mapped.target }
    : inferToolCall({ name, arguments: args });
  return { ...call, agentId: options.agentId };
}

function defaultBlocked(result: GuardResult): McpToolResult {
  return {
    content: [
      {
        type: "text",
        text: `tack-guard blocked this tool call — ${result.pattern} (${result.severity}): ${result.summary}`,
      },
    ],
    isError: true,
  };
}

/**
 * Wrap a low-level MCP CallTool request handler so EVERY tool call is guarded.
 * Drop it around your existing CallTool handler — one wrap covers all tools.
 */
export function guardMcpCallTool(
  guard: Guard,
  handler: (request: McpCallToolRequest, ...rest: unknown[]) => McpToolResult | Promise<McpToolResult>,
  options: GuardMcpOptions = {},
): (request: McpCallToolRequest, ...rest: unknown[]) => Promise<McpToolResult> {
  return async (request, ...rest) => {
    const name = request?.params?.name ?? "";
    const args = request?.params?.arguments ?? {};
    const result = guard.evaluate(resolve(name, args, options));
    if (result.blocked) {
      return options.onBlocked ? options.onBlocked(result, name, args) : defaultBlocked(result);
    }
    return handler(request, ...rest);
  };
}

/**
 * Wrap a single high-level tool handler (e.g. for McpServer.tool). Evaluates the
 * call first; in enforce mode a blocked call returns an MCP error result instead
 * of running the tool.
 */
export function guardMcpTool(
  guard: Guard,
  toolName: string,
  handler: (args: Args, ...rest: unknown[]) => McpToolResult | Promise<McpToolResult>,
  options: GuardMcpOptions = {},
): (args: Args, ...rest: unknown[]) => Promise<McpToolResult> {
  return async (args, ...rest) => {
    const a = args ?? {};
    const result = guard.evaluate(resolve(toolName, a, options));
    if (result.blocked) {
      return options.onBlocked ? options.onBlocked(result, toolName, a) : defaultBlocked(result);
    }
    return handler(args, ...rest);
  };
}
