/**
 * @module anonyma-mcp
 * @description Privacy for Model Context Protocol connections. Personal data
 * in what an MCP server returns — tool results, resources, prompts, sampling
 * requests — is replaced by tokens before it enters a model's context window;
 * tokens in what the model sends back — tool and prompt arguments — are
 * replaced by the original values before they reach the server.
 *
 * - {@link createMcpGuard}: the guard of one connection, for any transport.
 * - {@link runStdioProxy} and the `anonyma-mcp-proxy` command: any stdio
 *   server behind the guard, without changing the server or the host.
 * - {@link guardMcpClient}: an MCP client object an application drives itself.
 *
 * To expose anonyma's own detection and redaction as MCP tools, use
 * `createMcpServer()` from `anonyma/mcp` instead.
 *
 * @example
 * ```ts
 * import { createMcpGuard } from "anonyma-mcp";
 *
 * const guard = createMcpGuard({ session: { format: "brace" } });
 * const toHost = guard.fromServer({
 *   jsonrpc: "2.0",
 *   id: 1,
 *   result: { content: [{ type: "text", text: "Owner: ada@example.com" }] },
 * });
 * // content[0].text === "Owner: {{EMAIL_1}}"
 * ```
 */

export { createMcpGuard } from "./guard.js";
export type { McpGuard, McpGuardEvent, McpGuardOptions } from "./guard.js";
export { guardMcpClient } from "./client.js";
export type { GuardedMcpClient, McpClientLike } from "./client.js";
export { runStdioProxy } from "./proxy.js";
export type { StdioProxy, StdioProxyOptions } from "./proxy.js";
