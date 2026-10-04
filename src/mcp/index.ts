/**
 * @module mcp
 * @description Model Context Protocol integration, exposed as
 * `"anonyma/mcp"`: tool and resource declarations with JSON Schema, and a
 * dependency-free server that MCP clients such as Claude Code or Cursor can
 * launch.
 *
 * @example
 * ```ts
 * import { createMcpServer, serveStdio } from "anonyma/mcp";
 *
 * await serveStdio(createMcpServer(), {
 *   input: process.stdin,
 *   write: (line) => void process.stdout.write(line),
 * });
 * ```
 */

export {
  MCP_PROTOCOL_VERSIONS,
  MCP_RESOURCES,
  MCP_RESOURCE_TEMPLATES,
  MCP_TOOLS,
} from "./definitions.js";
export type { JsonSchema, McpResource, McpResourceTemplate, McpTool } from "./definitions.js";
export { createMcpServer, serveStdio } from "./server.js";
export type { JsonRpcResponse, McpServer, McpServerOptions } from "./server.js";
