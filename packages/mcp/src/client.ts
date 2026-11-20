/**
 * @module @anonyma/mcp/client
 * @description Guards an MCP client object — such as `Client` of
 * `@modelcontextprotocol/sdk` — that an application drives itself, for
 * example to hand tools to its own agent loop.
 */

import { createMcpGuard } from "./guard.js";
import type { McpGuard, McpGuardOptions } from "./guard.js";

/**
 * The methods of an MCP client that the guard wraps. Any of them may be
 * missing; every other member of the client is passed through.
 */
export interface McpClientLike {
  callTool?(
    params: { name: string; arguments?: Record<string, unknown> },
    ...rest: never[]
  ): Promise<unknown>;
  readResource?(params: { uri: string }, ...rest: never[]): Promise<unknown>;
  getPrompt?(
    params: { name: string; arguments?: Record<string, string> },
    ...rest: never[]
  ): Promise<unknown>;
}

/** A guarded client: the client itself, with its guard. */
export type GuardedMcpClient<C> = C & { readonly anonymaGuard: McpGuard };

/** The wrapped methods and the request each one sends. */
const WRAPPED: Readonly<Record<string, { readonly method: string; readonly field: string }>> = {
  callTool: { method: "tools/call", field: "arguments" },
  readResource: { method: "resources/read", field: "uri" },
  getPrompt: { method: "prompts/get", field: "arguments" },
};

/**
 * Wrap an MCP client so that the results of `callTool`, `readResource` and
 * `getPrompt` reach the caller with personal data replaced by tokens, and
 * tokens in their arguments reach the server as the original values.
 *
 * @param client - The connected client. It is not modified.
 * @param options - What to detect and how tokens look; see {@link McpGuardOptions}.
 * @returns A proxy of the client with an `anonymaGuard` member.
 *
 * @example
 * ```ts
 * import { Client } from "@modelcontextprotocol/sdk/client/index.js";
 * import { guardMcpClient } from "@anonyma/mcp";
 *
 * const client = guardMcpClient(new Client({ name: "app", version: "1.0.0" }));
 * await client.connect(transport);
 * const result = await client.callTool({ name: "lookup", arguments: { email: "[EMAIL_0001]" } });
 * // The server received the real address; `result` holds tokens.
 * ```
 */
export function guardMcpClient<C extends McpClientLike>(
  client: C,
  options: McpGuardOptions = {},
): GuardedMcpClient<C> {
  const guard = createMcpGuard(options);
  const wrappers = new Map<string, unknown>();

  return new Proxy(client, {
    get(target, property, receiver): unknown {
      if (property === "anonymaGuard") return guard;
      const value: unknown = Reflect.get(target, property, receiver);
      if (typeof property !== "string" || typeof value !== "function") return value;
      const wrapped = Object.hasOwn(WRAPPED, property) ? WRAPPED[property] : undefined;
      if (wrapped === undefined) return value;

      let wrapper = wrappers.get(property);
      if (wrapper === undefined) {
        const original = value as (...args: unknown[]) => Promise<unknown>;
        wrapper = async (params: unknown, ...rest: unknown[]): Promise<unknown> => {
          const restored =
            typeof params === "object" && params !== null && wrapped.field in params
              ? {
                  ...params,
                  [wrapped.field]: guard.restoreValue(
                    (params as Record<string, unknown>)[wrapped.field],
                  ),
                }
              : params;
          const result = await original.call(target, restored, ...rest);
          return guard.sanitizeResult(wrapped.method, result);
        };
        wrappers.set(property, wrapper);
      }
      return wrapper;
    },
  }) as GuardedMcpClient<C>;
}
