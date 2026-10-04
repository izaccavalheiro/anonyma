/**
 * @module mcp/server
 * @description A dependency-free Model Context Protocol server for anonyma.
 * It is transport-agnostic: {@link McpServer.handle} takes one JSON-RPC
 * message and returns the response, and {@link serveStdio} connects it to a
 * newline-delimited stream such as standard input and output.
 *
 * Privacy properties
 * - Original values behind tokens are kept in server memory, per session, and
 *   are never part of a tool result unless the operator enables
 *   `anonyma_detokenize`.
 * - `anonyma_detect` reports positions and categories, not the detected text.
 * - Strategies that need key material are not selectable by the model.
 * - With an audit logger, every tool call is recorded without its content.
 */

import { AnonymaError } from "../errors.js";
import { sanitizeJson } from "../ai/json.js";
import { summarizeSpans } from "../audit/fields.js";
import type { AuditLogger, AuditOperation } from "../audit/types.js";
import { REGULATIONS, isRegulationId } from "../compliance/regulations.js";
import { checkPolicy } from "../compliance/policy.js";
import { BUILTIN_CATEGORIES } from "../engine/builtin.js";
import { compilePipeline } from "../engine/compile.js";
import type { PipelineSpec, StrategySpec } from "../engine/types.js";
import { toHex } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";
import { PRESET_REGISTRY } from "../presets.js";
import { createSessionTokenizer } from "../vault/session.js";
import type { SessionTokenizer } from "../vault/session.js";
import {
  MCP_PROTOCOL_VERSIONS,
  MCP_RESOURCES,
  MCP_RESOURCE_TEMPLATES,
  MCP_TOOLS,
} from "./definitions.js";
import type { McpTool } from "./definitions.js";
import { validate } from "./schema.js";

/** JSON-RPC 2.0 error codes used by the server. */
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;
const RESOURCE_NOT_FOUND = -32002;

/**
 * A JSON-RPC 2.0 response.
 */
export type JsonRpcResponse =
  | { readonly jsonrpc: "2.0"; readonly id: string | number | null; readonly result: unknown }
  | {
      readonly jsonrpc: "2.0";
      readonly id: string | number | null;
      readonly error: { readonly code: number; readonly message: string };
    };

/**
 * Options accepted by {@link createMcpServer}.
 */
export interface McpServerOptions {
  /**
   * Serve `anonyma_detokenize`, which returns original values to the caller.
   * Defaults to `false`: tokens can then only be resolved outside the model's reach.
   */
  readonly allowDetokenize?: boolean;
  /** Records every tool call, without content. */
  readonly audit?: AuditLogger;
  /** Largest number of tokenization sessions kept; the least recently used is dropped. Defaults to `256`. */
  readonly maxSessions?: number;
  /**
   * Largest `json` argument of `anonyma_anonymize`, in characters of its
   * serialised form. Defaults to 1,000,000, the limit of the `text` argument.
   */
  readonly maxJsonLength?: number;
  /** Name and version reported to clients. */
  readonly serverInfo?: { readonly name: string; readonly version: string };
}

/**
 * A Model Context Protocol server.
 */
export interface McpServer {
  /**
   * Handle one JSON-RPC message.
   *
   * @param message - The parsed message, or an array of messages (a batch).
   * @returns The response, one response per request of a batch, or `undefined`
   *   when nothing has to be answered.
   */
  readonly handle: (
    message: unknown,
  ) => Promise<JsonRpcResponse | readonly JsonRpcResponse[] | undefined>;
  /**
   * Handle one line of a newline-delimited transport.
   *
   * @param line - One JSON-RPC message as JSON text.
   * @returns The response as JSON text without a line break, or `undefined` for a notification.
   */
  readonly handleLine: (line: string) => Promise<string | undefined>;
}

type Args = Record<string, unknown>;
interface ToolOutcome {
  readonly structured: Record<string, unknown>;
  readonly operation: AuditOperation;
  readonly fields: ReturnType<typeof summarizeSpans>;
}

/** How many problems an "Invalid arguments" message lists. */
const MAX_PROBLEMS = 10;

const invalidRequest: JsonRpcResponse = Object.freeze({
  jsonrpc: "2.0",
  id: null,
  error: Object.freeze({ code: INVALID_REQUEST, message: "Invalid request." }),
});

class RpcError extends Error {
  public constructor(
    public readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

const STRATEGY_NOTES: Readonly<Record<string, string>> = {
  redact: "Replaces the value with a label. Nothing of the value remains.",
  mask: "Replaces characters with a mask character; keepLeading/keepTrailing leave characters visible.",
  pseudonymize: "Replaces the value with a random identifier.",
  generalize: "Replaces a number with a range; other values are redacted.",
  synthesize: "Replaces the value with a made-up value of the same kind.",
};

/**
 * Create an MCP server.
 *
 * @param options - Server options.
 * @returns The {@link McpServer}.
 *
 * @example
 * ```ts
 * // anonyma-mcp.mjs — register with: claude mcp add anonyma -- node anonyma-mcp.mjs
 * import { createMcpServer, serveStdio } from "anonyma/mcp";
 *
 * await serveStdio(createMcpServer(), {
 *   input: process.stdin,
 *   write: (line) => void process.stdout.write(line),
 * });
 * ```
 */
export function createMcpServer(options: McpServerOptions = {}): McpServer {
  const { allowDetokenize = false, audit, maxSessions = 256, maxJsonLength = 1_000_000 } = options;
  const serverInfo = options.serverInfo ?? { name: "anonyma", version: "1.0.0" };
  const tools = MCP_TOOLS.filter((tool) => allowDetokenize || tool.name !== "anonyma_detokenize");
  const sessions = new Map<string, SessionTokenizer>();

  /**
   * Build the pipeline spec of a call. An explicit strategy applies to every
   * category, so it replaces the per-category rules of a preset.
   */
  function specOf(args: Args, forced?: StrategySpec): PipelineSpec {
    const preset = args["preset"] as NonNullable<PipelineSpec["preset"]> | undefined;
    const strategy = forced ?? (args["strategy"] as StrategySpec | undefined);
    const categories =
      (args["categories"] as PipelineSpec["categories"]) ??
      (strategy !== undefined && preset !== undefined
        ? PRESET_REGISTRY[preset].categories
        : undefined);
    return {
      ...(strategy === undefined && preset !== undefined ? { preset } : {}),
      ...(categories !== undefined ? { categories } : {}),
      ...(args["minConfidence"] !== undefined
        ? { minConfidence: args["minConfidence"] as number }
        : {}),
      ...(strategy !== undefined ? { defaultStrategy: strategy } : {}),
    };
  }

  async function sessionFor(id: unknown): Promise<{ id: string; session: SessionTokenizer }> {
    if (typeof id === "string") {
      const existing = sessions.get(id);
      if (existing === undefined)
        throw new AnonymaError("Unknown or expired session.", "MCP_UNKNOWN_SESSION");
      // Re-insert so that the map's order reflects recent use.
      sessions.delete(id);
      sessions.set(id, existing);
      return { id, session: existing };
    }
    const crypto = await webCrypto();
    const fresh = toHex(crypto.getRandomValues(new Uint8Array(16)));
    // A random tag in every token: text that merely looks like a token is never
    // replaced by a stored value when the session is detokenized.
    const tag = toHex(crypto.getRandomValues(new Uint8Array(4)));
    const session = createSessionTokenizer({ tag });
    sessions.set(fresh, session);
    while (sessions.size > maxSessions) {
      const oldest = sessions.keys().next();
      /* v8 ignore next -- the map is not empty here */
      if (oldest.done === true) break;
      sessions.delete(oldest.value);
    }
    return { id: fresh, session };
  }

  async function runTool(tool: McpTool, args: Args): Promise<ToolOutcome> {
    switch (tool.name) {
      case "anonyma_detect": {
        const pipeline = compilePipeline(specOf(args));
        const spans = pipeline.scan(args["text"] as string);
        return {
          structured: {
            found: spans.length > 0,
            count: spans.length,
            spans: spans.map(({ start, end, category, confidence, detector }) => ({
              start,
              end,
              category,
              confidence,
              detector,
            })),
          },
          operation: "detect",
          fields: summarizeSpans(spans, { rule: "detect" }),
        };
      }
      case "anonyma_anonymize": {
        const hasText = typeof args["text"] === "string";
        const json = args["json"];
        if (hasText === (json !== undefined)) {
          throw new AnonymaError(
            "Provide exactly one of `text` and `json`.",
            "MCP_INVALID_ARGUMENTS",
          );
        }
        const spec = specOf(args);
        const pipeline = compilePipeline(spec);
        const rule = (spec.defaultStrategy ?? { strategy: spec.preset ?? "redact" }).strategy;
        if (hasText) {
          const result = pipeline.transform(args["text"] as string);
          const fields = summarizeSpans(result.spans, { rule });
          return {
            structured: { text: result.text, replaced: result.spans.length, fields },
            operation: "anonymize",
            fields,
          };
        }
        if (typeof json !== "object" || json === null) {
          throw new AnonymaError("`json` must be an object or an array.", "MCP_INVALID_ARGUMENTS");
        }
        if (JSON.stringify(json).length > maxJsonLength) {
          throw new AnonymaError(
            `\`json\` is larger than ${String(maxJsonLength)} characters.`,
            "MCP_INVALID_ARGUMENTS",
          );
        }
        const result = sanitizeJson(json, { pipeline, ruleName: () => rule });
        return {
          structured: { json: result.value, replaced: result.replaced, fields: result.fields },
          operation: "anonymize",
          fields: [...result.fields],
        };
      }
      case "anonyma_tokenize": {
        const { id, session } = await sessionFor(args["session"]);
        const pipeline = compilePipeline(specOf(args, { strategy: "tokenize" }), {
          tokenization: session,
        });
        const result = pipeline.transform(args["text"] as string);
        const fields = summarizeSpans(result.spans, { rule: "tokenize" });
        return {
          structured: { text: result.text, session: id, replaced: result.spans.length, fields },
          operation: "tokenize",
          fields,
        };
      }
      case "anonyma_detokenize": {
        const { session } = await sessionFor(args["session"]);
        const result = session.restore(args["text"] as string);
        return {
          structured: {
            text: result.text,
            restored: result.restored,
            unresolved: [...result.unresolved],
          },
          operation: "detokenize",
          fields: [],
        };
      }
      default: {
        const { policy, issues } = checkPolicy(args["policy"]);
        return {
          structured: {
            valid: policy !== undefined,
            issues: issues.map(({ severity, path, code, message, reference }) => ({
              severity,
              path,
              code,
              message,
              ...(reference !== undefined ? { citation: reference.citation } : {}),
            })),
          },
          operation: "policy-load",
          fields: [],
        };
      }
    }
  }

  async function callTool(params: unknown): Promise<unknown> {
    const { name, arguments: args = {} } = (params ?? {}) as {
      name?: unknown;
      arguments?: unknown;
    };
    const tool = tools.find((candidate) => candidate.name === name);
    if (tool === undefined) throw new RpcError(INVALID_PARAMS, "Unknown tool.");

    const problems = validate(tool.inputSchema, args);
    if (problems.length > 0) {
      const shown = problems.slice(0, MAX_PROBLEMS).join("; ");
      const more = problems.length - MAX_PROBLEMS;
      return {
        content: [
          {
            type: "text",
            text: `Invalid arguments: ${shown}${more > 0 ? `; and ${String(more)} more` : ""}`,
          },
        ],
        isError: true,
      };
    }
    try {
      const outcome = await runTool(tool, args as Args);
      if (audit !== undefined) {
        await audit.record({
          operation: outcome.operation,
          actor: "mcp",
          source: tool.name,
          fields: outcome.fields,
        });
      }
      return {
        content: [{ type: "text", text: JSON.stringify(outcome.structured) }],
        structuredContent: outcome.structured,
      };
    } catch (error) {
      if (!(error instanceof AnonymaError)) throw error;
      return { content: [{ type: "text", text: error.message }], isError: true };
    }
  }

  function readResource(params: unknown): unknown {
    const uri = (params as { uri?: unknown } | null | undefined)?.uri;
    const json = (value: unknown): unknown => ({
      contents: [{ uri, mimeType: "application/json", text: JSON.stringify(value) }],
    });
    if (uri === "anonyma://categories") return json({ categories: BUILTIN_CATEGORIES });
    if (uri === "anonyma://strategies") return json({ strategies: STRATEGY_NOTES });
    if (uri === "anonyma://presets") {
      return json({
        presets: Object.values(PRESET_REGISTRY).map(
          ({ name, description, categories, defaultStrategy, rules }) => ({
            name,
            description,
            categories,
            defaultStrategy,
            rules: rules ?? [],
          }),
        ),
      });
    }
    if (uri === "anonyma://audit/head")
      return json(audit === undefined ? { enabled: false } : { enabled: true, ...audit.head() });
    if (typeof uri === "string" && uri.startsWith("anonyma://regulations/")) {
      const id = uri.slice("anonyma://regulations/".length);
      if (isRegulationId(id)) return json(REGULATIONS[id]);
    }
    throw new RpcError(RESOURCE_NOT_FOUND, "Resource not found.");
  }

  async function dispatch(method: string, params: unknown): Promise<unknown> {
    switch (method) {
      case "initialize": {
        const requested = (params as { protocolVersion?: unknown } | null | undefined)
          ?.protocolVersion;
        return {
          protocolVersion:
            typeof requested === "string" && MCP_PROTOCOL_VERSIONS.includes(requested)
              ? requested
              : MCP_PROTOCOL_VERSIONS[0],
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
          },
          serverInfo: { name: serverInfo.name, title: "anonyma", version: serverInfo.version },
          instructions:
            "Use anonyma_anonymize before writing text or JSON that may contain personal data to logs, files, " +
            "tickets or other tools. Use anonyma_tokenize when the data must stay meaningful for further work.",
        };
      }
      case "ping":
        return {};
      case "tools/list":
        return { tools };
      case "tools/call":
        return callTool(params);
      case "resources/list":
        return { resources: MCP_RESOURCES };
      case "resources/templates/list":
        return { resourceTemplates: MCP_RESOURCE_TEMPLATES };
      case "resources/read":
        return readResource(params);
      default:
        throw new RpcError(METHOD_NOT_FOUND, "Method not found.");
    }
  }

  async function handle(
    message: unknown,
  ): Promise<JsonRpcResponse | JsonRpcResponse[] | undefined> {
    if (Array.isArray(message)) {
      // A JSON-RPC batch, which protocol revisions before 2025-06-18 allow.
      if (message.length === 0) return invalidRequest;
      const responses: JsonRpcResponse[] = [];
      for (const entry of message as unknown[]) {
        const response = await handleOne(entry);
        if (response !== undefined) responses.push(response);
      }
      return responses.length > 0 ? responses : undefined;
    }
    return handleOne(message);
  }

  async function handleOne(message: unknown): Promise<JsonRpcResponse | undefined> {
    if (typeof message !== "object" || message === null || Array.isArray(message)) {
      return invalidRequest;
    }
    const { jsonrpc, id, method, params } = message as Record<string, unknown>;
    const isNotification = id === undefined;
    // An id such as 1e999 parses to Infinity, which cannot be sent back.
    const responseId =
      typeof id === "string" || (typeof id === "number" && Number.isFinite(id)) ? id : null;
    if (
      jsonrpc !== "2.0" ||
      typeof method !== "string" ||
      (!isNotification && responseId === null)
    ) {
      // A response sent by the client, or a malformed message.
      if (method === undefined && (message as Record<string, unknown>)["jsonrpc"] === "2.0")
        return undefined;
      return {
        jsonrpc: "2.0",
        id: responseId,
        error: { code: INVALID_REQUEST, message: "Invalid request." },
      };
    }
    if (isNotification) return undefined;

    try {
      return { jsonrpc: "2.0", id: responseId, result: await dispatch(method, params) };
    } catch (error) {
      const known = error instanceof RpcError;
      return {
        jsonrpc: "2.0",
        id: responseId,
        error: {
          code: known ? error.code : INTERNAL_ERROR,
          message: known ? error.message : "Internal error.",
        },
      };
    }
  }

  async function handleLine(line: string): Promise<string | undefined> {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      return JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: PARSE_ERROR, message: "Parse error." },
      });
    }
    const response = await handle(message);
    return response === undefined ? undefined : JSON.stringify(response);
  }

  return Object.freeze({ handle, handleLine });
}

/**
 * Serve an MCP server over a newline-delimited JSON transport, such as
 * standard input and output. Resolves when the input ends.
 *
 * @param server - The server.
 * @param io - `input` yields text or bytes in arbitrary chunks; `write`
 *   receives each response as one line including its line feed.
 *
 * @example
 * ```ts
 * await serveStdio(createMcpServer(), {
 *   input: process.stdin,
 *   write: (line) => void process.stdout.write(line),
 * });
 * ```
 */
export async function serveStdio(
  server: McpServer,
  io: {
    readonly input: AsyncIterable<string | Uint8Array>;
    readonly write: (line: string) => void | Promise<void>;
  },
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";

  async function consume(line: string): Promise<void> {
    if (line.trim() === "") return;
    const response = await server.handleLine(line);
    if (response !== undefined) await io.write(`${response}\n`);
  }

  for await (const chunk of io.input) {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      await consume(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf("\n");
    }
  }
  await consume(buffer + decoder.decode());
}
