/**
 * @module @anonyma/mcp/guard
 * @description A privacy guard for the messages of one Model Context Protocol
 * connection, independent of the transport.
 *
 * What a server sends towards the model — tool results, resources, prompts,
 * sampling requests, log messages, errors — has its personal data replaced by
 * session tokens. What the model sends back — tool arguments, prompt
 * arguments, resource URIs, sampling answers — has the tokens replaced by the
 * original values, so the server works on real data while the model only ever
 * sees tokens.
 *
 * The token mapping lives in the guard and never leaves the process. A guard
 * belongs to one server connection: it can only give back values that the same
 * server sent, so a token can never carry data from one server to another.
 */

import { sanitizeJson } from "anonyma/ai";
import type { KeyRule } from "anonyma/ai";
import { compilePipeline } from "anonyma/engine";
import type { Pipeline, PipelineSpec } from "anonyma/engine";
import { createSessionTokenizer } from "anonyma/vault";
import type { SessionSnapshot, SessionTokenizer, SessionTokenizerOptions } from "anonyma/vault";

/** A JSON-RPC message identifier. */
type MessageId = string | number;

/** Members of MCP content that describe structure or carry binary data, never text for a model. */
const CONTENT_KEEP: ReadonlySet<string> = new Set([
  "type",
  "mimeType",
  "uri",
  "data",
  "blob",
  "annotations",
  "_meta",
  "role",
  "isError",
  "size",
]);

/** Deepest nesting walked when restoring arguments. */
const MAX_DEPTH = 256;

/**
 * What the guard did to one message, without any of the replaced text.
 */
export interface McpGuardEvent {
  /** Which way the message travelled. */
  readonly direction: "to-client" | "to-server";
  /** The JSON-RPC method of the message, or of the request a response answers. */
  readonly method: string;
  /** Values replaced by tokens (`to-client`) or tokens replaced by values (`to-server`). */
  readonly replaced: number;
}

/**
 * Options accepted by {@link createMcpGuard}.
 */
export interface McpGuardOptions {
  /**
   * What to detect. The strategy members are ignored: every detection becomes
   * a session token. Defaults to every built-in category.
   */
  readonly spec?: Omit<PipelineSpec, "defaultStrategy" | "rules" | "tokenization">;
  /** Token shape and tag of the session. `lenient` defaults to `true`. */
  readonly session?: Omit<SessionTokenizerOptions, "snapshot">;
  /** Continue the token mapping of an earlier connection. */
  readonly snapshot?: SessionSnapshot;
  /** Keys whose values are tokenized whole, such as `password`, in structured content. */
  readonly keyRules?: readonly KeyRule[];
  /** Called for every message the guard changed. */
  readonly onEvent?: (event: McpGuardEvent) => void;
}

/**
 * The guard of one MCP connection.
 */
export interface McpGuard {
  /** The session that holds the token mapping. */
  readonly session: SessionTokenizer;
  /**
   * Process a JSON-RPC message (or batch) travelling from the server to the
   * client. Returns a sanitized copy; the input is not modified.
   */
  readonly fromServer: (message: unknown) => unknown;
  /**
   * Process a JSON-RPC message (or batch) travelling from the client to the
   * server. Returns a copy with tokens restored; the input is not modified.
   */
  readonly fromClient: (message: unknown) => unknown;
  /** Sanitize the result of `tools/call`, `resources/read` or `prompts/get`. */
  readonly sanitizeResult: (method: string, result: unknown) => unknown;
  /** Restore tokens in every string of a value, such as the arguments of a tool call. */
  readonly restoreValue: <T>(value: T) => T;
  /** Replace personal data in a text with tokens. */
  readonly sanitizeText: (text: string) => string;
  /** Replace tokens in a text with the original values. */
  readonly restoreText: (text: string) => string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function isId(value: unknown): value is MessageId {
  return typeof value === "string" || typeof value === "number";
}

/** A key for a message id that keeps `1` and `"1"` apart. */
function idKey(id: MessageId): string {
  return `${typeof id}:${String(id)}`;
}

/**
 * Create the guard of one MCP connection.
 *
 * @param options - What to detect, how tokens look, and an event callback.
 * @returns The {@link McpGuard}.
 * @throws ValidationError (from `anonyma`) When the spec or the session options are invalid.
 *
 * @example
 * ```ts
 * import { createMcpGuard } from "@anonyma/mcp";
 *
 * const guard = createMcpGuard();
 * upstream.onmessage = (message) => client.send(guard.fromServer(message));
 * client.onmessage = (message) => upstream.send(guard.fromClient(message));
 * ```
 */
export function createMcpGuard(options: McpGuardOptions = {}): McpGuard {
  const { keyRules, onEvent } = options;
  const session = createSessionTokenizer({
    lenient: true,
    ...options.session,
    ...(options.snapshot !== undefined ? { snapshot: options.snapshot } : {}),
  });
  const pipeline: Pipeline = compilePipeline(
    { ...options.spec, defaultStrategy: { strategy: "tokenize" } },
    { tokenization: session },
  );

  /** Methods of the requests each side sent, by id, to read the responses. */
  const clientRequests = new Map<string, string>();
  const serverRequests = new Map<string, string>();

  let replaced = 0;

  const sanitizeText = (text: string): string => {
    const result = pipeline.transform(text);
    replaced += result.spans.length;
    return result.text;
  };

  const restoreText = (text: string): string => {
    const result = session.restore(text);
    replaced += result.restored;
    return result.text;
  };

  /** Sanitize every string of a value, keys included. */
  const sanitizeAll = (value: unknown): unknown => {
    const result = sanitizeJson(value, {
      pipeline,
      ...(keyRules !== undefined ? { keyRules } : {}),
    });
    replaced += result.replaced;
    return result.value;
  };

  /** Sanitize MCP content: text and descriptions, not types, URIs or binary data. */
  const sanitizeContent = (value: unknown): unknown => {
    const result = sanitizeJson(value, {
      pipeline,
      skipMember: (key) => CONTENT_KEEP.has(key),
      ...(keyRules !== undefined ? { keyRules } : {}),
    });
    replaced += result.replaced;
    return result.value;
  };

  const restoreValue = <T>(value: T): T => {
    const walk = (item: unknown, depth: number): unknown => {
      if (typeof item === "string") return restoreText(item);
      if (depth >= MAX_DEPTH) return item;
      if (Array.isArray(item)) return item.map((entry: unknown) => walk(entry, depth + 1));
      if (!isRecord(item)) return item;
      const out: Record<string, unknown> = {};
      for (const [key, member] of Object.entries(item)) {
        Object.defineProperty(out, key, {
          value: walk(member, depth + 1),
          writable: true,
          enumerable: true,
          configurable: true,
        });
      }
      return out;
    };
    return walk(value, 0) as T;
  };

  /** A copy of `record` with `key` replaced through `transform`; `record` itself when nothing changed. */
  const withMember = (
    record: Record<string, unknown>,
    key: string,
    transform: (value: unknown) => unknown,
  ): Record<string, unknown> => {
    const value = record[key];
    if (value === undefined) return record;
    const next = transform(value);
    return next === value ? record : { ...record, [key]: next };
  };

  const sanitizeResult = (method: string, result: unknown): unknown => {
    if (!isRecord(result)) return result;
    switch (method) {
      case "tools/call": {
        const content = withMember(result, "content", sanitizeContent);
        return withMember(content, "structuredContent", sanitizeAll);
      }
      case "resources/read":
        return withMember(result, "contents", sanitizeContent);
      case "prompts/get": {
        const messages = withMember(result, "messages", sanitizeContent);
        return withMember(messages, "description", sanitizeAll);
      }
      default:
        return result;
    }
  };

  const sanitizeError = (error: unknown): unknown => {
    if (!isRecord(error)) return error;
    const message = withMember(error, "message", sanitizeAll);
    return withMember(message, "data", sanitizeAll);
  };

  /** Run `process` on one message and report what it changed. */
  const counted = (
    direction: McpGuardEvent["direction"],
    method: string,
    process: () => unknown,
  ): unknown => {
    replaced = 0;
    const out = process();
    if (replaced > 0) onEvent?.({ direction, method, replaced });
    return out;
  };

  function fromServerOne(message: unknown): unknown {
    if (!isRecord(message)) return message;
    const { id, method } = message;
    if (typeof method === "string") {
      // A request or a notification from the server.
      if (isId(id)) serverRequests.set(idKey(id), method);
      const params = message["params"];
      if (!isRecord(params)) return message;
      return counted("to-client", method, () => {
        switch (method) {
          case "sampling/createMessage": {
            const messages = withMember(params, "messages", sanitizeContent);
            return { ...message, params: withMember(messages, "systemPrompt", sanitizeAll) };
          }
          case "notifications/message":
            return { ...message, params: withMember(params, "data", sanitizeAll) };
          case "notifications/progress":
            return { ...message, params: withMember(params, "message", sanitizeAll) };
          default:
            return message;
        }
      });
    }
    if (!isId(id)) return message;
    // A response to a request of the client.
    const key = idKey(id);
    const request = clientRequests.get(key) ?? "";
    clientRequests.delete(key);
    return counted("to-client", request, () => {
      if (message["error"] !== undefined) {
        return { ...message, error: sanitizeError(message["error"]) };
      }
      return withMember(message, "result", (result) => sanitizeResult(request, result));
    });
  }

  function fromClientOne(message: unknown): unknown {
    if (!isRecord(message)) return message;
    const { id, method } = message;
    if (typeof method === "string") {
      // A request or a notification from the client.
      if (isId(id)) clientRequests.set(idKey(id), method);
      const params = message["params"];
      if (!isRecord(params)) return message;
      return counted("to-server", method, () => {
        switch (method) {
          case "tools/call":
          case "prompts/get":
            return { ...message, params: withMember(params, "arguments", restoreValue) };
          case "resources/read":
            return { ...message, params: withMember(params, "uri", restoreValue) };
          default:
            return message;
        }
      });
    }
    if (!isId(id)) return message;
    // A response to a request of the server.
    const key = idKey(id);
    const request = serverRequests.get(key) ?? "";
    serverRequests.delete(key);
    if (request !== "sampling/createMessage") return message;
    // The client's model answered the server: the server gets real values.
    return counted("to-server", request, () => withMember(message, "result", restoreValue));
  }

  const batch =
    (one: (message: unknown) => unknown) =>
    (message: unknown): unknown =>
      Array.isArray(message) ? message.map((item: unknown) => one(item)) : one(message);

  return Object.freeze({
    session,
    fromServer: batch(fromServerOne),
    fromClient: batch(fromClientOne),
    sanitizeResult: (method: string, result: unknown): unknown => {
      replaced = 0;
      return sanitizeResult(method, result);
    },
    restoreValue,
    sanitizeText,
    restoreText,
  });
}
