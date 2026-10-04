/**
 * @module ai/guard
 * @description Redaction middleware for LLM calls: personal data is replaced
 * by tokens before a prompt leaves the process, and the tokens are replaced
 * by the original values in what comes back — also when it comes back as a
 * stream. The mapping between tokens and values never leaves the process.
 */

import { ValidationError } from "../errors.js";
import type { AuditFieldEntry } from "../audit/types.js";
import { compilePipeline } from "../engine/compile.js";
import type { Pipeline, PipelineSpec } from "../engine/types.js";
import { createSessionTokenizer } from "../vault/session.js";
import type {
  SessionSnapshot,
  SessionTokenizer,
  SessionTokenizerOptions,
} from "../vault/session.js";
import type { RestoreResult } from "../vault/types.js";
import { sanitizeJson } from "./json.js";
import type { KeyRule } from "./json.js";
import {
  createRestoreStream,
  createRestoreTransformer,
  restoreChunks,
  restoreJsonText,
  textDeltaLens,
} from "./restore.js";

/**
 * Members of a chat message that describe structure and must reach the model
 * unchanged. They are only honoured at the top level of a message.
 */
const MESSAGE_KEEP: ReadonlySet<string> = new Set([
  "role",
  "name",
  "id",
  "type",
  "model",
  "tool_call_id",
  "toolCallId",
  "finish_reason",
  "stop_reason",
  "cache_control",
]);

/** Structural members of a content part, honoured at the top level of the part only. */
const PART_KEEP: ReadonlySet<string> = new Set([
  "type",
  "id",
  "name",
  "tool_use_id",
  "tool_call_id",
  "toolCallId",
  "toolName",
  "is_error",
  "cache_control",
]);

/** Structural members of an OpenAI-style tool call. */
const TOOL_CALL_KEEP: ReadonlySet<string> = new Set(["id", "type", "index"]);

/** Structural members of the `{ name, arguments }` object of a tool call. */
const FUNCTION_KEEP: ReadonlySet<string> = new Set(["name"]);

/**
 * Members a provider expects back byte for byte: signatures of thinking
 * blocks, encrypted reasoning and search results, provider-specific options.
 * Rewriting one makes the provider reject the next request.
 */
const OPAQUE_KEYS: ReadonlySet<string> = new Set([
  "signature",
  "thoughtSignature",
  "thought_signature",
  "encrypted_content",
  "encrypted_index",
  "reasoningEncryptedContent",
  "providerOptions",
  "providerMetadata",
  "experimental_providerMetadata",
]);

/** Members of a media part that hold or locate the media itself. */
const MEDIA_PAYLOAD_KEYS: ReadonlySet<string> = new Set([
  "data",
  "file_data",
  "url",
  "image_url",
  "image",
  "audio",
  "video",
  "file_id",
  "fileId",
]);

/** Deepest nesting of content parts accepted in a message. */
const MAX_DEPTH = 512;

/** The media type an object declares for its payload, if any. */
function mediaTypeOf(parent: Readonly<Record<string, unknown>>): string | undefined {
  for (const key of ["media_type", "mediaType", "mimeType", "mime_type"]) {
    const value = parent[key];
    if (typeof value === "string") return value;
  }
  return undefined;
}

/** Whether `parent.data` is text that can and must be inspected. */
function isTextPayload(parent: Readonly<Record<string, unknown>>): boolean {
  const media = mediaTypeOf(parent);
  return parent["type"] === "text" || (media !== undefined && /^text\//i.test(media));
}

/** Whether a member must reach the model untouched, wherever it occurs. */
function isOpaque(key: string, parent: Readonly<Record<string, unknown>>): boolean {
  if (OPAQUE_KEYS.has(key)) return true;
  const value = parent[key];
  // A data URL is a payload under any name.
  if (typeof value === "string" && /^data:[\w.+-]+\/[\w.+-]+;base64,/i.test(value)) return true;
  if (key !== "data") return false;
  if (parent["type"] === "redacted_thinking" || parent["type"] === "base64") return true;
  return mediaTypeOf(parent) !== undefined && !isTextPayload(parent);
}

/** Whether a member of a media part holds the media rather than text about it. */
function isMediaPayload(key: string, parent: Readonly<Record<string, unknown>>): boolean {
  if (isOpaque(key, parent)) return true;
  if (!MEDIA_PAYLOAD_KEYS.has(key)) return false;
  return !(key === "data" && isTextPayload(parent));
}

/** Content parts that carry media. Their payload is passed on; their text is inspected. */
const MEDIA_PARTS: ReadonlySet<string> = new Set([
  "image",
  "image_url",
  "input_image",
  "file",
  "input_file",
  "document",
  "audio",
  "input_audio",
  "video",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function setOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Options accepted by {@link createLlmGuard}.
 */
export interface LlmGuardOptions {
  /**
   * What to detect. The strategy members of the spec are ignored: every
   * detection is replaced by a session token. Defaults to every built-in
   * category.
   */
  readonly spec?: Omit<PipelineSpec, "defaultStrategy" | "rules">;
  /** Options for the session tokenizer of each exchange. `lenient` defaults to `true`. */
  readonly session?: Omit<SessionTokenizerOptions, "snapshot">;
  /** Message roles that are sent unchanged, for example `["system"]`. */
  readonly skipRoles?: readonly string[];
  /** Keys whose values are tokenized whole, such as `password`. */
  readonly keyRules?: readonly KeyRule[];
  /**
   * Further members that must reach the model byte for byte, by key name at
   * any depth. Signatures, encrypted reasoning, provider options and media
   * payloads are passed on without this. Whatever is passed on is listed in
   * {@link SanitizedMessages.unscanned}.
   */
  readonly passthroughKeys?: readonly string[];
  /**
   * Counts the tokens of a text with the tokenizer of the target model. When
   * given, {@link SanitizedMessages.tokens} reports the prompt size before and
   * after sanitization.
   */
  readonly countTokens?: (text: string) => number;
}

/**
 * Sanitized chat messages and an account of what was replaced.
 */
export interface SanitizedMessages<M> {
  /** The messages to send: same length, same structure, tokens in place of personal data. */
  readonly messages: M[];
  /** What was replaced where, without any of the replaced text. */
  readonly fields: readonly AuditFieldEntry[];
  /** Total number of replacements. */
  readonly replaced: number;
  /**
   * JSON Pointers of what was passed on without inspection: media payloads
   * (images, files, audio), members a provider needs byte for byte
   * (signatures, encrypted reasoning), `passthroughKeys`, and values that are
   * not JSON.
   */
  readonly unscanned: readonly string[];
  /** JSON Pointers of members whose key held personal data and was replaced by a token. */
  readonly flaggedKeys: readonly string[];
  /** Prompt size in model tokens before and after, when `countTokens` is configured. */
  readonly tokens?: { readonly before: number; readonly after: number };
}

/**
 * One guarded exchange with a model: a request and its response, or a whole
 * conversation. Everything sanitized through the same exchange shares one
 * token mapping, so a value keeps its token across turns.
 */
export interface LlmExchange {
  /** The session that holds the token mapping. */
  readonly session: SessionTokenizer;
  /** Replace personal data in a text with tokens. */
  readonly sanitizeText: (text: string) => string;
  /**
   * Replace personal data in chat messages with tokens, preserving their
   * structure. Structural members are left alone where the message formats
   * define them — `role`, `name`, identifiers and `type` on a message or a
   * content part, the function name of a tool call — and nowhere else: tool
   * arguments and tool results are sanitized at every depth, object keys
   * included. Of a media part the payload is passed on and listed in
   * `unscanned`; its text (title, context, file name, a text source) is
   * sanitized.
   *
   * @throws ValidationError When a message is not a plain object. A class
   *   instance cannot be copied with tokens in place of its content: sanitize
   *   the text before the message object is built, with `sanitizeText()`.
   */
  readonly sanitizeMessages: <M>(messages: readonly M[]) => SanitizedMessages<M>;
  /** Replace tokens in model output with the original values. */
  readonly restoreText: (text: string) => RestoreResult;
  /** A transform stream that restores tokens in streamed model output. */
  readonly restoreStream: () => TransformStream<string, string>;
  /** Restore tokens in model output delivered as an async iterable of text. */
  readonly restoreIterable: (
    source: AsyncIterable<string>,
  ) => AsyncGenerator<string, void, undefined>;
  /** A serialisable copy of the token mapping, to continue the conversation later. */
  readonly snapshot: () => SessionSnapshot;
}

/**
 * The redaction middleware.
 */
export interface LlmGuard {
  /**
   * Start an exchange.
   *
   * @param snapshot - The snapshot of an earlier exchange to continue from.
   */
  readonly begin: (snapshot?: SessionSnapshot) => LlmExchange;
}

/**
 * Create the redaction middleware for LLM calls.
 *
 * @param options - What to detect and how tokens look.
 * @returns The {@link LlmGuard}.
 * @throws {@link ValidationError} When the spec is invalid.
 *
 * @example
 * ```ts
 * import { createLlmGuard } from "anonyma/ai";
 *
 * const guard = createLlmGuard({ skipRoles: ["system"] });
 *
 * const exchange = guard.begin();
 * const { messages } = exchange.sanitizeMessages([
 *   { role: "system", content: "You are a support assistant." },
 *   { role: "user", content: "Email alice@example.com about invoice 42." },
 * ]);
 * // messages[1].content === "Email [EMAIL_0001] about invoice 42."
 *
 * const stream = await llm.streamText(messages);            // "Sure, I wrote to [EMAIL_0001]."
 * for await (const text of exchange.restoreIterable(stream)) {
 *   process.stdout.write(text);                             // "Sure, I wrote to alice@example.com."
 * }
 * ```
 */
export function createLlmGuard(options: LlmGuardOptions = {}): LlmGuard {
  const { skipRoles = [], keyRules, countTokens } = options;
  const passthrough = new Set(options.passthroughKeys ?? []);
  const exempt = (key: string, parent: Readonly<Record<string, unknown>>): boolean =>
    passthrough.has(key) || isOpaque(key, parent);
  const exemptInMedia = (key: string, parent: Readonly<Record<string, unknown>>): boolean =>
    passthrough.has(key) || isMediaPayload(key, parent);
  const sessionOptions = { lenient: true, ...options.session };
  const skip = new Set(skipRoles);

  // Fail on a bad spec now rather than on the first request.
  const probe = createSessionTokenizer(sessionOptions);
  const compile = (session: SessionTokenizer): Pipeline =>
    compilePipeline(
      { ...options.spec, defaultStrategy: { strategy: "tokenize" } },
      { tokenization: session },
    );
  compile(probe);

  function begin(snapshot?: SessionSnapshot): LlmExchange {
    const session = createSessionTokenizer({
      ...sessionOptions,
      ...(snapshot !== undefined ? { snapshot } : {}),
    });
    const pipeline = compile(session);

    function sanitizeText(text: string): string {
      return pipeline.transform(text).text;
    }

    function sanitizeMessages<M>(messages: readonly M[]): SanitizedMessages<M> {
      if (!Array.isArray(messages)) throw new ValidationError("messages", "must be an array");
      const fields: AuditFieldEntry[] = [];
      const unscanned: string[] = [];
      const flaggedKeys: string[] = [];
      let replaced = 0;
      type Exempt = (key: string, parent: Readonly<Record<string, unknown>>) => boolean;

      /** Sanitize a value in full: every string at every depth. */
      const json = (value: unknown, path: string, skipMember: Exempt = exempt): unknown => {
        const result = sanitizeJson(value, {
          pipeline,
          jsonStringKeys: ["arguments"],
          skipMember,
          ...(keyRules !== undefined ? { keyRules } : {}),
        });
        replaced += result.replaced;
        for (const field of result.fields) fields.push({ ...field, path: `${path}${field.path}` });
        for (const skipped of result.skipped) unscanned.push(`${path}${skipped}`);
        for (const flagged of result.flaggedKeys) flaggedKeys.push(`${path}${flagged}`);
        return result.value;
      };

      type Entry = readonly [key: string, value: unknown];

      /**
       * Sanitize one member together with its key, so that key rules and
       * embedded JSON documents are recognised, and a key that holds personal
       * data is replaced. `siblings` is the object the member comes from,
       * which decides whether it is a payload.
       */
      const member = (
        key: string,
        siblings: Readonly<Record<string, unknown>>,
        parent: string,
        skipMember: Exempt = exempt,
      ): Entry => {
        const holder: Record<string, unknown> = {};
        setOwn(holder, key, siblings[key]);
        const judge: Exempt = (name, object) =>
          skipMember(name, object === holder ? siblings : object);
        const [entry] = Object.entries(json(holder, parent, judge) as Record<string, unknown>);
        return entry ?? [key, undefined];
      };

      /** Copy an object, keeping its structural members and handing the others to `handle`. */
      const copy = (
        source: Record<string, unknown>,
        keep: ReadonlySet<string>,
        handle: (key: string, value: unknown) => Entry,
      ): Record<string, unknown> => {
        const out: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(source)) {
          const [name, item] = keep.has(key) ? [key, value] : handle(key, value);
          setOwn(out, name, item);
        }
        return out;
      };

      const part = (value: unknown, path: string, depth: number): unknown => {
        if (!isPlainObject(value)) return json(value, path);
        if (depth >= MAX_DEPTH) throw new ValidationError("messages", "are nested too deeply");
        // Of a media part the payload is passed on; what is written about it is not.
        const media = typeof value["type"] === "string" && MEDIA_PARTS.has(value["type"]);
        return copy(value, PART_KEEP, (key, item) =>
          key === "content"
            ? [key, content(item, `${path}/content`, depth + 1)]
            : member(key, value, path, media ? exemptInMedia : exempt),
        );
      };

      const content = (value: unknown, path: string, depth: number): unknown =>
        Array.isArray(value)
          ? (value as unknown[]).map((item, index) => part(item, `${path}/${String(index)}`, depth))
          : json(value, path);

      /** `{ name, arguments }`: the function name is structure, the arguments are data. */
      const call = (value: unknown, path: string): unknown =>
        isPlainObject(value)
          ? copy(value, FUNCTION_KEEP, (key) => member(key, value, path))
          : json(value, path);

      const out = (messages as readonly M[]).map((message, index) => {
        const path = `/${String(index)}`;
        if (!isPlainObject(message)) {
          if (typeof message === "object" && message !== null && !Array.isArray(message)) {
            throw new ValidationError(
              `messages[${String(index)}]`,
              "is not a plain object and cannot be sanitized; sanitize its text with sanitizeText() before building it",
            );
          }
          return json(message, path) as M;
        }
        if (typeof message["role"] === "string" && skip.has(message["role"])) return message;
        return copy(message, MESSAGE_KEEP, (key, value) => {
          if (key === "content") return [key, content(value, `${path}/content`, 0)];
          if (key === "function_call") return [key, call(value, `${path}/function_call`)];
          if (key === "tool_calls" && Array.isArray(value)) {
            const calls = (value as unknown[]).map((item, position) => {
              const itemPath = `${path}/tool_calls/${String(position)}`;
              if (!isPlainObject(item)) return json(item, itemPath);
              return copy(item, TOOL_CALL_KEEP, (callKey, callValue) =>
                callKey === "function"
                  ? [callKey, call(callValue, `${itemPath}/function`)]
                  : member(callKey, item, itemPath),
              );
            });
            return [key, calls];
          }
          return member(key, message, path);
        }) as M;
      });

      return {
        messages: out,
        fields,
        replaced,
        unscanned,
        flaggedKeys,
        ...(countTokens !== undefined
          ? {
              tokens: {
                before: countTokens(JSON.stringify(messages)),
                after: countTokens(JSON.stringify(out)),
              },
            }
          : {}),
      };
    }

    async function* restoreIterable(
      source: AsyncIterable<string>,
    ): AsyncGenerator<string, void, undefined> {
      const restorer = createRestoreTransformer(session);
      for await (const chunk of source) {
        const out = await restorer.push(chunk);
        if (out !== "") yield out;
      }
      const rest = await restorer.flush();
      if (rest !== "") yield rest;
    }

    return Object.freeze({
      session,
      sanitizeText,
      sanitizeMessages,
      restoreText: (text: string): RestoreResult => session.restore(text),
      restoreStream: (): TransformStream<string, string> => createRestoreStream(session),
      restoreIterable,
      snapshot: (): SessionSnapshot => session.snapshot(),
    });
  }

  return Object.freeze({ begin });
}

/**
 * The parts of a language-model middleware this adapter implements. The
 * shape matches `LanguageModelMiddleware` of the Vercel AI SDK structurally,
 * so the object can be passed to `wrapLanguageModel()` without this library
 * depending on the SDK.
 */
export interface LanguageModelMiddlewareLike {
  /** Sanitizes the prompt before it reaches the model. */
  readonly transformParams: (input: {
    readonly params: Record<string, unknown>;
  }) => Promise<Record<string, unknown>>;
  /** Restores tokens in a complete response. */
  readonly wrapGenerate: (input: {
    readonly doGenerate: () => PromiseLike<unknown>;
    readonly params: Record<string, unknown>;
  }) => Promise<unknown>;
  /** Restores tokens in a streamed response. */
  readonly wrapStream: (input: {
    readonly doStream: () => PromiseLike<{ readonly stream: ReadableStream<unknown> }>;
    readonly params: Record<string, unknown>;
  }) => Promise<{ readonly stream: ReadableStream<unknown> }>;
}

/** Members of a model result that hold a JSON document as text: the arguments of a tool call. */
const JSON_TEXT_KEYS: ReadonlySet<string> = new Set(["input", "args", "arguments"]);

/** Carries the exchange from `transformParams` to the call that uses its result. */
const EXCHANGE = Symbol("anonyma.exchange");

/**
 * Restore tokens in every string of a model result. The arguments of a tool
 * call are a JSON document: values are restored into the parsed document, so
 * that no restored value can break it or add an argument.
 */
async function restoreDeep(
  value: unknown,
  exchange: LlmExchange,
  key?: string,
  depth = 0,
): Promise<unknown> {
  if (typeof value === "string") {
    return key !== undefined && JSON_TEXT_KEYS.has(key)
      ? restoreJsonText(value, exchange.session)
      : exchange.restoreText(value).text;
  }
  if (typeof value !== "object" || value === null || depth > 64) return value;
  if (Array.isArray(value)) {
    const items: unknown[] = [];
    for (const item of value as unknown[]) {
      items.push(await restoreDeep(item, exchange, undefined, depth + 1));
    }
    return items;
  }
  const proto = Object.getPrototypeOf(value) as unknown;
  if (proto !== Object.prototype && proto !== null) return value;
  const out: Record<string, unknown> = {};
  for (const [name, member] of Object.entries(value)) {
    setOwn(out, name, await restoreDeep(member, exchange, name, depth + 1));
  }
  return out;
}

/**
 * Options accepted by {@link toLanguageModelMiddleware}.
 */
export interface LanguageModelMiddlewareOptions {
  /**
   * Called with the account of every sanitized prompt: what was replaced,
   * and above all what was passed on without inspection (`unscanned`). Throw
   * from it to stop a request that must not be sent.
   */
  readonly onSanitized?: (report: SanitizedMessages<unknown>) => void;
}

/**
 * Adapt a guard to the language-model middleware shape of the Vercel AI SDK.
 *
 * The prompt (`params.prompt`) is sanitized on the way in. On the way out,
 * tokens are restored in the result of `doGenerate()` and in the `text-delta`
 * and `tool-call` parts of `doStream()`; the arguments of a tool call are
 * restored as the JSON document they are. Partial tool input
 * (`tool-input-delta`) is passed on as it is. Each call gets its own exchange.
 *
 * @param guard - The guard to adapt.
 * @param options - A callback that receives the account of each sanitized prompt.
 * @returns An object to pass as `middleware` to `wrapLanguageModel()`.
 *
 * @remarks
 * The adapter is typed structurally and tested against stand-ins for the SDK,
 * not against the SDK itself. Check it against the SDK version you use.
 * `wrapGenerate` and `wrapStream` need the `params` object that
 * `transformParams` returned (a copy made with spread syntax works too) and
 * throw when they get another one: restoring nothing would go unnoticed.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel } from "ai";
 * import { createLlmGuard, toLanguageModelMiddleware } from "anonyma/ai";
 *
 * const model = wrapLanguageModel({
 *   model: baseModel,
 *   middleware: toLanguageModelMiddleware(createLlmGuard()),
 * });
 * ```
 */
export function toLanguageModelMiddleware(
  guard: LlmGuard,
  options: LanguageModelMiddlewareOptions = {},
): LanguageModelMiddlewareLike {
  const { onSanitized } = options;

  const exchangeOf = (params: Record<string, unknown>): LlmExchange => {
    const exchange = (params as { readonly [EXCHANGE]?: LlmExchange })[EXCHANGE];
    if (exchange === undefined) {
      throw new ValidationError(
        "params",
        "did not come from transformParams(), so the tokens in the response cannot be restored",
      );
    }
    return exchange;
  };

  /** Restore the parts of a stream that are not plain text deltas. */
  const restorePart = async (part: unknown, exchange: LlmExchange): Promise<unknown> => {
    if (!isPlainObject(part) || part["type"] !== "tool-call") return part;
    return restoreDeep(part, exchange);
  };

  return Object.freeze({
    transformParams({
      params,
    }: {
      readonly params: Record<string, unknown>;
    }): Promise<Record<string, unknown>> {
      const exchange = guard.begin();
      const prompt = params["prompt"];
      const transformed: Record<string, unknown> = { ...params };
      if (Array.isArray(prompt)) {
        const report = exchange.sanitizeMessages(prompt as unknown[]);
        onSanitized?.(report);
        transformed["prompt"] = report.messages;
      } else if (typeof prompt === "string") {
        transformed["prompt"] = exchange.sanitizeText(prompt);
      }
      // A symbol-keyed member survives a spread copy and is not serialised.
      Object.defineProperty(transformed, EXCHANGE, { value: exchange, enumerable: true });
      return Promise.resolve(transformed);
    },

    async wrapGenerate({
      doGenerate,
      params,
    }: {
      readonly doGenerate: () => PromiseLike<unknown>;
      readonly params: Record<string, unknown>;
    }): Promise<unknown> {
      const exchange = exchangeOf(params);
      return restoreDeep(await doGenerate(), exchange);
    },

    async wrapStream({
      doStream,
      params,
    }: {
      readonly doStream: () => PromiseLike<{ readonly stream: ReadableStream<unknown> }>;
      readonly params: Record<string, unknown>;
    }): Promise<{ readonly stream: ReadableStream<unknown> }> {
      const exchange = exchangeOf(params);
      const result = await doStream();

      async function* parts(): AsyncGenerator<unknown, void, undefined> {
        const reader = result.stream.getReader();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) return;
            yield value;
          }
        } finally {
          reader.releaseLock();
        }
      }
      const lens = {
        get: (part: unknown): string | undefined =>
          isPlainObject(part) ? textDeltaLens.get(part) : undefined,
        set: (part: unknown, text: string): unknown =>
          textDeltaLens.set(part as Record<string, unknown>, text),
        block: (part: unknown): string | undefined =>
          isPlainObject(part) ? textDeltaLens.block?.(part) : undefined,
      };
      // Held text is delivered before the next part without text, so nothing
      // arrives after the part that ends its block.
      const restored = restoreChunks(parts(), lens, exchange.session);

      const stream = new ReadableStream<unknown>({
        async pull(controller): Promise<void> {
          for (;;) {
            const next = await restored.next();
            if (next.done === true) {
              controller.close();
              return;
            }
            const part = next.value;
            const text = lens.get(part);
            // A delta whose text is all held back for now is not worth a part.
            if (text === "") continue;
            controller.enqueue(text === undefined ? await restorePart(part, exchange) : part);
            return;
          }
        },
        async cancel(reason): Promise<void> {
          await restored.return();
          await result.stream.cancel(reason);
        },
      });
      return { ...result, stream };
    },
  });
}
