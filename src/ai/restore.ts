/**
 * @module ai/restore
 * @description Restoring tokens in model output that arrives as a stream. A
 * token may be split across chunks (`[EMAIL_00` + `01]`), so the transformer
 * holds back a trailing fragment that could still become a token.
 */

import { ValidationError } from "../errors.js";
import type { AsyncChunkTransformer } from "../engine/types.js";
import { parseJsonLossless, stringifyJsonLossless } from "../internal/json-numbers.js";
import { restoreTokens } from "../vault/restore.js";
import type { TokenizationProvider } from "../vault/types.js";

/** Deepest nesting of a JSON document in which tokens are restored. */
const MAX_JSON_DEPTH = 512;

/**
 * Create a push-style transformer that restores the tokens of `provider` in
 * text arriving in arbitrary chunks.
 *
 * The output is the same as restoring the whole text at once, however the
 * text is split, and accepts the same spellings of a token: a provider with
 * its own `restore()` (a lenient session) is used through it.
 *
 * @param provider - The provider that issued the tokens.
 * @returns An {@link AsyncChunkTransformer}. Await each `push()` before the next.
 *
 * @example
 * ```ts
 * const restorer = createRestoreTransformer(session);
 * for await (const delta of modelStream) ui.append(await restorer.push(delta));
 * ui.append(await restorer.flush());
 * ```
 */
export function createRestoreTransformer(provider: TokenizationProvider): AsyncChunkTransformer {
  const partial =
    provider.partialTokenPattern === undefined
      ? undefined
      : new RegExp(
          provider.partialTokenPattern.source,
          provider.partialTokenPattern.flags.replace(/[gy]/g, ""),
        );
  const whole = new RegExp(
    provider.tokenPattern.source,
    provider.tokenPattern.flags.replace("y", "").replace("g", "") + "g",
  );
  let carry = "";

  async function push(chunk: string): Promise<string> {
    if (typeof chunk !== "string") throw new ValidationError("chunk", "must be a string");
    const buffer = carry + chunk;
    let hold: number;
    if (partial === undefined) {
      hold = Math.max(0, buffer.length - (provider.maxTokenLength - 1));
      // A complete token that crosses the cut goes out whole; only what follows it is held back.
      for (const match of buffer.matchAll(whole)) {
        if (match.index >= hold) break;
        const end = match.index + match[0].length;
        if (end > hold) hold = end;
      }
    } else {
      const match = partial.exec(buffer);
      // A fragment longer than any token cannot be the start of one.
      hold =
        match === null || buffer.length - match.index >= provider.maxTokenLength
          ? buffer.length
          : match.index;
    }
    carry = buffer.slice(hold);
    return hold === 0 ? "" : (await restoreTokens(buffer.slice(0, hold), provider)).text;
  }

  async function flush(): Promise<string> {
    const rest = carry;
    carry = "";
    return rest === "" ? "" : (await restoreTokens(rest, provider)).text;
  }

  return Object.freeze({ push, flush });
}

/**
 * Create a WHATWG `TransformStream` that restores tokens in a stream of text.
 *
 * @param provider - The provider that issued the tokens.
 * @returns A `TransformStream<string, string>`.
 * @throws {@link ValidationError} When `TransformStream` is unavailable.
 *
 * @example
 * ```ts
 * const restored = modelTextStream.pipeThrough(createRestoreStream(session));
 * ```
 */
export function createRestoreStream(
  provider: TokenizationProvider,
): TransformStream<string, string> {
  if (typeof TransformStream === "undefined") {
    throw new ValidationError("TransformStream", "is not available in this environment");
  }
  const restorer = createRestoreTransformer(provider);
  return new TransformStream<string, string>({
    async transform(chunk, controller): Promise<void> {
      const out = await restorer.push(chunk);
      if (out.length > 0) controller.enqueue(out);
    },
    async flush(controller): Promise<void> {
      const out = await restorer.flush();
      if (out.length > 0) controller.enqueue(out);
    },
  });
}

/**
 * Restore the tokens inside a JSON document held as text, such as the
 * arguments of a tool call. Values are restored into the parsed document and
 * the document is serialised again, so a restored value that contains a
 * quote, a backslash or a line break can neither break the document nor add
 * members to it. A text that is not JSON is restored as plain text; a
 * document without tokens is returned as it was written.
 *
 * @param text - The JSON document.
 * @param provider - The provider that issued the tokens.
 * @returns The document with restored values.
 * @throws {@link ValidationError} When the document is nested deeper than 512 levels.
 *
 * @example
 * ```ts
 * await restoreJsonText('{"to":"[EMAIL_0001]"}', session); // '{"to":"alice@example.com"}'
 * ```
 */
export async function restoreJsonText(
  text: string,
  provider: TokenizationProvider,
): Promise<string> {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");
  let parsed: ReturnType<typeof parseJsonLossless>;
  try {
    parsed = parseJsonLossless(text);
  } catch {
    return (await restoreTokens(text, provider)).text;
  }
  const { marker } = parsed;
  let restored = 0;

  const restore = async (value: string): Promise<string> => {
    const result = await restoreTokens(value, provider);
    restored += result.restored;
    return result.text;
  };
  const walk = async (value: unknown, depth: number): Promise<unknown> => {
    if (typeof value === "string") {
      return marker !== undefined && value.startsWith(marker) ? value : restore(value);
    }
    if (typeof value !== "object" || value === null) return value;
    if (depth >= MAX_JSON_DEPTH) throw new ValidationError("text", "is nested too deeply");
    if (Array.isArray(value)) {
      const items: unknown[] = [];
      for (const item of value as unknown[]) items.push(await walk(item, depth + 1));
      return items;
    }
    const out: Record<string, unknown> = {};
    for (const [key, member] of Object.entries(value)) {
      Object.defineProperty(out, await restore(key), {
        value: await walk(member, depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    return out;
  };

  const value = await walk(parsed.value, 0);
  return restored === 0 ? text : stringifyJsonLossless(value, marker);
}

/**
 * Reads and writes the text of a structured stream chunk.
 */
export interface ChunkLens<C> {
  /** The text of the chunk, or `undefined` when the chunk carries no text. */
  readonly get: (chunk: C) => string | undefined;
  /** A copy of the chunk with its text replaced. */
  readonly set: (chunk: C, text: string) => C;
  /**
   * Identifies the text block a chunk belongs to, when a stream can carry
   * several at once. Chunks of different blocks are restored independently.
   */
  readonly block?: (chunk: C) => string | undefined;
}

/**
 * Lens for chunks shaped `{ type: "text-delta", delta }` or
 * `{ type: "text-delta", textDelta }` (the stream parts of the Vercel AI SDK).
 */
export const textDeltaLens: ChunkLens<Record<string, unknown>> = Object.freeze({
  get(chunk: Record<string, unknown>): string | undefined {
    if (chunk["type"] !== "text-delta") return undefined;
    const text = chunk["delta"] ?? chunk["textDelta"];
    return typeof text === "string" ? text : undefined;
  },
  set(chunk: Record<string, unknown>, text: string): Record<string, unknown> {
    return typeof chunk["delta"] === "string"
      ? { ...chunk, delta: text }
      : { ...chunk, textDelta: text };
  },
  block: (chunk: Record<string, unknown>): string | undefined =>
    typeof chunk["id"] === "string" ? chunk["id"] : undefined,
});

/**
 * Lens for chunks whose text is a string member named `content` (message
 * chunks of LangChain) .
 */
export const contentLens: ChunkLens<Record<string, unknown>> = Object.freeze({
  get: (chunk: Record<string, unknown>): string | undefined =>
    typeof chunk["content"] === "string" ? chunk["content"] : undefined,
  set: (chunk: Record<string, unknown>, text: string): Record<string, unknown> => {
    const copy = Object.create(Object.getPrototypeOf(chunk) as object | null) as Record<
      string,
      unknown
    >;
    return Object.assign(copy, chunk, { content: text });
  },
});

/**
 * Lens for chunks whose text is a string member named `delta` (response
 * chunks of LlamaIndex).
 */
export const deltaLens: ChunkLens<Record<string, unknown>> = Object.freeze({
  get: (chunk: Record<string, unknown>): string | undefined =>
    typeof chunk["delta"] === "string" ? chunk["delta"] : undefined,
  set: (chunk: Record<string, unknown>, text: string): Record<string, unknown> => ({
    ...chunk,
    delta: text,
  }),
});

/**
 * Restore tokens in a stream of structured chunks. Text that is held back
 * because it may be the start of a token is delivered with the next text
 * chunk of its block, and in any case before the next chunk that carries no
 * text, so the order of the stream is kept: nothing arrives after the chunk
 * that ends its block. A token that is split around a chunk without text is
 * therefore not restored.
 *
 * @param source - The chunks produced by the model SDK.
 * @param lens - How to read and write the text of a chunk.
 * @param provider - The provider that issued the tokens.
 * @returns The chunks with restored text.
 *
 * @example
 * ```ts
 * for await (const chunk of restoreChunks(await chain.stream(input), contentLens, session)) {
 *   process.stdout.write(String(chunk.content));
 * }
 * ```
 */
export async function* restoreChunks<C>(
  source: AsyncIterable<C>,
  lens: ChunkLens<C>,
  provider: TokenizationProvider,
): AsyncGenerator<C, void, undefined> {
  /** Per text block: its restorer and the last chunk of it, used to carry held text. */
  const blocks = new Map<string, { readonly restorer: AsyncChunkTransformer; last: C }>();

  async function* drain(): AsyncGenerator<C, void, undefined> {
    for (const block of blocks.values()) {
      const rest = await block.restorer.flush();
      if (rest !== "") yield lens.set(block.last, rest);
    }
    blocks.clear();
  }

  for await (const chunk of source) {
    const text = lens.get(chunk);
    if (text === undefined) {
      yield* drain();
      yield chunk;
      continue;
    }
    const id = lens.block?.(chunk) ?? "";
    let block = blocks.get(id);
    if (block === undefined) {
      block = { restorer: createRestoreTransformer(provider), last: chunk };
      blocks.set(id, block);
    }
    block.last = chunk;
    yield lens.set(chunk, await block.restorer.push(text));
  }
  yield* drain();
}
