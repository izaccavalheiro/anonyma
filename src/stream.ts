/**
 * @module stream
 * @description Streaming support for anonyma via the WHATWG Streams API.
 *
 * Provides `TransformStream`-based wrappers so anonyma can be used in
 * Node.js stream pipelines and browser fetch-response chains.
 *
 * Requires Node ≥ 18 (global `TransformStream`) or a browser with Streams API.
 *
 * @example
 * ```ts
 * import { createAnonymizeStream } from "anonyma/stream";
 * import { createReadStream, createWriteStream } from "node:fs";
 *
 * const readable = ReadableStream.from(lines);
 * const anonymized = readable.pipeThrough(createAnonymizeStream());
 * for await (const chunk of anonymized) {
 *   process.stdout.write(chunk);
 * }
 * ```
 */

import { anonymize, anonymizeAsync } from "./anonymize.js";
import { tokenize } from "./tokenize.js";
import { ValidationError } from "./errors.js";
import type { AnonymizeOptions, AnonymizeResult, TokenizeResult, TokenizeOptions } from "./types.js";

/** Require the global `TransformStream` (Node ≥ 18 / browsers). */
function requireTransformStream(): typeof TransformStream {
  if (typeof TransformStream === "undefined") {
    throw new ValidationError(
      "TransformStream",
      "is not available in this environment. Use Node.js ≥ 18 or a polyfill.",
    );
  }
  return TransformStream;
}

// ---------------------------------------------------------------------------
// Public: createAnonymizeStream()
// ---------------------------------------------------------------------------

/**
 * Create a `TransformStream` that anonymizes each string chunk it receives.
 *
 * Input chunks are expected to be complete text strings (e.g. lines or
 * paragraphs). For true streaming over arbitrary byte chunks, split on
 * line boundaries before piping.
 *
 * @param options - Anonymization options forwarded to {@link anonymize}.
 * @returns A `TransformStream<string, AnonymizeResult>`.
 *
 * @example
 * ```ts
 * const stream = createAnonymizeStream({ defaultStrategy: { strategy: "mask" } });
 * const reader = readable.pipeThrough(stream).getReader();
 * const { value } = await reader.read();
 * // value: { text: "****", matches: [] }
 * ```
 */
export function createAnonymizeStream(
  options: AnonymizeOptions = {},
): TransformStream<string, AnonymizeResult> {
  const TS = requireTransformStream();
  return new TS<string, AnonymizeResult>({
    transform(chunk, controller): void {
      if (typeof chunk !== "string") {
        controller.error(new ValidationError("chunk", "must be a string"));
        return;
      }
      controller.enqueue(anonymize(chunk, options));
    },
  });
}

// ---------------------------------------------------------------------------
// Public: createAnonymizeStreamAsync() — uses async strategies (hash/encrypt)
// ---------------------------------------------------------------------------

/**
 * Create an async-capable `TransformStream` that anonymizes each string chunk.
 * Supports `hash`, `encrypt`, and other async strategies.
 *
 * @param options - Anonymization options forwarded to {@link anonymizeAsync}.
 * @returns A `TransformStream<string, AnonymizeResult>`.
 */
export function createAnonymizeStreamAsync(
  options: AnonymizeOptions = {},
): TransformStream<string, AnonymizeResult> {
  const TS = requireTransformStream();
  return new TS<string, AnonymizeResult>({
    async transform(chunk, controller): Promise<void> {
      if (typeof chunk !== "string") {
        controller.error(new ValidationError("chunk", "must be a string"));
        return;
      }
      try {
        const result = await anonymizeAsync(chunk, options);
        controller.enqueue(result);
      } catch (err) {
        controller.error(err);
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Public: createTokenizeStream()
// ---------------------------------------------------------------------------

/**
 * Create a `TransformStream` that tokenizes each string chunk it receives.
 *
 * Note: each chunk gets its **own** token map. If you need a shared map across
 * all chunks, manage the tokenization externally and feed results manually.
 *
 * @param options - Tokenization options forwarded to {@link tokenize}.
 * @returns A `TransformStream<string, TokenizeResult>`.
 *
 * @example
 * ```ts
 * const stream = createTokenizeStream({ categories: ["email"] });
 * const writer = stream.writable.getWriter();
 * const reader = stream.readable.getReader();
 *
 * writer.write("Contact alice@example.com");
 * writer.close();
 *
 * const { value } = await reader.read();
 * // value: { text: "Contact [EMAIL_0001]", mapping: Map { ... } }
 * ```
 */
export function createTokenizeStream(
  options: TokenizeOptions = {},
): TransformStream<string, TokenizeResult> {
  const TS = requireTransformStream();
  return new TS<string, TokenizeResult>({
    transform(chunk, controller): void {
      if (typeof chunk !== "string") {
        controller.error(new ValidationError("chunk", "must be a string"));
        return;
      }
      controller.enqueue(tokenize(chunk, options));
    },
  });
}
