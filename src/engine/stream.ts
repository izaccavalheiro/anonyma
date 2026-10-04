/**
 * @module engine/stream
 * @description Chunk-boundary-safe transformation. Text may arrive split at
 * arbitrary positions — in the middle of an email address, a card number or a
 * surrogate pair — and the output is the same as if it had arrived in one
 * piece.
 *
 * The transformer keeps the last `window` characters unemitted until more
 * input arrives, and re-scans them together with a `window` of already
 * emitted text as left context. It never emits part of a detection that is
 * still growing, nor part of an unbroken run of printable ASCII characters (a
 * key, a token, a URL) of up to `tokenLimit` characters, because such a value
 * cannot be recognised from its beginning. Output therefore lags input by at
 * most `window + batch` characters plus the length of what is being held.
 *
 * The guarantee holds for detections (including the look-around their
 * patterns need) that fit in the window or contain no whitespace and fit in
 * `tokenLimit`; a longer detection that is split across chunks may be
 * replaced only from the point where it became visible.
 */

import { AsyncStrategyError, ValidationError } from "../errors.js";
import type {
  AsyncChunkTransformer,
  ChunkOptions,
  ChunkTransformer,
  DetectedSpan,
  Pipeline,
  ReplaceContext,
} from "./types.js";

const DEFAULT_WINDOW = 256;
const DEFAULT_BATCH = 4096;
const DEFAULT_TOKEN_LIMIT = 8192;

/** Printable ASCII other than the space: the characters keys, tokens and URLs are made of. */
function isTokenCode(code: number): boolean {
  return code > 32 && code < 127;
}

/**
 * Move `cut` back to the start of the unbroken run of token characters it
 * falls in, unless the run began before `limit`.
 */
function startOfToken(text: string, cut: number, limit: number): number {
  if (cut >= text.length || !isTokenCode(text.charCodeAt(cut))) return cut;
  let at = cut;
  while (at > limit && isTokenCode(text.charCodeAt(at - 1))) at--;
  return at > limit || !isTokenCode(text.charCodeAt(at - 1)) ? at : cut;
}

/** One piece of settled output: literal text or a value to replace. */
type Piece = string | { readonly value: string; readonly context: ReplaceContext };

interface Buffer {
  /** Feed more input (or `""`), and return the pieces that are now settled. */
  readonly advance: (chunk: string, final: boolean) => Piece[];
}

function resolveWindow(pipeline: Pipeline, options: ChunkOptions): number {
  if (options.window !== undefined) {
    if (!Number.isInteger(options.window) || options.window < 1) {
      throw new ValidationError("window", "must be a positive integer");
    }
    return options.window;
  }
  let window = 1;
  for (const detector of pipeline.detectors) {
    window = Math.max(window, detector.maxMatchLength ?? DEFAULT_WINDOW);
  }
  return window;
}

function createBuffer(pipeline: Pipeline, options: ChunkOptions): Buffer {
  const window = resolveWindow(pipeline, options);
  const batch = options.batch ?? DEFAULT_BATCH;
  if (!Number.isInteger(batch) || batch < 0) {
    throw new ValidationError("batch", "must be a non-negative integer");
  }
  const tokenLimit = options.tokenLimit ?? DEFAULT_TOKEN_LIMIT;
  if (!Number.isInteger(tokenLimit) || tokenLimit < 0) {
    throw new ValidationError("tokenLimit", "must be a non-negative integer");
  }

  /** Already emitted input kept as left context for the next scan. */
  let context = "";
  /** Input that has not been emitted yet. */
  let pending = "";
  /** Number of input characters that precede `context` in the stream. */
  let consumed = 0;
  /** Number of replacements made so far. */
  let ordinal = 0;
  /** Length `pending` must reach before the next scan. */
  let threshold = window + batch;

  /**
   * Scanning costs the same for a short text as for a window of it, so the
   * next scan waits for a batch of new input. While a long value is held back
   * the wait grows with it, which keeps the total work linear in the input.
   */
  function scheduleNextScan(): void {
    const held = pending.length;
    threshold = held + Math.max(batch, held > 2 * (window + batch) ? held >> 1 : 0);
  }

  function advance(chunk: string, final: boolean): Piece[] {
    if (typeof chunk !== "string") {
      throw new ValidationError("chunk", "must be a string");
    }
    pending += chunk;
    if (!final && (chunk.length === 0 || pending.length < threshold)) return [];
    if (pending.length === 0) {
      reset();
      return [];
    }

    const text = context + pending;
    const offset = context.length;
    const spans = pipeline.scan(text);

    let cut = text.length;
    if (!final) {
      cut = text.length - window;
      // Never cut through a key or a token that is still arriving.
      cut = startOfToken(text, cut, Math.max(offset, cut - tokenLimit));
      // Never cut through a surrogate pair.
      const before = text.charCodeAt(cut - 1);
      if (before >= 0xd800 && before <= 0xdbff) cut--;
      // Never cut through a detection: hold it back until it is settled.
      for (const span of spans) {
        if (span.start >= cut) break;
        if (span.end > cut) {
          cut = span.start;
          break;
        }
      }
      if (cut <= offset) {
        scheduleNextScan();
        return [];
      }
    }

    const pieces: Piece[] = [];
    let cursor = offset;
    for (const span of spans) {
      if (span.end <= offset) continue;
      if (span.start >= cut) break;
      // A detection that begins in text already emitted can only be replaced from here on.
      const start = Math.max(span.start, offset);
      if (start > cursor) pieces.push(text.slice(cursor, start));
      pieces.push({
        value: text.slice(start, span.end),
        context: describe(span, start, span.start < offset),
      });
      cursor = span.end;
    }
    if (cut > cursor) pieces.push(text.slice(cursor, cut));

    if (final) {
      reset();
      return pieces;
    }
    const keepFrom = Math.max(0, cut - window);
    consumed += keepFrom;
    context = text.slice(keepFrom, cut);
    pending = text.slice(cut);
    scheduleNextScan();
    return pieces;
  }

  /** The end of the input: the next push starts a new text. */
  function reset(): void {
    context = "";
    pending = "";
    consumed = 0;
    ordinal = 0;
    threshold = window + batch;
  }

  function describe(span: DetectedSpan, start: number, clipped: boolean): ReplaceContext {
    return {
      category: span.category,
      detector: span.detector,
      confidence: span.confidence,
      start: consumed + start,
      end: consumed + span.end,
      ordinal: ordinal++,
      residual: span.residual || clipped,
    };
  }

  return { advance };
}

/**
 * Create a push-style transformer that accepts text in arbitrary chunks.
 *
 * @param pipeline - The pipeline to apply. Its replacers must be synchronous.
 * @param options - Hold-back window, scan batching and token limit.
 * @returns A {@link ChunkTransformer}. After `flush()` it is ready for a new
 *   text; discard it after an error.
 * @throws {@link ValidationError} When `window`, `batch` or `tokenLimit` is invalid.
 *
 * @example
 * ```ts
 * import { compilePipeline, createChunkTransformer } from "anonyma/engine";
 *
 * const transformer = createChunkTransformer(compilePipeline());
 * let out = transformer.push("Contact alice@exam");
 * out += transformer.push("ple.com today");
 * out += transformer.flush();
 * // "Contact [REDACTED] today"
 * ```
 */
export function createChunkTransformer(
  pipeline: Pipeline,
  options: ChunkOptions = {},
): ChunkTransformer {
  const buffer = createBuffer(pipeline, options);

  function render(pieces: Piece[]): string {
    let out = "";
    for (const piece of pieces) {
      if (typeof piece === "string") {
        out += piece;
        continue;
      }
      const replacement = pipeline.replace(piece.value, piece.context);
      if (typeof replacement !== "string") {
        void Promise.resolve(replacement).catch(() => undefined);
        throw new AsyncStrategyError(piece.context.category);
      }
      out += replacement;
    }
    return out;
  }

  return Object.freeze({
    push: (chunk: string): string => render(buffer.advance(chunk, false)),
    flush: (): string => render(buffer.advance("", true)),
  });
}

/**
 * Create a push-style transformer for pipelines with asynchronous replacers.
 * Calls must not overlap: await each `push()` before the next one.
 *
 * @param pipeline - The pipeline to apply.
 * @param options - Hold-back window, scan batching and token limit.
 * @returns An {@link AsyncChunkTransformer}. After `flush()` it is ready for a
 *   new text; discard it after an error.
 * @throws {@link ValidationError} When `window`, `batch` or `tokenLimit` is invalid.
 *
 * @example
 * ```ts
 * const transformer = createAsyncChunkTransformer(pipeline);
 * for await (const chunk of source) sink.write(await transformer.push(chunk));
 * sink.write(await transformer.flush());
 * ```
 */
export function createAsyncChunkTransformer(
  pipeline: Pipeline,
  options: ChunkOptions = {},
): AsyncChunkTransformer {
  const buffer = createBuffer(pipeline, options);

  async function render(pieces: Piece[]): Promise<string> {
    let out = "";
    for (const piece of pieces) {
      out += typeof piece === "string" ? piece : await pipeline.replace(piece.value, piece.context);
    }
    return out;
  }

  return Object.freeze({
    push: (chunk: string): Promise<string> => render(buffer.advance(chunk, false)),
    flush: (): Promise<string> => render(buffer.advance("", true)),
  });
}

/**
 * Create a WHATWG `TransformStream` that applies a pipeline to a stream of
 * string chunks. Unlike the 1.x `createAnonymizeStream()`, it detects values
 * that are split across chunk boundaries and emits plain strings.
 *
 * @param pipeline - The pipeline to apply. Replacers may be asynchronous.
 * @param options - Hold-back window, scan batching and token limit.
 * @returns A `TransformStream<string, string>`.
 * @throws {@link ValidationError} When `TransformStream` is unavailable or an option is invalid.
 *
 * @example
 * ```ts
 * import { compilePipeline, createPipelineStream } from "anonyma/engine";
 *
 * const scrubbed = response.body
 *   .pipeThrough(new TextDecoderStream())
 *   .pipeThrough(createPipelineStream(compilePipeline({ preset: "gdpr" })))
 *   .pipeThrough(new TextEncoderStream());
 * ```
 */
export function createPipelineStream(
  pipeline: Pipeline,
  options: ChunkOptions = {},
): TransformStream<string, string> {
  if (typeof TransformStream === "undefined") {
    throw new ValidationError("TransformStream", "is not available in this environment");
  }
  const transformer = createAsyncChunkTransformer(pipeline, options);
  return new TransformStream<string, string>({
    async transform(chunk, controller): Promise<void> {
      const out = await transformer.push(chunk);
      if (out.length > 0) controller.enqueue(out);
    },
    async flush(controller): Promise<void> {
      const out = await transformer.flush();
      if (out.length > 0) controller.enqueue(out);
    },
  });
}
