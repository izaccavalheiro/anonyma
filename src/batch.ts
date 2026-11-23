/**
 * @module batch
 * @description Batch processing utilities for anonymizing or tokenizing large
 * collections of texts in one call.
 *
 * Each item is processed independently — a failure in one item does **not**
 * abort the rest of the batch. Errors are collected per-item and exposed in
 * the returned {@link BatchResult}.
 *
 * @example
 * ```ts
 * import { anonymizeBatch } from "anonyma";
 *
 * const results = anonymizeBatch(["alice@example.com", "192.0.2.1"]);
 * // [
 * //   { index: 0, ok: true,  value: { text: "[REDACTED]", matches: [] } },
 * //   { index: 1, ok: true,  value: { text: "[REDACTED]", matches: [] } },
 * // ]
 * ```
 */

import {
  anonymize,
  anonymizeAsync,
  anonymizeDetected,
  detect,
  detectEach,
  prepareAnonymize,
  type PreparedAnonymize,
} from "./anonymize.js";
import { tokenize } from "./tokenize.js";
import type {
  AnonymizeOptions,
  AnonymizeResult,
  TokenizeResult,
  TokenizeOptions,
  BatchResult,
  PiiMatch,
  PiiCategory,
} from "./types.js";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Wrap a single sync call in a BatchResult entry. */
function wrapSync<T>(index: number, fn: () => T): BatchResult<T> {
  try {
    return { index, ok: true, value: fn() };
  } catch (err) {
    return {
      index,
      ok: false,
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }
}

/** Wrap a single async call in a BatchResult entry. */
async function wrapAsync<T>(index: number, fn: () => Promise<T>): Promise<BatchResult<T>> {
  try {
    return { index, ok: true, value: await fn() };
  } catch (err) {
    return {
      index,
      ok: false,
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }
}

// ---------------------------------------------------------------------------
// Public: anonymizeBatch()
// ---------------------------------------------------------------------------

/**
 * Synchronously anonymize an array of strings.
 *
 * Entries shorter than 8 KB are detected together: they are joined into one
 * text, scanned once, and the matches are split back by entry, which costs
 * less than one scan per entry and gives the same results. The options are
 * resolved once for the batch. Each entry is still replaced on its own, so a
 * failure, and the numbering of `consistentTokens`, stay per entry.
 *
 * @param texts   - The array of input strings.
 * @param options - Anonymization options applied to every item.
 * @returns An array of {@link BatchResult} objects, one per input item.
 */
export function anonymizeBatch(
  texts: readonly string[],
  options: AnonymizeOptions = {},
): BatchResult<AnonymizeResult>[] {
  let prepared: PreparedAnonymize;
  try {
    prepared = prepareAnonymize(options);
  } catch {
    // Every entry fails with the error anonymize() throws for these options.
    return texts.map((text, index) => wrapSync(index, () => anonymize(text, options)));
  }
  const detected = detectEach(
    texts,
    prepared.categories,
    options.customDetectors,
    options.aggressive ?? false,
  );
  return texts.map((text, index) => {
    const matches = detected[index];
    return wrapSync(index, () =>
      matches === undefined
        ? anonymize(text, options)
        : anonymizeDetected(text, matches, options, prepared),
    );
  });
}

// ---------------------------------------------------------------------------
// Public: anonymizeBatchAsync()
// ---------------------------------------------------------------------------

/**
 * Asynchronously anonymize an array of strings (supports `hash`, `encrypt`,
 * and other async strategies).
 *
 * Items are processed in parallel via `Promise.allSettled`.
 *
 * @param texts       - The array of input strings.
 * @param options     - Anonymization options applied to every item.
 * @param concurrency - Maximum number of items processed simultaneously.
 *   Defaults to unlimited. Pass a number to limit concurrency (useful for
 *   large datasets to avoid memory pressure).
 * @returns A promise resolving to an array of {@link BatchResult} objects.
 */
export async function anonymizeBatchAsync(
  texts: readonly string[],
  options: AnonymizeOptions = {},
  concurrency?: number,
): Promise<BatchResult<AnonymizeResult>[]> {
  if (concurrency && concurrency > 0) {
    const results: BatchResult<AnonymizeResult>[] = [];
    for (let i = 0; i < texts.length; i += concurrency) {
      const chunk = texts.slice(i, i + concurrency);
      const chunkResults = await Promise.all(
        chunk.map((text, j) => wrapAsync(i + j, () => anonymizeAsync(text, options))),
      );
      results.push(...chunkResults);
    }
    return results;
  }

  return Promise.all(
    texts.map((text, index) => wrapAsync(index, () => anonymizeAsync(text, options))),
  );
}

// ---------------------------------------------------------------------------
// Public: tokenizeBatch()
// ---------------------------------------------------------------------------

/**
 * Tokenize an array of strings, returning a separate token mapping per item.
 *
 * Token counters are **not** shared across items — each item gets fresh
 * sequential tokens starting at `_0001`. If you need a shared mapping across
 * all items, call {@link tokenize} directly in a loop with your own
 * `TokenStore`.
 *
 * @param texts   - The array of input strings.
 * @param options - Tokenization options applied to every item.
 * @returns An array of {@link BatchResult} objects containing {@link TokenizeResult}.
 */
export function tokenizeBatch(
  texts: readonly string[],
  options: TokenizeOptions = {},
): BatchResult<TokenizeResult>[] {
  return texts.map((text, index) => wrapSync(index, () => tokenize(text, options)));
}

// ---------------------------------------------------------------------------
// Public: detectBatch()
// ---------------------------------------------------------------------------

/**
 * Detect PII in an array of strings.
 *
 * Entries shorter than 8 KB are joined into one text, scanned once, and the
 * matches are split back by entry: the same results as {@link detect} on each
 * entry, at a fraction of the cost for short entries.
 *
 * @param texts      - The array of input strings.
 * @param categories - Optional category filter.
 * @returns An array of {@link BatchResult} objects containing PiiMatch arrays.
 */
export function detectBatch(
  texts: readonly string[],
  categories?: readonly PiiCategory[],
): BatchResult<PiiMatch[]>[] {
  const detected = detectEach(texts, categories, undefined, false);
  return texts.map((text, index): BatchResult<PiiMatch[]> => {
    const matches = detected[index];
    return matches === undefined
      ? wrapSync(index, () => detect(text, categories))
      : { index, ok: true, value: matches };
  });
}
