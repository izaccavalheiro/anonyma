/**
 * @module vault/restore
 * @description Helpers that connect tokenization providers to text and to the
 * span engine.
 */

import { ValidationError } from "../errors.js";
import type { Replacer } from "../engine/types.js";
import type { RestoreResult, TokenizationProvider } from "./types.js";

/**
 * Replace every token of `provider` found in `text` with its original value.
 * Tokens that do not resolve are left in place and reported. A provider that
 * has its own `restore()` is used through it.
 *
 * @param text - Text containing tokens.
 * @param provider - The provider that issued them.
 * @returns The restored text, the number of restored occurrences and the unresolved tokens.
 *
 * @example
 * ```ts
 * const { text, unresolved } = await restoreTokens(modelOutput, tokenizer);
 * ```
 */
export async function restoreTokens(
  text: string,
  provider: TokenizationProvider,
): Promise<RestoreResult> {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");
  if (provider.restore !== undefined) return provider.restore(text);

  const pattern = new RegExp(
    provider.tokenPattern.source,
    provider.tokenPattern.flags.replace("y", ""),
  );
  const resolved = new Map<string, string | undefined>();
  const parts: string[] = [];
  const unresolved: string[] = [];
  let restored = 0;
  let cursor = 0;

  for (const match of text.matchAll(pattern)) {
    const token = match[0];
    if (!resolved.has(token)) resolved.set(token, await provider.detokenize(token));
    const value = resolved.get(token);
    if (value === undefined) {
      unresolved.push(token);
      continue;
    }
    parts.push(text.slice(cursor, match.index), value);
    cursor = match.index + token.length;
    restored++;
  }
  if (restored === 0) return { text, restored, unresolved };
  parts.push(text.slice(cursor));
  return { text: parts.join(""), restored, unresolved };
}

/**
 * Build an engine replacer that tokenizes every value with `provider`.
 *
 * @param provider - The tokenization provider.
 * @param options - `subject` attaches a data-subject reference to every token,
 *   for later erasure.
 * @returns A {@link Replacer}; asynchronous unless the provider is synchronous.
 *
 * @example
 * ```ts
 * import { createPipeline, emailDetector } from "anonyma/engine";
 * import { createSessionTokenizer, tokenizeWith } from "anonyma/vault";
 *
 * const session = createSessionTokenizer();
 * const pipeline = createPipeline({
 *   detectors: [emailDetector],
 *   replace: { fallback: tokenizeWith(session) },
 * });
 * ```
 */
export function tokenizeWith(
  provider: TokenizationProvider,
  options: { readonly subject?: string } = {},
): Replacer {
  const { subject } = options;
  return (value, context) =>
    provider.tokenize(value, {
      category: context.category,
      ...(subject !== undefined ? { subject } : {}),
    });
}
