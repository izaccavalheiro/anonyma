/**
 * @module strategies/tokenize
 * @description The `tokenize` anonymization strategy — replaces PII with
 * deterministic, reversible tokens that can later be detokenized.
 *
 * Tokens are opaque identifiers (`[CATEGORY_xxxx]` or `<CATEGORY_N>`) that
 * carry no information about the original value but allow lossless recovery
 * when the token map is retained.
 *
 * This module provides low-level building blocks used by the public
 * `tokenize()` / `detokenize()` API in `src/tokenize.ts`.
 */

import type { TokenFormat } from "../types.js";

/**
 * A mutable in-memory token store mapping token→value and value→token.
 * Scoped to a single tokenisation session.
 *
 * @public
 */
export interface TokenStore {
  /** Map: token string → original PII value */
  readonly tokens: Map<string, string>;
  /** Map: `"CATEGORY:normalizedValue"` → existing token (for dedup) */
  readonly index: Map<string, string>;
  /** Per-category counters for generating sequential token IDs */
  readonly counters: Map<string, number>;
}

/** Create an empty token store. */
export function createTokenStore(): TokenStore {
  return {
    tokens: new Map(),
    index: new Map(),
    counters: new Map(),
  };
}

/**
 * Produce a new or existing token for `(category, value)`.
 *
 * Tokens are *deduplicated* — the same value in the same category always
 * receives the same token within a session.
 *
 * @param store    - The active token store.
 * @param category - The PII category (e.g. `"email"`).
 * @param value    - The original PII string.
 * @param prefix   - Category prefix used in the token label (e.g. `"EMAIL"`).
 * @param format   - Token format: `"bracket"` (`[EMAIL_0001]`) or `"angle"` (`<EMAIL_1>`).
 * @returns The deterministic token string.
 */
export function assignToken(
  store: TokenStore,
  category: string,
  value: string,
  prefix: string,
  format: TokenFormat = "bracket",
): string {
  const indexKey = `${prefix}:${value.toLowerCase()}`;
  const existing = store.index.get(indexKey);
  if (existing !== undefined) return existing;

  const count = (store.counters.get(prefix) ?? 0) + 1;
  store.counters.set(prefix, count);

  const id = format === "bracket" ? String(count).padStart(4, "0") : String(count);
  const token =
    format === "bracket" ? `[${prefix}_${id}]` : `<${prefix}_${id}>`;

  store.index.set(indexKey, token);
  store.tokens.set(token, value);
  return token;
}

/**
 * Replace a token with its original value. Returns `undefined` when the token
 * is not found in `store`.
 *
 * @param store - The active token store.
 * @param token - The token to resolve.
 */
export function resolveToken(store: TokenStore, token: string): string | undefined {
  return store.tokens.get(token);
}

/**
 * Restore all tokens in `text` using `store`.
 * Tokens that are not found in `store` are left unchanged.
 *
 * @param text  - The tokenized text.
 * @param store - The token store from the original tokenization call.
 * @returns The restored text and a list of any unresolved tokens.
 */
export function detokenizeText(
  text: string,
  store: TokenStore,
): { text: string; unresolved: string[] } {
  const unresolved: string[] = [];

  // Match both bracket `[PREFIX_NNNN]` and angle `<PREFIX_N>` format tokens.
  const re = /(\[[A-Z_]+_\d+\]|<[A-Z_]+_\d+>)/g;

  const result = text.replace(re, (token) => {
    const original = store.tokens.get(token);
    if (original !== undefined) return original;
    unresolved.push(token);
    return token;
  });

  return { text: result, unresolved };
}
