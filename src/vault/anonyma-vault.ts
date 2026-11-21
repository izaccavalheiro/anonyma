/**
 * @module vault/anonyma-vault
 * @description The minimal storage contract for reversible tokens, an
 * in-memory implementation of it, and {@link restore}, which puts the original
 * values back into a text.
 *
 * An {@link AnonymaVault} maps a token to the value it replaced. It is the
 * storage behind {@link createVaultTokenizer} and `tokenize(text, { vault })`,
 * and the input of {@link restore}. Its two methods may answer synchronously
 * (an in-memory map) or asynchronously (Redis, a KV namespace, a SQL table).
 *
 * A vault holds original values in clear. Keep one per conversation or per
 * request, and never let text from one user be restored against the vault of
 * another: a user who writes a token of somebody else's vault into a prompt
 * would otherwise get that person's data back.
 */

import { ValidationError } from "../errors.js";
import { ANY_TOKEN_BODY_SOURCE } from "./tokens.js";
import type { MaybePromise, RestoreResult } from "./types.js";

/**
 * Storage for reversible tokens: token in, original value out.
 *
 * Implement it to keep tokens somewhere other than memory. Both methods may
 * return a promise.
 *
 * @example
 * ```ts
 * import type { AnonymaVault } from "anonyma";
 *
 * // A Cloudflare KV namespace, one key prefix per conversation.
 * const kvVault = (kv: KVNamespace, conversation: string): AnonymaVault => ({
 *   store: (key, value) => kv.put(`${conversation}:${key}`, value, { expirationTtl: 3600 }),
 *   retrieve: async (key) => (await kv.get(`${conversation}:${key}`)) ?? undefined,
 * });
 * ```
 */
export interface AnonymaVault {
  /** Remember that `key` (a token) stands for `value`. */
  store(key: string, value: string): MaybePromise<void>;
  /** The value `key` stands for, or `undefined` when the vault does not know it. */
  retrieve(key: string): MaybePromise<string | undefined>;
}

/**
 * An {@link AnonymaVault} that answers synchronously. With one, {@link restore}
 * and `tokenize(text, { vault })` return their results directly.
 */
export interface SyncAnonymaVault extends AnonymaVault {
  store(key: string, value: string): void;
  retrieve(key: string): string | undefined;
}

/**
 * Options accepted by {@link restore}.
 */
export interface RestoreOptions {
  /**
   * What a token looks like. Defaults to the numbered tokens anonyma issues in
   * any shape: `{{EMAIL_1}}`, `[EMAIL_0001]` and `<EMAIL_1>`, with or without
   * a tag. Each match is looked up in the vault as a whole, so make the
   * pattern match whole tokens only.
   */
  readonly pattern?: RegExp;
}

/**
 * The default {@link AnonymaVault}: a map in memory, for the lifetime of one
 * request or one serverless invocation.
 *
 * @example
 * ```ts
 * import { InMemoryVault, restore, tokenize } from "anonyma";
 *
 * const vault = new InMemoryVault();
 * const { text } = tokenize("Mail john@example.com", { vault });
 * // "Mail {{EMAIL_1}}"
 * restore("Sent to {{EMAIL_1}}.", vault).text;
 * // "Sent to john@example.com."
 * ```
 */
export class InMemoryVault implements SyncAnonymaVault {
  readonly #entries: Map<string, string>;

  /**
   * @param entries - Entries to start with, for example from {@link InMemoryVault.entries} of another vault.
   */
  public constructor(entries: Iterable<readonly [key: string, value: string]> = []) {
    this.#entries = new Map();
    for (const [key, value] of entries) this.store(key, value);
  }

  /** Remember that `key` stands for `value`, replacing what it stood for before. */
  public store(key: string, value: string): void {
    if (typeof key !== "string" || key === "") {
      throw new ValidationError("key", "must be a non-empty string");
    }
    if (typeof value !== "string") throw new ValidationError("value", "must be a string");
    this.#entries.set(key, value);
  }

  /** The value `key` stands for, or `undefined`. */
  public retrieve(key: string): string | undefined {
    return this.#entries.get(key);
  }

  /** Forget one key. Returns `true` when it was known. */
  public delete(key: string): boolean {
    return this.#entries.delete(key);
  }

  /** Forget every key. */
  public clear(): void {
    this.#entries.clear();
  }

  /** Number of keys held. */
  public get size(): number {
    return this.#entries.size;
  }

  /**
   * A copy of every entry, in the order they were stored. It contains
   * original values: handle it as you would handle the data itself.
   */
  public entries(): [key: string, value: string][] {
    return [...this.#entries];
  }
}

/** Matches every numbered token anonyma issues, in any shape. */
const ANY_TOKEN = new RegExp(
  `\\{\\{${ANY_TOKEN_BODY_SOURCE}\\}\\}|\\[${ANY_TOKEN_BODY_SOURCE}\\]|<${ANY_TOKEN_BODY_SOURCE}>`,
  "g",
);

/**
 * Whether `value` is a promise or another thenable.
 * @internal
 */
export function isThenable<T>(value: MaybePromise<T>): value is Promise<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

/** Rebuild the text once every distinct token has been looked up. */
function assemble(
  text: string,
  matches: readonly RegExpExecArray[],
  values: ReadonlyMap<string, string | undefined>,
): RestoreResult {
  const parts: string[] = [];
  const unresolved: string[] = [];
  let restored = 0;
  let cursor = 0;
  for (const match of matches) {
    const token = match[0];
    const value = values.get(token);
    // A vault that answers with anything but a string does not know the token.
    if (typeof value !== "string") {
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
 * Replace every token found in `text` with the value `vault` holds for it.
 *
 * The text is scanned once and each match is a whole token, delimiters
 * included, so `{{PERSON_1}}` is never found inside `{{PERSON_10}}`. Restored
 * values are not scanned again: a value that itself looks like a token stays
 * as it is. Tokens the vault does not know are left in place and reported in
 * `unresolved`.
 *
 * @param text - Text containing tokens, such as a model's answer.
 * @param vault - The vault the tokens were stored in.
 * @param options - A custom token pattern.
 * @returns The restored text, the number of restored occurrences and the
 *   unresolved tokens; a promise of them when the vault is asynchronous.
 * @throws {@link ValidationError} When `text` is not a string or `pattern` is not a RegExp.
 *
 * @example
 * ```ts
 * import { InMemoryVault, restore } from "anonyma";
 *
 * const vault = new InMemoryVault([
 *   ["{{PERSON_1}}", "Ada"],
 *   ["{{PERSON_10}}", "Grace"],
 * ]);
 * restore("{{PERSON_10}} met {{PERSON_1}}", vault).text; // "Grace met Ada"
 *
 * const { text } = await restore(answer, redisVault); // asynchronous vault
 * ```
 */
export function restore(
  text: string,
  vault: SyncAnonymaVault,
  options?: RestoreOptions,
): RestoreResult;
export function restore(
  text: string,
  vault: AnonymaVault,
  options?: RestoreOptions,
): Promise<RestoreResult>;
export function restore(
  text: string,
  vault: AnonymaVault,
  options: RestoreOptions = {},
): MaybePromise<RestoreResult> {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");
  if (typeof (vault as Partial<AnonymaVault> | null)?.retrieve !== "function") {
    throw new ValidationError("vault", "must have a retrieve() method");
  }
  const { pattern = ANY_TOKEN } = options;
  if (!(pattern instanceof RegExp)) throw new ValidationError("pattern", "must be a RegExp");
  const scan = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "") + "g");

  const matches = [...text.matchAll(scan)].filter((match) => match[0] !== "");
  const values = new Map<string, string | undefined>();
  const pending: Promise<void>[] = [];
  for (const match of matches) {
    const token = match[0];
    if (values.has(token)) continue;
    const value = vault.retrieve(token);
    if (isThenable(value)) {
      values.set(token, undefined);
      pending.push(value.then((resolved) => void values.set(token, resolved)));
    } else {
      values.set(token, value);
    }
  }
  if (pending.length === 0) return assemble(text, matches, values);
  return Promise.all(pending).then(() => assemble(text, matches, values));
}
