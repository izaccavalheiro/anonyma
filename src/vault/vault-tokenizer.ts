/**
 * @module vault/vault-tokenizer
 * @description A tokenization provider that numbers values per category
 * (`{{EMAIL_1}}`, `{{EMAIL_2}}`, …) and keeps the mapping in an
 * {@link AnonymaVault}, so the tokens can be restored later — by this
 * tokenizer, by {@link restore}, or by another process that reaches the same
 * vault.
 */

import { TokenVaultError, ValidationError } from "../errors.js";
import { isThenable, restore } from "./anonyma-vault.js";
import type { AnonymaVault, SyncAnonymaVault } from "./anonyma-vault.js";
import { PREFIX_SOURCE, SHAPES, isTokenShape, prefixResolver } from "./tokens.js";
import type { TokenShape } from "./tokens.js";
import type { MaybePromise, RestoreResult, TokenContext, TokenizationProvider } from "./types.js";

/**
 * Options accepted by {@link createVaultTokenizer}.
 */
export interface VaultTokenizerOptions {
  /** Where the tokens are stored. */
  readonly vault: AnonymaVault;
  /**
   * Token shape: `{{EMAIL_1}}` (`"brace"`, default), `[EMAIL_0001]`
   * (`"bracket"`) or `<EMAIL_1>` (`"angle"`). Avoid `"brace"` when prompts go
   * through a template engine that treats `{{…}}` as a placeholder.
   */
  readonly format?: TokenShape;
  /**
   * 2 to 12 letters or digits inserted into every token (`{{EMAIL_k3Xf_1}}`).
   * With an unpredictable tag, text that merely looks like a token — in the
   * input, or invented by a model — is never mistaken for one.
   */
  readonly tag?: string;
  /** Token prefixes for categories, overriding the defaults. */
  readonly prefixes?: Readonly<Record<string, string>>;
  /**
   * Maps a value to the key used to decide whether two values are the same.
   * Defaults to the value itself, so values are compared exactly.
   */
  readonly normalize?: (value: string, category: string) => string;
}

/**
 * A {@link TokenizationProvider} backed by an {@link AnonymaVault}. Its
 * methods return promises only when the vault does.
 */
export interface VaultTokenizer extends TokenizationProvider {
  /** The vault the tokens are stored in. */
  readonly vault: AnonymaVault;
  /** Replace every token of this tokenizer's shape found in `text` with its value. */
  readonly restore: (text: string) => MaybePromise<RestoreResult>;
}

/**
 * A {@link VaultTokenizer} over a synchronous vault: every method answers directly.
 */
export interface SyncVaultTokenizer extends VaultTokenizer {
  readonly vault: SyncAnonymaVault;
  readonly tokenize: (value: string, context: TokenContext) => string;
  readonly detokenize: (token: string) => string | undefined;
  readonly restore: (text: string) => RestoreResult;
}

const TAG_PATTERN = /^[A-Za-z0-9]{2,12}$/;

/** Numbers probed for one value before the vault is considered broken. */
const MAX_PROBES = 1_000_000;

/**
 * Create a tokenizer that stores its tokens in `vault`.
 *
 * Tokens are numbered per category in the order values are first seen, and a
 * value keeps its token for the lifetime of the tokenizer. Before it issues a
 * number, the tokenizer asks the vault whether the token is taken: a token the
 * vault already holds for the same value is reused, one it holds for another
 * value is skipped. A new tokenizer over a vault that already holds tokens —
 * the next request of a conversation — therefore never overwrites them.
 *
 * Calls to an asynchronous vault are made one value at a time. Two tokenizers
 * that write to the same vault at the same moment can still pick the same
 * number, because `store` is not a compare-and-set: give each conversation
 * its own vault, or its own key prefix in a shared store.
 *
 * @param options - The vault, the token shape, an optional tag and prefixes.
 * @returns The {@link VaultTokenizer}; a {@link SyncVaultTokenizer} for a synchronous vault.
 * @throws {@link ValidationError} When an option is invalid.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { InMemoryVault, createVaultTokenizer, restore } from "anonyma/vault";
 *
 * const vault = new InMemoryVault();
 * const tokenization = createVaultTokenizer({ vault });
 * const pipeline = compilePipeline({ defaultStrategy: { strategy: "tokenize" } }, { tokenization });
 *
 * pipeline.transform("Mail john@example.com, cc jane@example.com").text;
 * // "Mail {{EMAIL_1}}, cc {{EMAIL_2}}"
 * restore("Done: {{EMAIL_2}}", vault).text; // "Done: jane@example.com"
 * ```
 */
export function createVaultTokenizer(
  options: VaultTokenizerOptions & { readonly vault: SyncAnonymaVault },
): SyncVaultTokenizer;
export function createVaultTokenizer(options: VaultTokenizerOptions): VaultTokenizer;
export function createVaultTokenizer(options: VaultTokenizerOptions): VaultTokenizer {
  const { vault, format = "brace", tag } = options;
  const normalize = options.normalize ?? ((value: string): string => value);

  const candidate = vault as Partial<AnonymaVault> | null | undefined;
  if (typeof candidate?.store !== "function" || typeof candidate.retrieve !== "function") {
    throw new ValidationError("vault", "must have store() and retrieve() methods");
  }
  if (!isTokenShape(format)) {
    throw new ValidationError("format", 'must be "brace", "bracket" or "angle"');
  }
  if (tag !== undefined && !TAG_PATTERN.test(tag)) {
    throw new ValidationError("tag", "must be 2-12 letters or digits");
  }

  const prefixOf = prefixResolver(options.prefixes);
  const shape = SHAPES[format];
  const infix = tag === undefined ? "" : `${tag}_`;
  const tokenPattern = new RegExp(
    `${shape.openSource}${PREFIX_SOURCE}_${infix}\\d{1,12}${shape.closeSource}`,
    "g",
  );

  /** prefix NUL normalised value -> token */
  const index = new Map<string, string>();
  /** prefix -> highest number this tokenizer has seen taken */
  const counters = new Map<string, number>();
  /** The allocation in flight against an asynchronous vault, if any. */
  let pending: Promise<void> | undefined;

  const render = (prefix: string, number: number): string =>
    `${shape.open}${prefix}_${infix}${String(number).padStart(shape.pad, "0")}${shape.close}`;

  /** One value to place, and how to recognise it in the vault. */
  interface Placement {
    readonly prefix: string;
    readonly key: string;
    readonly value: string;
    readonly category: string;
    readonly normalized: string;
  }

  function commit(placement: Placement, token: string, number: number): string {
    index.set(placement.key, token);
    counters.set(placement.prefix, Math.max(counters.get(placement.prefix) ?? 0, number));
    return token;
  }

  /**
   * Whether the vault's value for a token is the value being placed. A token
   * held for another value is remembered, so that every number up to the
   * counter is known and a later value the vault already holds is found
   * without probing again.
   */
  function isSame(placement: Placement, token: string, existing: string): boolean {
    const normalized = normalize(existing, placement.category);
    if (normalized === placement.normalized) return true;
    const key = `${placement.prefix}\0${normalized}`;
    if (!index.has(key)) index.set(key, token);
    return false;
  }

  function tooMany(): never {
    throw new TokenVaultError(`no free token number after ${String(MAX_PROBES)} attempts`);
  }

  async function allocateAsync(
    placement: Placement,
    first: number,
    answer: Promise<string | undefined>,
  ): Promise<string> {
    let existing = await answer;
    for (let number = first; number < first + MAX_PROBES; ) {
      const token = render(placement.prefix, number);
      if (typeof existing !== "string") {
        await vault.store(token, placement.value);
        return commit(placement, token, number);
      }
      if (isSame(placement, token, existing)) return commit(placement, token, number);
      number++;
      existing = await vault.retrieve(render(placement.prefix, number));
    }
    return tooMany();
  }

  function allocate(placement: Placement): MaybePromise<string> {
    const first = (counters.get(placement.prefix) ?? 0) + 1;
    for (let number = first; number < first + MAX_PROBES; number++) {
      const token = render(placement.prefix, number);
      const existing = vault.retrieve(token);
      if (isThenable(existing)) return allocateAsync(placement, number, existing);
      if (typeof existing !== "string") {
        const stored = vault.store(token, placement.value);
        return isThenable(stored)
          ? stored.then(() => commit(placement, token, number))
          : commit(placement, token, number);
      }
      if (isSame(placement, token, existing)) return commit(placement, token, number);
    }
    return tooMany();
  }

  function tokenize(value: string, context: TokenContext): MaybePromise<string> {
    if (typeof value !== "string") throw new ValidationError("value", "must be a string");
    const prefix = prefixOf(context.category);
    const normalized = normalize(value, context.category);
    const key = `${prefix}\0${normalized}`;
    const known = index.get(key);
    if (known !== undefined) return known;
    // One allocation at a time: two concurrent ones would probe the same number.
    if (pending !== undefined) return pending.then(() => tokenize(value, context));

    const token = allocate({ prefix, key, value, category: context.category, normalized });
    if (isThenable(token)) {
      const settled = token.then(
        () => undefined,
        () => undefined,
      );
      pending = settled;
      void settled.then(() => {
        if (pending === settled) pending = undefined;
      });
    }
    return token;
  }

  function detokenize(token: string): MaybePromise<string | undefined> {
    if (typeof token !== "string") throw new ValidationError("token", "must be a string");
    const value = vault.retrieve(token);
    if (isThenable(value)) {
      return value.then((resolved) => (typeof resolved === "string" ? resolved : undefined));
    }
    return typeof value === "string" ? value : undefined;
  }

  return Object.freeze({
    scheme: "vault",
    reversible: true,
    vault,
    tokenPattern,
    partialTokenPattern: new RegExp(shape.partialSource),
    maxTokenLength: 62 + shape.open.length + shape.close.length,
    tokenize,
    detokenize,
    restore: (text: string): MaybePromise<RestoreResult> =>
      restore(text, vault, { pattern: tokenPattern }),
  });
}
