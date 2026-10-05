/**
 * @module vault/sealed
 * @description Stateless reversible tokenization. The token carries the
 * original value sealed with AES-256-GCM, so restoring it needs only the key
 * ring — no vault, no shared state.
 *
 * The scheme is deterministic: the nonce is derived from the value with a
 * keyed PRF (a synthetic initialisation vector), so equal values produce equal
 * tokens and a nonce is never reused for different values except with
 * negligible probability. As with random 96-bit nonces, rotate the key version
 * well before 2^32 distinct values have been sealed under it (NIST SP 800-38D).
 * The length of a token grows with the length of the value.
 */

import { ValidationError } from "../errors.js";
import { encodeText } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";
import { macOf, seal, unseal } from "./seal.js";
import { KEY_ID_SOURCE, PREFIX_SOURCE, prefixResolver } from "./tokens.js";
import type { KeyRing, TokenContext, TokenizationProvider } from "./types.js";

/**
 * Options accepted by {@link createSealedTokenizer}.
 */
export interface SealedTokenizerOptions {
  /** The key ring that supplies the nonce and sealing keys. */
  readonly keyring: KeyRing;
  /** Token prefixes for categories, overriding the defaults. */
  readonly prefixes?: Readonly<Record<string, string>>;
  /**
   * Longest value, in UTF-8 bytes, that may be sealed. It bounds the length of
   * a token. Defaults to `256`.
   */
  readonly maxValueBytes?: number;
}

/**
 * A stateless, reversible {@link TokenizationProvider}.
 */
export interface SealedTokenizer extends TokenizationProvider {
  readonly tokenize: (value: string, context: TokenContext) => Promise<string>;
  readonly detokenize: (token: string) => Promise<string | undefined>;
}

/**
 * Create a stateless reversible tokenizer.
 *
 * Tokens look like `[EMAIL_k1.5wq…]`: category prefix, key version, then the
 * sealed value. A token that was altered, or whose prefix or key version was
 * swapped, does not resolve.
 *
 * @param options - Key ring and token options.
 * @returns The {@link SealedTokenizer}.
 * @throws {@link ValidationError} When an option is invalid.
 *
 * @example
 * ```ts
 * import { createKeyRing, createSealedTokenizer } from "anonyma/vault";
 *
 * const keyring = await createKeyRing({ namespace: "exports", keys: [{ id: "k1", material }] });
 * const tokenizer = createSealedTokenizer({ keyring });
 *
 * const token = await tokenizer.tokenize("alice@example.com", { category: "email" });
 * await tokenizer.detokenize(token); // "alice@example.com", on any machine holding the key
 * ```
 */
export function createSealedTokenizer(options: SealedTokenizerOptions): SealedTokenizer {
  const { keyring, maxValueBytes = 256 } = options;
  if (!Number.isInteger(maxValueBytes) || maxValueBytes < 1) {
    throw new ValidationError("maxValueBytes", "must be a positive integer");
  }

  const prefixOf = prefixResolver(options.prefixes);
  const tokenSource = `\\[(${PREFIX_SOURCE})_(${KEY_ID_SOURCE})\\.([A-Za-z0-9_-]{38,})\\]`;
  const wholeToken = new RegExp(`^${tokenSource}$`);

  async function tokenize(value: string, context: TokenContext): Promise<string> {
    if (typeof value !== "string") throw new ValidationError("value", "must be a string");
    if (encodeText(value).length > maxValueBytes) {
      throw new ValidationError("value", "is longer than maxValueBytes and cannot be sealed");
    }
    const crypto = await webCrypto();
    const keyId = keyring.activeKeyId();
    const header = `${prefixOf(context.category)}_${keyId}`;
    const mac = await macOf(crypto, await keyring.deriveKey(keyId, "token-id"), header, value);
    const sealed = await seal(
      crypto,
      await keyring.deriveKey(keyId, "token-seal"),
      value,
      header,
      mac.slice(0, 12),
    );
    return `[${header}.${sealed}]`;
  }

  async function detokenize(token: string): Promise<string | undefined> {
    if (typeof token !== "string") return undefined;
    const match = wholeToken.exec(token);
    const prefix = match?.[1];
    const keyId = match?.[2];
    const sealed = match?.[3];
    if (prefix === undefined || keyId === undefined || sealed === undefined) return undefined;
    let key: CryptoKey;
    try {
      key = await keyring.deriveKey(keyId, "token-seal");
    } catch {
      // Unknown or destroyed key version.
      return undefined;
    }
    return unseal(await webCrypto(), key, sealed, `${prefix}_${keyId}`);
  }

  return Object.freeze({
    scheme: "sealed",
    reversible: true,
    tokenPattern: new RegExp(tokenSource.replace(/\((?!\?)/g, "(?:"), "g"),
    partialTokenPattern: /\[[A-Za-z0-9_.-]*$/,
    // prefix + "_" + key id + "." + base64url(12-byte nonce, value, 16-byte tag) + brackets
    maxTokenLength: 2 + 40 + 1 + 16 + 1 + Math.ceil(((12 + maxValueBytes + 16) * 4) / 3),
    tokenize,
    detokenize,
  });
}
