/**
 * @module vault/keyed
 * @description Deterministic, keyed tokenization. A token identifier is an
 * HMAC-SHA-256 of the category and the value under a secret key, so the same
 * value always yields the same token for a key version — across calls,
 * processes and machines — without anyone being able to recompute it without
 * the key.
 *
 * With a vault the scheme is reversible: the original value is stored sealed
 * with AES-256-GCM. Without a vault it is a one-way keyed pseudonym.
 */

import { TokenVaultError, ValidationError } from "../errors.js";
import { toBase32, toBase64Url } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";
import { macOf, seal, unseal } from "./seal.js";
import { KEY_ID_SOURCE, PREFIX_SOURCE, isKeyId, prefixResolver } from "./tokens.js";
import type {
  ErasureReceipt,
  KeyRing,
  SubjectReference,
  TokenContext,
  TokenVault,
  TokenizationProvider,
  VaultRecord,
} from "./types.js";

/** How often a write is retried when another writer changed the record first. */
const MAX_ATTEMPTS = 5;

/**
 * Options accepted by {@link createKeyedTokenizer}.
 */
export interface KeyedTokenizerOptions {
  /** The key ring that supplies the identifier and sealing keys. */
  readonly keyring: KeyRing;
  /** Where sealed originals are kept. Leave it out for one-way pseudonyms. */
  readonly vault?: TokenVault;
  /**
   * Key version used for token identifiers. Pin it to keep tokens stable
   * while the sealing key rotates. Defaults to the ring's active version at
   * the time of each call.
   *
   * A pinned version must stay in the ring: once it is destroyed, nothing can
   * be tokenized any more. Tokens that must survive crypto-shredding of the
   * sealing keys therefore need an identifier version that is retired but
   * never destroyed.
   */
  readonly idKeyId?: string;
  /**
   * Length of the identifier in base32 characters (5 bits each), 8 to 26.
   * Defaults to `12` (60 bits).
   */
  readonly idLength?: number;
  /** Token prefixes for categories, overriding the defaults. */
  readonly prefixes?: Readonly<Record<string, string>>;
  /**
   * Lifetime of vault records in milliseconds, counted from the first time a
   * value is tokenized. Records never expire by default. A value that is
   * tokenized again after its record expired gets a fresh record under the
   * same token.
   */
  readonly ttlMs?: number;
  /** Clock. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/**
 * A keyed {@link TokenizationProvider} with erasure operations.
 */
export interface KeyedTokenizer extends TokenizationProvider {
  readonly tokenize: (value: string, context: TokenContext) => Promise<string>;
  readonly detokenize: (token: string) => Promise<string | undefined>;
  /**
   * Delete the vault record of one token. The token can no longer be resolved.
   * Returns `true` when a record was deleted.
   */
  readonly forgetToken: (token: string) => Promise<boolean>;
  /**
   * Delete every vault record of a value that was tokenized for this
   * data-subject reference, and return a receipt for the audit log. A value
   * that several subjects share has one record, so its token stops resolving
   * for all of them.
   */
  readonly forgetSubject: (subject: string) => Promise<ErasureReceipt>;
}

/**
 * Keyed digest of a data-subject reference under one key version.
 * @internal
 */
export async function subjectTagOf(
  keyring: KeyRing,
  keyId: string,
  subject: string,
): Promise<string> {
  const key = await keyring.deriveKey(keyId, "subject-tag");
  return toBase64Url(await macOf(await webCrypto(), key, "subject", subject));
}

/**
 * Additional authenticated data that binds a sealed subject reference to its token.
 * @internal
 */
export function subjectContext(token: string): string {
  return `${token}\0subject`;
}

/**
 * Additional authenticated data of a sealed value: the token and the record's
 * lifetime, so that neither can be changed without the value becoming unreadable.
 * @internal
 */
export function valueContext(
  record: Pick<VaultRecord, "token" | "createdAt" | "expiresAt">,
): string {
  return `${record.token}\0${String(record.createdAt)}\0${String(record.expiresAt ?? "")}`;
}

/**
 * Create a keyed tokenizer.
 *
 * Tokens look like `[EMAIL_k1_7ZK3M9QW2ABC]`: category prefix, key version,
 * identifier.
 *
 * @param options - Key ring, optional vault and token options.
 * @returns The {@link KeyedTokenizer}.
 * @throws {@link ValidationError} When an option is invalid.
 *
 * @example
 * ```ts
 * import { createKeyRing, createKeyedTokenizer, createMemoryVault } from "anonyma/vault";
 *
 * const keyring = await createKeyRing({ namespace: "crm", keys: [{ id: "k1", material }] });
 * const tokenizer = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
 *
 * const token = await tokenizer.tokenize("alice@example.com", { category: "email", subject: "user-42" });
 * await tokenizer.detokenize(token);        // "alice@example.com"
 * await tokenizer.forgetSubject("user-42"); // erasure: the token no longer resolves
 * ```
 */
export function createKeyedTokenizer(options: KeyedTokenizerOptions): KeyedTokenizer {
  const { keyring, vault, idKeyId, idLength = 12, ttlMs } = options;
  const now = options.now ?? Date.now;

  if (!Number.isInteger(idLength) || idLength < 8 || idLength > 26) {
    throw new ValidationError("idLength", "must be an integer between 8 and 26");
  }
  if (idKeyId !== undefined && !isKeyId(idKeyId)) {
    throw new ValidationError("idKeyId", "is not a valid key version identifier");
  }
  if (ttlMs !== undefined && !(ttlMs > 0)) {
    throw new ValidationError("ttlMs", "must be a positive number");
  }

  const prefixOf = prefixResolver(options.prefixes);
  const tokenSource = `\\[${PREFIX_SOURCE}_${KEY_ID_SOURCE}_[0-9A-HJKMNP-TV-Z]{${String(idLength)}}\\]`;
  const wholeToken = new RegExp(`^${tokenSource}$`);

  async function tokenize(value: string, context: TokenContext): Promise<string> {
    if (typeof value !== "string") throw new ValidationError("value", "must be a string");
    const crypto = await webCrypto();
    const keyId = idKeyId ?? keyring.activeKeyId();
    const mac = await macOf(
      crypto,
      await keyring.deriveKey(keyId, "token-id"),
      context.category,
      value,
    );
    const token = `[${prefixOf(context.category)}_${keyId}_${toBase32(mac, idLength)}]`;
    if (vault === undefined) return token;

    const check = toBase64Url(mac);
    // Another writer may create, erase or re-seal the record between two steps;
    // every write is conditional, and a lost race is simply looked at again.
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      let existing = await vault.get(token);
      if (existing === undefined) {
        const record = await create(crypto, token, check, value, context);
        existing = await vault.putIfAbsent(record);
        if (existing.sealed === record.sealed && existing.check === check) return token;
        // Another writer stored a record first: it is judged like one that was found.
      }
      const same = await holdsValue(crypto, existing, check, value);
      if (same === undefined || isExpired(existing)) {
        // Expired, or sealed under a destroyed key: the record resolves nothing, so it is renewed.
        const record = await create(crypto, token, check, value, context);
        if (await vault.replace(record, existing)) return token;
        continue;
      }
      if (!same) throw new TokenVaultError("token identifier collision; increase idLength");
      if (context.subject === undefined) return token;
      const tagged = await withSubject(crypto, existing, context.subject);
      if (tagged === existing || (await vault.replace(tagged, existing))) return token;
    }
    throw new TokenVaultError("the vault record kept changing; try again");
  }

  function isExpired(record: VaultRecord): boolean {
    return record.expiresAt !== undefined && record.expiresAt <= now();
  }

  async function create(
    crypto: Crypto,
    token: string,
    check: string,
    value: string,
    context: TokenContext,
  ): Promise<VaultRecord> {
    const keyId = keyring.activeKeyId();
    const sealKey = await keyring.deriveKey(keyId, "token-seal");
    const createdAt = now();
    const lifetime = {
      token,
      createdAt,
      ...(ttlMs !== undefined ? { expiresAt: createdAt + ttlMs } : {}),
    };
    return {
      ...lifetime,
      category: context.category,
      keyId,
      sealed: await seal(crypto, sealKey, value, valueContext(lifetime)),
      check,
      ...(context.subject !== undefined
        ? { subjects: [await subjectReference(crypto, token, keyId, context.subject)] }
        : {}),
    };
  }

  async function subjectReference(
    crypto: Crypto,
    token: string,
    keyId: string,
    subject: string,
  ): Promise<SubjectReference> {
    const sealKey = await keyring.deriveKey(keyId, "token-seal");
    return {
      tag: await subjectTagOf(keyring, keyId, subject),
      sealed: await seal(crypto, sealKey, subject, subjectContext(token)),
    };
  }

  /**
   * Whether `record` holds `value`: `undefined` when that cannot be told
   * because the record's key version is gone.
   */
  async function holdsValue(
    crypto: Crypto,
    record: VaultRecord,
    check: string,
    value: string,
  ): Promise<boolean | undefined> {
    if (record.check !== undefined) {
      // The check value is a MAC under the identifier key, which is still in the ring.
      return record.check === check;
    }
    try {
      const key = await keyring.deriveKey(record.keyId, "token-seal");
      return (await unseal(crypto, key, record.sealed, valueContext(record))) === value;
    } catch {
      return undefined;
    }
  }

  /** `record` with `subject` among its subjects; `record` itself when it already is. */
  async function withSubject(
    crypto: Crypto,
    record: VaultRecord,
    subject: string,
  ): Promise<VaultRecord> {
    const subjects = record.subjects ?? [];
    const tag = await subjectTagOf(keyring, record.keyId, subject);
    if (subjects.some((entry) => entry.tag === tag)) return record;
    const reference = await subjectReference(crypto, record.token, record.keyId, subject);
    return { ...record, subjects: [...subjects, reference] };
  }

  async function detokenize(token: string): Promise<string | undefined> {
    if (vault === undefined || typeof token !== "string" || !wholeToken.test(token))
      return undefined;
    const record = await vault.get(token);
    if (record === undefined || isExpired(record)) return undefined;
    let key: CryptoKey;
    try {
      key = await keyring.deriveKey(record.keyId, "token-seal");
    } catch {
      // The sealing key was destroyed: the value is gone for good.
      return undefined;
    }
    return unseal(await webCrypto(), key, record.sealed, valueContext(record));
  }

  async function forgetToken(token: string): Promise<boolean> {
    return vault === undefined ? false : vault.delete(token);
  }

  async function forgetSubject(subject: string): Promise<ErasureReceipt> {
    if (typeof subject !== "string" || subject.length === 0) {
      throw new ValidationError("subject", "must be a non-empty string");
    }
    const tags = new Map<string, string>();
    for (const version of keyring.manifest().versions) {
      if (version.state !== "destroyed") {
        tags.set(version.id, await subjectTagOf(keyring, version.id, subject));
      }
    }
    const isSubject = (record: VaultRecord): boolean => {
      const tag = tags.get(record.keyId);
      return tag !== undefined && (record.subjects ?? []).some((entry) => entry.tag === tag);
    };
    let erased = 0;
    const keyIds = new Set<string>();
    if (vault !== undefined) {
      const doomed: VaultRecord[] = [];
      for await (const record of vault.list()) {
        if (isSubject(record)) doomed.push(record);
      }
      for (const record of doomed) {
        if (await vault.delete(record.token)) {
          erased++;
          keyIds.add(record.keyId);
        }
      }
    }
    const activeTag = tags.get(keyring.activeKeyId());
    return Object.freeze({
      method: "vault-delete" as const,
      erased,
      keyIds: Object.freeze([...keyIds].sort()),
      // The active version cannot be destroyed, so it always has a tag.
      ...(activeTag !== undefined ? { subjectTag: activeTag } : /* v8 ignore next */ {}),
      completedAt: now(),
    });
  }

  return Object.freeze({
    scheme: "keyed",
    reversible: vault !== undefined,
    tokenPattern: new RegExp(tokenSource, "g"),
    partialTokenPattern: /\[[A-Za-z0-9_]{0,80}$/,
    maxTokenLength: 40 + 1 + 16 + 1 + idLength + 2,
    tokenize,
    detokenize,
    forgetToken,
    forgetSubject,
  });
}
