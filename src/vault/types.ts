/**
 * @module vault/types
 * @description Contracts for deterministic tokenization, key management and
 * token vaults exposed as `"anonyma/vault"`. This module contains types only —
 * it has no runtime code.
 */

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * A value that may be returned directly or through a promise. Implementations
 * backed by the Web Crypto API or by remote storage return promises; purely
 * in-memory implementations may return plain values.
 */
export type MaybePromise<T> = T | Promise<T>;

// ---------------------------------------------------------------------------
// Tokenization provider
// ---------------------------------------------------------------------------

/**
 * Context of the value being tokenized.
 */
export interface TokenContext {
  /** Category label of the value (e.g. `"email"`). */
  readonly category: string;
  /**
   * Optional reference to the data subject the value belongs to. It is never
   * stored in clear: vault-backed providers keep only a keyed digest of it, so
   * that all tokens of one subject can later be erased.
   */
  readonly subject?: string;
}

/**
 * Outcome of restoring the tokens found in a text.
 */
export interface RestoreResult {
  /** The text with every resolvable token replaced by its original value. */
  readonly text: string;
  /** Number of token occurrences that were restored. */
  readonly restored: number;
  /** Token occurrences that could not be resolved, in document order. */
  readonly unresolved: readonly string[];
}

/**
 * Replaces values with tokens and, when the scheme is reversible, resolves
 * tokens back to values.
 *
 * A provider is deterministic within its scope: the same category and value
 * always yield the same token for the lifetime of a session provider, and for
 * the lifetime of a key version for keyed providers.
 */
export interface TokenizationProvider {
  /** Identifier of the scheme, recorded in audit events (e.g. `"session"`, `"keyed"`, `"sealed"`). */
  readonly scheme: string;
  /** Whether {@link TokenizationProvider.detokenize} can recover original values. */
  readonly reversible: boolean;
  /**
   * A global regular expression that matches every token this provider can
   * emit and nothing shorter than a whole token.
   */
  readonly tokenPattern: RegExp;
  /**
   * A regular expression that matches, anchored at the end of a string, any
   * proper prefix of a token (for example `[EMAIL_00`). Stream restoration
   * uses it to hold back an incomplete token until the rest arrives. When it
   * is absent, streams hold back the last `maxTokenLength - 1` characters.
   */
  readonly partialTokenPattern?: RegExp;
  /**
   * Replace every token found in `text`. A provider implements it when it
   * accepts more spellings of a token than `tokenPattern` matches (a session
   * in lenient mode, for example); whole-text and stream restoration then go
   * through it, so both accept the same spellings.
   */
  readonly restore?: (text: string) => MaybePromise<RestoreResult>;
  /** Upper bound on the length of a token, used for stream hold-back. */
  readonly maxTokenLength: number;
  /** Return the token for `value`, creating it if necessary. */
  readonly tokenize: (value: string, context: TokenContext) => MaybePromise<string>;
  /**
   * Resolve one token. Returns `undefined` when the token is unknown, erased,
   * expired, fails authentication, or the scheme is irreversible.
   */
  readonly detokenize: (token: string) => MaybePromise<string | undefined>;
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * What a derived key is used for. Every purpose gets an independent key, so a
 * key is never used for two different algorithms.
 *
 * - `"token-id"`: HMAC-SHA-256 key that derives deterministic token identifiers.
 * - `"token-seal"`: AES-256-GCM key that encrypts original values.
 * - `"subject-tag"`: HMAC-SHA-256 key that derives data-subject tags.
 * - `"audit-mac"`: HMAC-SHA-256 key that authenticates audit records.
 *
 * Every key of a version is gone once the version is destroyed. An audit log
 * must stay verifiable after data keys are shredded, so take its `audit-mac`
 * key from a key ring of its own, whose versions are retired but not destroyed.
 */
export type KeyPurpose = "token-id" | "token-seal" | "subject-tag" | "audit-mac";

/**
 * Lifecycle state of a key version.
 *
 * - `"active"`: used for new tokens and for decryption. Exactly one version is active.
 * - `"retired"`: no longer used for new tokens; still available for decryption and verification.
 * - `"destroyed"`: the key material has been discarded. Everything sealed under
 *   this version is permanently unrecoverable (crypto-shredding).
 */
export type KeyState = "active" | "retired" | "destroyed";

/**
 * Secret input from which the keys of one version are derived.
 */
export type KeyMaterial =
  | {
      /** High-entropy secret bytes (at least 32). Used as HKDF input keying material. */
      readonly kind: "raw";
      readonly bytes: Uint8Array;
    }
  | {
      /** A passphrase, stretched with PBKDF2-HMAC-SHA-256 before HKDF. */
      readonly kind: "passphrase";
      readonly passphrase: string;
      /** PBKDF2 iteration count. Defaults to 600,000 and may not be lower than 100,000. */
      readonly iterations?: number;
    };

/**
 * Non-secret description of one key version. Safe to store next to the data.
 */
export interface KeyVersionInfo {
  /** Version identifier: 1–16 characters from `[A-Za-z0-9]`. Embedded in tokens. */
  readonly id: string;
  /** Lifecycle state. */
  readonly state: KeyState;
  /** Creation time, milliseconds since the Unix epoch. */
  readonly createdAt: number;
  /** Key-derivation function applied to the material before HKDF. */
  readonly kdf: "hkdf" | "pbkdf2-hkdf";
  /** Salt for this version, base64url. Random, at least 16 bytes, not secret. */
  readonly salt: string;
  /** PBKDF2 iteration count, present when `kdf` is `"pbkdf2-hkdf"`. */
  readonly iterations?: number;
}

/**
 * Non-secret description of a key ring. Together with the secret material of
 * each live version it is sufficient to reconstruct the ring.
 */
export interface KeyRingManifest {
  /** Manifest format version. */
  readonly v: 1;
  /**
   * Domain-separation label mixed into every derived key (tenant, dataset or
   * environment). Two rings with different namespaces never produce the same
   * token for the same value, even from identical material.
   */
  readonly namespace: string;
  /** Identifier of the active version. */
  readonly activeKeyId: string;
  /** All versions, oldest first. */
  readonly versions: readonly KeyVersionInfo[];
  /**
   * HMAC-SHA-256 (base64url) under a key of the active version. It covers the
   * namespace, the active version, and every version's identifier, creation
   * time, derivation parameters and salt. A manifest whose MAC does not verify
   * is refused.
   */
  readonly mac: string;
}

/**
 * A set of versioned secrets with independent, purpose-bound derived keys.
 *
 * A key ring is a stateful object: {@link KeyRing.rotate} and
 * {@link KeyRing.destroy} change it in place.
 */
export interface KeyRing {
  /** Identifier of the version used for new tokens. */
  readonly activeKeyId: () => string;
  /** The current non-secret manifest. */
  readonly manifest: () => KeyRingManifest;
  /**
   * Derive the key of a version for a purpose. Derived keys are cached and
   * non-extractable.
   *
   * @throws KeyManagementError When the version is unknown or destroyed.
   */
  readonly deriveKey: (keyId: string, purpose: KeyPurpose) => Promise<CryptoKey>;
  /**
   * Add a new version and make it active. The previously active version
   * becomes `"retired"`.
   *
   * @throws KeyManagementError When `id` is already in use or malformed.
   */
  readonly rotate: (version: {
    readonly id: string;
    readonly material: KeyMaterial;
  }) => Promise<void>;
  /**
   * Discard the material of a retired version.
   *
   * @throws KeyManagementError When the version is unknown or is the active version.
   */
  readonly destroy: (keyId: string) => void;
}

// ---------------------------------------------------------------------------
// Token vault
// ---------------------------------------------------------------------------

/**
 * One vault entry. It holds no plaintext: the original value is sealed with
 * AES-256-GCM under the `token-seal` key of `keyId`.
 */
export interface VaultRecord {
  /** The token this record resolves. Primary key. */
  readonly token: string;
  /** Category label of the original value. */
  readonly category: string;
  /** Key version whose `token-seal` key sealed `sealed`. */
  readonly keyId: string;
  /** base64url of `iv (12 bytes) ‖ ciphertext ‖ tag (16 bytes)`. The token is bound as additional authenticated data. */
  readonly sealed: string;
  /**
   * Keyed digest of the category and original value. It lets a provider tell
   * a repeated value from an identifier collision without unsealing the record.
   */
  readonly check?: string;
  /**
   * The data subjects this value was tokenized for. A value shared by several
   * subjects has one record and one entry per subject; erasing any of them
   * deletes the record.
   */
  readonly subjects?: readonly SubjectReference[];
  /** Creation time, milliseconds since the Unix epoch. Bound to `sealed`. */
  readonly createdAt: number;
  /**
   * Expiry time, milliseconds since the Unix epoch. Expired records do not
   * resolve. Bound to `sealed`: a record whose expiry was changed or removed
   * no longer resolves.
   */
  readonly expiresAt?: number;
}

/**
 * One data subject of a vault record. It holds no plaintext.
 */
export interface SubjectReference {
  /** Keyed digest of the data-subject reference under the `subject-tag` key of the record's `keyId`. */
  readonly tag: string;
  /**
   * The data-subject reference sealed under the `token-seal` key of the
   * record's `keyId`. Key rotation unseals it to recompute `tag` under the new
   * version, so erasure by subject keeps working after old versions are destroyed.
   */
  readonly sealed: string;
}

/**
 * Storage for {@link VaultRecord}s. Implement this interface to keep the
 * vault in Redis, a SQL table, a KV store, and so on.
 */
export interface TokenVault {
  /** Fetch the record of a token. */
  readonly get: (token: string) => MaybePromise<VaultRecord | undefined>;
  /**
   * Store `record` unless a record with the same token already exists.
   * Returns the record that is stored after the call (the existing one or the new one).
   */
  readonly putIfAbsent: (record: VaultRecord) => MaybePromise<VaultRecord>;
  /**
   * Overwrite the record of `record.token`, but only while the stored record
   * still is `expected` (same `keyId`, `sealed` and `subjects`). Returns
   * `false`, and stores nothing, when the record was deleted or changed in the
   * meantime. It never creates a record: an erasure that runs at the same time
   * as a key rotation must win.
   */
  readonly replace: (record: VaultRecord, expected: VaultRecord) => MaybePromise<boolean>;
  /** Delete the record of a token. Returns `true` when a record was deleted. */
  readonly delete: (token: string) => MaybePromise<boolean>;
  /** Enumerate all records. Required for key rotation and erasure by subject. */
  readonly list: () => AsyncIterable<VaultRecord> | Iterable<VaultRecord>;
}

// ---------------------------------------------------------------------------
// Erasure
// ---------------------------------------------------------------------------

/**
 * Proof that an erasure request was executed. It contains no personal data and
 * is meant to be written to the audit log.
 */
export interface ErasureReceipt {
  /** How the erasure was carried out. */
  readonly method: "vault-delete" | "crypto-shred";
  /** Number of vault records removed (`vault-delete`) or rendered unrecoverable (`crypto-shred`). */
  readonly erased: number;
  /** Key versions involved. */
  readonly keyIds: readonly string[];
  /** Keyed digest of the data-subject reference, for `vault-delete` by subject. */
  readonly subjectTag?: string;
  /** Completion time, milliseconds since the Unix epoch. */
  readonly completedAt: number;
}
