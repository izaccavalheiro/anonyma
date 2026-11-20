/**
 * @module vault
 * @description Deterministic tokenization, key management and token vaults,
 * exposed as `"anonyma/vault"`.
 *
 * | Provider | State | Reversible | Token |
 * |---|---|---|---|
 * | {@link createSessionTokenizer} | in memory, one session | yes | `[EMAIL_0001]` |
 * | {@link createKeyedTokenizer} with a vault | vault | yes | `[EMAIL_k1_7ZK3M9QW2ABC]` |
 * | {@link createKeyedTokenizer} without a vault | none | no | `[EMAIL_k1_7ZK3M9QW2ABC]` |
 * | {@link createSealedTokenizer} | none | yes | `[EMAIL_k1.5wq…]` |
 * | {@link createVaultTokenizer} | an {@link AnonymaVault} | yes | `{{EMAIL_1}}` |
 *
 * {@link restore} puts the values of an {@link AnonymaVault} back into a text,
 * and {@link InMemoryVault} is the vault for one request.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { createKeyRing, createKeyedTokenizer, createMemoryVault, restoreTokens } from "anonyma/vault";
 *
 * const keyring = await createKeyRing({ namespace: "crm", keys: [{ id: "k1", material }] });
 * const tokenization = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
 * const pipeline = compilePipeline({ defaultStrategy: { strategy: "tokenize" } }, { tokenization });
 *
 * const { text } = await pipeline.transformAsync("Mail alice@example.com");
 * const restored = await restoreTokens(text, tokenization);
 * ```
 */

export { createKeyRing, generateKeyMaterial } from "./keyring.js";
export type { KeyRingOptions } from "./keyring.js";
export { createSessionTokenizer } from "./session.js";
export type { SessionSnapshot, SessionTokenizer, SessionTokenizerOptions } from "./session.js";
export { createKeyedTokenizer } from "./keyed.js";
export type { KeyedTokenizer, KeyedTokenizerOptions } from "./keyed.js";
export { createSealedTokenizer } from "./sealed.js";
export type { SealedTokenizer, SealedTokenizerOptions } from "./sealed.js";
export { createMemoryVault } from "./memory-vault.js";
export type { MemoryVault } from "./memory-vault.js";
export { rewrapVault, shredKey } from "./rotation.js";
export type { RewrapResult } from "./rotation.js";
export { restoreTokens, tokenizeWith } from "./restore.js";
export { InMemoryVault, restore } from "./anonyma-vault.js";
export type { AnonymaVault, RestoreOptions, SyncAnonymaVault } from "./anonyma-vault.js";
export { createVaultTokenizer } from "./vault-tokenizer.js";
export type {
  SyncVaultTokenizer,
  VaultTokenizer,
  VaultTokenizerOptions,
} from "./vault-tokenizer.js";
export type { TokenShape } from "./tokens.js";
export type {
  ErasureReceipt,
  KeyMaterial,
  KeyPurpose,
  KeyRing,
  KeyRingManifest,
  KeyState,
  KeyVersionInfo,
  MaybePromise,
  RestoreResult,
  TokenContext,
  TokenVault,
  TokenizationProvider,
  VaultRecord,
} from "./types.js";
