/**
 * @module vault/rotation
 * @description Key rotation and erasure for token vaults.
 *
 * Rotation protocol
 * 1. `keyring.rotate()` adds a version and makes it active. New records are
 *    sealed under it; the previous version stays available for unsealing.
 * 2. {@link rewrapVault} re-seals every record under the active version.
 *    Tokens do not change, so data that already contains them is unaffected.
 * 3. `keyring.destroy()` (or {@link shredKey}) discards the old version.
 *
 * Erasure
 * - A single value or data subject: delete the vault records (see
 *   `KeyedTokenizer.forgetToken()` and `forgetSubject()`).
 * - Everything sealed under a key version: {@link shredKey}. Without the key
 *   the sealed values cannot be recovered by anyone, even from backups of the
 *   vault.
 */

import { webCrypto } from "../internal/webcrypto.js";
import { subjectContext, subjectTagOf, valueContext } from "./keyed.js";
import { seal, unseal } from "./seal.js";
import type {
  ErasureReceipt,
  KeyRing,
  SubjectReference,
  TokenVault,
  VaultRecord,
} from "./types.js";

/**
 * Outcome of {@link rewrapVault}.
 */
export interface RewrapResult {
  /** Records re-sealed under the active key version. */
  readonly rewrapped: number;
  /** Records that were already sealed under the active key version. */
  readonly current: number;
  /** Records whose key version is destroyed, or that failed authentication. They are left as they are. */
  readonly unrecoverable: number;
  /**
   * Records that were erased or changed while the rewrap ran. Nothing was
   * written for them; run the rewrap again to pick up the ones that still exist.
   */
  readonly skipped: number;
}

/**
 * Re-seal every vault record under the key ring's active version. A record
 * that is erased while the rewrap runs stays erased: the rewrap only replaces
 * records that are still what it read.
 *
 * @param vault - The vault to re-seal.
 * @param keyring - The key ring. It must still hold the versions the records were sealed under.
 * @returns Counts of what was done.
 *
 * @example
 * ```ts
 * await keyring.rotate({ id: "k2", material });
 * const { unrecoverable, skipped } = await rewrapVault(vault, keyring);
 * if (unrecoverable === 0 && skipped === 0) keyring.destroy("k1");
 * ```
 */
export async function rewrapVault(vault: TokenVault, keyring: KeyRing): Promise<RewrapResult> {
  const crypto = await webCrypto();
  const active = keyring.activeKeyId();
  const activeKey = await keyring.deriveKey(active, "token-seal");

  // Collect first: replacing records while a store is being enumerated is not portable.
  const stale: VaultRecord[] = [];
  let current = 0;
  for await (const record of vault.list()) {
    if (record.keyId === active) current++;
    else stale.push(record);
  }

  let rewrapped = 0;
  let unrecoverable = 0;
  let skipped = 0;
  for (const record of stale) {
    let value: string | undefined;
    const subjects: string[] = [];
    try {
      const oldKey = await keyring.deriveKey(record.keyId, "token-seal");
      value = await unseal(crypto, oldKey, record.sealed, valueContext(record));
      for (const entry of record.subjects ?? []) {
        const subject = await unseal(crypto, oldKey, entry.sealed, subjectContext(record.token));
        // A subject that cannot be read would no longer be erasable: leave the record alone.
        if (subject === undefined) value = undefined;
        else subjects.push(subject);
      }
    } catch {
      value = undefined;
    }
    if (value === undefined) {
      unrecoverable++;
      continue;
    }
    const references: SubjectReference[] = [];
    for (const subject of subjects) {
      references.push({
        tag: await subjectTagOf(keyring, active, subject),
        sealed: await seal(crypto, activeKey, subject, subjectContext(record.token)),
      });
    }
    const next: VaultRecord = {
      ...record,
      keyId: active,
      sealed: await seal(crypto, activeKey, value, valueContext(record)),
      ...(references.length > 0 ? { subjects: references } : {}),
    };
    // Conditional on the record still being what was read: an erasure that ran meanwhile wins.
    if (await vault.replace(next, record)) rewrapped++;
    else skipped++;
  }
  return { rewrapped, current, unrecoverable, skipped };
}

/**
 * Crypto-shred a key version: discard its material and, when a vault is
 * given, delete the records that were sealed under it.
 *
 * @param keyring - The key ring.
 * @param keyId - The version to destroy. It must not be the active version.
 * @param vault - The vault whose records under that version should be deleted.
 * @param now - Clock for the receipt. Defaults to `Date.now`.
 * @returns A receipt for the audit log.
 * @throws KeyManagementError When the version is unknown or active.
 *
 * @example
 * ```ts
 * const receipt = await shredKey(keyring, "k1", vault);
 * await audit.record({ operation: "key-destroy", fields: [], attributes: { erased: receipt.erased } });
 * ```
 */
export async function shredKey(
  keyring: KeyRing,
  keyId: string,
  vault?: TokenVault,
  now: () => number = Date.now,
): Promise<ErasureReceipt> {
  keyring.destroy(keyId);
  let erased = 0;
  if (vault !== undefined) {
    const doomed: string[] = [];
    for await (const record of vault.list()) {
      if (record.keyId === keyId) doomed.push(record.token);
    }
    for (const token of doomed) {
      if (await vault.delete(token)) erased++;
    }
  }
  return Object.freeze({
    method: "crypto-shred" as const,
    erased,
    keyIds: Object.freeze([keyId]),
    completedAt: now(),
  });
}
