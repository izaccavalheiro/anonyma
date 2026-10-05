/**
 * @module vault/memory-vault
 * @description An in-memory {@link TokenVault}. It is the reference
 * implementation of the interface and is suitable for tests and for
 * single-process, short-lived vaults.
 */

import type { TokenVault, VaultRecord } from "./types.js";

/**
 * A {@link TokenVault} that also reports how many records it holds.
 */
export interface MemoryVault extends TokenVault {
  /** Number of records currently stored. */
  readonly size: () => number;
}

/** Whether two records hold the same sealed value for the same subjects. */
function sameRecord(a: VaultRecord, b: VaultRecord): boolean {
  if (a.keyId !== b.keyId || a.sealed !== b.sealed) return false;
  const left = a.subjects ?? [];
  const right = b.subjects ?? [];
  return (
    left.length === right.length &&
    left.every((subject, index) => subject.tag === right[index]?.tag)
  );
}

/**
 * Create an in-memory token vault.
 *
 * @param records - Records to start with, for example from an earlier export.
 * @returns The vault.
 *
 * @example
 * ```ts
 * import { createMemoryVault, createKeyedTokenizer } from "anonyma/vault";
 *
 * const vault = createMemoryVault();
 * const tokenizer = createKeyedTokenizer({ keyring, vault });
 * ```
 */
export function createMemoryVault(records: Iterable<VaultRecord> = []): MemoryVault {
  const store = new Map<string, VaultRecord>();
  for (const record of records) store.set(record.token, Object.freeze({ ...record }));

  return Object.freeze({
    get: (token: string): VaultRecord | undefined => store.get(token),
    putIfAbsent(record: VaultRecord): VaultRecord {
      const existing = store.get(record.token);
      if (existing !== undefined) return existing;
      const stored = Object.freeze({ ...record });
      store.set(record.token, stored);
      return stored;
    },
    replace(record: VaultRecord, expected: VaultRecord): boolean {
      const stored = store.get(record.token);
      if (stored === undefined || !sameRecord(stored, expected)) return false;
      store.set(record.token, Object.freeze({ ...record }));
      return true;
    },
    delete: (token: string): boolean => store.delete(token),
    list: (): Iterable<VaultRecord> => [...store.values()],
    size: (): number => store.size,
  });
}
