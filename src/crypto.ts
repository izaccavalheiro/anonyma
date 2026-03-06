/**
 * @module crypto
 * @description Re-exports the AES-GCM encryption/decryption utilities.
 * Import via the `"anonyma/crypto"` subpath entry.
 *
 * @example
 * ```ts
 * import { encrypt, decrypt } from "anonyma/crypto";
 *
 * const cipher = await encrypt("alice@example.com", { passphrase: "s3cr3t" });
 * const plain  = await decrypt(cipher, { passphrase: "s3cr3t" });
 * ```
 */

export { encrypt, decrypt } from "./strategies/encrypt.js";
export type { EncryptOptions } from "./types.js";
