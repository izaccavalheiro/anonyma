/**
 * @module strategies/encrypt
 * @description The `encrypt` anonymization strategy — uses AES-GCM via the
 * Web Crypto API (Node ≥ 18 / browsers with Web Crypto support).
 *
 * The output format is `"<encoding>:<iv>:<ciphertext>"` where `<iv>` is the
 * random 12-byte initialisation vector and `<ciphertext>` is the encrypted
 * payload. Both parts are encoded in the same format (base64 or hex).
 *
 * @throws {@link CryptoNotAvailableError} When `globalThis.crypto.subtle` is not present.
 * @throws {@link EncryptionError} When the underlying Web Crypto operation fails.
 */

import { CryptoNotAvailableError, EncryptionError } from "../errors.js";
import type { EncryptOptions } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function requireCrypto(): SubtleCrypto {
  if (typeof globalThis.crypto.subtle === "undefined") throw new CryptoNotAvailableError();
  return globalThis.crypto.subtle;
}

function toBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function fromBase64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(s: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i += 2) bytes.push(parseInt(s.slice(i, i + 2), 16));
  return new Uint8Array(bytes);
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase string using PBKDF2 + SHA-256.
 *
 * @internal
 */
async function deriveKey(
  subtle: SubtleCrypto,
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await subtle.importKey(
    "raw",
    enc.encode(passphrase) as unknown as ArrayBuffer,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return subtle.deriveKey(
    { name: "PBKDF2", salt: salt as unknown as ArrayBuffer, iterations: 100_000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Derive an AES-GCM key from a raw 16- or 32-byte `Uint8Array`.
 *
 * @internal
 */
async function importRawKey(subtle: SubtleCrypto, keyBytes: Uint8Array): Promise<CryptoKey> {
  if (keyBytes.length !== 16 && keyBytes.length !== 32) {
    throw new EncryptionError("encrypt", new Error("keyBytes must be 16 or 32 bytes"));
  }
  return subtle.importKey("raw", keyBytes as unknown as ArrayBuffer, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt `value` using AES-GCM.
 *
 * @param value   - The plaintext string.
 * @param options - Encryption options including key/passphrase and encoding.
 * @returns A promise resolving to the `"<encoding>:<iv>:<ciphertext>"` string.
 *
 * @example
 * ```ts
 * import { encrypt } from "anonyma";
 *
 * const ciphertext = await encrypt("alice@example.com", {
 *   strategy: "encrypt",
 *   passphrase: "s3cr3t",
 * });
 * // "base64:abc...==:xyz...=="
 * ```
 */
export async function encrypt(value: string, options: EncryptOptions): Promise<string> {
  const subtle = requireCrypto();
  const encoding = options.encoding ?? "base64";

  try {
    const enc = new TextEncoder();
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

    let key: CryptoKey;
    if (options.keyBytes) {
      // 16- or 32-byte raw key
      key = await importRawKey(subtle, options.keyBytes);
    } else if (options.passphrase) {
      // Derive from passphrase using PBKDF2. Use a fixed well-known salt so
      // the same passphrase always produces the same key (deterministic).
      const salt = enc.encode("anonyma_kdf_v1");
      key = await deriveKey(subtle, options.passphrase, salt);
    } else {
      throw new EncryptionError("encrypt", new Error("Provide `passphrase` or `keyBytes`"));
    }

    const cipherBuf = await subtle.encrypt(
      { name: "AES-GCM", iv: iv as unknown as ArrayBuffer },
      key,
      enc.encode(value) as unknown as ArrayBuffer,
    );

    const encode = encoding === "hex" ? toHex : toBase64;
    return `${encoding}:${encode(iv.buffer)}:${encode(cipherBuf)}`;
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError("encrypt", err);
  }
}

/**
 * Decrypt a ciphertext produced by {@link encrypt}.
 *
 * @param ciphertext - The `"<encoding>:<iv>:<payload>"` string.
 * @param options    - Must include the same `passphrase` or `keyBytes` used to encrypt.
 * @returns A promise resolving to the original plaintext string.
 *
 * @throws {@link EncryptionError} When decryption fails (wrong key, corrupt data, etc.).
 *
 * @example
 * ```ts
 * const plain = await decrypt("base64:abc...==:xyz...==", { passphrase: "s3cr3t" });
 * ```
 */
export async function decrypt(ciphertext: string, options: EncryptOptions): Promise<string> {
  const subtle = requireCrypto();

  const parts = ciphertext.split(":");
  if (parts.length !== 3) {
    throw new EncryptionError("decrypt", new Error("Malformed ciphertext — expected `encoding:iv:payload`"));
  }

  const [encoding, ivEncoded, payloadEncoded] = parts as [string, string, string];
  const decode = encoding === "hex" ? fromHex : fromBase64;

  try {
    const iv = decode(ivEncoded);
    const payload = decode(payloadEncoded);

    const enc = new TextEncoder();
    let key: CryptoKey;
    if (options.keyBytes) {
      key = await importRawKey(subtle, options.keyBytes);
    } else if (options.passphrase) {
      const salt = enc.encode("anonyma_kdf_v1");
      key = await deriveKey(subtle, options.passphrase, salt);
    } else {
      throw new EncryptionError("decrypt", new Error("Provide `passphrase` or `keyBytes`"));
    }

    const plainBuf = await subtle.decrypt({ name: "AES-GCM", iv: iv as unknown as ArrayBuffer }, key, payload as unknown as ArrayBuffer);
    return new TextDecoder().decode(plainBuf);
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError("decrypt", err);
  }
}
