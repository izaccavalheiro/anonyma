/**
 * @module vault/seal
 * @description AES-256-GCM sealing and HMAC helpers shared by the providers.
 * @internal
 */

import {
  concatBytes,
  decodeText,
  encodeText,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8,
} from "../internal/encoding.js";
import type { Bytes } from "../internal/encoding.js";

const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * HMAC-SHA-256 over the category and the value, separated by a NUL byte so
 * that no two (category, value) pairs share an input.
 * @internal
 */
export async function macOf(
  crypto: Crypto,
  key: CryptoKey,
  category: string,
  value: string,
): Promise<Bytes> {
  const input = concatBytes(encodeText(category), new Uint8Array(1), encodeText(value));
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, input));
}

/**
 * Encrypt `value` with AES-256-GCM and return base64url of `iv ‖ ciphertext ‖ tag`.
 *
 * @param iv - A 12-byte nonce. A random one is generated when omitted.
 * @internal
 */
export async function seal(
  crypto: Crypto,
  key: CryptoKey,
  value: string,
  additionalData: string,
  iv: Bytes = randomBytes(crypto, IV_BYTES),
): Promise<string> {
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(additionalData), tagLength: TAG_BYTES * 8 },
    key,
    encodeText(value),
  );
  return toBase64Url(concatBytes(iv, new Uint8Array(sealed)));
}

/**
 * Reverse {@link seal}. Returns `undefined` when the input is malformed, the
 * key or the additional data is wrong, or the ciphertext was modified.
 * @internal
 */
export async function unseal(
  crypto: Crypto,
  key: CryptoKey,
  sealed: string,
  additionalData: string,
): Promise<string | undefined> {
  const bytes = fromBase64Url(sealed);
  if (bytes === undefined || bytes.length < IV_BYTES + TAG_BYTES) return undefined;
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes.subarray(0, IV_BYTES),
        additionalData: utf8(additionalData),
        tagLength: TAG_BYTES * 8,
      },
      key,
      bytes.subarray(IV_BYTES),
    );
    return decodeText(new Uint8Array(plain));
  } catch {
    return undefined;
  }
}
