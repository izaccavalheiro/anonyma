/**
 * @module strategies/hash
 * @description The `hash` anonymization strategy using SHA-256 (Web Crypto API).
 *
 * This strategy is one-way and cryptographically strong. Adding an optional
 * `pepper` makes the output specific to your deployment and prevents
 * rainbow-table attacks.
 *
 * Uses the Web Crypto API: `globalThis.crypto` where the runtime exposes it,
 * and Node's own implementation (`node:crypto`) on Node.js 18, which does not.
 */

import { ValidationError } from "../errors.js";
import { webCrypto } from "../internal/webcrypto.js";
import type { HashOptions } from "../types.js";

/**
 * Compute a SHA-256 hash of `value`, returning a hex string.
 *
 * @param value - The string to hash.
 * @param options - Hashing configuration.
 * @returns A Promise that resolves to a hex-encoded (possibly truncated) hash.
 *
 * @throws {@link CryptoNotAvailableError} When the runtime has no Web Crypto API at all.
 * @throws {@link ValidationError} When `truncate` is not a positive integer ≤ 64.
 *
 * @example
 * ```ts
 * import { hash } from "anonyma";
 *
 * await hash("alice@example.com");
 * // "5f3e4b3a9c1d8f2a" (first 16 hex chars of the SHA-256 digest)
 *
 * await hash("alice@example.com", { truncate: 32, pepper: "my-pepper" });
 * // A 32-character hex string, pepper-salted
 * ```
 */
export async function hash(value: string, options: HashOptions = {}): Promise<string> {
  const { truncate = 16, pepper } = options;

  if (!Number.isInteger(truncate) || truncate < 1 || truncate > 64) {
    throw new ValidationError("truncate", "must be an integer between 1 and 64 (inclusive)");
  }

  const { subtle } = await webCrypto();
  const input = pepper !== undefined ? `${pepper}:${value}` : value;
  const encoded = new TextEncoder().encode(input);
  const buffer = await subtle.digest("SHA-256", encoded);

  const hex = Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return hex.slice(0, truncate);
}
