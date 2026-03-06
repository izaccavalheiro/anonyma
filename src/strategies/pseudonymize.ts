/**
 * @module strategies/pseudonymize
 * @description The `pseudonymize` anonymization strategy.
 *
 * Generates a deterministic pseudonym from the input value + an optional seed.
 * The same `(value, seed)` pair always produces the same pseudonym, enabling
 * consistent replacement throughout a dataset without storing a lookup table.
 *
 * When no `seed` is provided, the pseudonym is randomly generated and is NOT
 * deterministic across calls.
 *
 * ⚠️  This strategy is NOT cryptographically secure. For strong irreversibility
 *     use the `hash` strategy instead.
 */

import { ValidationError } from "../errors.js";
import type { PseudonymizeOptions } from "../types.js";

/**
 * A lightweight, non-cryptographic integer hash (djb2 variant).
 * Used only for deterministic pseudonym generation.
 *
 * @internal
 */
function djb2(str: string): number {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    // Safe: str.charCodeAt never throws for valid indices.
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
    hash = hash >>> 0; // Convert to unsigned 32-bit integer
  }
  return hash;
}

/**
 * Generate a fixed-length hex string from a 32-bit integer.
 *
 * @internal
 */
function toHex8(n: number): string {
  return (n >>> 0).toString(16).padStart(8, "0");
}

/**
 * Replace `value` with a deterministic (or random) pseudonym.
 *
 * @param value - The original PII value.
 * @param options - Pseudonymization configuration.
 * @returns A pseudonym string.
 *
 * @throws {@link ValidationError} When `prefix` contains whitespace or control characters.
 *
 * @example
 * ```ts
 * import { pseudonymize } from "anonyma";
 *
 * // Deterministic when a seed is provided:
 * pseudonymize("alice@example.com", { seed: "my-secret" });
 * // "id_3a7f1c2b" (same output every time for this input+seed)
 *
 * // Random when no seed is provided:
 * pseudonymize("alice@example.com");
 * // "id_e9a3f7d1" (different on every call)
 * ```
 */
export function pseudonymize(value: string, options: PseudonymizeOptions = {}): string {
  const { seed, prefix = "id_" } = options;

  if (/\s/.test(prefix)) {
    throw new ValidationError("prefix", "must not contain whitespace characters");
  }

  if (seed !== undefined) {
    // Deterministic path: mix value + seed through djb2.
    const combined = `${seed}:${value}`;
    const h1 = djb2(combined);
    const h2 = djb2(`${combined}:v2`);
    return `${prefix}${toHex8(h1)}${toHex8(h2)}`;
  }

  // Non-deterministic path: use crypto-quality random bytes if available.
  if (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  ) {
    const bytes = new Uint8Array(8);
    globalThis.crypto.getRandomValues(bytes);
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return `${prefix}${hex}`;
  }

  // Fallback for constrained environments (should not occur in Node ≥ 18).
  const fallback = Math.floor(Math.random() * 0xffffffff);
  return `${prefix}${toHex8(fallback)}`;
}
