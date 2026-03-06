/**
 * @module strategies/mask
 * @description The `mask` anonymization strategy.
 */

import { ValidationError } from "../errors.js";
import type { MaskOptions } from "../types.js";

/**
 * Replace interior characters of `value` with a mask character, optionally
 * keeping a number of leading and/or trailing characters visible.
 *
 * The function is deterministic and pure — given the same inputs it always
 * produces the same output.
 *
 * @param value - The string to mask.
 * @param options - Masking configuration.
 * @returns The masked string.
 *
 * @throws {@link ValidationError} When `keepLeading` or `keepTrailing` is negative.
 * @throws {@link ValidationError} When `maskChar` is not exactly one character.
 *
 * @example
 * ```ts
 * import { mask } from "anonyma";
 *
 * mask("john.doe@example.com");
 * // "********************"
 *
 * mask("john.doe@example.com", { keepLeading: 1, keepTrailing: 4 });
 * // "j***************m"  (keeps "j" and ".com")
 *
 * mask("+1 (555) 867-5309", { keepLeading: 0, keepTrailing: 4 });
 * // "*************5309"
 * ```
 */
export function mask(value: string, options: MaskOptions = {}): string {
  const { maskChar = "*", keepLeading = 0, keepTrailing = 0, preserveFormat = false } = options;

  if (maskChar.length !== 1) {
    throw new ValidationError("maskChar", "must be exactly one character");
  }
  if (!Number.isInteger(keepLeading) || keepLeading < 0) {
    throw new ValidationError("keepLeading", "must be a non-negative integer");
  }
  if (!Number.isInteger(keepTrailing) || keepTrailing < 0) {
    throw new ValidationError("keepTrailing", "must be a non-negative integer");
  }

  if (value.length === 0) return value;

  // --- Format-preserving mode ---
  // Alpha → 'X', digit → '0', separators/punctuation preserved.
  // `keepLeading` / `keepTrailing` still apply (character counts, ignoring separators).
  if (preserveFormat) {
    const totalVisible = keepLeading + keepTrailing;
    if (totalVisible >= value.length) {
      return value; // everything is visible, nothing to mask
    }

    const chars = value.split("");
    // Determine the interior slice to mask (skip leading / trailing).
    const interior = chars.slice(keepLeading, value.length - (keepTrailing > 0 ? keepTrailing : 0));
    const maskedInterior = interior.map((ch) => {
      if (/[a-zA-Z]/.test(ch)) return ch === ch.toUpperCase() ? "X" : "x";
      if (/\d/.test(ch)) return "0";
      return ch; // separator / punctuation — preserved
    });

    return (
      chars.slice(0, keepLeading).join("") +
      maskedInterior.join("") +
      (keepTrailing > 0 ? chars.slice(-keepTrailing).join("") : "")
    );
  }

  // --- Standard mode ---
  // When the visible region covers or exceeds the whole string, just mask everything.
  const totalVisible = keepLeading + keepTrailing;
  if (totalVisible >= value.length) {
    return maskChar.repeat(value.length);
  }

  const leading = value.slice(0, keepLeading);
  const trailing = keepTrailing > 0 ? value.slice(-keepTrailing) : "";
  const maskedLength = value.length - keepLeading - keepTrailing;

  return leading + maskChar.repeat(maskedLength) + trailing;
}
