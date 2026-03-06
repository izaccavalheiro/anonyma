/**
 * @module detectors/iban
 * @description Detector for International Bank Account Numbers (IBAN).
 *
 * IBAN validation follows ISO 13616:
 * 1. Match the basic format (2-letter country code + 2-digit check digits + BBAN).
 * 2. Validate via MOD-97 check as per the ISO standard.
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches potential IBAN strings (basic format, optional space grouping).
 *
 * @internal
 */
const IBAN_PATTERN = /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){1,7}[A-Z0-9]{1,4}\b/g;

/**
 * Validate an IBAN string using the MOD-97 algorithm.
 *
 * @param iban - Raw IBAN string (may contain spaces).
 * @internal
 */
function isValidIban(iban: string): boolean {
  const cleaned = iban.replace(/\s/g, "").toUpperCase();

  if (cleaned.length < 5 || cleaned.length > 34) return false;

  // Move the first 4 characters to the end.
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);

  // Replace each letter with its numeric value (A=10, B=11, ..., Z=35).
  const numeric = rearranged
    .split("")
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code >= 65 && code <= 90 ? String(code - 55) : ch;
    })
    .join("");

  // Compute MOD 97 using BigInt to handle large numbers safely.
  return BigInt(numeric) % 97n === 1n;
}

/**
 * Detect IBAN (International Bank Account Number) strings in `text`.
 * Only matches that pass the MOD-97 check are included.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "iban"`.
 *
 * @example
 * ```ts
 * import { detectIban } from "anonyma/detectors";
 *
 * detectIban("IBAN: GB82 WEST 1234 5698 7654 32");
 * // [{ category: "iban", value: "GB82 WEST 1234 5698 7654 32", start: 6, end: 33, confidence: 0.99 }]
 * ```
 */
export function detectIban(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(IBAN_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    const value = match[0];
    if (!isValidIban(value)) continue;

    matches.push({
      category: "iban",
      value,
      start: match.index,
      end: match.index + value.length,
      confidence: 0.99,
    });
  }

  return matches;
}
