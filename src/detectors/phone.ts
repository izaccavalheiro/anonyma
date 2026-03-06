/**
 * @module detectors/phone
 * @description Detector for phone numbers (international and North American formats).
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches common phone number formats including:
 * - E.164: +14155552671
 * - North American: (415) 555-2671, 415-555-2671, 415.555.2671
 * - International with country code: +44 20 7946 0958
 *
 * @internal
 */
const PHONE_PATTERN =
  /(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)|(?:\+(?:[0-9] ?){6,14}[0-9])(?!\d)/g;

/**
 * Aggressive addition: catches 7-digit local number formats such as `555-1234`.
 * These are valid local phone numbers but have higher false-positive risk.
 *
 * @internal
 */
const PHONE_SEVEN_DIGIT_PATTERN = /\b\d{3}[-.\s]\d{4}\b/g;

/**
 * Detect phone numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "phone"`.
 *
 * @example
 * ```ts
 * import { detectPhone } from "anonyma/detectors";
 *
 * detectPhone("Call me at +1 (555) 867-5309.");
 * // [{ category: "phone", value: "+1 (555) 867-5309", start: 11, end: 28, confidence: 0.9 }]
 * ```
 */
export function detectPhone(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(PHONE_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    const value = match[0].trim();
    // PHONE_PATTERN's minimum match always contains ≥7 digits; this guard is a safety net.
    /* v8 ignore next */
    if (value.replace(/\D/g, "").length < 7) continue; // Too short to be a real number
    matches.push({
      category: "phone",
      value,
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.9,
    });
  }

  return matches;
}

/**
 * Aggressive variant of {@link detectPhone}.
 *
 * In addition to standard formats, also catches 7-digit local numbers such as
 * `555-1234`. Confidence is `0.7` for 7-digit matches due to higher false-positive risk.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "phone"`.
 *
 * @example
 * ```ts
 * import { detectPhoneAggressive } from "anonyma/detectors";
 *
 * detectPhoneAggressive("Call 555-1234 for info.");
 * // [{ category: "phone", value: "555-1234", confidence: 0.7, ... }]
 * ```
 */
export function detectPhoneAggressive(text: string): PiiMatch[] {
  const standard = detectPhone(text);
  const standardRanges = standard.map((m) => [m.start, m.end] as [number, number]);

  const extra: PiiMatch[] = [];
  const sevenDigit = new RegExp(PHONE_SEVEN_DIGIT_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = sevenDigit.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    const overlaps = standardRanges.some(([s, e]) => start < e && end > s);
    if (!overlaps) {
      extra.push({
        category: "phone",
        value: match[0],
        start,
        end,
        confidence: 0.7,
      });
    }
  }

  return [...standard, ...extra];
}
