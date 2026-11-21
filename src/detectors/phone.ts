/**
 * @module detectors/phone
 * @description Detector for phone numbers: international, North American, and the national
 * formats of Brazil, France, the United Kingdom, Spain, Italy and the German-speaking countries.
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches common phone number formats including:
 * - E.164: +14155552671
 * - North American: (415) 555-2671, 415-555-2671, 415.555.2671
 * - International with country code: +44 20 7946 0958, +55 (11) 91234-5678
 *
 * Up to two separators (space, dot, hyphen or parenthesis) may stand between
 * the digits of an international number.
 *
 * @internal
 */
const PHONE_PATTERN =
  /(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)|(?:\+(?:\d[ .\-()]{0,2}){6,14}\d)(?!\d)/g;

/**
 * National formats without a country code, each with its confidence. They
 * require the grouping each country writes its numbers in, so that a bare run
 * of digits is not taken for a phone number, and none may stop where a
 * separator and another digit follow: a longer number would be cut short.
 *
 * @internal
 */
const NATIONAL_PATTERNS: readonly { readonly pattern: RegExp; readonly confidence: number }[] = [
  // Brazil: (11) 91234-5678, (21) 3456-7890 — area code in parentheses.
  {
    pattern: /(?<![\d+])\(0?[1-9]{2}\)\s?(?:9\s?\d{4}|[2-5]\d{3})[\s.-]?\d{4}(?![ ./-]?\d)/g,
    confidence: 0.88,
  },
  // Brazil: 11 91234-5678, 021 3456 7890 — area code, then the number in two groups.
  {
    pattern: /(?<![\d+])0?[1-9]{2}[\s.]?(?:9\s?\d{4}|[2-5]\d{3})[-\s]\d{4}(?![ ./-]?\d)/g,
    confidence: 0.82,
  },
  // France: 06 12 34 56 78, 01.23.45.67.89 — five pairs with the same separator.
  { pattern: /(?<![\d+])0[1-9]([\s.-])\d{2}(?:\1\d{2}){3}(?![ ./-]?\d)/g, confidence: 0.85 },
  // United Kingdom: 020 7946 0958, 0161 496 0000, 07700 900123.
  {
    pattern: /(?<![\d+])0(?:\d{2} \d{4} \d{4}|\d{3} \d{3} \d{4}|\d{4} \d{5,6})(?![ ./-]?\d)/g,
    confidence: 0.82,
  },
  // Spain: 612 34 56 78, 91 123 45 67.
  {
    pattern: /(?<![\d+])(?:[6-9]\d{2}(?: \d{2}){3}|9[1-8] \d{3}(?: \d{2}){2})(?![ ./-]?\d)/g,
    confidence: 0.8,
  },
  // Italy: 06 1234 5678, 02 1234 567.
  { pattern: /(?<![\d+])0\d{1,3} \d{3,4} \d{3,4}(?![ ./-]?\d)/g, confidence: 0.78 },
  // Germany, Austria, Switzerland: 030 12345678, 089/1234567, 0151-23456789.
  { pattern: /(?<![\d+])0[1-9]\d{1,4}[ /-]\d{5,8}(?![ ./-]?\d)/g, confidence: 0.76 },
];

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

  // A national number is reported unless a match found so far covers it.
  for (const { pattern: national, confidence } of NATIONAL_PATTERNS) {
    const found = new RegExp(national.source, "g");
    while ((match = found.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      if (matches.some((m) => m.start <= start && end <= m.end)) continue;
      matches.push({ category: "phone", value: match[0], start, end, confidence });
    }
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
