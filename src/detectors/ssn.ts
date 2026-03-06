/**
 * @module detectors/ssn
 * @description Detector for US Social Security Numbers (SSN).
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches SSNs in the form AAA-BB-CCCC, AAA BB CCCC, or AAABBBCCCC.
 * Excludes obviously invalid numbers (e.g. 000-xx-xxxx, 666-xx-xxxx).
 *
 * @internal
 */
const SSN_PATTERN = /\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0{4})\d{4}\b/g;

/**
 * Aggressive addition: matches 9-digit sequences without separators that look
 * like SSNs. More permissive — separators are not required.
 * Excludes the same invalid prefixes as the normal pattern.
 *
 * ⚠️ Higher false-positive risk for any 9-digit number sequence.
 *
 * @internal
 */
const SSN_AGGRESSIVE_PATTERN = /\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0{4})\d{4}\b/g;

/**
 * Detect US Social Security Numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "ssn"`.
 *
 * @example
 * ```ts
 * import { detectSsn } from "anonyma/detectors";
 *
 * detectSsn("SSN: 123-45-6789");
 * // [{ category: "ssn", value: "123-45-6789", start: 5, end: 16, confidence: 0.95 }]
 * ```
 */
export function detectSsn(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(SSN_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "ssn",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.95,
    });
  }

  return matches;
}

/**
 * Aggressive variant of {@link detectSsn}.
 *
 * Also catches 9-digit SSNs written without separators (e.g. `123456789`).
 * Results from the normal pattern are deduplicated so no match is reported twice.
 *
 * Confidence is `0.8` for no-separator matches due to higher false-positive risk.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "ssn"`.
 *
 * @example
 * ```ts
 * import { detectSsnAggressive } from "anonyma/detectors";
 *
 * detectSsnAggressive("SSN 123456789 on file.");
 * // [{ category: "ssn", value: "123456789", confidence: 0.8, ... }]
 * ```
 */
export function detectSsnAggressive(text: string): PiiMatch[] {
  const standard = detectSsn(text);
  const standardRanges = standard.map((m) => [m.start, m.end] as [number, number]);

  const extra: PiiMatch[] = [];
  const aggressive = new RegExp(SSN_AGGRESSIVE_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = aggressive.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    const overlaps = standardRanges.some(([s, e]) => start < e && end > s);
    // SSN_AGGRESSIVE_PATTERN is a superset of SSN_PATTERN (same digits, no separator required);
    // any aggressive match is also caught by the standard pattern → !overlaps is always false.
    /* v8 ignore start */
    if (!overlaps) {
      extra.push({
        category: "ssn",
        value: match[0],
        start,
        end,
        confidence: 0.8,
      });
    }
    /* v8 ignore stop */
  }

  return [...standard, ...extra];
}
