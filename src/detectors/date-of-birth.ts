/**
 * @module detectors/date-of-birth
 * @description Detector for date-of-birth patterns in common formats.
 *
 * Supported formats:
 * - ISO 8601:         1990-01-15
 * - US short:         01/15/1990, 01-15-1990
 * - European short:   15/01/1990, 15.01.1990
 * - Long-form:        January 15, 1990 / 15 January 1990
 */

import type { PiiMatch } from "../types.js";

/** @internal */
const MONTH_NAMES =
  "(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";

/** ISO 8601: 1990-01-15 */
const ISO_PATTERN = /\b(19|20)\d{2}[- /](0[1-9]|1[0-2])[- /](0[1-9]|[12]\d|3[01])\b/g;

/** US: MM/DD/YYYY or MM-DD-YYYY */
const US_PATTERN =
  /\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b/g;

/** European: DD/MM/YYYY or DD.MM.YYYY */
const EU_PATTERN =
  /\b(0[1-9]|[12]\d|3[01])[/.](0[1-9]|1[0-2])[/.](19|20)\d{2}\b/g;

/** Long-form: January 15, 1990 */
const LONG_US_PATTERN = new RegExp(
  `\\b${MONTH_NAMES}\\s+(0?[1-9]|[12]\\d|3[01]),?\\s+(19|20)\\d{2}\\b`,
  "g",
);

/** Long-form: 15 January 1990 */
const LONG_EU_PATTERN = new RegExp(
  `\\b(0?[1-9]|[12]\\d|3[01])\\s+${MONTH_NAMES}\\s+(19|20)\\d{2}\\b`,
  "g",
);

/**
 * Run a single pattern against `text` and collect matches.
 *
 * @internal
 */
function collect(text: string, source: string, confidence: number): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "date-of-birth",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence,
    });
  }

  return matches;
}

/**
 * Detect date-of-birth patterns in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "date-of-birth"`.
 *
 * @example
 * ```ts
 * import { detectDateOfBirth } from "anonyma/detectors";
 *
 * detectDateOfBirth("DOB: 1990-04-15");
 * // [{ category: "date-of-birth", value: "1990-04-15", start: 5, end: 15, confidence: 0.85 }]
 * ```
 */
export function detectDateOfBirth(text: string): PiiMatch[] {
  const seen = new Set<number>();
  const all: PiiMatch[] = [];

  const candidates = [
    ...collect(text, ISO_PATTERN.source, 0.85),
    ...collect(text, US_PATTERN.source, 0.8),
    ...collect(text, EU_PATTERN.source, 0.78),
    ...collect(text, LONG_US_PATTERN.source, 0.88),
    ...collect(text, LONG_EU_PATTERN.source, 0.88),
  ];

  // De-duplicate overlapping matches, keeping the highest-confidence one.
  const sorted = [...candidates].sort((a, b) => b.confidence - a.confidence);

  for (const match of sorted) {
    let overlaps = false;
    for (const pos of seen) {
      if (match.start < pos) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) {
      for (let i = match.start; i < match.end; i++) seen.add(i);
      all.push(match);
    }
  }

  return all.sort((a, b) => a.start - b.start);
}
