/**
 * @module detectors/passport
 * @description Detector for passport numbers across multiple countries.
 *
 * Supported formats:
 * - US: 1 letter + 8 digits (e.g. A12345678)
 * - UK: 9 digits
 * - EU (generic): 1-2 letters + 6-8 digits
 * - Canada: 2 letters + 6 digits (e.g. AB123456)
 * - Australia: 1 letter + 7 digits (e.g. N1234567)
 *
 * Context keywords ("passport", "passport number", "passport no") boost confidence.
 */

import type { PiiMatch } from "../types.js";

/**
 * Passport number patterns per country.
 * @internal
 */
const PASSPORT_PATTERNS: readonly { pattern: RegExp; confidence: number }[] = [
  // US: 1 letter + 8 digits
  { pattern: /\b[A-Z]\d{8}\b/g, confidence: 0.75 },
  // Canada: 2 letters + 6 digits
  { pattern: /\b[A-Z]{2}\d{6}\b/g, confidence: 0.75 },
  // Australia: 1 letter + 7 digits
  { pattern: /\b[A-Z]\d{7}\b/g, confidence: 0.73 },
  // UK: 9 digits (no letters)
  { pattern: /\b\d{9}\b/g, confidence: 0.60 }, // lower confidence — many false positives
  // EU generic: 1-2 letters + 5-8 digits
  { pattern: /\b[A-Z]{1,2}\d{5,8}\b/g, confidence: 0.70 },
];

/**
 * Context keywords that precede a passport number.
 * @internal
 */
const PASSPORT_CONTEXT_RE =
  /\b(?:passport(?:\s+(?:number|no\.?|#))?)\s*:?\s*/gi;

/**
 * Detect passport numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "passport"`.
 */
export function detectPassport(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const contextPositions: number[] = [];

  // Find context keyword positions
  const ctxRe = new RegExp(PASSPORT_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  const seen = new Set<string>();

  for (const { pattern, confidence } of PASSPORT_PATTERNS) {
    const re = new RegExp(pattern.source, "g");
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      const match = m;
      const key = `${String(match.index)}-${String(match.index + match[0].length)}`;
      if (seen.has(key)) continue;

      // Check if there's a context keyword within 30 chars before this match
      const hasContext = contextPositions.some(
        (pos) => pos <= match.index && match.index - pos <= 30,
      );

      const adjustedConfidence = hasContext ? Math.min(confidence + 0.15, 0.95) : confidence;

      // Skip low-confidence matches without context (avoid FP spam)
      if (adjustedConfidence < 0.70 && !hasContext) continue;

      seen.add(key);
      matches.push({
        category: "passport",
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        confidence: adjustedConfidence,
      });
    }
  }

  return matches;
}
