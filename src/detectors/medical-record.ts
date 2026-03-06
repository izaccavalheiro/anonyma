/**
 * @module detectors/medical-record
 * @description Detector for medical record numbers and healthcare provider identifiers.
 *
 * Covered:
 * - MRN (Medical Record Number): various alphanumeric formats with context keyword
 * - US NPI (National Provider Identifier): 10 digits, Luhn-valid, prefix 80840
 * - DEA registration numbers: 2 letters + 7 digits with checksum validation
 */

import type { PiiMatch } from "../types.js";
import { luhn, deaChecksum } from "../validators.js";

/**
 * Context keywords for medical record numbers.
 * @internal
 */
const MRN_CONTEXT_RE =
  /\b(?:MRN|medical\s+record\s+(?:number|no\.?|#)|patient\s+(?:id|number|no\.?|#)|chart\s+(?:number|no\.?|#))\s*:?\s*/gi;

/**
 * US NPI: 10 digits starting with 1 or 2. Must pass Luhn check when prefixed with 80840.
 * @internal
 */
const US_NPI_PATTERN = /\b[12]\d{9}\b/g;

/**
 * DEA registration number: registrant letter + alpha + 7 digits.
 * Valid registrant letters: A, B, C, D, E, F, G, H, J, K, L, M, N, P, R, S, T, U, X.
 * @internal
 */
const DEA_PATTERN = /\b[ABCDEFGHJKLMNPRSTUX][A-Z9]\d{7}\b/gi;

/**
 * Generic MRN pattern: alphanumeric 6-12 chars (requires context).
 * @internal
 */
const MRN_PATTERN = /\b[A-Z0-9]{6,12}\b/g;

/**
 * Detect medical record numbers, NPI numbers, and DEA numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "medical-record"`.
 */
export function detectMedicalRecord(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(MRN_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "medical-record", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // DEA numbers — distinctive + checksum
  const deaRe = new RegExp(DEA_PATTERN.source, "gi");
  while ((m = deaRe.exec(text)) !== null) {
    if (deaChecksum(m[0])) {
      push(m[0], m.index, m.index + m[0].length, 0.90);
    }
  }

  // US NPI — 10 digits Luhn check with 80840 prefix
  const npiRe = new RegExp(US_NPI_PATTERN.source, "g");
  while ((m = npiRe.exec(text)) !== null) {
    const withPrefix = "80840" + m[0];
    if (luhn(withPrefix)) {
      push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.88 : 0.75);
    }
  }

  // Generic MRN — requires context
  const mrnRe = new RegExp(MRN_PATTERN.source, "g");
  while ((m = mrnRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.85);
    }
  }

  return matches;
}
