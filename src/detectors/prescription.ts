/**
 * @module detectors/prescription
 * @description Detector for prescription and pharmaceutical identifiers.
 *
 * Covered:
 * - DEA registration numbers (with checksum)
 * - NDC (National Drug Code): 10-11 digit codes in various formats
 * - Rx (prescription) numbers: numeric identifiers with context keywords
 */

import type { PiiMatch } from "../types.js";
import { deaChecksum } from "../validators.js";

/**
 * Context keywords for prescriptions.
 * @internal
 */
const RX_CONTEXT_RE =
  /\b(?:Rx\s*(?:number|no\.?|#)?|prescription\s*(?:number|no\.?|#)?|prescription\s+id|NDC|drug\s+code|DEA\s*(?:number|no\.?|#)?)\s*:?\s*/gi;

/**
 * DEA number: registrant letter + alpha + 7 digits.
 * @internal
 */
const DEA_PATTERN = /\b[ABCDEFGHJKLMNPRSTUX][A-Z9]\d{7}\b/gi;

/**
 * NDC (National Drug Code): 10-11 digits in formats:
 * - 4-4-2 (labeler-product-package)
 * - 5-3-2
 * - 5-4-1
 * - 5-4-2 (11-digit NDC)
 * @internal
 */
const NDC_PATTERN =
  /\b\d{4}-\d{4}-\d{2}\b|\b\d{5}-\d{3}-\d{2}\b|\b\d{5}-\d{4}-\d{1}\b|\b\d{5}-\d{4}-\d{2}\b/g;

/**
 * Rx number: 4-12 digits with context keyword.
 * @internal
 */
const RX_NUMBER_PATTERN = /\b\d{4,12}\b/g;

/**
 * Detect prescription identifiers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "prescription"`.
 */
export function detectPrescription(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(RX_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // Prescription patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "prescription", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // DEA numbers — validated with checksum
  const deaRe = new RegExp(DEA_PATTERN.source, "gi");
  while ((m = deaRe.exec(text)) !== null) {
    if (deaChecksum(m[0])) {
      push(m[0], m.index, m.index + m[0].length, 0.90);
    }
  }

  // NDC codes — distinctive format
  const ndcRe = new RegExp(NDC_PATTERN.source, "g");
  while ((m = ndcRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.90 : 0.78);
  }

  // Rx numbers — require context
  const rxRe = new RegExp(RX_NUMBER_PATTERN.source, "g");
  while ((m = rxRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.82);
    }
  }

  return matches;
}
