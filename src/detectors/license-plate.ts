/**
 * @module detectors/license-plate
 * @description Detector for vehicle license/number plates.
 *
 * Covered formats:
 * - US: generic state format (2-8 alphanumeric, context required)
 * - UK: current format (AB12 ABC) and older (A123 BCD)
 * - EU generic: 1-2 letters + 2-4 digits + 1-3 letters
 *
 * Context keywords strongly boost reliability.
 */

import type { PiiMatch } from "../types.js";

/**
 * Context keywords for license plates.
 * @internal
 */
const LP_CONTEXT_RE =
  /\b(?:licen[sc]e\s+plate|number\s+plate|registration\s+(?:plate|number)|reg(?:istration)?\s*(?:no\.?|#|:)|plate(?:\s+(?:number|no\.?))?)\s*:?\s*/gi;

/**
 * UK current format: AB12 ABC or AB12ABC (letters-digits-letters).
 * @internal
 */
const UK_CURRENT_LP_PATTERN = /\b[A-Z]{2}\d{2}[\s]?[A-Z]{3}\b/gi;

/**
 * UK older prefix format: A123 BCD or A123BCD
 * @internal
 */
const UK_OLD_LP_PATTERN = /\b[A-Z]\d{1,4}[\s]?[A-Z]{3}\b/gi;

/**
 * EU generic: 1-2 letters + 1-4 digits + 1-3 letters (typically on black/white plates)
 * @internal
 */
const EU_LP_PATTERN = /\b[A-Z]{1,2}[\s-]?\d{1,4}[\s-]?[A-Z]{1,3}\b/gi;

/**
 * US generic: state plates are typically 2-8 alphanumeric chars.
 * Too generic to report without context.
 * @internal
 */
const US_LP_PATTERN = /\b[A-Z0-9]{2,8}\b/g;

/**
 * Detect vehicle license plate numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "license-plate"`.
 */
export function detectLicensePlate(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(LP_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 20);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "license-plate", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // UK current format — distinctive
  const ukCurrentRe = new RegExp(UK_CURRENT_LP_PATTERN.source, "gi");
  while ((m = ukCurrentRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.90 : 0.78);
  }

  // UK older format
  const ukOldRe = new RegExp(UK_OLD_LP_PATTERN.source, "gi");
  while ((m = ukOldRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.85 : 0.70);
  }

  // EU generic — context recommended
  const euRe = new RegExp(EU_LP_PATTERN.source, "gi");
  while ((m = euRe.exec(text)) !== null) {
    const conf = hasContextAt(m.index) ? 0.82 : 0.65;
    if (conf >= 0.70) push(m[0], m.index, m.index + m[0].length, conf);
  }

  // US generic — requires context
  const usRe = new RegExp(US_LP_PATTERN.source, "g");
  while ((m = usRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.80);
  }

  return matches;
}
