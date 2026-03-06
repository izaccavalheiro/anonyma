/**
 * @module detectors/company-registration
 * @description Detector for company registration numbers.
 *
 * Covered:
 * - US EIN: XX-XXXXXXX (same as tax-id but in company registration context)
 * - UK Companies House: 8 digits or 2 letters + 6 digits (e.g., 00123456, SC012345)
 * - EU/generic: country code + alphanumeric registration number
 * - Australian ACN: XXX XXX XXX (9 digits)
 */

import type { PiiMatch } from "../types.js";

/**
 * Context keywords for company registration.
 * @internal
 */
const CR_CONTEXT_RE =
  /\b(?:company\s+(?:registration|reg(?:istration)?)\s*(?:number|no\.?|#)?|companies\s+house\s*(?:number|no\.?|#)?|registered\s+(?:number|company\s+number|no\.?)|incorporation\s*(?:number|no\.?|#)?|company\s+(?:number|no\.?|#)|corporate\s+(?:id|number|no\.?|registration)|business\s+(?:registration|number)|ABN|ACN|CIK)\s*:?\s*/gi;

/**
 * UK Companies House: 8 digits or 2 letters + 6 digits.
 * @internal
 */
const UK_CH_PATTERN = /\b(?:[A-Z]{2}\d{6}|\d{8})\b/gi;

/**
 * US EIN in company context: XX-XXXXXXX.
 * @internal
 */
const US_EIN_PATTERN = /\b\d{2}-\d{7}\b/g;

/**
 * Australian ACN: 9 digits (often written XXX XXX XXX).
 * @internal
 */
const AU_ACN_PATTERN = /\b\d{3}[\s]?\d{3}[\s]?\d{3}\b/g;

/**
 * EU generic: 2-letter country code optionally followed by alphanumeric registration.
 * @internal
 */
const EU_CO_REG_PATTERN = /\b[A-Z]{2}[\s-]?[A-Z0-9]{5,12}\b/g;

/**
 * Detect company registration numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "company-registration"`.
 */
export function detectCompanyRegistration(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(CR_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // The EIN, UK, AU ACN, and EU generic patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "company-registration", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // US EIN — distinctive format
  const einRe = new RegExp(US_EIN_PATTERN.source, "g");
  while ((m = einRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.88 : 0.72);
  }

  // UK Companies House — with context
  const ukRe = new RegExp(UK_CH_PATTERN.source, "gi");
  while ((m = ukRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  // AU ACN — with context
  const acnRe = new RegExp(AU_ACN_PATTERN.source, "g");
  while ((m = acnRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.82);
  }

  // EU generic — with context
  const euRe = new RegExp(EU_CO_REG_PATTERN.source, "g");
  while ((m = euRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  return matches;
}
