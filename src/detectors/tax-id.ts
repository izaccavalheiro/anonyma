/**
 * @module detectors/tax-id
 * @description Detector for tax identification numbers.
 *
 * Covered:
 * - US EIN: XX-XXXXXXX
 * - US ITIN: 9XX-XX-XXXX (where second group is 50-65, 70-88, 90-92, 94-99)
 * - UK UTR: 10 digits (Unique Taxpayer Reference)
 * - EU VAT numbers: country prefix + digits/letters
 * - Australia TFN: XXX XXX XXX (shared with national-id, context disambiguates)
 * - Australia ABN: 11 digits XX XXX XXX XXX
 */

import type { PiiMatch } from "../types.js";

/**
 * US EIN: XX-XXXXXXX (Employer Identification Number)
 * @internal
 */
const US_EIN_PATTERN = /\b\d{2}-\d{7}\b/g;

/**
 * US ITIN: 9XX-XX-XXXX (Individual Taxpayer ID, second group 50-65,70-88,90-92,94-99)
 * @internal
 */
const US_ITIN_PATTERN =
  /\b9\d{2}[\s-](?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|90|91|92|9[4-9])[\s-]\d{4}\b/g;

/**
 * UK UTR: 10 digits (Unique Taxpayer Reference). Requires context.
 * @internal
 */
const UK_UTR_PATTERN = /\b\d{10}\b/g;

/**
 * EU VAT prefixes + number patterns:
 * Each EU country has a specific format, but we use a general pattern + country code prefix.
 * @internal
 */
const EU_VAT_PATTERN =
  /\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[\s-]?[A-Z0-9]{8,12}\b/g;

/**
 * Australia ABN: XX XXX XXX XXX (11 digits)
 * @internal
 */
const AU_ABN_PATTERN = /\b\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3}\b/g;

/**
 * Tax ID context keywords.
 * @internal
 */
const TAX_CONTEXT_RE =
  /\b(?:tax(?:\s+(?:id(?:entification)?|number|no\.?|#|reference))?|T\.?I\.?N\.?|EIN|ITIN|UTR|VAT(?:\s+(?:number|no\.?|reg(?:istration)?|#))?|ABN|TFN)\s*:?\s*/gi;

/**
 * Detect tax identification numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "tax-id"`.
 */
export function detectTaxId(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(TAX_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContext(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // Tax-id patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "tax-id", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // US EIN: XX-XXXXXXX — distinctive format
  const einRe = new RegExp(US_EIN_PATTERN.source, "g");
  while ((m = einRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContext(m.index) ? 0.92 : 0.80);
  }

  // US ITIN — distinctive format
  const itinRe = new RegExp(US_ITIN_PATTERN.source, "g");
  while ((m = itinRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.90);
  }

  // EU VAT — distinctive format
  const vatRe = new RegExp(EU_VAT_PATTERN.source, "g");
  while ((m = vatRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContext(m.index) ? 0.90 : 0.78);
  }

  // AU ABN — distinctive format
  const abnRe = new RegExp(AU_ABN_PATTERN.source, "g");
  while ((m = abnRe.exec(text)) !== null) {
    if (hasContext(m.index)) push(m[0], m.index, m.index + m[0].length, 0.82);
  }

  // UK UTR — requires context (plain 10 digits too generic)
  const utrRe = new RegExp(UK_UTR_PATTERN.source, "g");
  while ((m = utrRe.exec(text)) !== null) {
    if (hasContext(m.index)) push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  return matches;
}
