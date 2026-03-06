/**
 * @module detectors/health-insurance
 * @description Detector for health insurance identifiers.
 *
 * Covered:
 * - US Medicare Beneficiary Identifier (MBI): alphanumeric 11 chars
 * - US Medicaid: state-specific formats (alphanumeric, context required)
 * - UK NHS numbers: 10 digits with mod-11 validation
 * - EU EHIC (European Health Insurance Card): country code + series + personal ID
 */

import type { PiiMatch } from "../types.js";
import { nhsMod11 } from "../validators.js";

/**
 * Context keywords for health insurance.
 * @internal
 */
const HI_CONTEXT_RE =
  /\b(?:health\s+insurance(?:\s+(?:number|id|no\.?|#|card))?|insurance\s+(?:number|id|no\.?|#|member\s+id)|member\s+(?:id|number|no\.?)|policy\s+(?:number|no\.?|#)|medicare|medicaid|NHS(?:\s+(?:number|no\.?|#))?|EHIC|beneficiary\s+(?:id|number))\s*:?\s*/gi;

/**
 * US Medicare Beneficiary Identifier (MBI): format 1C2W-A00-AA00
 * Pattern: digit + capital-letter (non-SLOIBZ) + digit + capital-letter/digit pair (×2) + ...
 * Simplified: alphanumeric 11 chars with specific char-class restrictions.
 * @internal
 */
const US_MBI_PATTERN =
  /\b[1-9][AC-HJ-NP-RT-Y][0-9][AC-HJ-NP-RT-Y][AC-HJ-NP-RT-Y0-9]\d[AC-HJ-NP-RT-Y][AC-HJ-NP-RT-Y0-9]{2}\d{2}\b/gi;

/**
 * UK NHS number: 10 digits (validated with mod-11).
 * @internal
 */
const UK_NHS_PATTERN = /\b\d{3}[\s-]\d{3}[\s-]\d{4}\b|\b\d{10}\b/g;

/**
 * EU EHIC number: country code + 3-digit institution + 7-digit personal + 8-digit serial
 * (simplified — per-country formats vary significantly)
 * @internal
 */
const EU_EHIC_PATTERN =
  /\b[A-Z]{2}\d{6,10}\b/g;

/**
 * Generic insurance member ID with context.
 * @internal
 */
const GENERIC_MEMBER_ID = /\b[A-Z0-9]{8,14}\b/g;

/**
 * Detect health insurance identifiers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "health-insurance"`.
 */
export function detectHealthInsurance(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(HI_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 40);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "health-insurance", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // US MBI — distinctive format
  const mbiRe = new RegExp(US_MBI_PATTERN.source, "gi");
  while ((m = mbiRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.90 : 0.80);
  }

  // UK NHS — with mod-11 validation
  const nhsRe = new RegExp(UK_NHS_PATTERN.source, "g");
  while ((m = nhsRe.exec(text)) !== null) {
    if (nhsMod11(m[0])) {
      push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.92 : 0.82);
    }
  }

  // EU EHIC — with context
  const ehicRe = new RegExp(EU_EHIC_PATTERN.source, "g");
  while ((m = ehicRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.78);
    }
  }

  // Generic member ID — requires context
  const genericRe = new RegExp(GENERIC_MEMBER_ID.source, "g");
  while ((m = genericRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.75);
    }
  }

  return matches;
}
