/**
 * @module detectors/bank-account
 * @description Detector for bank account numbers and routing information.
 *
 * Covered formats:
 * - US: ABA routing number (9 digits with specific prefix ranges) + account numbers
 * - UK: Sort code (XX-XX-XX) + 8-digit account number
 * - SWIFT/BIC codes (8 or 11 chars)
 *
 * Context keywords are essential for reducing false positives.
 */

import type { PiiMatch } from "../types.js";

/**
 * Context keywords for bank account information.
 * @internal
 */
const BANK_CONTEXT_RE =
  /\b(?:routing\s+(?:number|no\.?|#)|sort\s+code|account\s+(?:number|no\.?|#)|bank\s+account|IBAN|BIC|SWIFT|ABA)\s*:?\s*/gi;

/**
 * US ABA routing number: 9 digits, first two digits must be 01-12, 21-32, 61-72, or 80.
 * @internal
 */
const US_ABA_ROUTING_PATTERN =
  /\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b/g;

/**
 * UK sort code: XX-XX-XX
 * @internal
 */
const UK_SORT_CODE_PATTERN = /\b\d{2}-\d{2}-\d{2}\b/g;

/**
 * SWIFT/BIC code: 8 or 11 chars (4 bank + 2 country + 2 location + optional 3 branch)
 * @internal
 */
const SWIFT_BIC_PATTERN =
  /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;

/**
 * Generic bank account number: 7-18 digits (only with context)
 * @internal
 */
const GENERIC_ACCOUNT_PATTERN = /\b\d{7,18}\b/g;

/**
 * Detect bank account numbers and related identifiers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "bank-account"`.
 */
export function detectBankAccount(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(BANK_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContext(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "bank-account", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // US ABA routing — only with context
  const abaRe = new RegExp(US_ABA_ROUTING_PATTERN.source, "g");
  while ((m = abaRe.exec(text)) !== null) {
    if (hasContext(m.index)) push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  // UK sort code — distinctive format, no context needed
  const scRe = new RegExp(UK_SORT_CODE_PATTERN.source, "g");
  while ((m = scRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.80);
  }

  // SWIFT/BIC — distinctive, no context needed
  const swiftRe = new RegExp(SWIFT_BIC_PATTERN.source, "g");
  while ((m = swiftRe.exec(text)) !== null) {
    // Basic SWIFT validity: country code must be valid 2-letter ISO
    const countryCode = m[0].slice(4, 6);
    if (/^[A-Z]{2}$/.test(countryCode)) {
      push(m[0], m.index, m.index + m[0].length, 0.82);
    }
  }

  // Generic account number — only with context
  const genericRe = new RegExp(GENERIC_ACCOUNT_PATTERN.source, "g");
  while ((m = genericRe.exec(text)) !== null) {
    if (hasContext(m.index)) push(m[0], m.index, m.index + m[0].length, 0.80);
  }

  return matches;
}
