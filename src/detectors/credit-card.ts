/**
 * @module detectors/credit-card
 * @description Detector for credit/debit card numbers with Luhn algorithm validation.
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches 13–19 digit sequences that may be separated by spaces or hyphens,
 * matching the typical formatting of credit card numbers.
 *
 * @internal
 */
const CARD_PATTERN = /\b(?:\d[ -]?){13,19}\b/g;

/**
 * Aggressive addition: matches masked card forms like `****-****-****-1234` or
 * `**** **** **** 1234` where the first three groups are obscured.
 *
 * @internal
 */
const CARD_MASKED_PATTERN = /\*{4}[ -]?\*{4}[ -]?\*{4}[ -]?\d{4}\b/g;

/**
 * Luhn algorithm validator.
 * Returns `true` if `digits` passes the Luhn check.
 *
 * @param digits - String of digits only.
 * @internal
 */
function luhn(digits: string): boolean {
  let sum = 0;
  let isEven = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    // digits[i] is always defined because we control the loop bounds.
    /* v8 ignore next */
    let d = parseInt(digits[i] ?? "0", 10);

    if (isEven) {
      d *= 2;
      if (d > 9) d -= 9;
    }

    sum += d;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/**
 * Detect credit/debit card numbers in `text`.
 * Uses the Luhn algorithm to reject invalid sequences.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "credit-card"`.
 *
 * @example
 * ```ts
 * import { detectCreditCard } from "anonyma/detectors";
 *
 * detectCreditCard("Card: 4111 1111 1111 1111");
 * // [{ category: "credit-card", value: "4111 1111 1111 1111", start: 6, end: 25, confidence: 0.97 }]
 * ```
 */
export function detectCreditCard(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(CARD_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    const raw = match[0];
    const digitsOnly = raw.replace(/[ -]/g, "");
    // CARD_PATTERN enforces {13,19} digit groups; length will always be in [13, 19].
    /* v8 ignore next */
    if (digitsOnly.length < 13 || digitsOnly.length > 19) continue;
    if (!luhn(digitsOnly)) continue;

    matches.push({
      category: "credit-card",
      value: raw,
      start: match.index,
      end: match.index + raw.length,
      confidence: 0.97,
    });
  }

  return matches;
}

/**
 * Aggressive variant of {@link detectCreditCard}.
 *
 * In addition to Luhn-validated card numbers, also detects masked card formats
 * such as `****-****-****-1234`. Masked cards cannot be Luhn-validated, so
 * confidence is lower (`0.8`).
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "credit-card"`.
 *
 * @example
 * ```ts
 * import { detectCreditCardAggressive } from "anonyma/detectors";
 *
 * detectCreditCardAggressive("Card ending: ****-****-****-1234");
 * // [{ category: "credit-card", value: "****-****-****-1234", confidence: 0.8, ... }]
 * ```
 */
export function detectCreditCardAggressive(text: string): PiiMatch[] {
  const standard = detectCreditCard(text);
  const standardRanges = standard.map((m) => [m.start, m.end] as [number, number]);

  const extra: PiiMatch[] = [];
  const maskedPattern = new RegExp(CARD_MASKED_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = maskedPattern.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    const overlaps = standardRanges.some(([s, e]) => start < e && end > s);
    if (!overlaps) {
      extra.push({
        category: "credit-card",
        value: match[0],
        start,
        end,
        confidence: 0.8,
      });
    }
  }

  return [...standard, ...extra];
}

