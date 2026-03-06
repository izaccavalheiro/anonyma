/**
 * @module detectors/drivers-license
 * @description Detector for driver's license numbers (US, UK DVLA, EU generic).
 *
 * Detection strongly depends on context keywords ("driver's license", "dl#", etc.)
 * to reduce false positives — raw number patterns are too generic.
 *
 * Supported:
 * - US: state-specific patterns (generalised as alphanumeric 5-15 chars)
 * - UK DVLA: SURNAME(5) + DOB(6) + GENDER(1) + NAME_INITIALS(2) + CHECK(2)
 * - EU generic: alphanumeric 8-15 chars after context keyword
 */

import type { PiiMatch } from "../types.js";

/**
 * Context keyword pattern for driver's licenses.
 * @internal
 */
const DL_CONTEXT_PATTERN =
  /\b(?:driver(?:'?s)?\s+licen[cs]e|driving\s+licen[cs]e|DL\s*#?|D\.?L\.?(?:\s*#)?|licen[cs]e\s+(?:no|number|#))\s*:?\s*/gi;

/**
 * UK DVLA format: SURNAME(1-5 uppercase, padded with 9) + 6-digit DOB +
 * gender-indicator digit + 2 name chars + 2 check chars.
 * Example: MORGA753116SM9IJ
 * @internal
 */
const UK_DVLA_PATTERN = /\b[A-Z9]{5}\d{6}[02-9]\d[A-Z]{2}\w{2}\b/g;

/**
 * Generic alphanumeric DL number (used with context requirement).
 * @internal
 */
const GENERIC_DL_PATTERN = /\b[A-Z0-9]{5,15}\b/g;

/**
 * Detect driver's license numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "drivers-license"`.
 */
export function detectDriversLicense(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  // Find context keyword end positions
  const contextPositions: number[] = [];
  const ctxRe = new RegExp(DL_CONTEXT_PATTERN.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // License patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "drivers-license", value, start, end, confidence });
  }

  // UK DVLA — no context needed, format is distinctive
  const ukRe = new RegExp(UK_DVLA_PATTERN.source, "g");
  let m: RegExpExecArray | null;
  while ((m = ukRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  // Generic pattern — only report when preceded by context keyword
  const genericRe = new RegExp(GENERIC_DL_PATTERN.source, "g");
  while ((m = genericRe.exec(text)) !== null) {
    const match = m;
    const hasContext = contextPositions.some(
      (pos) => pos <= match.index && match.index - pos <= 20,
    );
    if (hasContext) {
      push(match[0], match.index, match.index + match[0].length, 0.85);
    }
  }

  return matches;
}
