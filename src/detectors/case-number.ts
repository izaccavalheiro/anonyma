/**
 * @module detectors/case-number
 * @description Detector for US federal/state court case numbers.
 *
 * US federal court case numbers follow the pattern:
 * - YEAR:COURT DIVISION - CASE_TYPE - NUMBER (e.g., 1:21-cv-00123)
 * - Or: YEAR-CASE_TYPE-NUMBER (e.g., 21-CR-0456)
 *
 * Requires context keywords to reduce false positives.
 */

import type { PiiMatch } from "../types.js";

/**
 * US Federal court case number: e.g., 1:21-cv-00123, 21-cv-00123
 * @internal
 */
const FEDERAL_CASE_PATTERN =
  /\b(?:\d:\s*)?\d{2}[\s-](?:cv|cr|civ|crim|mc|mj|po|br|ap|adv|bk)[\s-]\d{4,6}\b/gi;

/**
 * General legal case number with context.
 * @internal
 */
const GENERAL_CASE_PATTERN =
  /\b(?:[A-Z]{1,4}[-\s])?\d{2,4}[-/]\d{2,6}(?:[-/][A-Z0-9]{1,5})?\b/gi;

/**
 * Case number context keywords.
 * @internal
 */
const CASE_CONTEXT_RE =
  /\b(?:case(?:\s+(?:number|no\.?|#|id))?|docket(?:\s+(?:number|no\.?|#))?|civil\s+action|criminal\s+(?:case|no\.?|#)|court\s+(?:case|file(?:\s+no\.?)?)|matter\s+no\.?|file\s+(?:number|no\.?|#))\s*:?\s*/gi;

/**
 * Detect court case numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "case-number"`.
 */
export function detectCaseNumber(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(CASE_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    // The federal and general patterns never produce overlapping ranges in practice.
    /* v8 ignore next */
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "case-number", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // Federal court pattern — relatively distinctive
  const fedRe = new RegExp(FEDERAL_CASE_PATTERN.source, "gi");
  while ((m = fedRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, hasContextAt(m.index) ? 0.92 : 0.80);
  }

  // General pattern — requires context
  const generalRe = new RegExp(GENERAL_CASE_PATTERN.source, "gi");
  while ((m = generalRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  return matches;
}
