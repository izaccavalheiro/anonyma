/**
 * @module detectors/address
 * @description Heuristic detector for physical street addresses (US, UK, EU formats).
 *
 * Detection combines:
 * - Common address context keywords ("address:", "lives at", "ship to", etc.)
 * - US street patterns: number + direction + street name + type
 * - UK postcode patterns
 * - PO Box patterns
 *
 * Confidence: 0.80 (heuristic — high false-negative rate for uncommon formats).
 */

import type { PiiMatch } from "../types.js";

/**
 * US-style street address: optional apt/suite, followed by city+state+zip or just zip context.
 * Pattern: number + optional direction + words + street type
 * @internal
 */
const US_STREET_PATTERN =
  /\b\d{1,5}\s+(?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)\.?\s+)?(?:[A-Z][a-z]+\s+){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Rd|Road|Ln|Lane|Ct|Court|Pl|Place|Cir|Circle|Way|Pkwy|Parkway|Hwy|Highway|Trl|Trail|Terr(?:ace)?|Terr)\.?(?:\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\s*\w+)?\b/gi;

/**
 * UK postcode: e.g. SW1A 2AA, EC1A 1BB, W1A 0AX
 * @internal
 */
const UK_POSTCODE_PATTERN =
  /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi;

/**
 * PO Box pattern.
 * @internal
 */
const PO_BOX_PATTERN =
  /\bP\.?O\.?\s+Box\s+\d+\b/gi;

/**
 * Context-keyword prefixed addresses.
 * @internal
 */
const ADDRESS_CONTEXT_PATTERN =
  /(?:address(?:ed to)?|lives at|located at|shipped? to|mailing address|billing address|residence|resides at|home address|headquartered at|office address)\s*:?\s*([^\n,]{10,80})/gi;

/**
 * Detect physical addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "address"`.
 */
export function detectAddress(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "address", value, start, end, confidence });
  }

  // US street addresses
  const usPattern = new RegExp(US_STREET_PATTERN.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = usPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.80);
  }

  // UK postcodes
  const ukPattern = new RegExp(UK_POSTCODE_PATTERN.source, "gi");
  while ((m = ukPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  // PO Boxes
  const poPattern = new RegExp(PO_BOX_PATTERN.source, "gi");
  while ((m = poPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  // Context-keyword addresses
  const ctxPattern = new RegExp(ADDRESS_CONTEXT_PATTERN.source, "gi");
  while ((m = ctxPattern.exec(text)) !== null) {
    // ADDRESS_CONTEXT_PATTERN always captures group 1; fallback to m[0] is never needed.
    /* v8 ignore next */
    const captured = (m[1] ?? m[0]).trim();
    const start = text.indexOf(captured, m.index);
    if (start !== -1) {
      push(captured, start, start + captured.length, 0.82);
    }
  }

  return matches;
}
