/**
 * @module detectors/vin
 * @description Detector for Vehicle Identification Numbers (VIN).
 *
 * VINs are 17 characters per ISO 3779. The 9th character is a check digit
 * validated using transliteration and a mod-11 algorithm. Characters I, O, Q
 * are excluded from valid VINs.
 *
 * Confidence: 0.95 when checksum passes, 0.70 for format-only match.
 */

import type { PiiMatch } from "../types.js";
import { vinChecksum } from "../validators.js";

/**
 * VIN candidates: 17 chars from valid VIN alphabet (A-H, J-N, P, R-Z, 0-9).
 * @internal
 */
const VIN_PATTERN = /\b[A-HJ-NPR-Z0-9]{17}\b/gi;

/**
 * Detect Vehicle Identification Numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "vin"`.
 */
export function detectVin(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const re = new RegExp(VIN_PATTERN.source, "gi");
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    const upper = m[0].toUpperCase();
    const valid = vinChecksum(upper);
    if (valid) {
      matches.push({
        category: "vin",
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence: 0.95,
      });
    }
  }

  return matches;
}

/**
 * Aggressive variant of {@link detectVin}.
 * Also reports format-valid VINs that fail the checksum (e.g. non-North-American
 * vehicles where the check digit is not enforced).
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "vin"`.
 */
export function detectVinAggressive(text: string): PiiMatch[] {
  const strict = detectVin(text);
  const strictRanges = new Set(strict.map((m) => `${String(m.start)}-${String(m.end)}`));

  const matches: PiiMatch[] = [...strict];
  const re = new RegExp(VIN_PATTERN.source, "gi");
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    const key = `${String(m.index)}-${String(m.index + m[0].length)}`;
    if (!strictRanges.has(key)) {
      matches.push({
        category: "vin",
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence: 0.70,
      });
    }
  }

  return matches;
}
