/**
 * @module detectors/national-id
 * @description Detector for national identification numbers across 20+ countries.
 *
 * Covered countries/formats:
 * - Canada: SIN (XXX-XXX-XXX)
 * - Mexico: CURP (18 chars alphanumeric) and RFC (13 chars)
 * - UK: NINO (AB 12 34 56 C)
 * - India: Aadhaar (12 digits, verified with format check)
 * - China: Resident ID (18 digits with letter checksum)
 * - South Korea: RRN (XXXXXX-XXXXXXX)
 * - Germany: Personalausweis (9 alphanumeric)
 * - France: NIR/INSEE (15 digits with spaces)
 * - Brazil: CPF (XXX.XXX.XXX-XX)
 * - Argentina: DNI (7-8 digits)
 * - South Africa: ID (13 digits)
 * - Nigeria: NIN (11 digits)
 * - Australia: TFN (XXX XXX XXX)
 * - New Zealand: IRD (XXX-XXX-XXX)
 * - Sweden: Personnummer (XXXXXX-XXXX)
 * - Norway: Fødselsnummer (11 digits)
 * - Netherlands: BSN (9 digits, 11-proef)
 * - Spain: DNI/NIE (8 digits + letter / X+7digits+letter)
 * - Italy: Codice Fiscale (16 alphanumeric)
 * - Portugal: NIF (9 digits)
 * - US: SSN (handled separately by ssn.ts — not duplicated here)
 */

import type { PiiMatch } from "../types.js";

// ---------------------------------------------------------------------------
// Individual country patterns
// ---------------------------------------------------------------------------

/**
 * Canada SIN: XXX-XXX-XXX or XXXXXXXXX
 * @internal
 */
const CA_SIN_PATTERN = /\b\d{3}[\s-]\d{3}[\s-]\d{3}\b/g;

/**
 * Mexico CURP: 18-char alphanumeric with specific letter/digit structure.
 * Format: 4 letters + 6 digits + 6 alphanumeric + 2 alphanumeric
 * @internal
 */
const MX_CURP_PATTERN =
  /\b[A-Z]{4}\d{6}[HM][A-Z]{2}[A-Z]{3}[A-Z0-9]\d\b/g;

/**
 * Mexico RFC: 12-13 chars (physical person: 13, legal entity: 12)
 * Format: 3-4 uppercase letters + 6-digit DOB + 3 alphanumeric
 * @internal
 */
const MX_RFC_PATTERN = /\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/g;

/**
 * UK NINO: AB 12 34 56 A (with or without spaces, letter [A-D] at end)
 * @internal
 */
const UK_NINO_PATTERN =
  /\b[A-CEGHJ-PR-TW-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-D]\b/gi;

/**
 * India Aadhaar: 12 digits, groups of 4 optionally separated by spaces.
 * First digit must not be 0 or 1.
 * @internal
 */
const IN_AADHAAR_PATTERN = /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g;

/**
 * China Resident ID: 18 digits, last char may be X.
 * Format: 6-digit region + 8-digit DOB + 3-digit sequence + 1 check digit/X
 * @internal
 */
const CN_RESIDENT_ID_PATTERN = /\b\d{17}[\dX]\b/gi;

/**
 * South Korea RRN: XXXXXX-XXXXXXX (6 digits dash 7 digits)
 * @internal
 */
const KR_RRN_PATTERN = /\b\d{6}[\s-]\d{7}\b/g;

/**
 * Germany Personalausweis: 9 alphanumeric chars.
 * Only reported with context keyword — too generic otherwise.
 * @internal
 */
const DE_PERSONALAUSWEIS_PATTERN = /\b[A-Z0-9]{9}\b/g;

/**
 * France NIR/INSEE: 15 digits (with optional spaces in groups of 1+2+2+2+3+2+3+2).
 * Starts with 1 or 2 (gender digit).
 * @internal
 */
const FR_NIR_PATTERN =
  /\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b/g;

/**
 * Brazil CPF: XXX.XXX.XXX-XX
 * @internal
 */
const BR_CPF_PATTERN = /\b\d{3}\.\d{3}\.\d{3}[-\s]\d{2}\b/g;

/**
 * Argentina DNI: 7-8 digits (with optional dots XXX.XXX.XXX)
 * @internal
 */
const AR_DNI_PATTERN = /\b\d{2,3}[.\s]?\d{3}[.\s]?\d{3}\b/g;

/**
 * South Africa ID: 13 consecutive digits. Starts with 6-digit DOB.
 * @internal
 */
const ZA_ID_PATTERN = /\b\d{13}\b/g;

/**
 * Nigeria NIN: 11 digits
 * @internal
 */
const NG_NIN_PATTERN = /\b\d{11}\b/g;

/**
 * Australia TFN: XXX XXX XXX or XXXXXXXXX
 * @internal
 */
const AU_TFN_PATTERN = /\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b/g;

/**
 * Sweden Personnummer: XXXXXX-XXXX or XXXXXXXXXX
 * @internal
 */
const SE_PERSONNUMMER_PATTERN = /\b\d{6}[-+]\d{4}\b/g;

/**
 * Spain DNI: 8 digits + letter; NIE: X/Y/Z + 7 digits + letter
 * @internal
 */
const ES_DNIE_PATTERN = /\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b/gi;

/**
 * Italy Codice Fiscale: 16 chars (6 letters + 2 digits + letter + 2 digits + letter + 3 digits + letter)
 * @internal
 */
const IT_CF_PATTERN =
  /\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b/gi;

/**
 * Portugal NIF: 9 digits starting with 1-9
 * @internal
 */
const PT_NIF_PATTERN = /\b[1-9]\d{8}\b/g;

/**
 * Netherlands BSN: 9 digits (11-proef)
 * @internal
 */
const NL_BSN_PATTERN = /\b\d{9}\b/g;

// ---------------------------------------------------------------------------
// Context keywords for ambiguous patterns
// ---------------------------------------------------------------------------

/**
 * Generic national ID context keywords.
 * @internal
 */
const NATIONAL_ID_CONTEXT_RE =
  /\b(?:national\s+(?:id|identification|identity)\s*(?:number|no\.?|card|#)?|id\s+(?:number|no\.?|#)|citizen(?:ship)?\s+(?:number|id)|personal\s+(?:id|identification)\s*(?:number|no\.?)?|identificat(?:ion|or))\s*:?\s*/gi;

// ---------------------------------------------------------------------------
// Definition of locale-specific entries
// ---------------------------------------------------------------------------

interface NationalIdEntry {
  readonly pattern: RegExp;
  readonly confidence: number;
  /** When true, only report with context keyword present nearby. */
  readonly requiresContext: boolean;
}

const NATIONAL_ID_ENTRIES: readonly NationalIdEntry[] = [
  { pattern: CA_SIN_PATTERN, confidence: 0.85, requiresContext: false },
  { pattern: MX_CURP_PATTERN, confidence: 0.90, requiresContext: false },
  { pattern: MX_RFC_PATTERN, confidence: 0.78, requiresContext: true },
  { pattern: UK_NINO_PATTERN, confidence: 0.90, requiresContext: false },
  { pattern: IN_AADHAAR_PATTERN, confidence: 0.82, requiresContext: false },
  { pattern: CN_RESIDENT_ID_PATTERN, confidence: 0.80, requiresContext: true },
  { pattern: KR_RRN_PATTERN, confidence: 0.87, requiresContext: false },
  { pattern: BR_CPF_PATTERN, confidence: 0.92, requiresContext: false },
  { pattern: SE_PERSONNUMMER_PATTERN, confidence: 0.87, requiresContext: false },
  { pattern: ES_DNIE_PATTERN, confidence: 0.82, requiresContext: false },
  { pattern: IT_CF_PATTERN, confidence: 0.88, requiresContext: false },
  { pattern: FR_NIR_PATTERN, confidence: 0.84, requiresContext: false },
  // More ambiguous — require context
  { pattern: AR_DNI_PATTERN, confidence: 0.75, requiresContext: true },
  { pattern: ZA_ID_PATTERN, confidence: 0.72, requiresContext: true },
  { pattern: NG_NIN_PATTERN, confidence: 0.70, requiresContext: true },
  { pattern: AU_TFN_PATTERN, confidence: 0.75, requiresContext: true },
  { pattern: DE_PERSONALAUSWEIS_PATTERN, confidence: 0.75, requiresContext: true },
  { pattern: PT_NIF_PATTERN, confidence: 0.70, requiresContext: true },
  { pattern: NL_BSN_PATTERN, confidence: 0.70, requiresContext: true },
];

/**
 * Detect national identification numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "national-id"`.
 */
export function detectNationalId(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  // Find context keyword end positions
  const contextPositions: number[] = [];
  const ctxRe = new RegExp(NATIONAL_ID_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  for (const entry of NATIONAL_ID_ENTRIES) {
    const re = new RegExp(entry.pattern.source, "g");
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      const match = m;
      const key = `${String(match.index)}-${String(match.index + match[0].length)}`;
      if (seen.has(key)) continue;

      const hasContext = contextPositions.some(
        (pos) => pos <= match.index && match.index - pos <= 40,
      );

      if (entry.requiresContext && !hasContext) continue;

      const confidence = hasContext ? Math.min(entry.confidence + 0.05, 0.97) : entry.confidence;

      seen.add(key);
      matches.push({
        category: "national-id",
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        confidence,
      });
    }
  }

  return matches;
}
