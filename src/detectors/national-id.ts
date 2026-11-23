/**
 * @module detectors/national-id
 * @description Detector for national identification numbers across 20+ countries.
 *
 * Covered countries/formats:
 * - Canada: SIN (XXX-XXX-XXX)
 * - Mexico: CURP (18 chars alphanumeric) and RFC (13 chars)
 * - UK: NINO (AB 12 34 56 C)
 * - India: Aadhaar (12 digits, verified with format check; never part of a
 *   longer number written in groups, such as a card number)
 * - China: Resident ID (18 digits with letter checksum)
 * - South Korea: RRN (XXXXXX-XXXXXXX)
 * - Germany: Personalausweis (9 alphanumeric)
 * - France: NIR/INSEE (15 digits with spaces)
 * - Brazil: CPF (XXX.XXX.XXX-XX) and RG (XX.XXX.XXX-X, with an "RG" label)
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
 *
 * {@link detectNationalIdStrict} also verifies the check digits of the formats
 * that have them and discards the numbers that fail.
 */

import type { PiiMatch } from "../types.js";
import {
  australianTfnChecksum,
  bsnChecksum,
  chineseResidentIdChecksum,
  cpfChecksum,
  frNirChecksum,
  italianFiscalCodeChecksum,
  luhn,
  ninoValid,
  ptNifChecksum,
  spanishIdChecksum,
  swedishPersonnummerChecksum,
  verhoeff,
} from "../validators.js";

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
const MX_CURP_PATTERN = /\b[A-Z]{4}\d{6}[HM][A-Z]{2}[A-Z]{3}[A-Z0-9]\d\b/g;

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
const UK_NINO_PATTERN = /\b[A-CEGHJ-PR-TW-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-D]\b/gi;

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
const FR_NIR_PATTERN = /\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b/g;

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
const IT_CF_PATTERN = /\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b/gi;

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

/**
 * Brazil RG (Registro Geral): 7 to 9 characters, the last a digit or `X`,
 * usually written XX.XXX.XXX-X. The format differs from state to state and
 * has no common check digit, so it is reported only after an RG label.
 * @internal
 */
const BR_RG_PATTERN = /\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dXx]\b/g;

/**
 * Labels of a Brazilian RG.
 * @internal
 */
const BR_RG_CONTEXT_RE =
  /\b(?:RG|R\.G\.|registro\s+geral|(?:carteira|c[ée]dula)\s+de\s+identidade|identidade)\s*(?:n[º°o.]?\s*)?:?\s*/gi;

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
  /** The labels this entry's context consists of. Defaults to the generic national-ID labels. */
  readonly context?: RegExp;
  /** Check digits that {@link detectNationalIdStrict} verifies. */
  readonly validate?: (value: string) => boolean;
  /**
   * When true, a match that is part of a longer number written in groups (see
   * {@link inLongerNumber}) is not reported: `4111 1111 1111` of a 16-digit
   * card number is not an Aadhaar number.
   */
  readonly standalone?: boolean;
}

const NATIONAL_ID_ENTRIES: readonly NationalIdEntry[] = [
  { pattern: CA_SIN_PATTERN, confidence: 0.85, requiresContext: false, validate: luhn },
  { pattern: MX_CURP_PATTERN, confidence: 0.9, requiresContext: false },
  { pattern: MX_RFC_PATTERN, confidence: 0.78, requiresContext: true },
  { pattern: UK_NINO_PATTERN, confidence: 0.9, requiresContext: false, validate: ninoValid },
  {
    pattern: IN_AADHAAR_PATTERN,
    confidence: 0.82,
    requiresContext: false,
    validate: verhoeff,
    standalone: true,
  },
  {
    pattern: CN_RESIDENT_ID_PATTERN,
    confidence: 0.8,
    requiresContext: true,
    validate: chineseResidentIdChecksum,
  },
  { pattern: KR_RRN_PATTERN, confidence: 0.87, requiresContext: false },
  { pattern: BR_CPF_PATTERN, confidence: 0.92, requiresContext: false, validate: cpfChecksum },
  {
    pattern: SE_PERSONNUMMER_PATTERN,
    confidence: 0.87,
    requiresContext: false,
    validate: swedishPersonnummerChecksum,
  },
  {
    pattern: ES_DNIE_PATTERN,
    confidence: 0.82,
    requiresContext: false,
    validate: spanishIdChecksum,
  },
  {
    pattern: IT_CF_PATTERN,
    confidence: 0.88,
    requiresContext: false,
    validate: italianFiscalCodeChecksum,
  },
  { pattern: FR_NIR_PATTERN, confidence: 0.84, requiresContext: false, validate: frNirChecksum },
  // More ambiguous — require context
  { pattern: AR_DNI_PATTERN, confidence: 0.75, requiresContext: true },
  { pattern: ZA_ID_PATTERN, confidence: 0.72, requiresContext: true, validate: luhn },
  { pattern: NG_NIN_PATTERN, confidence: 0.7, requiresContext: true },
  {
    pattern: AU_TFN_PATTERN,
    confidence: 0.75,
    requiresContext: true,
    validate: australianTfnChecksum,
  },
  { pattern: DE_PERSONALAUSWEIS_PATTERN, confidence: 0.75, requiresContext: true },
  { pattern: PT_NIF_PATTERN, confidence: 0.7, requiresContext: true, validate: ptNifChecksum },
  { pattern: NL_BSN_PATTERN, confidence: 0.7, requiresContext: true, validate: bsnChecksum },
  { pattern: BR_RG_PATTERN, confidence: 0.85, requiresContext: true, context: BR_RG_CONTEXT_RE },
];

/**
 * True when the digits from `start` to `end` of `text` continue a longer
 * number: a digit and a space or hyphen come right before them, or a space or
 * hyphen and a digit right after.
 *
 * @internal
 */
function inLongerNumber(text: string, start: number, end: number): boolean {
  return (
    /\d[ -]$/.test(text.slice(Math.max(0, start - 2), start)) ||
    /^[ -]\d/.test(text.slice(end, end + 2))
  );
}

/** End offsets of every label `context` finds in `text`. @internal */
function labelEnds(text: string, context: RegExp): number[] {
  const ends: number[] = [];
  const re = new RegExp(context.source, "gi");
  let found: RegExpExecArray | null;
  while ((found = re.exec(text)) !== null) ends.push(found.index + found[0].length);
  return ends;
}

/** The shared scan behind {@link detectNationalId} and {@link detectNationalIdStrict}. @internal */
function scanNationalId(text: string, strict: boolean): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();
  const labels = new Map<RegExp, number[]>();

  for (const entry of NATIONAL_ID_ENTRIES) {
    const context = entry.context ?? NATIONAL_ID_CONTEXT_RE;
    let ends = labels.get(context);
    if (ends === undefined) {
      ends = labelEnds(text, context);
      labels.set(context, ends);
    }
    // Without a label, a format that requires one reports nothing.
    if (entry.requiresContext && ends.length === 0) continue;
    const re = new RegExp(entry.pattern.source, "g");
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      const match = m;
      const key = `${String(match.index)}-${String(match.index + match[0].length)}`;
      if (seen.has(key)) continue;

      const hasContext = ends.some((pos) => pos <= match.index && match.index - pos <= 40);

      if (entry.requiresContext && !hasContext) continue;
      const end = match.index + match[0].length;
      if (entry.standalone === true && inLongerNumber(text, match.index, end)) continue;
      // A number whose check digits fail may still be another country's number.
      if (strict && entry.validate !== undefined && !entry.validate(match[0])) continue;

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

/**
 * Detect national identification numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "national-id"`.
 */
export function detectNationalId(text: string): PiiMatch[] {
  return scanNationalId(text, false);
}

/**
 * Detect national identification numbers in `text`, discarding those whose
 * check digits fail: Canadian SIN and South African ID (Luhn), UK NINO
 * (prefixes), Aadhaar (Verhoeff), Chinese resident ID (ISO 7064), CPF, Swedish
 * personnummer, Spanish DNI/NIE, Italian fiscal code, French NIR, Australian
 * TFN, Portuguese NIF and Dutch BSN. Formats without check digits are
 * reported as {@link detectNationalId} reports them.
 *
 * The validating span detector of `"anonyma/engine"` uses it.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "national-id"`.
 *
 * @example
 * ```ts
 * import { detectNationalIdStrict } from "anonyma/detectors";
 *
 * detectNationalIdStrict("CPF 529.982.247-25, not 529.982.247-26").map((m) => m.value);
 * // ["529.982.247-25"]
 * ```
 */
export function detectNationalIdStrict(text: string): PiiMatch[] {
  return scanNationalId(text, true);
}
