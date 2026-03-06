/**
 * @module validators
 * @description PII checksum and format validation algorithms.
 *
 * All validators are pure functions that accept a string and return a boolean.
 * Export them from `"anonyma/validators"` for standalone use.
 *
 * @example
 * ```ts
 * import { luhn, verhoeff, nhsMod11, cpfChecksum } from "anonyma/validators";
 *
 * luhn("4111111111111111"); // true
 * nhsMod11("943-476-5919");  // true
 * ```
 */

// ---------------------------------------------------------------------------
// Luhn Algorithm (credit cards, some national IDs)
// ---------------------------------------------------------------------------

/**
 * Validate a string of digits using the Luhn algorithm (ISO/IEC 7812).
 * Used for credit/debit card numbers and some national IDs.
 *
 * @param digits - Digit-only string (spaces/hyphens stripped before calling).
 * @returns `true` if the number passes the Luhn check.
 *
 * @example
 * ```ts
 * luhn("4111111111111111"); // true
 * luhn("4111111111111112"); // false
 * ```
 */
export function luhn(digits: string): boolean {
  const stripped = digits.replace(/[\s-]/g, "");
  if (!/^\d+$/.test(stripped) || stripped.length < 2) return false;

  let sum = 0;
  let isEven = false;

  for (let i = stripped.length - 1; i >= 0; i--) {
    /* v8 ignore next -- regex guarantees digit chars so stripped[i] is always defined */
    let d = parseInt(stripped[i] ?? "0", 10);
    if (isEven) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

// ---------------------------------------------------------------------------
// Verhoeff Algorithm (Indian Aadhaar and others)
// ---------------------------------------------------------------------------

/** Verhoeff multiplication table. @internal */
const VERHOEFF_D: readonly number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/** Verhoeff permutation table. @internal */
const VERHOEFF_P: readonly number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/**
 * Validate a digit string using the Verhoeff algorithm.
 * Used for Indian Aadhaar numbers and some other national IDs.
 *
 * @param digits - Digit-only string.
 * @returns `true` if the number passes the Verhoeff check.
 *
 * @example
 * ```ts
 * verhoeff("236"); // true (canonical Verhoeff test case)
 * ```
 */
export function verhoeff(digits: string): boolean {
  const stripped = digits.replace(/[\s-]/g, "");
  if (!/^\d+$/.test(stripped) || stripped.length === 0) return false;

  let c = 0;
  const reversed = stripped.split("").reverse();

  for (let i = 0; i < reversed.length; i++) {
    /* v8 ignore next -- reversed array is same length as stripped so reversed[i] is always defined */
    const digit = parseInt(reversed[i] ?? "0", 10);
    const pRow = VERHOEFF_P[i % 8];
    /* v8 ignore next 3 -- lookup tables always cover valid indices (0-7 for P, 0-9 for D) */
    const pVal = pRow ? pRow[digit] ?? digit : digit;
    const dRow = VERHOEFF_D[c];
    c = dRow ? dRow[pVal] ?? 0 : 0;
  }

  return c === 0;
}

// ---------------------------------------------------------------------------
// NHS Mod-11 (UK NHS numbers)
// ---------------------------------------------------------------------------

/**
 * Validate a UK NHS number using the mod-11 algorithm.
 * NHS numbers are 10 digits. Weighting factors are 10..2 for the first 9 digits;
 * the 10th digit is the check digit (11 - sum mod 11, or 0 if sum mod 11 == 0).
 *
 * @param value - NHS number (digits or with spaces/hyphens).
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * nhsMod11("9434765919"); // true
 * nhsMod11("943 476 5919"); // true
 * ```
 */
export function nhsMod11(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "");
  if (!/^\d{10}$/.test(stripped)) return false;

  let sum = 0;
  /* v8 ignore start -- regex guarantees \d{10} so indices 0-9 are always defined */
  for (let i = 0; i < 9; i++) {
    sum += parseInt(stripped[i] ?? "0", 10) * (10 - i);
  }
  /* v8 ignore stop */

  const remainder = sum % 11;
  if (remainder === 1) return false; // Invalid NHS number
  const checkDigit = remainder === 0 ? 0 : 11 - remainder;

  /* v8 ignore next -- regex guarantees \d{10} so stripped[9] is always defined */
  return parseInt(stripped[9] ?? "0", 10) === checkDigit;
}

// ---------------------------------------------------------------------------
// Brazilian CPF Checksum
// ---------------------------------------------------------------------------

/**
 * Validate a Brazilian CPF (Cadastro de Pessoas Físicas) number.
 * CPF has 11 digits with two check digits at positions 10 and 11.
 *
 * @param value - CPF with or without formatting (e.g. `"123.456.789-09"` or `"12345678909"`).
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * cpfChecksum("529.982.247-25"); // true
 * cpfChecksum("529.982.247-26"); // false
 * ```
 */
export function cpfChecksum(value: string): boolean {
  const stripped = value.replace(/[.\-\s]/g, "");
  if (!/^\d{11}$/.test(stripped)) return false;

  // Reject known invalid patterns (all same digit)
  if (/^(\d)\1{10}$/.test(stripped)) return false;

  // Compute first check digit
  let sum = 0;
  /* v8 ignore start -- regex guarantees \d{11} so all string indices are defined */
  for (let i = 0; i < 9; i++) {
    sum += parseInt(stripped[i] ?? "0", 10) * (10 - i);
  }
  let remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  if (remainder !== parseInt(stripped[9] ?? "0", 10)) return false;

  // Compute second check digit
  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(stripped[i] ?? "0", 10) * (11 - i);
  }
  remainder = (sum * 10) % 11;
  if (remainder === 10 || remainder === 11) remainder = 0;
  return remainder === parseInt(stripped[10] ?? "0", 10);
  /* v8 ignore stop */
}

// ---------------------------------------------------------------------------
// VIN Transliteration Checksum (ISO 3779)
// ---------------------------------------------------------------------------

/** VIN transliteration map: letters → numeric values. @internal */
const VIN_TRANSLITERATION: Readonly<Record<string, number>> = {
  A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8,
  J: 1, K: 2, L: 3, M: 4, N: 5,         P: 7, R: 9,
  S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
  0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9,
} as const;

/** VIN position weight factors (positions 1–9 = check, 1-based). @internal */
const VIN_WEIGHTS: readonly number[] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

/**
 * Validate a Vehicle Identification Number (VIN) using the ISO 3779 mod-11 checksum.
 * The check digit is position 9 (index 8).
 *
 * @param vin - 17-character VIN string. Must contain only A-Z (excluding I, O, Q) and 0-9.
 * @returns `true` if the VIN passes the checksum and has valid characters.
 *
 * @example
 * ```ts
 * vinChecksum("1HGBH41JXMN109186"); // true
 * vinChecksum("1HGBH41JXMN109187"); // false
 * ```
 */
export function vinChecksum(vin: string): boolean {
  const upper = vin.toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(upper)) return false;

  let sum = 0;
  for (let i = 0; i < 17; i++) {
    /* v8 ignore next -- regex guarantees 17 chars so upper[i] is always defined */
    const char = upper[i] ?? "";
    const val = VIN_TRANSLITERATION[char];
    const weight = VIN_WEIGHTS[i];
    /* v8 ignore next -- regex already guarantees all chars are in the translation table */
    if (val === undefined || weight === undefined) return false;
    sum += val * weight;
  }

  const remainder = sum % 11;
  /* v8 ignore next -- regex guarantees 17 chars so upper[8] is always defined */
  const checkChar = upper[8] ?? "";
  const expected = remainder === 10 ? "X" : String(remainder);

  return checkChar === expected;
}

// ---------------------------------------------------------------------------
// DEA Registration Number Checksum
// ---------------------------------------------------------------------------

/**
 * Validate a US DEA (Drug Enforcement Administration) registration number.
 * Format: two letters (registrant type + first letter of last name) + 7 digits.
 * Check digit = (sum of digits 1,3,5 + 2 * sum of digits 2,4,6) mod 10.
 *
 * @param value - DEA number, e.g. `"AB1234563"`.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * deaChecksum("AB1234563"); // true
 * ```
 */
export function deaChecksum(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[ABCDEFGHJKLMNPRSTUX][A-Z9]\d{7}$/.test(stripped)) return false;

  const digits = stripped.slice(2);
  /* v8 ignore start -- regex guarantees \d{7} so indices 0-6 are always defined */
  const oddSum = parseInt(digits[0] ?? "0", 10) +
    parseInt(digits[2] ?? "0", 10) +
    parseInt(digits[4] ?? "0", 10);
  const evenSum = parseInt(digits[1] ?? "0", 10) +
    parseInt(digits[3] ?? "0", 10) +
    parseInt(digits[5] ?? "0", 10);
  const checksum = (oddSum + 2 * evenSum) % 10;

  return checksum === parseInt(digits[6] ?? "0", 10);
  /* v8 ignore stop */
}

// ---------------------------------------------------------------------------
// IBAN Mod-97 Checksum
// ---------------------------------------------------------------------------

/**
 * Validate an IBAN using the ISO 13616 mod-97 algorithm.
 *
 * @param value - IBAN string, with or without spaces.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * ibanMod97("GB82 WEST 1234 5698 7654 32"); // true
 * ```
 */
export function ibanMod97(value: string): boolean {
  const stripped = value.replace(/\s/g, "").toUpperCase();
  if (stripped.length < 15 || stripped.length > 34) return false;

  // Move first 4 chars to end
  const rearranged = stripped.slice(4) + stripped.slice(0, 4);

  // Convert letters to digits (A=10, B=11, ..., Z=35)
  const numeric = rearranged.split("").map((c) => {
    const code = c.charCodeAt(0);
    return code >= 65 && code <= 90 ? String(code - 55) : c;
  }).join("");

  // Compute mod-97 on large number via chunking
  let remainder = 0;
  for (let i = 0; i < numeric.length; i += 7) {
    const chunk = String(remainder) + numeric.slice(i, i + 7);
    remainder = parseInt(chunk, 10) % 97;
  }

  return remainder === 1;
}

// ---------------------------------------------------------------------------
// UK NINO Validation
// ---------------------------------------------------------------------------

/**
 * Validate a UK National Insurance Number (NINO) format.
 * Format: two letters + six digits + one letter (A-D).
 * Excludes certain invalid prefixes.
 *
 * @param value - NINO string, with or without spaces.
 * @returns `true` if the format is valid.
 *
 * @example
 * ```ts
 * ninoValid("AB 12 34 56 A"); // true
 * ninoValid("DA 12 34 56 A"); // false (invalid prefix DA)
 * ```
 */
export function ninoValid(value: string): boolean {
  const stripped = value.replace(/\s/g, "").toUpperCase();
  // Exclude invalid prefixes: D, F, I, Q, U, V as first letter
  // BG, GB, KN, NK, NT, TN, ZZ as first two letters
  if (!/^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(stripped)) return false;
  const invalidPrefixes = ["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"];
  const prefix = stripped.slice(0, 2);
  return !invalidPrefixes.includes(prefix);
}

// ---------------------------------------------------------------------------
// Indian Aadhaar format check (12 digits, not starting with 0 or 1)
// ---------------------------------------------------------------------------

/**
 * Validate the format of an Indian Aadhaar number.
 * Does not include Verhoeff checksum by default (call `verhoeff()` for that).
 *
 * @param value - Aadhaar number, 12 digits optionally separated by spaces.
 * @returns `true` if the format is valid.
 */
export function aadhaarFormat(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "");
  if (!/^\d{12}$/.test(stripped)) return false;
  // Must not start with 0 or 1
  return !stripped.startsWith("0") && !stripped.startsWith("1");
}
