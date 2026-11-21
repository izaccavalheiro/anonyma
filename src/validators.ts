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
    /* v8 ignore start -- lookup tables always cover valid indices (0-7 for P, 0-9 for D) */
    const pVal = pRow ? (pRow[digit] ?? digit) : digit;
    const dRow = VERHOEFF_D[c];
    c = dRow ? (dRow[pVal] ?? 0) : 0;
    /* v8 ignore stop */
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
  A: 1,
  B: 2,
  C: 3,
  D: 4,
  E: 5,
  F: 6,
  G: 7,
  H: 8,
  J: 1,
  K: 2,
  L: 3,
  M: 4,
  N: 5,
  P: 7,
  R: 9,
  S: 2,
  T: 3,
  U: 4,
  V: 5,
  W: 6,
  X: 7,
  Y: 8,
  Z: 9,
  0: 0,
  1: 1,
  2: 2,
  3: 3,
  4: 4,
  5: 5,
  6: 6,
  7: 7,
  8: 8,
  9: 9,
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
  const oddSum =
    parseInt(digits[0] ?? "0", 10) +
    parseInt(digits[2] ?? "0", 10) +
    parseInt(digits[4] ?? "0", 10);
  const evenSum =
    parseInt(digits[1] ?? "0", 10) +
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
  const numeric = rearranged
    .split("")
    .map((c) => {
      const code = c.charCodeAt(0);
      return code >= 65 && code <= 90 ? String(code - 55) : c;
    })
    .join("");

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

// ---------------------------------------------------------------------------
// Weighted-sum checksums (mod 10, mod 11, ISO 7064)
// ---------------------------------------------------------------------------

/** The value of each character of `text`: digits are 0-9, letters `A`-`Z` are 17-42. @internal */
function charValues(text: string): number[] {
  return Array.from(text, (char) => char.charCodeAt(0) - 48);
}

/** Σ value × weight over the shorter of the two lists. @internal */
function weightedSum(values: readonly number[], weights: readonly number[]): number {
  let sum = 0;
  weights.forEach((weight, index) => {
    /* v8 ignore next -- every caller passes at least as many values as weights */
    sum += (values[index] ?? 0) * weight;
  });
  return sum;
}

/** `true` when every character of `text` is the same, which issuers never assign. @internal */
function isRepeated(text: string): boolean {
  return /^(.)\1*$/.test(text);
}

/**
 * Validate a US ABA routing transit number: nine digits whose weighted sum
 * with the weights 3, 7, 1 is a multiple of 10.
 *
 * @param value - Routing number, with or without spaces or hyphens.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * abaRoutingChecksum("011000015"); // true
 * abaRoutingChecksum("011000016"); // false
 * ```
 */
export function abaRoutingChecksum(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "");
  if (!/^\d{9}$/.test(stripped) || isRepeated(stripped)) return false;
  return weightedSum(charValues(stripped), [3, 7, 1, 3, 7, 1, 3, 7, 1]) % 10 === 0;
}

/** CNPJ check digit over `values` with `weights`. @internal */
function cnpjDigit(values: readonly number[], weights: readonly number[]): number {
  const remainder = weightedSum(values, weights) % 11;
  return remainder < 2 ? 0 : 11 - remainder;
}

/**
 * Validate a Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica), in the
 * numeric form and in the alphanumeric form issued from July 2026: twelve
 * digits or upper-case letters followed by two mod-11 check digits, each
 * character counting as its character code minus 48.
 *
 * @param value - CNPJ with or without formatting (e.g. `"11.222.333/0001-81"`).
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * cnpjChecksum("11.222.333/0001-81"); // true
 * cnpjChecksum("12.ABC.345/01DE-35"); // true (alphanumeric)
 * cnpjChecksum("11.222.333/0001-82"); // false
 * ```
 */
export function cnpjChecksum(value: string): boolean {
  const stripped = value.replace(/[.\-/\s]/g, "").toUpperCase();
  if (!/^[A-Z0-9]{12}\d{2}$/.test(stripped) || isRepeated(stripped)) return false;
  const values = charValues(stripped);
  const first = cnpjDigit(values, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const second = cnpjDigit(
    [...values.slice(0, 12), first],
    [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
  );
  return values[12] === first && values[13] === second;
}

/**
 * Validate a US National Provider Identifier: ten digits that pass the Luhn
 * check behind the prefix `80840`.
 *
 * @param value - NPI, with or without spaces.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * npiChecksum("1234567893"); // true
 * ```
 */
export function npiChecksum(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "");
  return /^[12]\d{9}$/.test(stripped) && luhn(`80840${stripped}`);
}

/**
 * Validate a 15-digit IMEI (mobile device identity) with the Luhn check.
 *
 * @param value - IMEI, with or without spaces, hyphens or slashes.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * imeiChecksum("49-015420-323751-8"); // true
 * ```
 */
export function imeiChecksum(value: string): boolean {
  const stripped = value.replace(/[\s\-/]/g, "");
  return /^\d{15}$/.test(stripped) && !isRepeated(stripped) && luhn(stripped);
}

/**
 * Validate a Dutch citizen service number (BSN) with the eleven test
 * (elfproef): weights 9 to 2 and -1 give a multiple of 11.
 *
 * @param value - BSN of 8 or 9 digits, with or without separators.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * bsnChecksum("111222333"); // true
 * ```
 */
export function bsnChecksum(value: string): boolean {
  const stripped = value.replace(/[\s.-]/g, "").padStart(9, "0");
  if (!/^\d{9}$/.test(stripped) || isRepeated(stripped)) return false;
  return weightedSum(charValues(stripped), [9, 8, 7, 6, 5, 4, 3, 2, -1]) % 11 === 0;
}

/**
 * Validate a Portuguese tax number (NIF): nine digits, the last a mod-11
 * check digit over weights 9 to 2.
 *
 * @param value - NIF, with or without spaces.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * ptNifChecksum("123456789"); // true
 * ```
 */
export function ptNifChecksum(value: string): boolean {
  const stripped = value.replace(/[\s.-]/g, "");
  if (!/^[1-9]\d{8}$/.test(stripped) || isRepeated(stripped)) return false;
  const values = charValues(stripped);
  const remainder = weightedSum(values, [9, 8, 7, 6, 5, 4, 3, 2]) % 11;
  return values[8] === (remainder < 2 ? 0 : 11 - remainder);
}

/** Control letters of the Spanish DNI and NIE, indexed by the number mod 23. @internal */
const SPANISH_ID_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

/**
 * Validate a Spanish DNI (eight digits and a letter) or NIE (`X`, `Y` or `Z`,
 * seven digits and a letter): the letter is the number modulo 23.
 *
 * @param value - DNI or NIE, with or without a hyphen or space before the letter.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * spanishIdChecksum("12345678Z"); // true
 * spanishIdChecksum("X1234567L"); // true
 * ```
 */
export function spanishIdChecksum(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "").toUpperCase();
  const match = /^([XYZ]\d{7}|\d{8})([A-Z])$/.exec(stripped);
  if (match === null) return false;
  const [, body = "", letter] = match;
  const number = Number(body.replace(/^[XYZ]/, (prefix) => String("XYZ".indexOf(prefix))));
  return SPANISH_ID_LETTERS.charAt(number % 23) === letter;
}

/** Values of characters in odd positions of an Italian fiscal code, for 0-9 then A-Z. @internal */
const IT_ODD = [
  1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8,
  12, 14, 16, 10, 22, 25, 24, 23,
];

/**
 * Validate an Italian fiscal code (codice fiscale) of a natural person: its
 * sixteenth character is the check letter over the first fifteen.
 *
 * @param value - The 16-character fiscal code.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * italianFiscalCodeChecksum("RSSMRA85T10A562S"); // true
 * ```
 */
export function italianFiscalCodeChecksum(value: string): boolean {
  const stripped = value.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z0-9]{15}[A-Z]$/.test(stripped)) return false;
  let sum = 0;
  for (let index = 0; index < 15; index++) {
    const code = stripped.charCodeAt(index);
    const ordinal = code <= 57 ? code - 48 : code - 55; // 0-9 → 0-9, A-Z → 10-35
    // Positions are counted from 1, so even indices are the odd positions.
    const even = code <= 57 ? ordinal : ordinal - 10; // 0-9 → 0-9, A-Z → 0-25
    /* v8 ignore next -- the pattern admits only 0-9 and A-Z, which the table covers */
    sum += index % 2 === 0 ? (IT_ODD[ordinal] ?? 0) : even;
  }
  return String.fromCharCode(65 + (sum % 26)) === stripped.charAt(15);
}

/**
 * Validate a French social security number (NIR): thirteen digits and a
 * two-digit key equal to 97 minus the number modulo 97. The Corsican
 * departments `2A` and `2B` count as 19 and 18.
 *
 * @param value - NIR of 15 characters, with or without spaces.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * frNirChecksum("2 84 05 75 123 456 72"); // true
 * ```
 */
export function frNirChecksum(value: string): boolean {
  const stripped = value.replace(/\s/g, "").toUpperCase();
  const match = /^([12]\d{4})(\d{2}|2A|2B)(\d{6})(\d{2})$/.exec(stripped);
  if (match === null) return false;
  const [, head = "", department = "", tail = "", key = ""] = match;
  const corsica = department === "2A" ? "19" : department === "2B" ? "18" : department;
  return 97 - (Number(`${head}${corsica}${tail}`) % 97) === Number(key);
}

/**
 * Validate a Chinese resident identity card number: seventeen digits and an
 * ISO 7064 MOD 11-2 check character (`0`-`9` or `X`).
 *
 * @param value - The 18-character number.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * chineseResidentIdChecksum("11010519491231002X"); // true
 * ```
 */
export function chineseResidentIdChecksum(value: string): boolean {
  const stripped = value.replace(/\s/g, "").toUpperCase();
  if (!/^\d{17}[\dX]$/.test(stripped)) return false;
  const sum = weightedSum(
    charValues(stripped),
    [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2],
  );
  return "10X98765432".charAt(sum % 11) === stripped.charAt(17);
}

/**
 * Validate a nine-digit Australian tax file number: weights 1, 4, 3, 7, 5, 8,
 * 6, 9 and 10 give a multiple of 11.
 *
 * @param value - TFN, with or without spaces.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * australianTfnChecksum("123 456 782"); // true
 * ```
 */
export function australianTfnChecksum(value: string): boolean {
  const stripped = value.replace(/[\s-]/g, "");
  if (!/^\d{9}$/.test(stripped) || isRepeated(stripped)) return false;
  return weightedSum(charValues(stripped), [1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11 === 0;
}

/**
 * Validate a Swedish personal identity number (personnummer or
 * samordningsnummer): the last ten digits pass the Luhn check.
 *
 * @param value - `YYMMDD-NNNN`, `YYMMDD+NNNN` or `YYYYMMDDNNNN`.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * swedishPersonnummerChecksum("811218-9876"); // true
 * ```
 */
export function swedishPersonnummerChecksum(value: string): boolean {
  const stripped = value.replace(/[\s\-+]/g, "");
  if (!/^(?:\d{2})?\d{10}$/.test(stripped)) return false;
  return luhn(stripped.slice(-10));
}

/**
 * Validate the CRC of a Brazilian PIX "copia e cola" payload (an EMV QR
 * code): its last four characters are the CRC-16/CCITT-FALSE of everything
 * before them, in upper-case hexadecimal.
 *
 * @param value - The whole payload, ending in `6304` and the CRC.
 * @returns `true` if valid.
 *
 * @example
 * ```ts
 * pixPayloadChecksum(payload); // true when the payload was not altered
 * ```
 */
export function pixPayloadChecksum(value: string): boolean {
  if (!/6304[0-9A-Fa-f]{4}$/.test(value)) return false;
  let crc = 0xffff;
  for (let index = 0; index < value.length - 4; index++) {
    crc ^= value.charCodeAt(index) << 8;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, "0") === value.slice(-4).toUpperCase();
}

// ---------------------------------------------------------------------------
// Validators by name
// ---------------------------------------------------------------------------

/**
 * Every checksum validator, by the name a declarative pattern uses for it
 * (`PatternSpec.validator` in `"anonyma/engine"`).
 *
 * @example
 * ```ts
 * import { CHECKSUMS } from "anonyma/validators";
 *
 * CHECKSUMS.cnpj("11.222.333/0001-81"); // true
 * ```
 */
export const CHECKSUMS = Object.freeze({
  luhn,
  verhoeff,
  iban: ibanMod97,
  nhs: nhsMod11,
  cpf: cpfChecksum,
  cnpj: cnpjChecksum,
  "aba-routing": abaRoutingChecksum,
  npi: npiChecksum,
  imei: imeiChecksum,
  dea: deaChecksum,
  vin: vinChecksum,
  nino: ninoValid,
  aadhaar: (value: string): boolean => aadhaarFormat(value) && verhoeff(value),
  bsn: bsnChecksum,
  "pt-nif": ptNifChecksum,
  "es-dni": spanishIdChecksum,
  "it-fiscal-code": italianFiscalCodeChecksum,
  "fr-nir": frNirChecksum,
  "cn-resident-id": chineseResidentIdChecksum,
  "au-tfn": australianTfnChecksum,
  "se-personnummer": swedishPersonnummerChecksum,
  pix: pixPayloadChecksum,
} satisfies Readonly<Record<string, (value: string) => boolean>>);

/** The name of a validator in {@link CHECKSUMS}. */
export type ChecksumName = keyof typeof CHECKSUMS;
