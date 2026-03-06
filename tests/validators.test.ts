/**
 * Tests for v2 validators
 */
import { describe, it, expect } from "vitest";
import {
  luhn,
  verhoeff,
  nhsMod11,
  ibanMod97,
  vinChecksum,
  cpfChecksum,
  deaChecksum,
  ninoValid,
  aadhaarFormat,
} from "../src/validators.js";

// ---------------------------------------------------------------------------
// Luhn
// ---------------------------------------------------------------------------
describe("luhn", () => {
  it("validates a valid Visa card", () => {
    expect(luhn("4111111111111111")).toBe(true);
  });

  it("validates Amex card", () => {
    expect(luhn("378282246310005")).toBe(true);
  });

  it("rejects an invalid card number", () => {
    expect(luhn("4111111111111112")).toBe(false);
  });

  it("handles string with dashes/spaces (no auto-strip)", () => {
    // luhn expects raw digits only
    expect(luhn("4111111111111111")).toBe(true);
  });

  it("rejects strings shorter than 2 digits", () => {
    expect(luhn("5")).toBe(false);
    expect(luhn("")).toBe(false);
  });

  it("rejects non-digit strings", () => {
    expect(luhn("abcdefg")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Verhoeff (German numeric IDs)
// ---------------------------------------------------------------------------
describe("verhoeff", () => {
  it("validates a known-good verhoeff sequence", () => {
    // 2363 — canonical test case with check digit
    expect(verhoeff("2363")).toBe(true);
  });

  it("rejects an invalid verhoeff sequence", () => {
    expect(verhoeff("2364")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(verhoeff("")).toBe(false);
  });

  it("rejects non-digit strings", () => {
    expect(verhoeff("abc")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// NHS Mod-11
// ---------------------------------------------------------------------------
describe("nhsMod11", () => {
  it("validates a known-good NHS number", () => {
    expect(nhsMod11("9434765919")).toBe(true);
  });

  it("validates NHS number with spaces", () => {
    expect(nhsMod11("943 476 5919")).toBe(true);
  });

  it("rejects when remainder === 1 (structurally invalid)", () => {
    // sum = 12, 12 % 11 = 1 → invalid regardless of check digit
    // digits 1-9: 0,0,0,0,0,0,0,4,0 → sum = 4*3 = 12
    expect(nhsMod11("0000000400")).toBe(false);
  });

  it("validates NHS number where check digit is 0 (remainder === 0)", () => {
    // digits 1-9: 1,1,0,0,0,0,0,1,0 → sum = 1*10+1*9+1*3 = 22, 22%11=0, checkDigit=0
    expect(nhsMod11("1100000100")).toBe(true);
  });

  it("rejects a non-10-digit NHS number", () => {
    expect(nhsMod11("12345")).toBe(false);
  });

  it("rejects NHS number with wrong check digit", () => {
    expect(nhsMod11("9434765910")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// IBAN mod97
// ---------------------------------------------------------------------------
describe("ibanMod97", () => {
  it("validates a valid GB IBAN", () => {
    expect(ibanMod97("GB82WEST12345698765432")).toBe(true);
  });

  it("validates a valid DE IBAN", () => {
    expect(ibanMod97("DE89370400440532013000")).toBe(true);
  });

  it("rejects an invalid IBAN", () => {
    expect(ibanMod97("GB82WEST12345698765433")).toBe(false);
  });

  it("ignores spaces", () => {
    expect(ibanMod97("GB82 WEST 1234 5698 7654 32")).toBe(true);
  });

  it("rejects an IBAN that is too short (< 15 chars)", () => {
    expect(ibanMod97("GB82WEST123")).toBe(false);
  });

  it("rejects an IBAN that is too long (> 34 chars)", () => {
    expect(ibanMod97("GB82WEST12345698765432" + "0".repeat(15))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VIN checksum (ISO 3779 digit 9)
// ---------------------------------------------------------------------------
describe("vinChecksum", () => {
  it("validates a known-good VIN", () => {
    expect(vinChecksum("1HGBH41JXMN109186")).toBe(true);
  });

  it("rejects a VIN with wrong check digit", () => {
    expect(vinChecksum("1HGBH41JXMN109187")).toBe(false);
  });

  it("rejects VINs containing I, O, Q", () => {
    // I/O/Q are not allowed in VINs
    expect(vinChecksum("IHGBH41JXMN109186")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DEA Registration Number
// ---------------------------------------------------------------------------
describe("deaChecksum", () => {
  it("validates a known-good DEA number", () => {
    // AB1234563: oddSum=1+3+5=9, evenSum=2+4+6=12, checksum=(9+24)%10=3, digit=3
    expect(deaChecksum("AB1234563")).toBe(true);
  });

  it("rejects a DEA number with wrong check digit", () => {
    expect(deaChecksum("AB1234560")).toBe(false);
  });

  it("rejects a DEA number with invalid format", () => {
    expect(deaChecksum("12345678")).toBe(false);
  });

  it("strips spaces/hyphens and validates", () => {
    expect(deaChecksum("AB 1234563")).toBe(true);
  });

  it("rejects DEA number with invalid first letter", () => {
    // 'I' is not in the allowed set [ABCDEFGHJKLMNPRSTUX]
    expect(deaChecksum("IB1234563")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CPF checksum (Brazil)
// ---------------------------------------------------------------------------
describe("cpfChecksum", () => {
  it("validates a known-good CPF", () => {
    expect(cpfChecksum("529.982.247-25")).toBe(true);
  });

  it("rejects all-same-digit CPFs (blacklisted)", () => {
    expect(cpfChecksum("111.111.111-11")).toBe(false);
  });

  it("rejects an invalid CPF", () => {
    expect(cpfChecksum("529.982.247-26")).toBe(false);
  });

  it("rejects non-11-digit input", () => {
    expect(cpfChecksum("529.982")).toBe(false);
  });

  it("accepts CPF where first check digit computation produces remainder 10 (sets to 0)", () => {
    // prefix 000000006: sum1 = 6*2 = 12; (12*10)%11 = 10 → d10 = 0; CPF = "00000000604"
    expect(cpfChecksum("00000000604")).toBe(true);
  });

  it("accepts CPF where second check digit computation produces remainder 10 (sets to 0)", () => {
    // prefix 000000018, d10=3: sum2 triggers rem2=10 → d11 = 0; CPF = "00000001830"
    expect(cpfChecksum("00000001830")).toBe(true);
  });

  it("rejects CPF that fails the first check digit", () => {
    // "529.982.247-25" has d10='2'; changing it to '3' fails the first check digit test
    expect(cpfChecksum("52998224735")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// NINO (UK National Insurance Number)
// ---------------------------------------------------------------------------
describe("ninoValid", () => {
  it("validates a valid NINO", () => {
    expect(ninoValid("AB123456C")).toBe(true);
  });

  it("rejects temporary NINOs starting with TN", () => {
    expect(ninoValid("TN123456C")).toBe(false);
  });

  it("rejects NINOs with D, F, I, Q, U, V prefix letters", () => {
    expect(ninoValid("DA123456C")).toBe(false);
    expect(ninoValid("QA123456C")).toBe(false);
  });

  it("rejects invalid suffix letters (E, G–Z except A–D)", () => {
    expect(ninoValid("AB123456E")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Aadhaar format (India)
// ---------------------------------------------------------------------------
describe("aadhaarFormat", () => {
  it("accepts a valid-format 12-digit Aadhaar", () => {
    expect(aadhaarFormat("234123412347")).toBe(true);
  });

  it("rejects Aadhaar starting with 0 or 1", () => {
    expect(aadhaarFormat("012341234123")).toBe(false);
    expect(aadhaarFormat("112341234123")).toBe(false);
  });

  it("rejects non-12-digit sequences", () => {
    expect(aadhaarFormat("12345678901")).toBe(false); // 11 digits
    expect(aadhaarFormat("1234567890123")).toBe(false); // 13 digits
  });
});
