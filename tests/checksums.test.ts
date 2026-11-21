/**
 * Tests for the checksum validators added in 1.3.0 and for the CHECKSUMS registry.
 * Every number is synthetic: made up so that its check digits hold.
 */
import { describe, expect, it } from "vitest";
import {
  CHECKSUMS,
  abaRoutingChecksum,
  australianTfnChecksum,
  bsnChecksum,
  chineseResidentIdChecksum,
  cnpjChecksum,
  frNirChecksum,
  imeiChecksum,
  italianFiscalCodeChecksum,
  npiChecksum,
  pixPayloadChecksum,
  ptNifChecksum,
  spanishIdChecksum,
  swedishPersonnummerChecksum,
} from "../src/validators.js";
import { crc16, pixPayload } from "./fixtures/pix.js";

describe("crc16 test helper", () => {
  it("computes the standard check value", () => {
    expect(crc16("123456789")).toBe("29B1");
  });
});

describe("abaRoutingChecksum", () => {
  it("accepts a routing number whose 3-7-1 sum is a multiple of 10", () => {
    expect(abaRoutingChecksum("011000015")).toBe(true);
    expect(abaRoutingChecksum("0110-0001 5")).toBe(true);
  });
  it("rejects a wrong check digit, a wrong length and a repeated digit", () => {
    expect(abaRoutingChecksum("011000016")).toBe(false);
    expect(abaRoutingChecksum("01100001")).toBe(false);
    expect(abaRoutingChecksum("000000000")).toBe(false);
  });
});

describe("cnpjChecksum", () => {
  it("accepts numeric and alphanumeric CNPJs, with or without punctuation", () => {
    expect(cnpjChecksum("11.222.333/0001-81")).toBe(true);
    expect(cnpjChecksum("11222333000181")).toBe(true);
    expect(cnpjChecksum("12.ABC.345/01DE-35")).toBe(true);
    expect(cnpjChecksum("12abc34501de35")).toBe(true);
  });
  it("uses 0 as the check digit when the remainder is below 2", () => {
    expect(cnpjChecksum("11.222.333/0005-05")).toBe(true);
    expect(cnpjChecksum("11.222.333/0005-15")).toBe(false);
  });
  it("rejects a wrong first or second check digit", () => {
    expect(cnpjChecksum("11.222.333/0001-91")).toBe(false);
    expect(cnpjChecksum("11.222.333/0001-82")).toBe(false);
  });
  it("rejects letters in the check digits, a wrong length and a repeated character", () => {
    expect(cnpjChecksum("11.222.333/0001-8A")).toBe(false);
    expect(cnpjChecksum("1122233300018")).toBe(false);
    expect(cnpjChecksum("00000000000000")).toBe(false);
  });
});

describe("npiChecksum", () => {
  it("accepts an NPI that passes Luhn behind the 80840 prefix", () => {
    expect(npiChecksum("1234567893")).toBe(true);
  });
  it("rejects a wrong check digit and a number not starting with 1 or 2", () => {
    expect(npiChecksum("1234567890")).toBe(false);
    expect(npiChecksum("3234567893")).toBe(false);
  });
});

describe("imeiChecksum", () => {
  it("accepts a 15-digit IMEI with separators", () => {
    expect(imeiChecksum("49-015420-323751-8")).toBe(true);
    expect(imeiChecksum("49/015420/323751/8")).toBe(true);
  });
  it("rejects a wrong check digit, a wrong length and a repeated digit", () => {
    expect(imeiChecksum("490154203237519")).toBe(false);
    expect(imeiChecksum("49015420323751")).toBe(false);
    expect(imeiChecksum("000000000000000")).toBe(false);
  });
});

describe("bsnChecksum", () => {
  it("accepts a BSN that passes the eleven test, padding 8-digit numbers", () => {
    expect(bsnChecksum("111222333")).toBe(true);
    expect(bsnChecksum("1112.22.333")).toBe(true);
    expect(bsnChecksum("12345672")).toBe(true);
  });
  it("rejects a failing number, letters and zeros", () => {
    expect(bsnChecksum("111222334")).toBe(false);
    expect(bsnChecksum("11122233A")).toBe(false);
    expect(bsnChecksum("000000000")).toBe(false);
  });
});

describe("ptNifChecksum", () => {
  it("accepts a NIF with a valid check digit", () => {
    expect(ptNifChecksum("123456789")).toBe(true);
    expect(ptNifChecksum("123 456 789")).toBe(true);
  });
  it("accepts a check digit of 0 when the remainder is below 2", () => {
    expect(ptNifChecksum("100000010")).toBe(true);
  });
  it("rejects a wrong check digit, a leading 0 and a repeated digit", () => {
    expect(ptNifChecksum("123456780")).toBe(false);
    expect(ptNifChecksum("023456789")).toBe(false);
    expect(ptNifChecksum("111111111")).toBe(false);
  });
});

describe("spanishIdChecksum", () => {
  it("accepts a DNI and an NIE of each prefix", () => {
    expect(spanishIdChecksum("12345678Z")).toBe(true);
    expect(spanishIdChecksum("12345678-z")).toBe(true);
    expect(spanishIdChecksum("X1234567L")).toBe(true);
    expect(spanishIdChecksum("Y1234567X")).toBe(true);
    expect(spanishIdChecksum("Z1234567R")).toBe(true);
  });
  it("rejects a wrong letter and a malformed number", () => {
    expect(spanishIdChecksum("12345678A")).toBe(false);
    expect(spanishIdChecksum("A1234567L")).toBe(false);
  });
});

describe("italianFiscalCodeChecksum", () => {
  it("accepts a fiscal code whose last letter is the check letter", () => {
    expect(italianFiscalCodeChecksum("RSSMRA85T10A562S")).toBe(true);
    expect(italianFiscalCodeChecksum("rssmra85t10a562s")).toBe(true);
  });
  it("rejects a wrong check letter and a wrong length", () => {
    expect(italianFiscalCodeChecksum("RSSMRA85T10A562T")).toBe(false);
    expect(italianFiscalCodeChecksum("RSSMRA85T10A562")).toBe(false);
  });
});

describe("frNirChecksum", () => {
  it("accepts a NIR whose key is 97 minus the number modulo 97", () => {
    expect(frNirChecksum("2 84 05 75 123 456 72")).toBe(true);
  });
  it("accepts the Corsican departments 2A and 2B", () => {
    expect(frNirChecksum("184052A00000057")).toBe(true);
    expect(frNirChecksum("184052B00000057")).toBe(false);
  });
  it("rejects a wrong key and a malformed number", () => {
    expect(frNirChecksum("2 84 05 75 123 456 73")).toBe(false);
    expect(frNirChecksum("3840575123456 72")).toBe(false);
  });
});

describe("chineseResidentIdChecksum", () => {
  it("accepts an ID with a check character X", () => {
    expect(chineseResidentIdChecksum("11010519491231002X")).toBe(true);
    expect(chineseResidentIdChecksum("11010519491231002x")).toBe(true);
  });
  it("rejects a wrong check character and a malformed number", () => {
    expect(chineseResidentIdChecksum("110105194912310021")).toBe(false);
    expect(chineseResidentIdChecksum("1101051949123100")).toBe(false);
  });
});

describe("australianTfnChecksum", () => {
  it("accepts a TFN whose weighted sum is a multiple of 11", () => {
    expect(australianTfnChecksum("123 456 782")).toBe(true);
  });
  it("rejects a wrong check digit, a wrong length and a repeated digit", () => {
    expect(australianTfnChecksum("123456783")).toBe(false);
    expect(australianTfnChecksum("12345678")).toBe(false);
    expect(australianTfnChecksum("000000000")).toBe(false);
  });
});

describe("swedishPersonnummerChecksum", () => {
  it("accepts the short and the long form", () => {
    expect(swedishPersonnummerChecksum("811218-9876")).toBe(true);
    expect(swedishPersonnummerChecksum("811218+9876")).toBe(true);
    expect(swedishPersonnummerChecksum("198112189876")).toBe(true);
  });
  it("rejects a wrong check digit and a wrong length", () => {
    expect(swedishPersonnummerChecksum("811218-9877")).toBe(false);
    expect(swedishPersonnummerChecksum("8112189876123")).toBe(false);
  });
});

describe("pixPayloadChecksum", () => {
  it("accepts a payload whose CRC matches, in either case", () => {
    const payload = pixPayload();
    expect(pixPayloadChecksum(payload)).toBe(true);
    expect(pixPayloadChecksum(payload.slice(0, -4) + payload.slice(-4).toLowerCase())).toBe(true);
  });
  it("rejects an altered payload and a payload without a CRC field", () => {
    const payload = pixPayload();
    expect(pixPayloadChecksum(payload.replace("FULANO", "BELTRANO"))).toBe(false);
    expect(pixPayloadChecksum(payload.slice(0, -8))).toBe(false);
  });
});

describe("CHECKSUMS", () => {
  it("names every validator", () => {
    expect(CHECKSUMS.cnpj("11.222.333/0001-81")).toBe(true);
    expect(CHECKSUMS["aba-routing"]("011000015")).toBe(true);
    expect(CHECKSUMS.luhn("4111111111111111")).toBe(true);
    expect(CHECKSUMS.iban("GB82 WEST 1234 5698 7654 32")).toBe(true);
  });
  it("checks the format and the Verhoeff digit of an Aadhaar number", () => {
    expect(CHECKSUMS.aadhaar("2345 6789 0124")).toBe(true);
    expect(CHECKSUMS.aadhaar("2345 6789 0125")).toBe(false);
    expect(CHECKSUMS.aadhaar("1345 6789 0124")).toBe(false);
  });
  it("is frozen", () => {
    expect(Object.isFrozen(CHECKSUMS)).toBe(true);
  });
});
