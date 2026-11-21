/**
 * Tests for the Brazilian and European formats added in 1.3.0: phone numbers,
 * street addresses, RG, CNPJ, PIX keys and payloads, ABA check digits, and the
 * checksum-validating national-ID detector. All values are synthetic.
 */
import { describe, expect, it } from "vitest";
import { anonymize } from "../src/index.js";
import {
  detectAddress,
  detectBankAccount,
  detectNationalId,
  detectNationalIdStrict,
  detectPhone,
  detectTaxId,
} from "../src/detectors/index.js";
import { pixPayload } from "./fixtures/pix.js";

const values = (matches: readonly { value: string }[]): string[] => matches.map((m) => m.value);

describe("detectPhone", () => {
  it.each([
    "+55 11 91234-5678",
    "+55 (11) 91234-5678",
    "(11) 91234-5678",
    "(21) 3456-7890",
    "(011) 3456 7890",
    "11 91234-5678",
    "021 3456 7890",
  ])("finds the Brazilian number %s whole", (phone) => {
    expect(values(detectPhone(`Ligue ${phone} hoje`))).toEqual([phone]);
  });

  it.each([
    ["France", "06 12 34 56 78"],
    ["France", "01.23.45.67.89"],
    ["United Kingdom", "020 7946 0958"],
    ["United Kingdom", "0161 496 0000"],
    ["United Kingdom", "07700 900123"],
    ["Spain", "612 34 56 78"],
    ["Spain", "91 123 45 67"],
    ["Italy", "06 1234 5678"],
    ["Germany", "030 12345678"],
    ["Germany", "089/1234567"],
  ])("finds a national number of %s: %s", (_country, phone) => {
    expect(values(detectPhone(`Tel. ${phone}.`))).toEqual([phone]);
  });

  it("does not take a longer run of digit groups for a phone number", () => {
    expect(detectPhone("order 0123 456789 12")).toEqual([]);
    expect(detectPhone("01 23 45 67 89 10")).toEqual([]);
  });

  it("does not take years, ISSNs or references for phone numbers", () => {
    expect(detectPhone("ISSN 1234-5678, ref 2023-0001, page 12")).toEqual([]);
  });

  it("reports a national number once when an international match covers it", () => {
    const found = detectPhone("+44 020 7946 0958");
    expect(values(found)).toEqual(["+44 020 7946 0958"]);
  });

  it("gives national numbers a lower confidence than international ones", () => {
    const [national] = detectPhone("030 12345678");
    expect(national?.confidence).toBeLessThan(0.9);
  });
});

describe("detectAddress", () => {
  it.each([
    ["Musterstraße 12, 10115 Berlin", "Ich wohne in der Musterstraße 12, 10115 Berlin."],
    ["Berliner Str. 5a", "Adresse: Berliner Str. 5a"],
    ["Hauptstrasse 7", "Hauptstrasse 7"],
    ["Kerkstraat 12, 1012 AB Amsterdam", "Kerkstraat 12, 1012 AB Amsterdam"],
    ["Storgatan 3", "Bor på Storgatan 3"],
    ["12 rue de la Paix, 75002 Paris", "Il habite au 12 rue de la Paix, 75002 Paris."],
    ["5 bis avenue Foch", "5 bis avenue Foch"],
    ["Calle Mayor 5, 28013 Madrid", "Vive en Calle Mayor 5, 28013 Madrid"],
    ["Via Roma 10", "Abita in Via Roma 10"],
    ["Av. Paulista, 1578, 01310-100 São Paulo", "Av. Paulista, 1578, 01310-100 São Paulo"],
    ["Rua das Flores, nº 123", "Mora na Rua das Flores, nº 123"],
    ["Rua Augusta 100, 1000-001 Lisboa", "Rua Augusta 100, 1000-001 Lisboa"],
  ])("finds %s", (address, text) => {
    expect(values(detectAddress(text))).toEqual([address]);
  });

  it("ignores street types in ordinary sentences", () => {
    for (const text of [
      "We met via Zoom 3 times",
      "Plaza Hotel",
      "Use Via 2 for this",
      "The weg 5 is",
      "rue 5",
    ]) {
      expect(detectAddress(text)).toEqual([]);
    }
  });
});

describe("detectNationalId: Brazilian RG", () => {
  it("finds an RG after a label", () => {
    for (const text of [
      "RG: 12.345.678-9",
      "Identidade nº 12.345.678-X",
      "registro geral 123456789",
    ]) {
      expect(detectNationalId(text)).toHaveLength(1);
    }
  });

  it("ignores the same digits without a label", () => {
    expect(detectNationalId("Pedido 12.345.678-9")).toEqual([]);
  });
});

describe("detectNationalIdStrict", () => {
  it("keeps numbers whose check digits hold", () => {
    const text = [
      "CPF 529.982.247-25",
      "SIN 046 454 286",
      "NINO AB 12 34 56 C",
      "Aadhaar 2345 6789 0124",
      "personnummer 811218-9876",
      "DNI 12345678Z",
      "CF RSSMRA85T10A562S",
      "NIR 2 84 05 75 123 456 72",
    ].join("; ");
    expect(values(detectNationalIdStrict(text))).toEqual([
      "046 454 286",
      "AB 12 34 56 C",
      "2345 6789 0124",
      "529.982.247-25",
      "811218-9876",
      "12345678Z",
      "RSSMRA85T10A562S",
      "2 84 05 75 123 456 72",
    ]);
  });

  it("discards numbers whose check digits fail, which the 1.x detector reports", () => {
    const text =
      "CPF 529.982.247-26, DNI 12345678A, CF RSSMRA85T10A562T, NIR 2 84 05 75 123 456 73";
    expect(detectNationalIdStrict(text)).toEqual([]);
    expect(detectNationalId(text)).toHaveLength(4);
  });

  it("validates the formats that need a label", () => {
    expect(values(detectNationalIdStrict("national ID: 11010519491231002X"))).toEqual([
      "11010519491231002X",
    ]);
    expect(detectNationalIdStrict("national ID: 110105194912310021")).toEqual([]);
    expect(values(detectNationalIdStrict("ID number: 8001015009087"))).toEqual(["8001015009087"]);
    expect(values(detectNationalIdStrict("ID number: 111222333"))).toEqual(["111222333"]);
  });

  it("lets a number that fails one country's check be another country's", () => {
    // 100 000 001 fails the Luhn check of a Canadian SIN but is a valid Australian TFN.
    const [found] = detectNationalIdStrict("national ID: 100 000 001");
    expect(found?.value).toBe("100 000 001");
  });

  it("reports formats without check digits as the 1.x detector does", () => {
    expect(detectNationalIdStrict("RG: 12.345.678-9")).toEqual(
      detectNationalId("RG: 12.345.678-9"),
    );
  });
});

describe("detectTaxId: CNPJ", () => {
  it("finds a punctuated CNPJ, numeric or alphanumeric, without a label", () => {
    expect(values(detectTaxId("Empresa 11.222.333/0001-81 e 12.ABC.345/01DE-35"))).toEqual([
      "11.222.333/0001-81",
      "12.ABC.345/01DE-35",
    ]);
  });

  it("finds a bare CNPJ after a label", () => {
    expect(values(detectTaxId("CNPJ: 11222333000181"))).toEqual(["11222333000181"]);
    expect(detectTaxId("Pedido 11222333000181")).toEqual([]);
  });

  it("ignores a CNPJ whose check digits fail", () => {
    expect(detectTaxId("CNPJ 11.222.333/0001-82")).toEqual([]);
    expect(detectTaxId("CNPJ: 11222333000182")).toEqual([]);
  });
});

describe("detectBankAccount: PIX", () => {
  it("finds a PIX payload whose CRC holds, whole", () => {
    const payload = pixPayload();
    const found = detectBankAccount(`Pague com: ${payload} obrigado`);
    expect(values(found)).toContain(payload);
    expect(found.find((m) => m.value === payload)?.confidence).toBe(0.97);
  });

  it("accepts the PIX identifier in capitals", () => {
    const payload = pixPayload("fulano@example.com", "BR.GOV.BCB.PIX");
    expect(values(detectBankAccount(payload))).toContain(payload);
  });

  it("finds two payloads in a row", () => {
    const first = pixPayload("fulano@example.com");
    const second = pixPayload("beltrano@example.com");
    const found = values(detectBankAccount(`${first}\n${second}`));
    expect(found).toContain(first);
    expect(found).toContain(second);
  });

  it("ignores a payload that was altered, or that is not a PIX payload", () => {
    const altered = pixPayload().replace("FULANO", "BELTRANO");
    expect(values(detectBankAccount(altered))).not.toContain(altered);
    const other = pixPayload().replace("br.gov.bcb.pix", "br.gov.bcb.xyz");
    expect(values(detectBankAccount(other))).not.toContain(other);
  });

  it("stops at text that cannot be part of a payload", () => {
    const payload = pixPayload();
    const broken = `${payload.slice(0, 20)}é${payload.slice(20)}`;
    expect(values(detectBankAccount(broken))).not.toContain(broken);
  });

  it("finds a random key after a PIX label only", () => {
    const key = "123e4567-e89b-42d3-a456-426614174000";
    expect(values(detectBankAccount(`Chave PIX: ${key}`))).toEqual([key]);
    expect(values(detectBankAccount(`chave aleatória ${key}`))).toEqual([key]);
    expect(detectBankAccount(`request id ${key}`)).toEqual([]);
    expect(detectBankAccount(`${key} is not a chave PIX`)).toEqual([]);
    expect(
      detectBankAccount(`Chave PIX: see the message that we sent you earlier, ${key}`),
    ).toEqual([]);
  });
});

describe("detectBankAccount: ABA routing numbers", () => {
  it("gives valid check digits a higher confidence", () => {
    const [valid] = detectBankAccount("routing number: 011000015");
    const [invalid] = detectBankAccount("routing number: 011000016");
    expect(valid?.confidence).toBe(0.9);
    expect(invalid?.confidence).toBe(0.85);
  });
});

describe("anonymize with the new formats", () => {
  it("redacts a Brazilian record under the LGPD preset", () => {
    const text =
      "Cliente: CPF 529.982.247-25, RG: 12.345.678-9, tel. (11) 91234-5678, " +
      "Rua das Flores, nº 123, empresa 11.222.333/0001-81.";
    const result = anonymize(text, { preset: "lgpd" });
    for (const value of [
      "529.982.247-25",
      "12.345.678-9",
      "91234-5678",
      "Rua das Flores",
      "11.222.333/0001-81",
    ]) {
      expect(result.text).not.toContain(value);
    }
  });
});
