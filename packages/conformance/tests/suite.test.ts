import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  OPERATIONS,
  SCHEMA_URL,
  SUITE_URL,
  compareResult,
  jsonEqual,
  loadSuite,
  parseSuite,
  runCase,
  utf16ToCodePoints,
} from "../src/index.js";
import type { Adapter, ConformanceCase } from "../src/index.js";

const raw = JSON.parse(readFileSync(SUITE_URL, "utf8")) as Record<string, unknown>;
const schema = JSON.parse(readFileSync(SCHEMA_URL, "utf8")) as {
  $defs: {
    case: { properties: { op: { enum: string[] }; id: { pattern: string } } };
    capability: { pattern: string };
  };
};

describe("suite file", () => {
  const suite = loadSuite();

  it("lists the operations the runners implement", () => {
    expect(schema.$defs.case.properties.op.enum).toEqual([...OPERATIONS]);
  });

  it("names every case and capability in the form the schema requires", () => {
    const id = new RegExp(schema.$defs.case.properties.id.pattern);
    const capability = new RegExp(schema.$defs.capability.pattern);
    for (const testCase of suite.cases) {
      expect(testCase.id).toMatch(id);
      for (const required of testCase.requires) expect(required).toMatch(capability);
    }
  });

  it("covers every operation", () => {
    expect(new Set(suite.cases.map((testCase) => testCase.op))).toEqual(new Set(OPERATIONS));
  });

  it("covers the detectors, checksums, presets and token edge cases the specification lists", () => {
    const ids = suite.cases.map((testCase) => testCase.id);
    const covered = (prefix: string): boolean => ids.some((id) => id.startsWith(prefix));
    for (const prefix of [
      "detect.email.",
      "detect.ipv4.",
      "detect.ipv6.",
      "detect.credit-card.",
      "detect.ssn.",
      "detect.iban.",
      "detect.national-id.cpf",
      "detect.tax-id.cnpj",
      "detect.bank-account.pix",
      "validate.luhn.",
      "validate.cpf.",
      "validate.cnpj.",
      "validate.iban.",
      "restore.overlapping-numbers",
      "preset.lgpd",
      "preset.gdpr",
      "preset.hipaa",
      "receipt.sign",
    ]) {
      expect(covered(prefix), prefix).toBe(true);
    }
  });

  it("states offsets in code points, after a character outside the BMP", () => {
    const testCase = suite.cases.find((entry) => entry.id === "detect.email.astral-offsets");
    expect(testCase?.expected).toMatchObject({ matches: [{ start: 2, end: 19 }] });
  });
});

describe("parseSuite", () => {
  const valid = { ...raw };

  it("accepts the suite file", () => {
    expect(parseSuite(valid).cases.length).toBeGreaterThan(0);
  });

  it.each([
    ["not an object", [], /JSON object/],
    ["another suite", { ...valid, suite: "x" }, /suite/],
    ["no version", { ...valid, version: 1 }, /version/],
    ["other offsets", { ...valid, offsets: "utf-16" }, /offsets/],
    ["no cases", { ...valid, cases: {} }, /cases/],
    ["a case that is not an object", { ...valid, cases: [1] }, /case 0/],
    ["a case without id", { ...valid, cases: [{ id: "" }] }, /no id/],
  ])("rejects %s", (_name, json, message) => {
    expect(() => parseSuite(json)).toThrow(message);
  });

  const base = {
    id: "x.y",
    description: "d",
    op: "digest",
    requires: ["receipt"],
    input: { text: "" },
    expected: { hex: "0".repeat(64) },
  };

  it.each([
    ["a duplicate id", [base, base], /duplicate/],
    ["no description", [{ ...base, description: 1 }], /description/],
    ["an unknown operation", [{ ...base, op: "nope" }], /unknown operation/],
    ["no capabilities", [{ ...base, requires: [] }], /requires/],
    ["an input that is not an object", [{ ...base, input: [] }], /input/],
  ])("rejects %s", (_name, cases, message) => {
    expect(() => parseSuite({ ...valid, cases })).toThrow(message);
  });
});

describe("compareResult", () => {
  const detectCase: ConformanceCase = {
    id: "d",
    description: "d",
    op: "detect",
    requires: ["detect:email"],
    input: {},
    expected: {
      matches: [{ category: "email", value: "a@example.com", start: 0, end: 13, confidence: 0.99 }],
    },
  };

  it("tolerates rounding in confidence values", () => {
    const actual = {
      matches: [
        { category: "email", value: "a@example.com", start: 0, end: 13, confidence: 0.99 + 1e-12 },
      ],
    };
    expect(compareResult(detectCase, actual)).toEqual([]);
  });

  it("reports each difference of a match", () => {
    const actual = {
      matches: [{ category: "ssn", value: "a@example.com", start: 1, end: 13, confidence: 0.5 }],
    };
    expect(compareResult(detectCase, actual)).toHaveLength(3);
  });

  it("reports missing and unexpected matches", () => {
    expect(compareResult(detectCase, { matches: [] })[1]).toMatch(/missing match/);
    const extra = { matches: [...(detectCase.expected["matches"] as unknown[]), { x: 1 }] };
    expect(compareResult(detectCase, extra)[1]).toMatch(/unexpected match/);
    expect(compareResult(detectCase, { matches: "x" })[0]).toMatch(/matches/);
    expect(compareResult(detectCase, { matches: [1] })[0]).toMatch(/match 0/);
    expect(compareResult(detectCase, "x")[0]).toMatch(/expected an object/);
  });

  it("compares mappings and vaults as sets", () => {
    const shield: ConformanceCase = {
      ...detectCase,
      op: "shield",
      expected: {
        text: "t",
        vault: [
          ["a", "1"],
          ["b", "2"],
        ],
      },
    };
    expect(
      compareResult(shield, {
        text: "t",
        vault: [
          ["b", "2"],
          ["a", "1"],
        ],
      }),
    ).toEqual([]);
    expect(compareResult(shield, { text: "t", vault: [["a", "1"]] })).toHaveLength(1);
  });

  it("matches a text pattern", () => {
    const anonymizeCase: ConformanceCase = {
      ...detectCase,
      op: "anonymize",
      expected: { textPattern: "^id_[0-9a-f]{4}$" },
    };
    expect(compareResult(anonymizeCase, { text: "id_00ff" })).toEqual([]);
    expect(compareResult(anonymizeCase, { text: "id_" })).toHaveLength(1);
    const exact: ConformanceCase = { ...anonymizeCase, expected: { text: "x" } };
    expect(compareResult(exact, { text: "x" })).toEqual([]);
  });

  it("requires an issued receipt to hold the expected members and to verify", () => {
    const issue: ConformanceCase = {
      ...detectCase,
      op: "receipt.issue",
      expected: { receipt: { v: 1, total: 2 } },
    };
    expect(compareResult(issue, { receipt: { v: 1, total: 2, id: "x" }, verified: true })).toEqual(
      [],
    );
    expect(compareResult(issue, { receipt: { v: 1, total: 3 }, verified: false })).toHaveLength(2);
    expect(compareResult(issue, { receipt: 1 })).toHaveLength(1);
  });
});

describe("runCase", () => {
  const testCase: ConformanceCase = {
    id: "c",
    description: "d",
    op: "digest",
    requires: ["receipt"],
    input: { text: "" },
    expected: { hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  };

  it("skips a case that needs a capability the implementation lacks", async () => {
    const adapter: Adapter = { name: "none", provides: () => false, run: () => ({}) };
    expect(await runCase(testCase, adapter)).toEqual({
      id: "c",
      status: "skipped",
      missing: ["receipt"],
    });
  });

  it("fails a case whose operation throws", async () => {
    const adapter: Adapter = {
      name: "throws",
      provides: () => true,
      run: () => {
        throw new RangeError("boom");
      },
    };
    expect(await runCase(testCase, adapter)).toEqual({
      id: "c",
      status: "failed",
      problems: ["threw RangeError: boom"],
    });
  });
});

describe("jsonEqual", () => {
  it("ignores the order of object members, not of array items", () => {
    expect(jsonEqual({ a: 1, b: [1, 2] }, { b: [1, 2], a: 1 })).toBe(true);
    expect(jsonEqual([1, 2], [2, 1])).toBe(false);
    expect(jsonEqual({ a: 1 }, { a: 1, b: 2 })).toBe(false);
    expect(jsonEqual({ a: 1 }, { b: 1 })).toBe(false);
    expect(jsonEqual(1, "1")).toBe(false);
  });
});

describe("utf16ToCodePoints", () => {
  it("counts a surrogate pair once", () => {
    expect(utf16ToCodePoints("\u{1F4E7} a", 3)).toBe(2);
    expect(utf16ToCodePoints("abc", 2)).toBe(2);
  });

  it("counts a lone surrogate, and the first half of a pair cut by the offset, as one", () => {
    expect(utf16ToCodePoints("\uD83D", 1)).toBe(1);
    expect(utf16ToCodePoints("\u{1F4E7}", 1)).toBe(1);
    expect(utf16ToCodePoints("\uD83Dx", 2)).toBe(2);
  });
});
