import { describe, it, expect, vi } from "vitest";
import { anonymize, createAnonymizer } from "../src/anonymize.js";
import { UnknownCategoryError, UnsupportedStrategyError, ValidationError } from "../src/errors.js";
import { cpfChecksum } from "../src/validators.js";
import type { AnonymaPlugin, Detector, PiiCategory } from "../src/types.js";

/** A detector that reports every match of `pattern` as `category`. */
function regexDetector(category: PiiCategory, pattern: RegExp): Detector {
  return (text) =>
    [...text.matchAll(pattern)].map((m) => ({
      category,
      value: m[0],
      start: m.index ?? 0,
      end: (m.index ?? 0) + m[0].length,
      confidence: 0.95,
    }));
}

/** Finds case numbers of a made-up organisation, which no built-in detector finds. */
const acme: AnonymaPlugin = {
  name: "acme",
  detectors: { "case-number": regexDetector("case-number", /\bACME-\d{6}\b/g) },
  strategies: {
    "keep-domain": (value, options) =>
      `${String(options?.["user"] ?? "[USER]")}@${value.slice(value.indexOf("@") + 1)}`,
  },
};

const CPF_FORMAT = /^\d{3}\.\d{3}\.\d{3}-\d{2}$/;

/** Keeps a CPF-shaped national ID only when its check digits are right. */
const cpf: AnonymaPlugin = {
  name: "cpf",
  validators: { "national-id": (value) => !CPF_FORMAT.test(value) || cpfChecksum(value) },
};

describe("createAnonymizer() — plugins", () => {
  describe("detectors", () => {
    it("replaces the built-in detector of its category in every method", async () => {
      const anonymizer = createAnonymizer({ categories: ["case-number"], plugins: [acme] });
      const text = "Case ACME-004211 was opened";

      expect(anonymizer.detect(text)).toEqual([
        { category: "case-number", value: "ACME-004211", start: 5, end: 16, confidence: 0.95 },
      ]);
      expect(anonymizer.hasPII(text)).toBe(true);
      expect(anonymizer.anonymize(text).text).toBe("Case [REDACTED] was opened");
      expect((await anonymizer.anonymizeAsync(text)).text).toBe("Case [REDACTED] was opened");
      expect(anonymizer.anonymizeObject({ notes: [text] })).toEqual({
        notes: ["Case [REDACTED] was opened"],
      });
      expect(anonymizer.tokenize(text).text).toBe("Case [CASE_NUMBER_0001] was opened");
    });

    it("is used on the asynchronous path of anonymizeAsync()", async () => {
      const anonymizer = createAnonymizer({ categories: ["case-number"], plugins: [acme] });
      const { text } = await anonymizer.anonymizeAsync("Case ACME-004211", {
        rules: [{ category: "case-number", strategy: { strategy: "hash" } }],
      });
      expect(text).toMatch(/^Case [0-9a-f]{16}$/);
    });

    it("leaves the other categories to the built-in detectors", () => {
      const anonymizer = createAnonymizer({
        categories: ["case-number", "email"],
        plugins: [acme],
      });
      expect(anonymizer.anonymize("ACME-004211 from alice@example.com").text).toBe(
        "[REDACTED] from [REDACTED]",
      );
    });

    it("runs only for the categories the anonymizer detects", () => {
      const anonymizer = createAnonymizer({ categories: ["email"], plugins: [acme] });
      expect(anonymizer.anonymize("ACME-004211").text).toBe("ACME-004211");
      expect(anonymizer.hasPII("ACME-004211")).toBe(false);
    });

    it("gives the customDetectors of the configuration precedence", () => {
      const anonymizer = createAnonymizer({
        categories: ["case-number"],
        customDetectors: { "case-number": () => [] },
        plugins: [acme],
      });
      expect(anonymizer.anonymize("ACME-004211").text).toBe("ACME-004211");
      expect(anonymizer.detect("ACME-004211")).toEqual([]);
    });

    it("stays in use when a call passes customDetectors of its own", () => {
      const anonymizer = createAnonymizer({
        categories: ["case-number", "email"],
        plugins: [acme],
      });
      const noEmails = { email: (): [] => [] };

      expect(
        anonymizer.anonymize("ACME-004211 from alice@example.com", { customDetectors: noEmails })
          .text,
      ).toBe("[REDACTED] from alice@example.com");
      expect(
        anonymizer.tokenize("ACME-004211 from alice@example.com", { customDetectors: noEmails })
          .text,
      ).toBe("[CASE_NUMBER_0001] from alice@example.com");
    });

    it("replaces the aggressive detector of its category", () => {
      const quiet: AnonymaPlugin = { name: "quiet", detectors: { email: () => [] } };
      const obfuscated = "Write to user [at] example [dot] com";

      expect(
        createAnonymizer({ categories: ["email"], aggressive: true }).detect(obfuscated),
      ).not.toEqual([]);
      expect(
        createAnonymizer({ categories: ["email"], aggressive: true, plugins: [quiet] }).detect(
          obfuscated,
        ),
      ).toEqual([]);
    });

    it("merges the detectors of several plugins", () => {
      const corp: AnonymaPlugin = {
        name: "corp",
        detectors: { email: regexDetector("email", /\b\w+@corp\.example\b/g) },
      };
      const anonymizer = createAnonymizer({
        categories: ["case-number", "email"],
        plugins: [acme, corp],
      });
      expect(anonymizer.anonymize("ACME-004211 bob@corp.example alice@example.com").text).toBe(
        "[REDACTED] [REDACTED] alice@example.com",
      );
    });

    it("throws UnknownCategoryError for a detector of a category that is not built in", () => {
      expect(() =>
        createAnonymizer({ plugins: [{ name: "ids", detectors: { "employee-id": () => [] } }] }),
      ).toThrow(UnknownCategoryError);
    });

    it("throws UnknownCategoryError for a detector named like an Object.prototype member", () => {
      expect(() =>
        createAnonymizer({ plugins: [{ name: "odd", detectors: { toString: () => [] } }] }),
      ).toThrow(UnknownCategoryError);
    });

    it("throws ValidationError when two plugins register a detector for a category", () => {
      const other: AnonymaPlugin = { name: "other", detectors: { "case-number": () => [] } };
      expect(() => createAnonymizer({ plugins: [acme, other] })).toThrow(ValidationError);
      expect(() => createAnonymizer({ plugins: [acme, other] })).toThrow(
        /plugins\[1\]\.detectors\.case-number.*"acme"/,
      );
    });
  });

  describe("strategies", () => {
    it("applies a plugin strategy that a rule names", () => {
      const anonymizer = createAnonymizer({ plugins: [acme] });
      const { text } = anonymizer.anonymize("Mail alice@example.com", {
        rules: [{ category: "email", strategy: { strategy: "keep-domain" } }],
      });
      expect(text).toBe("Mail [USER]@example.com");
    });

    it("passes the options of the strategy options to the strategy function", () => {
      const upper = vi.fn((value: string) => value.toUpperCase());
      const anonymizer = createAnonymizer({ plugins: [{ name: "upper", strategies: { upper } }] });

      anonymizer.anonymize("alice@example.com", {
        rules: [{ category: "email", strategy: { strategy: "upper", options: { level: 2 } } }],
      });
      expect(upper).toHaveBeenLastCalledWith("alice@example.com", { level: 2 });

      anonymizer.anonymize("alice@example.com", {
        rules: [{ category: "email", strategy: { strategy: "upper" } }],
      });
      expect(upper).toHaveBeenLastCalledWith("alice@example.com", undefined);
    });

    it("applies a plugin strategy given as the default strategy", () => {
      const anonymizer = createAnonymizer({
        categories: ["email"],
        defaultStrategy: { strategy: "keep-domain", options: { user: "someone" } },
        plugins: [acme],
      });
      expect(anonymizer.anonymize("alice@example.com").text).toBe("someone@example.com");
    });

    it("applies plugin strategies next to built-in ones", () => {
      const anonymizer = createAnonymizer({ plugins: [acme] });
      const { text } = anonymizer.anonymize("ACME-004211 alice@example.com", {
        rules: [
          { category: "case-number", strategy: { strategy: "mask", keepTrailing: 4 } },
          { category: "email", strategy: { strategy: "keep-domain" } },
        ],
      });
      expect(text).toBe("*******4211 [USER]@example.com");
    });

    it("applies plugin strategies in anonymizeAsync(), next to an asynchronous strategy or not", async () => {
      const anonymizer = createAnonymizer({ plugins: [acme] });
      const keepDomain = { category: "email", strategy: { strategy: "keep-domain" } } as const;

      expect(
        (await anonymizer.anonymizeAsync("alice@example.com", { rules: [keepDomain] })).text,
      ).toBe("[USER]@example.com");
      const { text } = await anonymizer.anonymizeAsync("ACME-004211 alice@example.com", {
        rules: [{ category: "case-number", strategy: { strategy: "hash" } }, keepDomain],
      });
      expect(text).toMatch(/^[0-9a-f]{16} \[USER\]@example\.com$/);
    });

    it("applies plugin strategies in anonymizeObject()", () => {
      const anonymizer = createAnonymizer({
        categories: ["email"],
        defaultStrategy: { strategy: "keep-domain" },
        plugins: [acme],
      });
      expect(anonymizer.anonymizeObject({ user: { contacts: ["alice@example.com"] } })).toEqual({
        user: { contacts: ["[USER]@example.com"] },
      });
    });

    it("applies plugin strategies in anonymizeRecord()", () => {
      const anonymizer = createAnonymizer({ plugins: [acme] });
      const record = anonymizer.anonymizeRecord(
        { email: "alice@example.com", age: 27 },
        {
          email: { strategy: { strategy: "keep-domain" } },
          age: { strategy: { strategy: "generalize" } },
        },
      );
      expect(record).toEqual({ email: "[USER]@example.com", age: "20-29" });
    });

    it("throws UnsupportedStrategyError on creation for a default strategy that no plugin registers", () => {
      expect(() => createAnonymizer({ defaultStrategy: { strategy: "keep-domain" } })).toThrow(
        UnsupportedStrategyError,
      );
    });

    it("throws UnsupportedStrategyError when a rule names a strategy that no plugin registers", () => {
      const anonymizer = createAnonymizer({ plugins: [acme] });
      expect(() =>
        anonymizer.anonymize("alice@example.com", {
          rules: [{ category: "email", strategy: { strategy: "keep-user" } }],
        }),
      ).toThrow(UnsupportedStrategyError);
    });

    it("throws ValidationError, without the value, when a strategy returns no string", () => {
      const broken = {
        name: "broken",
        strategies: { broken: () => undefined },
      } as unknown as AnonymaPlugin;
      const anonymizer = createAnonymizer({
        categories: ["email"],
        defaultStrategy: { strategy: "broken" },
        plugins: [broken],
      });

      let error: unknown;
      try {
        anonymizer.anonymize("alice@example.com");
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(ValidationError);
      expect((error as ValidationError).field).toBe("strategies.broken");
      expect((error as ValidationError).message).not.toContain("alice");
    });

    it("throws ValidationError for a strategy with the name of a built-in one", () => {
      expect(() =>
        createAnonymizer({ plugins: [{ name: "x", strategies: { mask: (value) => value } }] }),
      ).toThrow(/plugins\[0\]\.strategies\.mask/);
    });

    it("throws ValidationError when two plugins register a strategy under one name", () => {
      const other: AnonymaPlugin = { name: "other", strategies: { "keep-domain": (v) => v } };
      expect(() => createAnonymizer({ plugins: [acme, other] })).toThrow(ValidationError);
      expect(() => createAnonymizer({ plugins: [acme, other] })).toThrow(
        /plugins\[1\]\.strategies\.keep-domain.*"acme"/,
      );
    });
  });

  describe("validators", () => {
    it("drops the matches that a validator rejects, in every method", async () => {
      const anonymizer = createAnonymizer({ categories: ["national-id"], plugins: [cpf] });
      const text = "CPF 529.982.247-25, ref 529.982.247-26";

      expect(anonymizer.detect(text).map((m) => m.value)).toEqual(["529.982.247-25"]);
      expect(anonymizer.hasPII(text)).toBe(true);
      expect(anonymizer.hasPII("ref 529.982.247-26")).toBe(false);
      expect(anonymizer.anonymize(text, { includeMatches: true })).toEqual({
        text: "CPF [REDACTED], ref 529.982.247-26",
        matches: [anonymizer.detect(text)[0]],
      });
      expect((await anonymizer.anonymizeAsync(text)).text).toBe(
        "CPF [REDACTED], ref 529.982.247-26",
      );
      expect(anonymizer.tokenize(text).tokens.map((t) => t.original)).toEqual(["529.982.247-25"]);
    });

    it("is applied on the asynchronous path of anonymizeAsync()", async () => {
      const anonymizer = createAnonymizer({
        categories: ["national-id"],
        defaultStrategy: { strategy: "hash" },
        plugins: [cpf],
      });
      const { text } = await anonymizer.anonymizeAsync("529.982.247-25 529.982.247-26");
      expect(text).toMatch(/^[0-9a-f]{16} 529\.982\.247-26$/);
    });

    it("requires every validator of the category to accept a match", () => {
      const notTwentyFive: AnonymaPlugin = {
        name: "not-25",
        validators: { "national-id": (value) => !value.endsWith("-25") },
      };
      const anonymizer = createAnonymizer({
        categories: ["national-id"],
        plugins: [cpf, notTwentyFive],
      });
      expect(anonymizer.detect("529.982.247-25 529.982.247-26")).toEqual([]);
    });

    it("checks the matches of customDetectors and plugin detectors too", () => {
      const anonymizer = createAnonymizer({
        categories: ["case-number", "email"],
        customDetectors: { email: regexDetector("email", /\S+@\S+/g) },
        plugins: [
          acme,
          {
            name: "checks",
            validators: {
              "case-number": (value) => value.endsWith("1"),
              email: (value) => value.endsWith(".com"),
            },
          },
        ],
      });
      expect(anonymizer.anonymize("ACME-004211 ACME-004212 a@example.com b@example.org").text).toBe(
        "[REDACTED] ACME-004212 [REDACTED] b@example.org",
      );
    });

    it("drops a rejected match before overlapping matches are resolved", () => {
      const anonymizer = createAnonymizer({
        categories: ["case-number", "tracking-number"],
        plugins: [
          acme,
          {
            name: "tracking",
            detectors: { "tracking-number": regexDetector("tracking-number", /\d{6}/g) },
            validators: { "case-number": () => false },
          },
        ],
      });
      // Without the validator the case number would hide the overlapping tracking number.
      expect(anonymizer.anonymize("ACME-004211").text).toBe("ACME-[REDACTED]");
    });

    it("throws UnknownCategoryError for a validator of a category that is not built in", () => {
      expect(() =>
        createAnonymizer({ plugins: [{ name: "cpf", validators: { cpf: () => true } }] }),
      ).toThrow(UnknownCategoryError);
    });
  });

  describe("names", () => {
    it("throws ValidationError when two plugins have the same name", () => {
      expect(() => createAnonymizer({ plugins: [acme, { name: "acme" }] })).toThrow(
        /plugins\[1\]\.name/,
      );
    });

    it("throws ValidationError for a plugin without a name", () => {
      expect(() => createAnonymizer({ plugins: [{ name: "" }] })).toThrow(ValidationError);
      expect(() => createAnonymizer({ plugins: [{} as AnonymaPlugin] })).toThrow(ValidationError);
    });
  });

  it("changes nothing for a plugin that registers nothing", () => {
    const anonymizer = createAnonymizer({ categories: ["email"], plugins: [{ name: "empty" }] });
    expect(anonymizer.anonymize("alice@example.com").text).toBe("[REDACTED]");
  });

  it("keeps the plugins of an anonymizer to its own methods", () => {
    createAnonymizer({ categories: ["case-number"], plugins: [acme] });

    expect(createAnonymizer({ categories: ["case-number"] }).anonymize("ACME-004211").text).toBe(
      "ACME-004211",
    );
    expect(
      anonymize("ACME-004211", {
        rules: [{ category: "case-number", strategy: { strategy: "redact" } }],
      }).text,
    ).toBe("ACME-004211");
    expect(() =>
      anonymize("alice@example.com", {
        rules: [{ category: "email", strategy: { strategy: "keep-domain" } as never }],
      }),
    ).toThrow(UnsupportedStrategyError);
  });
});
