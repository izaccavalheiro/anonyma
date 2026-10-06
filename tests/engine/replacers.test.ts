import { describe, expect, it } from "vitest";
import { UnknownCategoryError, ValidationError } from "../../src/errors.js";
import { anonymize } from "../../src/anonymize.js";
import { decrypt } from "../../src/strategies/encrypt.js";
import {
  BUILTIN_CATEGORIES,
  LEGACY_AGGRESSIVE_DETECTORS,
  LEGACY_DETECTORS,
  builtinDetectors,
  compilePipeline,
  constant,
  encryptWith,
  generalizeWith,
  hashWith,
  maskWith,
  pseudonymizeWith,
  redactWith,
  strategyReplacer,
  synthesizeWith,
} from "../../src/engine/index.js";
import type { ReplaceContext, StrategySpec } from "../../src/engine/index.js";
import { DETECTOR_REGISTRY } from "../../src/detectors/index.js";
import type { TokenizationProvider } from "../../src/vault/types.js";

const context: ReplaceContext = {
  category: "email",
  detector: "email",
  confidence: 0.99,
  start: 0,
  end: 17,
  ordinal: 0,
  residual: false,
};
const keyBytes = new Uint8Array(32).fill(7);

describe("engine/replacers", () => {
  describe("constant", () => {
    it("returns the fixed replacement and rejects an empty one", () => {
      expect(constant("#")("alice@example.com", context)).toBe("#");
      expect(() => constant("")).toThrow(ValidationError);
      expect(() => constant("  ")).toThrow(ValidationError);
      expect(() => constant(1 as unknown as string)).toThrow(ValidationError);
    });
  });

  describe("redactWith", () => {
    it("returns the label and validates it when the replacer is created", () => {
      expect(redactWith()("alice@example.com", context)).toBe("[REDACTED]");
      expect(redactWith({ label: "[EMAIL]" })("alice@example.com", context)).toBe("[EMAIL]");
      expect(() => redactWith({ label: " " })).toThrow(ValidationError);
    });
  });

  describe("maskWith", () => {
    it("masks, and validates options when the replacer is created", () => {
      expect(maskWith({ keepTrailing: 4 })("4111111111111111", context)).toBe("************1111");
      expect(() => maskWith({ keepLeading: -1 })).toThrow(ValidationError);
    });

    it("redacts when the configuration would leave the value fully visible", () => {
      const leaky = maskWith({ keepLeading: 6, keepTrailing: 6, preserveFormat: true });
      expect(leaky("123-45-6789", context)).toBe("[REDACTED]");
      expect(leaky("", context)).toBe("");
    });
  });

  describe("pseudonymizeWith", () => {
    it("is deterministic with a seed and validates the prefix eagerly", () => {
      const replacer = pseudonymizeWith({ seed: "s", prefix: "u_" });
      expect(replacer("alice@example.com", context)).toBe(replacer("alice@example.com", context));
      expect(replacer("alice@example.com", context)).toMatch(/^u_[0-9a-f]{16}$/);
      expect(() => pseudonymizeWith({ prefix: "a b" })).toThrow(ValidationError);
    });
  });

  describe("generalizeWith", () => {
    it("buckets numbers and redacts everything else instead of passing it through", () => {
      const replacer = generalizeWith({ bucketSize: 10 });
      expect(replacer("27", context)).toBe("20-29");
      expect(replacer("alice@example.com", context)).toBe("[REDACTED]");
      expect(replacer("123-45-6789", context)).toBe("[REDACTED]");
      expect(() => generalizeWith({ bucketSize: 0 })).toThrow(ValidationError);
    });
  });

  describe("synthesizeWith", () => {
    it("generates by the category of the span, deterministically", () => {
      const replacer = synthesizeWith({ seed: "s" });
      const first = replacer("alice@example.com", context);
      expect(first).toMatch(/^[a-z.]+\d+@[a-z.]+$/);
      expect(replacer("alice@example.com", context)).toBe(first);
      expect(replacer("203.0.113.9", { ...context, category: "ipv4" })).toMatch(/^192\.0\.2\.\d+$/);
    });
  });

  describe("hashWith", () => {
    it("returns a real SHA-256 digest", async () => {
      const digest = await hashWith({ truncate: 64 })("alice@example.com", context);
      expect(digest).toBe("ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976");
    });
  });

  describe("encryptWith", () => {
    it("produces ciphertext that the 1.x decrypt() restores", async () => {
      const ciphertext = await encryptWith({ keyBytes })("alice@example.com", context);
      expect(ciphertext).toMatch(/^base64:/);
      expect(await decrypt(ciphertext, { keyBytes })).toBe("alice@example.com");
    });

    it("rejects missing key material when the replacer is created", () => {
      expect(() => encryptWith({})).toThrow(ValidationError);
      expect(() => encryptWith({ passphrase: "" })).toThrow(ValidationError);
      expect(() => encryptWith({ passphrase: "p" })).not.toThrow();
    });
  });

  describe("strategyReplacer", () => {
    it("builds every dependency-free strategy", async () => {
      const cases: [StrategySpec, RegExp][] = [
        [{ strategy: "redact" }, /^\[REDACTED\]$/],
        [{ strategy: "mask" }, /^\*+$/],
        [{ strategy: "generalize" }, /^\[REDACTED\]$/],
        [{ strategy: "pseudonymize" }, /^id_[0-9a-f]{16}$/],
        [{ strategy: "synthesize" }, /@/],
        [{ strategy: "hash" }, /^[0-9a-f]{16}$/],
      ];
      for (const [spec, shape] of cases) {
        expect(await strategyReplacer(spec)("alice@example.com", context)).toMatch(shape);
      }
    });

    it("takes secrets from the dependencies when the spec leaves them out", async () => {
      const secrets = { hashPepper: "pep", pseudonymizeSeed: "seed", synthesizeSeed: "seed" };
      const value = "alice@example.com";
      expect(await strategyReplacer({ strategy: "hash" }, { secrets })(value, context)).toBe(
        await hashWith({ pepper: "pep" })(value, context),
      );
      expect(
        await strategyReplacer({ strategy: "hash", pepper: "own" }, { secrets })(value, context),
      ).toBe(await hashWith({ pepper: "own" })(value, context));
      expect(strategyReplacer({ strategy: "pseudonymize" }, { secrets })(value, context)).toBe(
        pseudonymizeWith({ seed: "seed" })(value, context),
      );
      expect(
        strategyReplacer({ strategy: "pseudonymize", seed: "own" }, { secrets })(value, context),
      ).toBe(pseudonymizeWith({ seed: "own" })(value, context));
      expect(strategyReplacer({ strategy: "synthesize" }, { secrets })(value, context)).toBe(
        synthesizeWith({ seed: "seed" })(value, context),
      );
      expect(
        strategyReplacer({ strategy: "synthesize", seed: "own" }, { secrets })(value, context),
      ).toBe(synthesizeWith({ seed: "own" })(value, context));
    });

    it("requires a provider for tokenize and key material for encrypt", async () => {
      expect(() => strategyReplacer({ strategy: "tokenize" })).toThrow(ValidationError);
      expect(() => strategyReplacer({ strategy: "encrypt" })).toThrow(ValidationError);

      const seen: unknown[] = [];
      const tokenization: TokenizationProvider = {
        scheme: "test",
        reversible: false,
        tokenPattern: /\[T\]/g,
        maxTokenLength: 3,
        tokenize: (value, tokenContext) => {
          seen.push([value, tokenContext]);
          return "[T]";
        },
        detokenize: () => undefined,
      };
      expect(strategyReplacer({ strategy: "tokenize" }, { tokenization })("v", context)).toBe(
        "[T]",
      );
      expect(seen).toEqual([["v", { category: "email" }]]);

      const encrypted = await strategyReplacer(
        { strategy: "encrypt" },
        { encryption: { keyBytes } },
      )("v", context);
      expect(await decrypt(encrypted, { keyBytes })).toBe("v");
    });

    it("rejects an unknown strategy name", () => {
      expect(() => strategyReplacer({ strategy: "shred" } as unknown as StrategySpec)).toThrow(
        /"shred" is not a known strategy/,
      );
    });
  });
});

describe("engine/compile", () => {
  describe("builtinDetectors", () => {
    it("covers exactly the 27 built-in categories, in the 1.x scan order", () => {
      expect([...BUILTIN_CATEGORIES]).toEqual(Object.keys(DETECTOR_REGISTRY));
      expect(Object.keys(LEGACY_DETECTORS)).toEqual(Object.keys(DETECTOR_REGISTRY));
      expect(Object.keys(LEGACY_AGGRESSIVE_DETECTORS).sort()).toEqual(
        Object.keys(DETECTOR_REGISTRY).sort(),
      );
      expect(builtinDetectors().map((d) => d.category)).toEqual([...BUILTIN_CATEGORIES]);
    });

    it("uses the validating detectors by default and the 1.x ones on request", () => {
      expect(builtinDetectors(["email"])[0]).not.toBe(LEGACY_DETECTORS.email);
      expect(builtinDetectors(["email"], { detection: "legacy" })).toEqual([
        LEGACY_DETECTORS.email,
      ]);
      expect(builtinDetectors(["phone"])).toEqual([LEGACY_DETECTORS.phone]);
    });

    it("adds the permissive variants in aggressive mode", () => {
      expect(
        builtinDetectors(["email", "ssn", "credit-card"], { aggressive: true }).map((d) => d.id),
      ).toEqual([
        "email",
        "email/obfuscated",
        "ssn",
        "ssn/bare",
        "credit-card",
        "credit-card/masked",
      ]);
      expect(
        builtinDetectors(["phone", "email"], { aggressive: true, detection: "legacy" }),
      ).toEqual([LEGACY_AGGRESSIVE_DETECTORS.phone, LEGACY_AGGRESSIVE_DETECTORS.email]);
    });

    it("ignores repeated categories and rejects unknown ones", () => {
      expect(builtinDetectors(["email", "email"])).toHaveLength(1);
      expect(() => builtinDetectors(["nope" as "email"])).toThrow(UnknownCategoryError);
    });
  });

  describe("compilePipeline", () => {
    it("detects every built-in category and redacts by default", () => {
      const pipeline = compilePipeline();
      expect(pipeline.detectors).toHaveLength(27);
      expect(pipeline.transform("Mail alice@example.com from 203.0.113.57").text).toBe(
        "Mail [REDACTED] from [REDACTED]",
      );
    });

    it("starts from a preset and lets explicit members override it", () => {
      const pci = compilePipeline({ preset: "pci-dss" });
      expect(pci.transform("Card 4111 1111 1111 1111, SSN 123-45-6789").text).toBe(
        "Card ***************1111, SSN 123-45-6789",
      );
      const overridden = compilePipeline({
        preset: "pci-dss",
        categories: ["credit-card", "ssn"],
        defaultStrategy: { strategy: "redact", label: "#" },
        rules: { "credit-card": { strategy: "redact", label: "<card>" } },
      });
      expect(overridden.transform("Card 4111 1111 1111 1111, SSN 123-45-6789").text).toBe(
        "Card <card>, SSN #",
      );
    });

    it("keeps the categories of a preset when rules are added", () => {
      // The 1.x engine dropped every preset category that had no explicit rule.
      const pipeline = compilePipeline({ preset: "hipaa", rules: { email: { strategy: "mask" } } });
      expect(pipeline.transform("j@example.org, SSN 123-45-6789").text).toBe(
        "*************, SSN [REDACTED]",
      );
    });

    it("compiles custom patterns with their own strategies", () => {
      const pipeline = compilePipeline({
        categories: ["email"],
        patterns: [
          { source: "ACME-\\d{6}", category: "order-id", confidence: 0.9 },
          { source: "emp-\\d+", flags: "i", category: "employee" },
        ],
        rules: { "order-id": { strategy: "redact", label: "[ORDER]" } },
      });
      expect(pipeline.transform("ACME-123456 EMP-7 a@example.com").text).toBe(
        "[ORDER] [REDACTED] [REDACTED]",
      );
      expect(pipeline.scan("ACME-123456")[0]).toMatchObject({
        detector: "pattern/0",
        confidence: 0.9,
      });
    });

    it("passes filters and the overlap policy through", () => {
      const pipeline = compilePipeline({
        categories: ["email"],
        allow: ["NOREPLY@example.com"],
        allowCaseSensitive: true,
        minConfidence: 0.5,
        overlap: "legacy",
        detection: "legacy",
        aggressive: false,
      });
      expect(pipeline.transform("noreply@example.com NOREPLY@example.com").text).toBe(
        "[REDACTED] NOREPLY@example.com",
      );
    });

    it("leaves its own redaction labels alone on a second pass", () => {
      // The 1.x engine turns "[REDACTED]" into "[[REDACTED]]": its bank-account detector reads "REDACTED" as a BIC.
      const pipeline = compilePipeline();
      const once = pipeline.transform("Mail alice@example.com, SSN 123-45-6789").text;
      expect(once).toBe("Mail [REDACTED], SSN [REDACTED]");
      expect(pipeline.transform(once).text).toBe(once);
      expect(anonymize(anonymize("Mail alice@example.com").text).text).toBe("Mail [[REDACTED]]");

      const custom = compilePipeline({
        defaultStrategy: { strategy: "redact", label: "<<WITHHELD>>" },
        rules: { email: { strategy: "redact", label: "MAILADDR" } },
      });
      const twice = custom.transform(custom.transform("a@example.com 123-45-6789").text).text;
      expect(twice).toBe("MAILADDR <<WITHHELD>>");
    });

    it("reports configuration errors while compiling", () => {
      expect(() => compilePipeline({ categories: ["nope" as "email"] })).toThrow(
        UnknownCategoryError,
      );
      expect(() => compilePipeline({ patterns: [{ source: "(", category: "c" }] })).toThrow(
        ValidationError,
      );
      expect(() => compilePipeline({ patterns: [{ source: "x", category: "" }] })).toThrow(
        ValidationError,
      );
      expect(() => compilePipeline({ defaultStrategy: { strategy: "tokenize" } })).toThrow(
        ValidationError,
      );
      expect(() =>
        compilePipeline({ rules: { email: { strategy: "mask", keepLeading: -1 } } }),
      ).toThrow(ValidationError);
      expect(() => compilePipeline({ preset: "nope" as "gdpr" })).toThrow(
        /Unknown compliance preset/,
      );
    });

    it("does not let a rule named like an Object.prototype member leak into other categories", () => {
      const pipeline = compilePipeline({
        categories: ["email"],
        rules: { __proto__: { strategy: "redact", label: "<proto>" } } as Record<
          string,
          StrategySpec
        >,
      });
      expect(pipeline.transform("a@example.com").text).toBe("[REDACTED]");
    });
  });
});

describe("engine/replacers", () => {
  describe("generalizeWith", () => {
    it("redacts identifiers instead of showing all but their last digit", () => {
      const replace = generalizeWith();
      expect(replace("27", context)).toBe("20-29");
      expect(replace("1987", context)).toBe("1980-1989");
      expect(replace("123456789", context)).toBe("[REDACTED]");
      expect(replace("4111111111111111", context)).toBe("[REDACTED]");
      expect(replace("", context)).toBe("[REDACTED]");
      expect(generalizeWith({ bucketSize: 10_000 })("54321", context)).toBe("50000-59999");
      expect(() => generalizeWith({ bucketSize: 1 })).toThrow(ValidationError);
    });
  });

  describe("maskWith and synthesizeWith", () => {
    it("change letters and digits of every script", () => {
      const masked = maskWith({ preserveFormat: true })(
        "\u0438\u0432\u0430\u043d@example.com",
        context,
      );
      expect(masked).toBe("xxxx@xxxxxxx.xxx");
      expect(maskWith({ preserveFormat: true })("\u738b\u5c0f\u660e 42", context)).toBe("xxx 00");
      const synthetic = synthesizeWith({ seed: "s" })("emp-m\u00fcller-\u0664\u0662", {
        ...context,
        category: "employee",
      });
      expect(synthetic).toMatch(/^[a-z]{3}-[a-z]{6}-\d{2}$/);
    });

    it("treat a category named like an Object.prototype member as any other", () => {
      for (const category of ["__proto__", "constructor", "toString", "valueOf"]) {
        const out = synthesizeWith()("ACME-123", { ...context, category });
        expect(out, category).toMatch(/^[A-Z]{4}-\d{3}$/);
      }
    });
  });

  describe("hashWith and encryptWith", () => {
    it("reject invalid options when they are created", () => {
      expect(() => hashWith({ truncate: -1 })).toThrow(ValidationError);
      expect(() => hashWith({ truncate: 65 })).toThrow(ValidationError);
      expect(() => encryptWith({ keyBytes: new Uint8Array(5) })).toThrow(ValidationError);
      expect(() =>
        encryptWith({ passphrase: "p", encoding: "base32" as unknown as "hex" }),
      ).toThrow(ValidationError);
    });
  });
});

describe("engine/compile", () => {
  describe("compilePipeline", () => {
    it("rejects invalid options while compiling, not on the first match", () => {
      expect(() =>
        compilePipeline({ defaultStrategy: { strategy: "hash", truncate: -1 } }),
      ).toThrow(ValidationError);
      expect(() =>
        compilePipeline({ patterns: [{ source: "x", category: "c", confidence: 5 }] }),
      ).toThrow(ValidationError);
      expect(() => compilePipeline({ detection: "strict" as unknown as "precise" })).toThrow(
        ValidationError,
      );
    });

    it("rejects a specification or a rule that is not an object", () => {
      expect(() => compilePipeline(null as unknown as object)).toThrow(ValidationError);
      expect(() => compilePipeline({ rules: { email: null as unknown as StrategySpec } })).toThrow(
        ValidationError,
      );
    });

    it("leaves the fail-closed label alone on a second pass", () => {
      const pipeline = compilePipeline({ defaultStrategy: { strategy: "generalize" } });
      const once = pipeline.transform("mail alice@example.com").text;
      expect(once).toBe("mail [REDACTED]");
      expect(pipeline.transform(once).text).toBe(once);
    });

    it("redacts every date of birth in a text, whatever follows it", () => {
      const pipeline = compilePipeline({ categories: ["date-of-birth"] });
      expect(pipeline.transform("Patient born 12/05/1987. Admitted on March 3, 2021.").text).toBe(
        "Patient born [REDACTED]. Admitted on [REDACTED].",
      );
      expect(pipeline.transform("DOB 12/05/1987, discharge 2021-03-03").text).toBe(
        "DOB [REDACTED], discharge [REDACTED]",
      );
    });
  });
});

describe("engine/replacers", () => {
  describe("compilePipeline", () => {
    it("compiles an encrypt strategy into a pipeline whose ciphertext decrypt() restores", async () => {
      const pipeline = compilePipeline(
        { defaultStrategy: { strategy: "encrypt" } },
        { encryption: { keyBytes } },
      );
      const { text } = await pipeline.transformAsync("mail alice@example.com");
      const ciphertext = text.slice("mail ".length);
      expect(ciphertext).toMatch(/^base64:/);
      expect(await decrypt(ciphertext, { keyBytes })).toBe("alice@example.com");
    });
  });
});
