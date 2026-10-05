import { describe, it, expect } from "vitest";
import { anonymize, anonymizeAsync, createAnonymizer } from "../src/anonymize.js";
import { sanitizeForLLM } from "../src/llm.js";
import { tokenize } from "../src/tokenize.js";

// An allowlist entry exempts a detected value only when the value equals it.
// A value that merely contains an entry is anonymized.

describe("allowlist", () => {
  describe("anonymize()", () => {
    it("skips only values equal to an entry, ignoring case", () => {
      const { text } = anonymize("bob@example.com, BOB@example.com and jimbob@example.com", {
        allowlist: ["bob@example.com"],
      });
      expect(text).toBe("bob@example.com, BOB@example.com and [REDACTED]");
    });

    it("does not skip the addresses of a domain for an entry naming the domain", () => {
      expect(anonymize("alice@example.com", { allowlist: ["example.com"] }).text).toBe(
        "[REDACTED]",
      );
    });

    it("does not skip every value for an empty entry", () => {
      expect(anonymize("alice@example.com", { allowlist: [""] }).text).toBe("[REDACTED]");
    });

    it("matches an entry with regular-expression characters literally", () => {
      const { text } = anonymize("x.y@example.com and xzy@example.com", {
        allowlist: ["x.y@example.com"],
      });
      expect(text).toBe("x.y@example.com and [REDACTED]");
    });

    it("compares case-sensitively with allowlistCaseSensitive", () => {
      const { text } = anonymize("bob@example.com and BOB@example.com", {
        allowlist: ["bob@example.com"],
        allowlistCaseSensitive: true,
      });
      expect(text).toBe("bob@example.com and [REDACTED]");
    });

    it("lets allowlistPatterns match part of a value", () => {
      const { text } = anonymize("alice@example.com and alice@example.org", {
        allowlistPatterns: [/@example\.com$/],
      });
      expect(text).toBe("alice@example.com and [REDACTED]");
    });

    it("applies a global or sticky pattern to every value alike, without changing it", () => {
      const global = /^alice@/g;
      const sticky = /alice@/y;
      const text = "alice@example.com, alice@example.com, alice@example.com";

      expect(anonymize(text, { allowlistPatterns: [global] }).text).toBe(text);
      expect(anonymize(text, { allowlistPatterns: [sticky] }).text).toBe(text);
      expect(global.lastIndex).toBe(0);
      expect(sticky.lastIndex).toBe(0);
    });
  });

  describe("anonymizeAsync()", () => {
    it("skips only values equal to an entry, with or without an asynchronous strategy", async () => {
      const text = "bob@example.com and jimbob@example.com";

      expect((await anonymizeAsync(text, { allowlist: ["bob@example.com"] })).text).toBe(
        "bob@example.com and [REDACTED]",
      );
      const hashed = await anonymizeAsync(text, {
        allowlist: ["bob@example.com"],
        defaultStrategy: { strategy: "hash" },
      });
      expect(hashed.text).toMatch(/^bob@example\.com and [0-9a-f]{16}$/);
    });

    it("applies a global pattern to every value alike with an asynchronous strategy", async () => {
      const pattern = /^alice@/g;
      const text = "alice@example.com, alice@example.com";
      const { text: result } = await anonymizeAsync(text, {
        allowlistPatterns: [pattern],
        defaultStrategy: { strategy: "hash" },
      });
      expect(result).toBe(text);
      expect(pattern.lastIndex).toBe(0);
    });
  });

  describe("tokenize()", () => {
    it("tokenizes the values that only contain an entry", () => {
      const { tokens } = tokenize("bob@example.com, jimbob@example.com, xzy@example.com", {
        allowlist: ["bob@example.com", "x.y@example.com", ""],
      });
      expect(tokens.map((t) => t.original).sort()).toEqual([
        "jimbob@example.com",
        "xzy@example.com",
      ]);
    });

    it("keeps such values out of the text that sanitizeForLLM() returns", () => {
      const { text } = sanitizeForLLM("Ask jimbob@example.com", { allowlist: ["bob@example.com"] });
      expect(text).toBe("Ask [EMAIL_0001]");
    });
  });

  describe("createAnonymizer()", () => {
    it("tokenize() accepts an entry with regular-expression characters", () => {
      const anonymizer = createAnonymizer({ categories: ["email"] });
      expect(anonymizer.tokenize("alice@example.com", { allowlist: ["a(b"] }).text).toBe(
        "[EMAIL_0001]",
      );
    });

    it("tokenize() skips only values equal to an entry", () => {
      const anonymizer = createAnonymizer({ categories: ["email"] });
      const { tokens } = anonymizer.tokenize(
        "x.y@example.com, xzy@example.com, jimbob@example.com",
        { allowlist: ["x.y@example.com", "bob@example.com"] },
      );
      expect(tokens.map((t) => t.original).sort()).toEqual([
        "jimbob@example.com",
        "xzy@example.com",
      ]);
    });

    it("anonymize() skips only values equal to an entry", () => {
      const anonymizer = createAnonymizer({ categories: ["email"] });
      const { text } = anonymizer.anonymize("bob@example.com, jimbob@example.com", {
        allowlist: ["bob@example.com"],
      });
      expect(text).toBe("bob@example.com, [REDACTED]");
    });
  });
});
