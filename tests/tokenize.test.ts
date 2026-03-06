/**
 * Tests for v2 tokenize / detokenize / sanitizeForLLM / restoreFromLLM
 */
import { vi, describe, it, expect } from "vitest";
import { tokenize, tokenizeAsync, detokenize } from "../src/tokenize.js";
import { sanitizeForLLM, restoreFromLLM } from "../src/llm.js";
import type { PiiMatch } from "../src/types.js";

// Mock the anonymize module so we can inject a PiiMatch with an unknown category
// to exercise the TOKEN_PREFIX_MAP fallback path in tokenize().
vi.mock("../src/anonymize.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/anonymize.js")>();
  return { ...actual, detect: vi.fn(actual.detect) };
});

// ---------------------------------------------------------------------------
// tokenize() shape
// ---------------------------------------------------------------------------
describe("tokenize() shape", () => {
  const text = "Contact alice@example.com or call +1-202-555-0101";

  it("returns text, mapping and tokens fields", () => {
    const result = tokenize(text);
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("mapping");
    expect(result).toHaveProperty("tokens");
  });

  it("result.mapping is a Map<string, string>", () => {
    const { mapping } = tokenize(text);
    expect(mapping instanceof Map).toBe(true);
    expect(mapping.size).toBeGreaterThan(0);
  });

  it("result.tokens is an array of TokenMatch objects", () => {
    const { tokens } = tokenize(text);
    expect(Array.isArray(tokens)).toBe(true);
    expect(tokens.length).toBeGreaterThan(0);
    for (const t of tokens) {
      expect(t).toHaveProperty("token");
      expect(t).toHaveProperty("original");
      expect(t).toHaveProperty("category");
    }
  });

  it("replaces PII in result.text with tokens", () => {
    const { text: out } = tokenize(text);
    expect(out).not.toContain("alice@example.com");
    expect(out).not.toContain("+1-202-555-0101");
  });

  it("tokens contain the category info", () => {
    const { tokens } = tokenize(text);
    const emailToken = tokens.find((t) => t.category === "email");
    const phoneToken = tokens.find((t) => t.category === "phone");
    expect(emailToken).toBeDefined();
    expect(phoneToken).toBeDefined();
  });

  it("tokens include the original value", () => {
    const { tokens } = tokenize(text);
    const et = tokens.find((t) => t.category === "email");
    expect(et?.original).toBe("alice@example.com");
  });

  it("different values get different tokens", () => {
    const { tokens } = tokenize("Email a@b.com and c@d.com");
    const emailTokens = tokens.filter((t) => t.category === "email");
    const tokenStrings = emailTokens.map((t) => t.token);
    expect(new Set(tokenStrings).size).toBe(emailTokens.length);
  });

  it("same value gets the same token", () => {
    const { tokens } = tokenize("From alice@example.com to alice@example.com");
    const emailTokens = tokens.filter((t) => t.category === "email");
    if (emailTokens.length === 2) {
      expect(emailTokens[0]?.token).toBe(emailTokens[1]?.token);
    } else {
      // deduplicated — still fine
      expect(emailTokens.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// tokenize() — format options
// ---------------------------------------------------------------------------
describe("tokenize() format options", () => {
  it("bracket format wraps tokens in []", () => {
    const { text } = tokenize("Email: user@example.com", { format: "bracket" });
    expect(text).toMatch(/\[EMAIL_\d+\]/);
  });

  it("angle format wraps tokens in <>", () => {
    const { text } = tokenize("Email: user@example.com", { format: "angle" });
    expect(text).toMatch(/<EMAIL_\d+>/);
  });
});

// ---------------------------------------------------------------------------
// tokenize() — category filtering
// ---------------------------------------------------------------------------
describe("tokenize() category filtering", () => {
  it("only tokenizes specified categories", () => {
    const text = "Email user@example.com phone +1-202-555-0101";
    const { tokens } = tokenize(text, { categories: ["email"] });
    expect(tokens.every((t) => t.category === "email")).toBe(true);
    expect(tokens.some((t) => t.category === "phone")).toBe(false);
  });

  it("result text preserves phone when only email tokenized", () => {
    const text = "Email user@example.com phone +1-202-555-0101";
    const { text: out } = tokenize(text, { categories: ["email"] });
    expect(out).not.toContain("user@example.com");
    expect(out).toContain("+1-202-555-0101");
  });
});

// ---------------------------------------------------------------------------
// tokenize() — empty / no-PII input
// ---------------------------------------------------------------------------
describe("tokenize() edge cases", () => {
  it("returns unchanged text when no PII found", () => {
    const text = "The quick brown fox";
    const { text: out, tokens, mapping } = tokenize(text);
    expect(out).toBe(text);
    expect(tokens).toHaveLength(0);
    expect(mapping.size).toBe(0);
  });

  it("handles empty string", () => {
    const { text: out, tokens } = tokenize("");
    expect(out).toBe("");
    expect(tokens).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// detokenize()
// ---------------------------------------------------------------------------
describe("detokenize() shape", () => {
  it("returns text, replacedCount, unresolved fields", () => {
    const { text: tokenized, mapping } = tokenize("Email: user@example.com");
    const result = detokenize(tokenized, mapping);
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("replacedCount");
    expect(result).toHaveProperty("unresolved");
  });

  it("restores original text", () => {
    const original = "Contact user@example.com for details";
    const { text: tokenized, mapping } = tokenize(original);
    const { text: restored } = detokenize(tokenized, mapping);
    expect(restored).toBe(original);
  });

  it("replacedCount equals number of unique PII replaced", () => {
    const original = "alice@example.com and bob@example.com";
    const { text: tokenized, mapping } = tokenize(original);
    const { replacedCount } = detokenize(tokenized, mapping);
    expect(replacedCount).toBeGreaterThanOrEqual(2);
  });

  it("unresolved is empty when all tokens can be resolved", () => {
    const { text: tokenized, mapping } = tokenize("Email: user@example.com");
    const { unresolved } = detokenize(tokenized, mapping);
    expect(unresolved).toHaveLength(0);
  });

  it("tracks unresolved tokens", () => {
    // Inject a fake token that is not in the mapping
    const fakeTokenized = "Contact [EMAIL_9999] for help";
    const emptyMap = new Map<string, string>();
    const { unresolved, replacedCount } = detokenize(fakeTokenized, emptyMap);
    expect(unresolved).toContain("[EMAIL_9999]");
    expect(replacedCount).toBe(0);
  });

  it("round-trips multiple PII types", () => {
    const original =
      "From alice@example.com, SSN 001-01-0001, card 4111111111111111";
    const { text: tokenized, mapping } = tokenize(original);
    const { text: restored } = detokenize(tokenized, mapping);
    expect(restored).toBe(original);
  });

  it("handles text with no token-like patterns (replacedCount is 0)", () => {
    const { replacedCount, unresolved } = detokenize("plain text no tokens", new Map());
    expect(replacedCount).toBe(0);
    expect(unresolved).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// tokenizeAsync()
// ---------------------------------------------------------------------------
describe("tokenizeAsync()", () => {
  it("returns a Promise that resolves to the same shape as tokenize()", async () => {
    const text = "Email: user@example.com";
    const result = await tokenizeAsync(text);
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("mapping");
    expect(result).toHaveProperty("tokens");
    expect(result.text).not.toContain("user@example.com");
  });

  it("is consistent with sync tokenize()", async () => {
    const text = "SSN 123-45-6789";
    const sync = tokenize(text);
    const async_ = await tokenizeAsync(text);
    // Token strings may differ in index but both should replace SSN
    expect(async_.text).not.toContain("123-45-6789");
    expect(sync.text).not.toContain("123-45-6789");
    expect(async_.tokens.length).toBe(sync.tokens.length);
  });
});

// ---------------------------------------------------------------------------
// tokenize() / detokenize() — ValidationError for non-string input
// ---------------------------------------------------------------------------
describe("tokenize() / detokenize() — input validation", () => {
  it("tokenize() throws ValidationError when text is not a string", () => {
    expect(() => tokenize(42 as unknown as string)).toThrow("text");
  });

  it("detokenize() throws ValidationError when text is not a string", () => {
    expect(() => detokenize(null as unknown as string, new Map())).toThrow("text");
  });
});

// ---------------------------------------------------------------------------
// tokenize() — allowlist filtering
// ---------------------------------------------------------------------------
describe("tokenize() allowlist", () => {
  it("allowlisted values are not tokenized (case-insensitive by default)", () => {
    const text = "Email alice@example.com for info";
    const { tokens } = tokenize(text, { allowlist: ["alice@example.com"] });
    expect(tokens.some((t) => t.original === "alice@example.com")).toBe(false);
  });

  it("allowlist is case-insensitive by default", () => {
    const text = "Email alice@example.com for info";
    const { tokens } = tokenize(text, { allowlist: ["ALICE@EXAMPLE.COM"] });
    expect(tokens.some((t) => t.original === "alice@example.com")).toBe(false);
  });

  it("allowlist is case-sensitive when allowlistCaseSensitive is true", () => {
    const text = "Email alice@example.com for info";
    // Uppercase allowlist entry won't match lowercase email when case-sensitive
    const { tokens } = tokenize(text, {
      allowlist: ["ALICE@EXAMPLE.COM"],
      allowlistCaseSensitive: true,
    });
    expect(tokens.some((t) => t.original === "alice@example.com")).toBe(true);
  });

  it("allowlist with exact case match suppresses the token when case-sensitive", () => {
    const text = "Email alice@example.com for info";
    const { tokens } = tokenize(text, {
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    expect(tokens.some((t) => t.original === "alice@example.com")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// tokenize() — TOKEN_PREFIX_MAP fallback
// ---------------------------------------------------------------------------
describe("tokenize() TOKEN_PREFIX_MAP fallback", () => {
  it("uses category.toUpperCase() as prefix for unknown categories", async () => {
    const anonymizeModule = await import("../src/anonymize.js");
    const fakePiiMatch: PiiMatch = {
      category: "widget-id" as "email", // not in TOKEN_PREFIX_MAP at runtime
      value: "WIDGET-123",
      start: 6,
      end: 16,
      confidence: 0.9,
    };
    vi.mocked(anonymizeModule.detect).mockReturnValueOnce([fakePiiMatch]);

    const { tokens, text } = tokenize("Order WIDGET-123 shipped");
    expect(tokens.length).toBeGreaterThan(0);
    // Prefix should fall back to category.toUpperCase() = "WIDGET-ID"
    expect(text).toMatch(/\[WIDGET-ID_\d+\]|<WIDGET-ID_\d+>/);

    // Restore the original implementation for subsequent tests
    vi.mocked(anonymizeModule.detect).mockRestore();
  });
});

// ---------------------------------------------------------------------------
// sanitizeForLLM() / restoreFromLLM()
// ---------------------------------------------------------------------------
describe("sanitizeForLLM()", () => {
  it("returns a TokenizeResult-compatible object", () => {
    const text = "Alice's SSN is 001-01-0001 and email is alice@example.com";
    const result = sanitizeForLLM(text);
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("mapping");
    expect(result).toHaveProperty("tokens");
  });

  it("sanitized text contains bracket-style tokens", () => {
    const { text } = sanitizeForLLM("Email alice@example.com for info");
    expect(text).toMatch(/\[EMAIL_\d+\]/);
  });

  it("sanitized text does not contain PII", () => {
    const pii =
      "Contact alice@example.com, SSN 001-01-0001, card 4111111111111111";
    const { text } = sanitizeForLLM(pii);
    expect(text).not.toContain("alice@example.com");
    expect(text).not.toContain("001-01-0001");
    expect(text).not.toContain("4111111111111111");
  });

  it("mapping contains enough entries to restore", () => {
    const { mapping } = sanitizeForLLM(
      "Contact alice@example.com for help",
    );
    expect(mapping.size).toBeGreaterThan(0);
  });
});

describe("restoreFromLLM()", () => {
  it("restores PII from LLM response", () => {
    const original = "Contact alice@example.com for help";
    const { text: sanitized, mapping } = sanitizeForLLM(original);

    // Simulate LLM paraphrasing around the token
    const llmResponse = sanitized.replace(
      /\[EMAIL_\d+\]/,
      (m) => `the address ${m}`,
    );

    const { text: restored } = restoreFromLLM(llmResponse, mapping);
    expect(restored).toContain("alice@example.com");
  });

  it("returns replacedCount > 0 for successful restore", () => {
    const { text: sanitized, mapping } = sanitizeForLLM(
      "alice@example.com",
    );
    const { replacedCount } = restoreFromLLM(sanitized, mapping);
    expect(replacedCount).toBeGreaterThan(0);
  });

  it("returns DetokenizeResult shape", () => {
    const { text: sanitized, mapping } = sanitizeForLLM("user@test.com");
    const result = restoreFromLLM(sanitized, mapping);
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("replacedCount");
    expect(result).toHaveProperty("unresolved");
  });
});
