import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  anonymize,
  anonymizeAsync,
  detect,
  anonymizeRecord,
  anonymizeObject,
  hasPII,
  createAnonymizer,
} from "../src/anonymize.js";
import {
  ValidationError,
  UnknownCategoryError,
  UnsupportedStrategyError,
  PresetNotFoundError,
} from "../src/errors.js";

// ---------------------------------------------------------------------------
// detect()
// ---------------------------------------------------------------------------
describe("detect", () => {
  it("detects email and IP in the same string", () => {
    const matches = detect("Email: alice@example.com, IP: 192.168.1.1");
    const categories = matches.map((m) => m.category);
    expect(categories).toContain("email");
    expect(categories).toContain("ipv4");
  });

  it("returns matches sorted by start position", () => {
    const matches = detect("a@b.io and 192.168.0.1 and c@d.io");
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i]!.start).toBeGreaterThan(matches[i - 1]!.start);
    }
  });

  it("de-duplicates overlapping matches", () => {
    // A string that shouldn't produce two matches at the same position.
    const matches = detect("test@example.com");
    const starts = matches.map((m) => m.start);
    const unique = new Set(starts);
    expect(unique.size).toBe(starts.length);
  });

  it("respects category filtering", () => {
    const matches = detect("alice@example.com and 192.168.1.1", ["email"]);
    expect(matches.every((m) => m.category === "email")).toBe(true);
  });

  it("throws UnknownCategoryError for invalid category", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => detect("text", ["not-a-category" as any])).toThrow(UnknownCategoryError);
  });

  it("throws ValidationError when text is not a string", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => detect(42 as any)).toThrow(ValidationError);
  });

  it("returns empty array for text with no PII", () => {
    expect(detect("The quick brown fox jumps over the lazy dog.")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// anonymize()
// ---------------------------------------------------------------------------
describe("anonymize", () => {
  it("redacts email and phone by default", () => {
    const { text } = anonymize("alice@example.com and 555-867-5309");
    expect(text).not.toContain("alice@example.com");
    expect(text).not.toContain("555-867-5309");
    expect(text).toContain("[REDACTED]");
  });

  it("returns unchanged text when no PII is found", () => {
    const { text } = anonymize("No PII here at all.");
    expect(text).toBe("No PII here at all.");
  });

  it("applies mask strategy via defaultStrategy", () => {
    const { text } = anonymize("test@example.com", {
      defaultStrategy: { strategy: "mask" },
    });
    expect(text).toMatch(/^\*+$/);
  });

  it("applies mask with keepLeading/keepTrailing", () => {
    const { text } = anonymize("test@example.com", {
      defaultStrategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 },
    });
    expect(text).toMatch(/^t.*com$/);
  });

  it("applies pseudonymize strategy", () => {
    const { text } = anonymize("alice@example.com", {
      defaultStrategy: { strategy: "pseudonymize", seed: "my-seed" },
    });
    expect(text).toMatch(/^id_[0-9a-f]+$/);
  });

  it("applies generalize strategy to a numeric value", () => {
    const { text } = anonymize("Age: 27 years old.", {
      // generalize is typically used with anonymizeRecord; here we ensure it runs
      rules: [],
      defaultStrategy: { strategy: "generalize" },
    });
    // Text has no numeric PII categories, so should be unchanged
    expect(text).toBe("Age: 27 years old.");
  });

  it("includes matches when includeMatches: true", () => {
    const { matches } = anonymize("alice@example.com", { includeMatches: true });
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("email");
  });

  it("does not include matches by default", () => {
    const { matches } = anonymize("alice@example.com");
    expect(matches).toHaveLength(0);
  });

  it("supports per-category rules", () => {
    const { text } = anonymize("alice@example.com and 192.168.1.1", {
      rules: [
        { category: "email", strategy: { strategy: "redact", label: "[EMAIL]" } },
        { category: "ipv4", strategy: { strategy: "redact", label: "[IP]" } },
      ],
    });
    expect(text).toContain("[EMAIL]");
    expect(text).toContain("[IP]");
  });

  it("handles multiple PII entities preserving surrounding text", () => {
    const { text } = anonymize("From: alice@a.com. IP: 10.0.0.1.");
    expect(text).toBe("From: [REDACTED]. IP: [REDACTED].");
  });

  it("throws ValidationError when text is not a string", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => anonymize(42 as any)).toThrow(ValidationError);
  });

  it("throws UnknownCategoryError for unknown category in rules", () => {
    expect(() =>
      anonymize("text", {
        rules: [
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { category: "bad-category" as any, strategy: { strategy: "redact" } },
        ],
      }),
    ).toThrow(UnknownCategoryError);
  });

  it("is deterministic for the same input", () => {
    const text = "Contact alice@example.com for more info.";
    expect(anonymize(text).text).toBe(anonymize(text).text);
  });
});

// ---------------------------------------------------------------------------
// anonymizeRecord()
// ---------------------------------------------------------------------------
describe("anonymizeRecord", () => {
  it("anonymizes a flat record field", () => {
    const result = anonymizeRecord(
      { email: "alice@example.com", name: "Alice" },
      { email: { strategy: { strategy: "redact" } } },
    );
    expect(result.email).toBe("[REDACTED]");
    expect(result.name).toBe("Alice"); // untouched
  });

  it("anonymizes a nested field via dot notation", () => {
    const record = { user: { email: "alice@example.com", role: "admin" } };
    const result = anonymizeRecord(record, {
      "user.email": { strategy: { strategy: "redact" } },
    });
    expect((result.user as Record<string, unknown>)["email"]).toBe("[REDACTED]");
    expect((result.user as Record<string, unknown>)["role"]).toBe("admin");
  });

  it("does not mutate the input record", () => {
    const original = { email: "alice@example.com" };
    anonymizeRecord(original, { email: { strategy: { strategy: "redact" } } });
    expect(original.email).toBe("alice@example.com");
  });

  it("applies generalize to a numeric field", () => {
    const result = anonymizeRecord(
      { age: "27" },
      { age: { strategy: { strategy: "generalize" } } },
    );
    expect(result.age).toBe("20-29");
  });

  it("applies mask to a field", () => {
    const result = anonymizeRecord(
      { ssn: "123-45-6789" },
      {
        ssn: {
          strategy: { strategy: "mask", keepLeading: 0, keepTrailing: 4 },
        },
      },
    );
    expect(result.ssn).toMatch(/^\*+6789$/);
  });

  it("skips undefined/null fields gracefully", () => {
    const result = anonymizeRecord(
      { email: null },
      { email: { strategy: { strategy: "redact" } } },
    );
    expect(result.email).toBeNull();
  });

  it("throws ValidationError for non-object input", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => anonymizeRecord("not-object" as any, {})).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// createAnonymizer()
// ---------------------------------------------------------------------------
describe("createAnonymizer", () => {
  it("creates an anonymizer with a default strategy", () => {
    const anonymizer = createAnonymizer({
      categories: ["email"],
      defaultStrategy: { strategy: "redact", label: "[EMAIL_GONE]" },
    });
    const { text } = anonymizer.anonymize("alice@example.com");
    expect(text).toBe("[EMAIL_GONE]");
  });

  it("exposes detect()", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const matches = anonymizer.detect("alice@example.com");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("email");
  });

  it("exposes anonymizeRecord()", () => {
    const anonymizer = createAnonymizer();
    const result = anonymizer.anonymizeRecord(
      { email: "alice@example.com" },
      { email: { strategy: { strategy: "redact" } } },
    );
    expect(result.email).toBe("[REDACTED]");
  });

  it("throws UnknownCategoryError for invalid category in config", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => createAnonymizer({ categories: ["bad" as any] })).toThrow(
      UnknownCategoryError,
    );
  });

  it("only detects the configured categories", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const matches = anonymizer.detect("alice@example.com and 192.168.1.1");
    expect(matches.every((m) => m.category === "email")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// hasPII()
// ---------------------------------------------------------------------------
describe("hasPII", () => {
  it("returns true when PII is present", () => {
    expect(hasPII("My email is alice@example.com")).toBe(true);
  });

  it("returns false when no PII is present", () => {
    expect(hasPII("The quick brown fox jumps over the lazy dog.")).toBe(false);
  });

  it("returns false for an empty string", () => {
    expect(hasPII("")).toBe(false);
  });

  it("respects category filtering — returns false when PII is only in excluded categories", () => {
    // Text has email but we only check phone
    expect(hasPII("alice@example.com", ["phone"])).toBe(false);
  });

  it("respects category filtering — returns true when PII is in checked category", () => {
    // Text has email and we check email
    expect(hasPII("alice@example.com", ["email"])).toBe(true);
  });

  it("detects phone PII", () => {
    expect(hasPII("Call 555-867-5309 now.")).toBe(true);
  });

  it("detects SSN PII", () => {
    expect(hasPII("SSN: 123-45-6789")).toBe(true);
  });

  it("throws ValidationError when text is not a string", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => hasPII(42 as any)).toThrow(ValidationError);
  });

  it("throws UnknownCategoryError for invalid category", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => hasPII("text", ["not-a-category" as any])).toThrow(UnknownCategoryError);
  });

  it("respects customDetectors override", () => {
    // Replace email detector with one that never matches
    const noOpDetector = () => [];
    expect(hasPII("alice@example.com", ["email"], { email: noOpDetector })).toBe(false);
  });

  it("createAnonymizer exposes hasPII()", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    expect(anonymizer.hasPII("alice@example.com")).toBe(true);
    expect(anonymizer.hasPII("no pii here")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// anonymizeObject()
// ---------------------------------------------------------------------------
describe("anonymizeObject", () => {
  it("anonymizes flat string values", () => {
    const result = anonymizeObject({ email: "alice@example.com", name: "Alice" });
    expect(result.email).toBe("[REDACTED]");
    // "Alice" by itself has no PII (no greeting context)
    expect(result.name).toBe("Alice");
  });

  it("anonymizes deeply nested string values", () => {
    const result = anonymizeObject({
      user: { contact: { email: "alice@example.com" } },
    });
    expect((result as { user: { contact: { email: string } } }).user.contact.email).toBe(
      "[REDACTED]",
    );
  });

  it("anonymizes string values inside arrays", () => {
    const result = anonymizeObject({ notes: ["555-867-5309", "No PII here"] });
    expect((result as { notes: string[] }).notes[0]).toBe("[REDACTED]");
    expect((result as { notes: string[] }).notes[1]).toBe("No PII here");
  });

  it("handles mixed-type arrays without mutating non-strings", () => {
    const result = anonymizeObject({ data: ["alice@example.com", 42, true, null] });
    const data = (result as { data: unknown[] }).data;
    expect(data[0]).toBe("[REDACTED]");
    expect(data[1]).toBe(42);
    expect(data[2]).toBe(true);
    expect(data[3]).toBeNull();
  });

  it("passes null and undefined through unchanged", () => {
    const result = anonymizeObject({ a: null, b: undefined });
    expect((result as { a: null; b: undefined }).a).toBeNull();
    expect((result as { a: null; b: undefined }).b).toBeUndefined();
  });

  it("passes non-string primitives through unchanged", () => {
    const result = anonymizeObject({ count: 42, active: false, score: 3.14 });
    expect((result as { count: number; active: boolean; score: number }).count).toBe(42);
    expect((result as { count: number; active: boolean; score: number }).active).toBe(false);
  });

  it("does not mutate the input object", () => {
    const input = { email: "alice@example.com" };
    anonymizeObject(input);
    expect(input.email).toBe("alice@example.com");
  });

  it("throws ValidationError for circular references", () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj["self"] = obj;
    expect(() => anonymizeObject(obj)).toThrow(ValidationError);
  });

  it("throws ValidationError when called with a non-object", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => anonymizeObject("not an object" as any)).toThrow(ValidationError);
  });

  it("forwards options to anonymize()", () => {
    const result = anonymizeObject(
      { email: "alice@example.com" },
      { globalReplacement: "***" },
    );
    expect((result as { email: string }).email).toBe("***");
  });

  it("createAnonymizer exposes anonymizeObject()", () => {
    const anonymizer = createAnonymizer({ defaultStrategy: { strategy: "redact" } });
    const result = anonymizer.anonymizeObject({ msg: "555-867-5309" });
    expect((result as { msg: string }).msg).toBe("[REDACTED]");
  });

  it("consistent tokens work across all string values in an object", () => {
    const result = anonymizeObject(
      { a: "alice@example.com", b: "alice@example.com is back" },
      { consistentTokens: true },
    );
    const typed = result as { a: string; b: string };
    // Both occurrences should use the same token
    expect(typed.a).toBe("EMAIL_1");
    expect(typed.b).toContain("EMAIL_1");
  });
});

// ---------------------------------------------------------------------------
// customPatterns option
// ---------------------------------------------------------------------------
describe("anonymize() — customPatterns", () => {
  it("replaces custom pattern matches", () => {
    const { text } = anonymize("Order ACME-001234 confirmed.", {
      customPatterns: [{ pattern: /\bACME-\d{6}\b/g, label: "[ORDER_ID]" }],
      rules: [], // don't run built-in detectors
    });
    expect(text).toBe("Order [ORDER_ID] confirmed.");
  });

  it("uses default label [REDACTED] when no label is provided", () => {
    const { text } = anonymize("ID: XYZ-999", {
      customPatterns: [{ pattern: /\bXYZ-\d+\b/g }],
      rules: [],
    });
    expect(text).toBe("ID: [REDACTED]");
  });

  it("auto-adds global flag if missing", () => {
    // Pattern without 'g' flag — should still work
    const { text } = anonymize("token ABCABC", {
      customPatterns: [{ pattern: /ABC/ }],
      rules: [],
    });
    expect(text).not.toContain("ABC");
  });

  it("multiple custom patterns all apply", () => {
    const { text } = anonymize("token=abc123 id=XYZ", {
      customPatterns: [
        { pattern: /\btoken=[a-z0-9]+\b/g, label: "[TOKEN]" },
        { pattern: /\bid=[A-Z]+\b/g, label: "[ID]" },
      ],
      rules: [],
    });
    expect(text).toBe("[TOKEN] [ID]");
  });

  it("custom patterns participate in deduplication with built-in detectors", () => {
    // Custom pattern overlapping with email detector
    const { text } = anonymize("alice@example.com", {
      customPatterns: [{ pattern: /alice@example\.com/g, label: "[CUSTOM]" }],
    });
    // The built-in email detector wins or the custom one wins, but not both
    const counts = (text.match(/\[REDACTED\]|\[CUSTOM\]/g) ?? []).length;
    expect(counts).toBe(1);
  });

  it("throws ValidationError for non-RegExp pattern", () => {
    expect(() =>
      anonymize("text", {
        customPatterns: [
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { pattern: "not-a-regex" as any },
        ],
        rules: [],
      }),
    ).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// globalReplacement option
// ---------------------------------------------------------------------------
describe("anonymize() — globalReplacement", () => {
  it("replaces all PII with the global string", () => {
    const { text } = anonymize("Email alice@example.com or call 555-867-5309.", {
      globalReplacement: "***",
    });
    expect(text).toBe("Email *** or call ***.");
  });

  it("overrides defaultStrategy", () => {
    const { text } = anonymize("alice@example.com", {
      globalReplacement: "[PII]",
      defaultStrategy: { strategy: "mask" },
    });
    expect(text).toBe("[PII]");
  });

  it("overrides per-category rules", () => {
    const { text } = anonymize("alice@example.com", {
      globalReplacement: "[GONE]",
      rules: [{ category: "email", strategy: { strategy: "redact", label: "[EMAIL]" } }],
    });
    expect(text).toBe("[GONE]");
  });

  it("throws ValidationError for empty string", () => {
    expect(() => anonymize("text", { globalReplacement: "" })).toThrow(ValidationError);
  });

  it("throws ValidationError for whitespace-only string", () => {
    expect(() => anonymize("text", { globalReplacement: "   " })).toThrow(ValidationError);
  });

  it("works with createAnonymizer globalReplacement config", () => {
    const anonymizer = createAnonymizer({ globalReplacement: "REMOVED" });
    const { text } = anonymizer.anonymize("alice@example.com");
    expect(text).toBe("REMOVED");
  });
});

// ---------------------------------------------------------------------------
// consistentTokens option
// ---------------------------------------------------------------------------
describe("anonymize() — consistentTokens", () => {
  it("maps the same email to the same token", () => {
    const { text } = anonymize(
      "alice@example.com and alice@example.com again",
      { consistentTokens: true },
    );
    expect(text).toBe("EMAIL_1 and EMAIL_1 again");
  });

  it("maps different emails to different tokens", () => {
    const { text } = anonymize(
      "alice@example.com and bob@example.com",
      { consistentTokens: true },
    );
    expect(text).toContain("EMAIL_1");
    expect(text).toContain("EMAIL_2");
  });

  it("increments counters per category separately", () => {
    const { text } = anonymize(
      "alice@example.com bob@example.com 555-867-5309",
      { consistentTokens: true },
    );
    expect(text).toContain("EMAIL_1");
    expect(text).toContain("EMAIL_2");
    expect(text).toContain("PHONE_1");
  });

  it("uses PERSON prefix for name category", () => {
    // Use two separate sentences so both are at sentence-boundary positions
    const { text } = anonymize("Dear Alice Smith, how are you. Dear Alice Smith, welcome.", {
      consistentTokens: true,
      rules: [{ category: "name", strategy: { strategy: "redact" } }],
    });
    expect(text).toContain("PERSON_1");
    // Same name appears twice — both should get the same token PERSON_1
    expect((text.match(/PERSON_1/g) ?? []).length).toBe(2);
  });

  it("token state is NOT shared across separate anonymize() calls", () => {
    const first = anonymize("alice@example.com", { consistentTokens: true });
    const second = anonymize("alice@example.com", { consistentTokens: true });
    // Both should be EMAIL_1, not EMAIL_2
    expect(first.text).toBe("EMAIL_1");
    expect(second.text).toBe("EMAIL_1");
  });

  it("works with anonymizeObject() — same value across fields gets same token", () => {
    const result = anonymizeObject(
      { a: "alice@example.com", b: "alice@example.com" },
      { consistentTokens: true },
    );
    const typed = result as { a: string; b: string };
    expect(typed.a).toBe("EMAIL_1");
    expect(typed.b).toBe("EMAIL_1");
  });
});

// ---------------------------------------------------------------------------
// aggressive mode
// ---------------------------------------------------------------------------
describe("anonymize() — aggressive mode", () => {
  it("catches obfuscated emails", () => {
    const { text } = anonymize("Email user [at] example [dot] com for info.", {
      aggressive: true,
    });
    expect(text).not.toContain("user [at] example [dot] com");
  });

  it("catches masked credit cards", () => {
    const { text } = anonymize("Card on file: ****-****-****-1234", {
      aggressive: true,
    });
    expect(text).not.toContain("****-****-****-1234");
  });

  it("catches 7-digit phone numbers", () => {
    const { text } = anonymize("Local: 555-1234", { aggressive: true });
    expect(text).not.toContain("555-1234");
  });

  it("catches SSN without separators", () => {
    const { text } = anonymize("SSN 123456789 on file.", { aggressive: true });
    expect(text).not.toContain("123456789");
  });

  it("works with createAnonymizer aggressive config", () => {
    const anonymizer = createAnonymizer({ aggressive: true });
    const { text } = anonymizer.anonymize("user [at] example [dot] com");
    expect(text).not.toContain("[at]");
  });
});

// ---------------------------------------------------------------------------
// enabledCategories option
// ---------------------------------------------------------------------------
describe("anonymize() — enabledCategories", () => {
  it("only processes categories set to true", () => {
    const { text } = anonymize("alice@example.com and 555-867-5309", {
      enabledCategories: { email: true },
    });
    // Email should be redacted
    expect(text).not.toContain("alice@example.com");
    // Phone should be untouched
    expect(text).toContain("555-867-5309");
  });

  it("processes nothing when map is empty", () => {
    const { text } = anonymize("alice@example.com", {
      enabledCategories: {},
    });
    expect(text).toBe("alice@example.com");
  });

  it("rules take precedence over enabledCategories for covered categories", () => {
    const { text } = anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "redact", label: "[EMAIL]" } }],
      enabledCategories: { phone: true }, // email also covered by rules, rules win
    });
    expect(text).toBe("[EMAIL]");
  });
});

// ---------------------------------------------------------------------------
// Bug fix: anonymize() forwards customDetectors
// ---------------------------------------------------------------------------
describe("anonymize() — customDetectors forwarding (bug fix)", () => {
  it("uses custom detector when passed via options", () => {
    const alwaysMatches = (text: string) => [
      { category: "email" as const, value: text, start: 0, end: text.length, confidence: 1 },
    ];
    const { text } = anonymize("no email here", {
      customDetectors: { email: alwaysMatches },
      rules: [{ category: "email", strategy: { strategy: "redact", label: "[CUSTOM_EMAIL]" } }],
    });
    expect(text).toBe("[CUSTOM_EMAIL]");
  });

  it("replacing built-in email detector with no-op suppresses detections", () => {
    const noOp = () => [];
    const { text } = anonymize("alice@example.com", {
      customDetectors: { email: noOp },
      rules: [{ category: "email", strategy: { strategy: "redact" } }],
    });
    expect(text).toBe("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// anonymize() — sync fallbacks for async strategies (applyStrategySync)
// ---------------------------------------------------------------------------
describe("anonymize() — sync fallbacks for async strategies", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("hash strategy warns and falls back to a deterministic pseudonym", () => {
    const { text } = anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "hash" } }],
    });
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("hash"));
    expect(text).toMatch(/^hsh_[0-9a-f]+$/);
  });

  it("tokenize strategy warns and falls back to redact", () => {
    const { text } = anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "tokenize" } }],
    });
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("tokenize"));
    expect(text).toBe("[REDACTED]");
  });

  it("encrypt strategy warns and falls back to redact", () => {
    const { text } = anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "encrypt" } }],
    });
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("encrypt"));
    expect(text).toBe("[REDACTED]");
  });

  it("synthesize strategy warns and falls back to redact", () => {
    const { text } = anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "synthesize" } }],
    });
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("synthesize"));
    expect(text).toBe("[REDACTED]");
  });

  it("unknown strategy throws UnsupportedStrategyError", () => {
    expect(() =>
      anonymize("alice@example.com", {
        rules: [
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { category: "email", strategy: { strategy: "not-a-real-strategy" as any } },
        ],
      }),
    ).toThrow(UnsupportedStrategyError);
  });
});

// ---------------------------------------------------------------------------
// anonymize() — allowlist options (branch coverage)
// ---------------------------------------------------------------------------
describe("anonymize() — allowlist options", () => {
  it("allowlistCaseSensitive: true suppresses a case-matching entry", () => {
    const { text } = anonymize("alice@example.com", {
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    expect(text).toBe("alice@example.com");
  });

  it("allowlistCaseSensitive: true does not suppress a differently-cased entry", () => {
    const { text } = anonymize("ALICE@EXAMPLE.COM", {
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    expect(text).not.toBe("ALICE@EXAMPLE.COM");
  });

  it("allowlistPatterns accepts regex instances directly", () => {
    const { text } = anonymize("alice@example.com", {
      allowlistPatterns: [/alice@example\.com/i],
    });
    expect(text).toBe("alice@example.com");
  });

  it("confidenceThreshold filters out low-confidence matches", () => {
    // All built-in email matches have confidence 0.99 — threshold above that suppresses them
    const { text } = anonymize("alice@example.com", {
      confidenceThreshold: 1.0,
    });
    expect(text).toBe("alice@example.com");
  });

  it("allowlist (string array) without allowlistCaseSensitive uses case-insensitive flag", () => {
    // Exercises the `allowlistCaseSensitive ? "" : "i"` false-branch (line ~461):
    // allowlist.map is called and RegExp is built with the "i" flag.
    const { text } = anonymize("alice@example.com", {
      allowlist: ["alice@example.com"],
      // allowlistCaseSensitive intentionally omitted → defaults to false → "i" flag
    });
    expect(text).toBe("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// anonymize() — preset resolves categories and preset-level rules
// ---------------------------------------------------------------------------
describe("anonymize() — preset", () => {
  it("applies the gdpr preset to detected PII", () => {
    const { text } = anonymize("alice@example.com", { preset: "gdpr" });
    expect(text).not.toContain("alice@example.com");
  });

  it("throws PresetNotFoundError for an unknown preset name", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => anonymize("text", { preset: "nonexistent-preset" as any })).toThrow(
      PresetNotFoundError,
    );
  });
});

// ---------------------------------------------------------------------------
// anonymizeAsync()
// ---------------------------------------------------------------------------
describe("anonymizeAsync", () => {
  it("throws ValidationError for non-string input", async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(anonymizeAsync(42 as any)).rejects.toThrow(ValidationError);
  });

  it("delegates to sync path when no async strategy is used", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "redact" },
    });
    expect(text).toBe("[REDACTED]");
  });

  it("applies hash strategy with true SHA-256 output", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
    });
    // hash() truncates to 16 hex chars by default
    expect(text).toMatch(/^[0-9a-f]{16}$/);
  });

  it("applies hash strategy via rules[]", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "hash" } }],
    });
    expect(text).toMatch(/^[0-9a-f]{16}$/);
  });

  it("falls back to sync strategy for non-hash strategies in needsAsync path", async () => {
    // tokenize triggers the needsAsync path; non-hash matches use applyStrategySync
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "tokenize" },
    });
    expect(text).toBe("[REDACTED]");
    warnSpy.mockRestore();
  });

  it("applies encrypt strategy (async path falls back to sync redact)", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "encrypt" },
    });
    expect(text).not.toContain("alice@example.com");
    warnSpy.mockRestore();
  });

  it("applies synthesize strategy (async path falls back to sync redact)", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "synthesize" },
    });
    expect(text).not.toContain("alice@example.com");
    warnSpy.mockRestore();
  });

  it("globalReplacement works in the async path", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
      globalReplacement: "***",
    });
    expect(text).toBe("***");
  });

  it("consistentTokens works in the async path", async () => {
    const { text } = await anonymizeAsync(
      "alice@example.com and alice@example.com again",
      { defaultStrategy: { strategy: "hash" }, consistentTokens: true },
    );
    expect(text).toBe("EMAIL_1 and EMAIL_1 again");
  });

  it("includeMatches works in the async path", async () => {
    const { matches } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
      includeMatches: true,
    });
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("email");
  });

  it("customPatterns work in the async path", async () => {
    const { text } = await anonymizeAsync("ORDER-12345 confirmed.", {
      defaultStrategy: { strategy: "hash" },
      customPatterns: [{ pattern: /ORDER-\d+/g, label: "[ORDER]" }],
      rules: [],
    });
    expect(text).toBe("[ORDER] confirmed.");
  });

  it("allowlist suppresses matches in the async path", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
      allowlist: ["alice@example.com"],
    });
    expect(text).toBe("alice@example.com");
  });

  it("confidenceThreshold filters matches in the async path", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
      confidenceThreshold: 1.0,
    });
    expect(text).toBe("alice@example.com");
  });

  it("preset in async path resolves categories from preset config", async () => {
    // Pass explicit rules with hash strategy so needsAsync=true,
    // but also provide a preset so the preset-resolution block is entered.
    const { text } = await anonymizeAsync("alice@example.com", {
      preset: "gdpr",
      rules: [{ category: "email", strategy: { strategy: "hash" } }],
    });
    // email matched by hash rule → 16-char hex
    expect(text).toMatch(/^[0-9a-f]{16}$/);
  });

  it("preset async path builds rules from preset categories when no explicit rules given", async () => {
    // defaultStrategy: hash makes needsAsync=true; no options.rules so the destructuring
    // default uses resolvedPreset.categories.map() — covers the preset-rules-building branch.
    const { text } = await anonymizeAsync("alice@example.com", {
      preset: "gdpr",
      defaultStrategy: { strategy: "hash" },
    });
    // GDPR preset maps email → preset's own defaultStrategy (pseudonymize),
    // which overrides the passed defaultStrategy for preset-covered categories.
    expect(text).not.toContain("alice@example.com");
  });

  it("throws PresetNotFoundError for unknown preset in async path", async () => {
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      anonymizeAsync("text", { preset: "nonexistent" as any, defaultStrategy: { strategy: "hash" } }),
    ).rejects.toThrow(PresetNotFoundError);
  });

  it("throws UnknownCategoryError for invalid category in rules in async path", async () => {
    await expect(
      anonymizeAsync("text", {
        rules: [
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { category: "bad-cat" as any, strategy: { strategy: "hash" } },
        ],
      }),
    ).rejects.toThrow(UnknownCategoryError);
  });

  it("enabledCategories works in async path (via sync delegation)", async () => {
    const { text } = await anonymizeAsync("alice@example.com and 555-867-5309", {
      enabledCategories: { email: true },
    });
    expect(text).not.toContain("alice@example.com");
    expect(text).toContain("555-867-5309");
  });

  it("returns unchanged text when no PII found in async path", async () => {
    const { text } = await anonymizeAsync("No PII here.", {
      defaultStrategy: { strategy: "hash" },
    });
    expect(text).toBe("No PII here.");
  });
});

// ---------------------------------------------------------------------------
// anonymizeRecord() — edge cases
// ---------------------------------------------------------------------------
describe("anonymizeRecord() — edge cases", () => {
  it("converts a non-string field value to string before applying strategy", () => {
    // age is a number, not a string — String(27) → '27' → generalize → '20-29'
    const result = anonymizeRecord(
      { age: 27 } as unknown as Record<string, unknown>,
      { age: { strategy: { strategy: "generalize" } } },
    );
    expect(result.age).toBe("20-29");
  });

  it("skips a dotted-path field when an intermediate key is null", () => {
    const record = { a: null } as unknown as Record<string, unknown>;
    // 'a.b' traversal: first key 'a' is null → getByPath returns undefined → skipped
    const result = anonymizeRecord(record, {
      "a.b": { strategy: { strategy: "redact" } },
    });
    expect(result["a"]).toBeNull();
  });

  it("skips a dotted-path field when an intermediate key is an array", () => {
    const record = { items: ["alice@example.com"] } as unknown as Record<string, unknown>;
    // 'items.0' traversal: items is an array → getByPath returns undefined
    const result = anonymizeRecord(record, {
      "items.0": { strategy: { strategy: "redact" } },
    });
    // The array itself should be untouched since traversal short-circuits
    expect(Array.isArray(result["items"])).toBe(true);
  });

  it("skips a dotted-path field when an intermediate key is a non-object primitive", () => {
    const record = { meta: "not-an-object" } as unknown as Record<string, unknown>;
    const result = anonymizeRecord(record, {
      "meta.author": { strategy: { strategy: "redact" } },
    });
    expect(result["meta"]).toBe("not-an-object");
  });

  it("skips a targeted field whose value is a non-primitive (object/array) — line 879 branch", () => {
    // 'tags' value is an array → typeof is 'object' → not string/number/boolean → skipped
    const record = { name: "Alice", tags: ["a", "b"] } as unknown as Record<string, unknown>;
    const result = anonymizeRecord(record, {
      tags: { strategy: { strategy: "redact" } },
    });
    // The array should remain untouched
    expect(result["tags"]).toEqual(["a", "b"]);
    // Other fields unaffected
    expect(result["name"]).toBe("Alice");
  });
});

// ---------------------------------------------------------------------------
// createAnonymizer() — preset config
// ---------------------------------------------------------------------------
describe("createAnonymizer() — preset", () => {
  it("throws PresetNotFoundError for an unknown preset", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => createAnonymizer({ preset: "nonexistent-preset" as any })).toThrow(
      PresetNotFoundError,
    );
  });

  it("creates an anonymizer from a valid preset and processes text", () => {
    const anonymizer = createAnonymizer({ preset: "gdpr" });
    const { text } = anonymizer.anonymize("alice@example.com");
    expect(text).not.toContain("alice@example.com");
  });

  it("preset anonymizer detect() filters to preset categories", () => {
    const anonymizer = createAnonymizer({ preset: "gdpr" });
    const matches = anonymizer.detect("alice@example.com");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("anonymizeAsync on createAnonymizer uses baseOptions with preset", async () => {
    const anonymizer = createAnonymizer({ preset: "gdpr" });
    const { text } = await anonymizer.anonymizeAsync("alice@example.com");
    expect(text).not.toContain("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// createAnonymizer().tokenize() — allowlist and edge cases
// ---------------------------------------------------------------------------
describe("createAnonymizer().tokenize()", () => {
  it("tokenizes PII and returns mapping", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { text, mapping } = anonymizer.tokenize("alice@example.com");
    expect(text).not.toContain("alice@example.com");
    // mapping is a Map<token, originalValue>
    expect(mapping.size).toBeGreaterThan(0);
  });

  it("allowlist suppresses tokenization of matching values", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { text } = anonymizer.tokenize("alice@example.com", {
      allowlist: ["alice@example.com"],
    });
    expect(text).toBe("alice@example.com");
  });

  it("allowlistCaseSensitive: true suppresses exact-case matches only", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { text } = anonymizer.tokenize("alice@example.com", {
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    expect(text).toBe("alice@example.com");
  });

  it("allowlistCaseSensitive: true does not suppress a differently-cased value in tokenize", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    // Case-sensitive allowlist — "ALICE@..." doesn't match "alice@..."
    const { text } = anonymizer.tokenize("ALICE@EXAMPLE.COM", {
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    // ALICE@EXAMPLE.COM should still be tokenized (not in allowlist when case-sensitive)
    expect(text).not.toBe("ALICE@EXAMPLE.COM");
  });

  it("allowlist with multiple entries, caseSensitive:true, tokenize passes through allowlisted email", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { text, tokens } = anonymizer.tokenize(
      "alice@example.com and bob@example.com",
      {
        allowlist: ["alice@example.com", "bob@example.com"],
        allowlistCaseSensitive: true,
      },
    );
    // Both emails are in the case-sensitive allowlist → both pass through
    expect(text).toBe("alice@example.com and bob@example.com");
    expect(tokens).toHaveLength(0);
  });

  it("tokenize with large allowlist and case-sensitive flag exercises the tCaseSensitive branch", () => {
    // A large allowlist forces V8 to fully compile the map callback
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const allowlist = Array.from({ length: 20 }, (_, i) => `user${i}@example.com`);
    const { tokens } = anonymizer.tokenize("test@example.com", {
      allowlist,
      allowlistCaseSensitive: true,
    });
    // test@example.com is not in the allowlist → gets tokenized
    expect(tokens).toHaveLength(1);
  });

  it("confidenceThreshold filters tokenize matches", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { text } = anonymizer.tokenize("alice@example.com", {
      confidenceThreshold: 1.0,
    });
    expect(text).toBe("alice@example.com");
  });

  it("returns tokens list with correct structure", () => {
    const anonymizer = createAnonymizer({ categories: ["email"] });
    const { tokens } = anonymizer.tokenize("alice@example.com");
    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.category).toBe("email");
    expect(tokens[0]?.original).toBe("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// anonymize() — pci-dss preset (preset with per-category rules coverage)
// ---------------------------------------------------------------------------
describe("anonymize() — pci-dss preset with per-category rules", () => {
  it("applies preset-specific rule for credit-card (mask) and default for email (redact)", () => {
    // pci-dss has rules: credit-card → mask, bank-account → mask; default: redact
    // This exercises the resolvedPreset!.rules?.find(...)?.strategy branch (both
    // found and not-found outcomes at line 421).
    const { text } = anonymize(
      "Card: 4111111111111111 email: alice@example.com",
      { preset: "pci-dss" },
    );
    // Credit card is masked (ends with last 4 digits)
    expect(text).not.toContain("4111111111111111");
    // Email is redacted
    expect(text).not.toContain("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// anonymize() — consistentTokens with custom category (TOKEN_PREFIX_MAP fallback)
// ---------------------------------------------------------------------------
describe("anonymize() — consistentTokens with custom pattern category", () => {
  it("uses toUpperCase prefix for a custom category not in TOKEN_PREFIX_MAP", () => {
    // Custom pattern category "order-id" is not in TOKEN_PREFIX_MAP \u2192 falls back to toUpperCase
    const { text } = anonymize("ORDER-00001 and ORDER-00002", {
      customPatterns: [{ pattern: /ORDER-\d+/g, category: "order-id" }],
      rules: [],
      consistentTokens: true,
    });
    // Custom categories get prefix from toUpperCase → "ORDER-ID_1", "ORDER-ID_2"
    expect(text).toContain("ORDER-ID_1");
    expect(text).toContain("ORDER-ID_2");
  });
});

// ---------------------------------------------------------------------------
// anonymizeAsync() — additional branch coverage
// ---------------------------------------------------------------------------
describe("anonymizeAsync() — additional branch coverage", () => {
  it("allowlistCaseSensitive: true in async path suppresses matches", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
      allowlist: ["alice@example.com"],
      allowlistCaseSensitive: true,
    });
    expect(text).toBe("alice@example.com");
  });

  it("enabledCategories in async path (hash strategy trigger)", async () => {
    const { text } = await anonymizeAsync("alice@example.com and 555-867-5309", {
      defaultStrategy: { strategy: "hash" },
      enabledCategories: { email: true },
    });
    // Email should be hashed
    expect(text).not.toContain("alice@example.com");
    // Phone NOT in enabledCategories → not processed
    expect(text).toContain("555-867-5309");
  });

  it("pci-dss preset in async — applies preset per-category rules", async () => {
    // No options.rules provided: preset's own rules are used via resolvedPreset.categories.map
    // pci-dss has rules for credit-card + bank-account; other categories fallback to defaultStrategy
    const { text } = await anonymizeAsync(
      "Card: 4111111111111111 and alice@example.com",
      { preset: "pci-dss", defaultStrategy: { strategy: "hash" } },
    );
    expect(text).not.toContain("4111111111111111");
    expect(text).not.toContain("alice@example.com");
  });

  it("consistentTokens with custom category uses toUpperCase prefix in async path", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { text } = await anonymizeAsync("ORDER-00001 and ORDER-00001", {
      customPatterns: [{ pattern: /ORDER-\d+/g, category: "order-id" }],
      rules: [],
      defaultStrategy: { strategy: "tokenize" }, // triggers async path
      consistentTokens: true,
    });
    // Both occurrences should receive the same custom-category token
    expect((text.match(/ORDER-ID_1/g) ?? []).length).toBe(2);
    warnSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// createAnonymizer() — config property spreading in baseOptions
// ---------------------------------------------------------------------------
describe("createAnonymizer() — optional config properties in baseOptions", () => {
  it("customDetectors config is forwarded to baseOptions", () => {
    const noop = () => [] as ReturnType<typeof import("../src/anonymize.js").detect>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const anonymizer = createAnonymizer({ customDetectors: { email: noop as any } });
    // With noop email detector, email should NOT be redacted
    const { text } = anonymizer.anonymize("alice@example.com");
    expect(text).toBe("alice@example.com");
  });

  it("customPatterns config is forwarded to baseOptions", () => {
    const anonymizer = createAnonymizer({
      categories: [],
      customPatterns: [{ pattern: /ORDER-\d+/g, label: "[ORDER]" }],
    });
    const { text } = anonymizer.anonymize("ORDER-12345");
    expect(text).toBe("[ORDER]");
  });

  it("consistentTokens config is forwarded to baseOptions", () => {
    const anonymizer = createAnonymizer({ categories: ["email"], consistentTokens: true });
    const { text } = anonymizer.anonymize("alice@example.com and alice@example.com");
    expect(text).toBe("EMAIL_1 and EMAIL_1");
  });

  it("overrides.rules in baseOptions takes precedence over preset/categories mapping", () => {
    const anonymizer = createAnonymizer({ preset: "gdpr" });
    // Passing overrides with explicit rules inside anonymize()
    const { text } = anonymizer.anonymize("alice@example.com", {
      rules: [{ category: "email", strategy: { strategy: "redact", label: "[EMAIL_OVERRIDE]" } }],
    });
    expect(text).toBe("[EMAIL_OVERRIDE]");
  });

  it("pci-dss preset in createAnonymizer uses per-category rules in baseOptions", () => {
    const anonymizer = createAnonymizer({ preset: "pci-dss" });
    const { text } = anonymizer.anonymize("Card: 4111111111111111");
    // pci-dss maps credit-card → mask, so card digits should be masked
    expect(text).not.toContain("4111111111111111");
  });
});
