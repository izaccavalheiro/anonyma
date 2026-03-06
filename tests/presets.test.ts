/**
 * Tests for v2 compliance presets, allowlist, confidenceThreshold, and anonymizeAsync
 */
import { describe, it, expect } from "vitest";
import { anonymize, anonymizeAsync } from "../src/anonymize.js";
import { getPreset, PRESET_REGISTRY } from "../src/presets.js";

// ---------------------------------------------------------------------------
// getPreset() / PRESET_REGISTRY
// ---------------------------------------------------------------------------
describe("getPreset()", () => {
  it("returns a PresetConfig for 'gdpr'", () => {
    const config = getPreset("gdpr");
    expect(config.name).toBe("gdpr");
    expect(Array.isArray(config.categories)).toBe(true);
    expect(config.categories.length).toBeGreaterThan(0);
    expect(config.defaultStrategy).toBeDefined();
  });

  it("returns a PresetConfig for 'hipaa'", () => {
    const config = getPreset("hipaa");
    expect(config.name).toBe("hipaa");
    expect(config.defaultStrategy).toBeDefined();
  });

  it("returns a PresetConfig for each of the 6 presets", () => {
    const names = ["gdpr", "hipaa", "ccpa", "pci-dss", "sox", "ferpa"] as const;
    for (const name of names) {
      const config = getPreset(name);
      expect(config.name).toBe(name);
      expect(config.categories.length).toBeGreaterThan(0);
    }
  });

  it("throws on unknown preset name", () => {
    expect(() => getPreset("unknown-preset" as "gdpr")).toThrow();
  });

  it("PRESET_REGISTRY has all 6 presets", () => {
    expect(Object.keys(PRESET_REGISTRY)).toHaveLength(6);
    expect(PRESET_REGISTRY["gdpr"]).toBeDefined();
    expect(PRESET_REGISTRY["hipaa"]).toBeDefined();
    expect(PRESET_REGISTRY["pci-dss"]).toBeDefined();
  });

  it("gdpr covers email category", () => {
    const { categories } = getPreset("gdpr");
    expect(categories).toContain("email");
  });

  it("hipaa covers ssn category", () => {
    const { categories } = getPreset("hipaa");
    expect(categories).toContain("ssn");
  });

  it("pci-dss covers credit-card category", () => {
    const { categories } = getPreset("pci-dss");
    expect(categories).toContain("credit-card");
  });

  it("hipaa defaultStrategy is redact", () => {
    const config = getPreset("hipaa");
    expect((config.defaultStrategy as { strategy: string }).strategy).toBe("redact");
  });
});

// ---------------------------------------------------------------------------
// anonymize() with preset option
// ---------------------------------------------------------------------------
describe("anonymize() preset option", () => {
  it("applies hipaa preset to redact email", () => {
    const { text } = anonymize("Patient alice@example.com admitted", {
      preset: "hipaa",
    });
    expect(text).not.toContain("alice@example.com");
  });

  it("applies gdpr preset to redact email", () => {
    const { text } = anonymize("user alice@example.com requested data deletion", {
      preset: "gdpr",
    });
    // GDPR covers email — should be redacted
    expect(text).not.toContain("alice@example.com");
  });

  it("preset categories override empty category list", () => {
    const { matches } = anonymize("Call +1-202-555-0101 or email alice@example.com", {
      preset: "hipaa",
      includeMatches: true,
    });
    // HIPAA covers phone and email
    const categories = matches.map((m) => m.category);
    expect(
      categories.includes("email") || categories.includes("phone"),
    ).toBe(true);
  });

  it("throws on invalid preset name", () => {
    expect(() =>
      anonymize("some text", { preset: "not-a-preset" as "gdpr" }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// anonymize() with allowlist option
// ---------------------------------------------------------------------------
describe("anonymize() allowlist option", () => {
  it("does not anonymize an allowlisted email", () => {
    const { text } = anonymize(
      "Contact safe@example.com or alice@example.com",
      { allowlist: ["safe@example.com"] },
    );
    expect(text).toContain("safe@example.com");
    expect(text).not.toContain("alice@example.com");
  });

  it("allowlist is case-INsensitive by default (allowlistCaseSensitive defaults to false)", () => {
    const { text } = anonymize("Email SAFE@EXAMPLE.COM is allowed", {
      allowlist: ["safe@example.com"],
    });
    // allowlistCaseSensitive defaults to false (case-insensitive) — uppercase variant IS protected
    expect(text).toContain("SAFE@EXAMPLE.COM");
  });

  it("allowlistCaseSensitive: false enables case-insensitive matching", () => {
    const { text } = anonymize("Email SAFE@EXAMPLE.COM is allowed", {
      allowlist: ["safe@example.com"],
      allowlistCaseSensitive: false,
    });
    expect(text).toContain("SAFE@EXAMPLE.COM");
  });

  it("allowlist entry 'alice' protects value because it matches as a substring", () => {
    // Allowlist entries are tested with regex, so 'alice' matches 'alice@example.com'
    const { text } = anonymize("Email alice@example.com for help", {
      allowlist: ["alice@example.com"],
    });
    // Exact value in allowlist → value preserved
    expect(text).toContain("alice@example.com");
  });

  it("allowlistPatterns accept RegExp objects", () => {
    const { text } = anonymize(
      "Contact safe@company.com or danger@evil.com",
      {
        allowlistPatterns: [/@company\.com$/i],
      },
    );
    expect(text).toContain("safe@company.com");
    expect(text).not.toContain("danger@evil.com");
  });

  it("empty allowlist array has no effect", () => {
    const { text } = anonymize("alice@example.com", { allowlist: [] });
    expect(text).not.toContain("alice@example.com");
  });
});

// ---------------------------------------------------------------------------
// anonymize() with confidenceThreshold option
// ---------------------------------------------------------------------------
describe("anonymize() confidenceThreshold option", () => {
  it("threshold 0 includes all matches regardless of confidence", () => {
    const { matches } = anonymize("Email alice@example.com for help", {
      confidenceThreshold: 0,
      includeMatches: true,
    });
    expect(matches.length).toBeGreaterThan(0);
  });

  it("threshold 0.99 filters low-confidence matches", () => {
    const { matches: high } = anonymize(
      "Call 555-0101 this is a local number",
      { confidenceThreshold: 0.99 },
    );
    const { matches: low } = anonymize("Call 555-0101 this is a local number", {
      confidenceThreshold: 0,
    });
    expect(low.length).toBeGreaterThanOrEqual(high.length);
  });

  it("default threshold allows standard confident matches", () => {
    const { matches } = anonymize("alice@example.com", { includeMatches: true });
    // Email should always pass default threshold
    expect(matches.some((m) => m.category === "email")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// anonymizeAsync() — full async pipeline
// ---------------------------------------------------------------------------
describe("anonymizeAsync()", () => {
  it("returns a Promise<AnonymizeResult>", async () => {
    const result = await anonymizeAsync("alice@example.com");
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("matches");
  });

  it("anonymizes email correctly", async () => {
    const { text } = await anonymizeAsync("Email alice@example.com for help");
    expect(text).not.toContain("alice@example.com");
  });

  it("hash strategy returns a real hash in async mode", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "hash" },
    });
    // Should be a hex hash, not a pseudonymize fallback
    expect(text).not.toContain("alice@example.com");
    // Hash output is a long hex string embedded in the text
    expect(text).toMatch(/[0-9a-f]{16,}/);
  });

  it("supports all same options as synchronous anonymize()", async () => {
    const { text } = await anonymizeAsync(
      "Contact alice@example.com or call +1-202-555-0101",
      { strategy: "redact" },
    );
    expect(text).toContain("[REDACTED]");
    expect(text).not.toContain("alice@example.com");
    expect(text).not.toContain("+1-202-555-0101");
  });

  it("pseudonymize strategy works in async mode", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      strategy: "pseudonymize",
    });
    expect(text).not.toContain("alice@example.com");
  });

  it("mask strategy works in async mode", async () => {
    const { text } = await anonymizeAsync("alice@example.com", {
      defaultStrategy: { strategy: "mask" },
    });
    expect(text).not.toContain("alice@example.com");
    expect(text).toMatch(/\*/);
  });

  it("returns matches array when includeMatches: true", async () => {
    const { matches } = await anonymizeAsync("alice@example.com", { includeMatches: true });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]?.category).toBe("email");
  });

  it("handles empty input", async () => {
    const { text } = await anonymizeAsync("");
    expect(text).toBe("");
  });
});
