import { describe, it, expect } from "vitest";
import { mask } from "../src/strategies/mask.js";
import { redact } from "../src/strategies/redact.js";
import { pseudonymize } from "../src/strategies/pseudonymize.js";
import { hash } from "../src/strategies/hash.js";
import { generalize } from "../src/strategies/generalize.js";
import { ValidationError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// mask
// ---------------------------------------------------------------------------
describe("mask", () => {
  it("masks the entire string by default", () => {
    expect(mask("hello")).toBe("*****");
  });

  it("respects keepLeading", () => {
    expect(mask("hello", { keepLeading: 2 })).toBe("he***");
  });

  it("respects keepTrailing", () => {
    expect(mask("hello", { keepTrailing: 2 })).toBe("***lo");
  });

  it("respects both keepLeading and keepTrailing", () => {
    expect(mask("hello world", { keepLeading: 2, keepTrailing: 3 })).toBe("he******rld");
  });

  it("uses a custom mask character", () => {
    expect(mask("hello", { maskChar: "X" })).toBe("XXXXX");
  });

  it("returns all masked when keepLeading + keepTrailing >= length", () => {
    expect(mask("hi", { keepLeading: 1, keepTrailing: 2 })).toBe("**");
  });

  it("handles empty string", () => {
    expect(mask("")).toBe("");
  });

  it("throws ValidationError for invalid maskChar", () => {
    expect(() => mask("x", { maskChar: "**" })).toThrow(ValidationError);
  });

  it("throws ValidationError for negative keepLeading", () => {
    expect(() => mask("x", { keepLeading: -1 })).toThrow(ValidationError);
  });

  it("throws ValidationError for negative keepTrailing", () => {
    expect(() => mask("x", { keepTrailing: -1 })).toThrow(ValidationError);
  });

  it("throws ValidationError for non-integer keepLeading", () => {
    expect(() => mask("x", { keepLeading: 1.5 })).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// redact
// ---------------------------------------------------------------------------
describe("redact", () => {
  it("replaces with default label", () => {
    expect(redact("anything")).toBe("[REDACTED]");
  });

  it("uses a custom label", () => {
    expect(redact("anything", { label: "[REMOVED]" })).toBe("[REMOVED]");
  });

  it("throws ValidationError for empty label", () => {
    expect(() => redact("x", { label: "" })).toThrow(ValidationError);
  });

  it("throws ValidationError for whitespace-only label", () => {
    expect(() => redact("x", { label: "   " })).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// pseudonymize
// ---------------------------------------------------------------------------
describe("pseudonymize", () => {
  it("returns a string starting with the default prefix", () => {
    const result = pseudonymize("alice@example.com");
    expect(result).toMatch(/^id_[0-9a-f]+$/);
  });

  it("is deterministic when a seed is provided", () => {
    const a = pseudonymize("alice@example.com", { seed: "secret" });
    const b = pseudonymize("alice@example.com", { seed: "secret" });
    expect(a).toBe(b);
  });

  it("produces different outputs for different seeds", () => {
    const a = pseudonymize("alice@example.com", { seed: "seed1" });
    const b = pseudonymize("alice@example.com", { seed: "seed2" });
    expect(a).not.toBe(b);
  });

  it("produces different outputs for different values with same seed", () => {
    const a = pseudonymize("alice@example.com", { seed: "secret" });
    const b = pseudonymize("bob@example.com", { seed: "secret" });
    expect(a).not.toBe(b);
  });

  it("respects a custom prefix", () => {
    const result = pseudonymize("val", { seed: "s", prefix: "user_" });
    expect(result).toMatch(/^user_/);
  });

  it("throws ValidationError for prefix with whitespace", () => {
    expect(() => pseudonymize("val", { prefix: "id_ " })).toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------
describe("hash", () => {
  it("returns a hex string of the default truncate length (16)", async () => {
    const result = await hash("alice@example.com");
    expect(result).toMatch(/^[0-9a-f]{16}$/);
  });

  it("respects a custom truncate length", async () => {
    const result = await hash("alice@example.com", { truncate: 32 });
    expect(result).toHaveLength(32);
  });

  it("is deterministic", async () => {
    const a = await hash("alice@example.com");
    const b = await hash("alice@example.com");
    expect(a).toBe(b);
  });

  it("produces different output with a pepper", async () => {
    const plain = await hash("alice@example.com");
    const peppered = await hash("alice@example.com", { pepper: "secret-pepper" });
    expect(plain).not.toBe(peppered);
  });

  it("pepper is deterministic", async () => {
    const a = await hash("alice@example.com", { pepper: "p" });
    const b = await hash("alice@example.com", { pepper: "p" });
    expect(a).toBe(b);
  });

  it("throws ValidationError for truncate = 0", async () => {
    await expect(hash("x", { truncate: 0 })).rejects.toThrow(ValidationError);
  });

  it("throws ValidationError for truncate > 64", async () => {
    await expect(hash("x", { truncate: 65 })).rejects.toThrow(ValidationError);
  });

  it("throws ValidationError for non-integer truncate", async () => {
    await expect(hash("x", { truncate: 1.5 })).rejects.toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// generalize
// ---------------------------------------------------------------------------
describe("generalize", () => {
  it("buckets a numeric string into the default 10-wide range", () => {
    expect(generalize("27")).toBe("20-29");
    expect(generalize("20")).toBe("20-29");
    expect(generalize("29")).toBe("20-29");
    expect(generalize("30")).toBe("30-39");
  });

  it("respects a custom bucketSize", () => {
    expect(generalize("27", { bucketSize: 5 })).toBe("25-29");
    expect(generalize("10", { bucketSize: 5 })).toBe("10-14");
  });

  it("handles zero", () => {
    expect(generalize("0")).toBe("0-9");
  });

  it("passes through non-numeric strings unchanged", () => {
    expect(generalize("N/A")).toBe("N/A");
    expect(generalize("unknown")).toBe("unknown");
  });

  it("handles floating-point by flooring", () => {
    expect(generalize("27.9")).toBe("20-29");
  });

  it("throws ValidationError for bucketSize = 0", () => {
    expect(() => generalize("27", { bucketSize: 0 })).toThrow(ValidationError);
  });

  it("throws ValidationError for negative bucketSize", () => {
    expect(() => generalize("27", { bucketSize: -5 })).toThrow(ValidationError);
  });
});
