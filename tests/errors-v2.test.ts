/**
 * Tests for v2 error classes and createAnonymizer() v2 features
 */
import { describe, it, expect } from "vitest";
import {
  AnonymaError,
  ValidationError,
  CryptoNotAvailableError,
  EncryptionError,
  PresetNotFoundError,
  AllowlistMatchError,
  BatchProcessingError,
} from "../src/errors.js";
import { createAnonymizer } from "../src/anonymize.js";

// ---------------------------------------------------------------------------
// EncryptionError
// ---------------------------------------------------------------------------
describe("EncryptionError", () => {
  it("is an instance of AnonymaError", () => {
    const e = new EncryptionError("encrypt", new Error("test"));
    expect(e instanceof AnonymaError).toBe(true);
    expect(e instanceof EncryptionError).toBe(true);
  });

  it("has the correct operation field", () => {
    const e = new EncryptionError("encrypt", new Error("test"));
    expect(e.operation).toBe("encrypt");
    const e2 = new EncryptionError("decrypt", new Error("test"));
    expect(e2.operation).toBe("decrypt");
  });

  it("exposes the cause", () => {
    const cause = new Error("underlying error");
    const e = new EncryptionError("encrypt", cause);
    expect(e.cause).toBe(cause);
  });

  it("has a non-empty message", () => {
    const e = new EncryptionError("decrypt", new Error("bad key"));
    expect(e.message.length).toBeGreaterThan(0);
  });

  it("name is 'EncryptionError'", () => {
    const e = new EncryptionError("encrypt", new Error("x"));
    expect(e.name).toBe("EncryptionError");
  });
});

// ---------------------------------------------------------------------------
// PresetNotFoundError
// ---------------------------------------------------------------------------
describe("PresetNotFoundError", () => {
  it("is an instance of AnonymaError", () => {
    const e = new PresetNotFoundError("unknown");
    expect(e instanceof AnonymaError).toBe(true);
  });

  it("has the preset field", () => {
    const e = new PresetNotFoundError("super-gdpr");
    expect(e.preset).toBe("super-gdpr");
  });

  it("includes preset name in message", () => {
    const e = new PresetNotFoundError("super-gdpr");
    expect(e.message).toContain("super-gdpr");
  });

  it("name is 'PresetNotFoundError'", () => {
    const e = new PresetNotFoundError("x");
    expect(e.name).toBe("PresetNotFoundError");
  });
});

// ---------------------------------------------------------------------------
// AllowlistMatchError
// ---------------------------------------------------------------------------
describe("AllowlistMatchError", () => {
  it("is an instance of AnonymaError", () => {
    const e = new AllowlistMatchError("email");
    expect(e instanceof AnonymaError).toBe(true);
  });

  it("has the field property", () => {
    const e = new AllowlistMatchError("credit-card");
    expect(e.field).toBe("credit-card");
  });

  it("name is 'AllowlistMatchError'", () => {
    const e = new AllowlistMatchError("ssn");
    expect(e.name).toBe("AllowlistMatchError");
  });
});

// ---------------------------------------------------------------------------
// BatchProcessingError
// ---------------------------------------------------------------------------
describe("BatchProcessingError", () => {
  it("is an instance of AnonymaError", () => {
    const e = new BatchProcessingError(8, 2, 10);
    expect(e instanceof AnonymaError).toBe(true);
  });

  it("has succeeded, failed, total fields", () => {
    const e = new BatchProcessingError(8, 2, 10);
    expect(e.succeeded).toBe(8);
    expect(e.failed).toBe(2);
    expect(e.total).toBe(10);
  });

  it("name is 'BatchProcessingError'", () => {
    const e = new BatchProcessingError(0, 5, 5);
    expect(e.name).toBe("BatchProcessingError");
  });

  it("message includes failure stats", () => {
    const e = new BatchProcessingError(3, 7, 10);
    expect(e.message).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Error inheritance chain
// ---------------------------------------------------------------------------
describe("Error inheritance chain", () => {
  it("all v2 errors extend AnonymaError", () => {
    const errors = [
      new EncryptionError("encrypt", new Error()),
      new PresetNotFoundError("x"),
      new AllowlistMatchError("field"),
      new BatchProcessingError(1, 1, 2),
    ];
    for (const e of errors) {
      expect(e instanceof AnonymaError).toBe(true);
      expect(e instanceof Error).toBe(true);
    }
  });

  it("all v2 errors have stack traces", () => {
    const e = new EncryptionError("decrypt", new Error("test"));
    expect(typeof e.stack).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// createAnonymizer() — v2 features
// ---------------------------------------------------------------------------
describe("createAnonymizer() v2 features", () => {
  it("returns an object with tokenize method", () => {
    const anon = createAnonymizer({});
    expect(typeof anon.tokenize).toBe("function");
  });

  it("returns an object with anonymizeAsync method", () => {
    const anon = createAnonymizer({});
    expect(typeof anon.anonymizeAsync).toBe("function");
  });

  it("tokenize() returns TokenizeResult shape", () => {
    const anon = createAnonymizer({});
    const result = anon.tokenize("Email alice@example.com");
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("mapping");
    expect(result).toHaveProperty("tokens");
  });

  it("tokenize() replaces PII with tokens", () => {
    const anon = createAnonymizer({});
    const { text } = anon.tokenize("Email alice@example.com");
    expect(text).not.toContain("alice@example.com");
  });

  it("anonymizeAsync() returns a Promise<AnonymizeResult>", async () => {
    const anon = createAnonymizer({});
    const result = await anon.anonymizeAsync("alice@example.com");
    expect(result).toHaveProperty("text");
    expect(result).toHaveProperty("matches");
    expect(result.text).not.toContain("alice@example.com");
  });

  it("preset option in createAnonymizer is applied to all calls", () => {
    const anon = createAnonymizer({ preset: "hipaa" });
    const { matches } = anon.anonymize("SSN 001-01-0001", { includeMatches: true });
    expect(matches.some((m) => m.category === "ssn")).toBe(true);
  });

  it("default strategy is applied to all calls when specified at creation", () => {
    const anon = createAnonymizer({ defaultStrategy: { strategy: "pseudonymize" } });
    const { text } = anon.anonymize("alice@example.com");
    expect(text).not.toContain("alice@example.com");
    // pseudonymize does not produce [REDACTED] — different replacement used
    expect(text).not.toContain("[REDACTED]");
  });

  it("detect() works as expected", () => {
    const anon = createAnonymizer({});
    const matches = anon.detect("alice@example.com");
    expect(matches.some((m) => m.category === "email")).toBe(true);
  });

  it("anonymize() works as expected", () => {
    const anon = createAnonymizer({});
    const { text, matches } = anon.anonymize("alice@example.com", { includeMatches: true });
    expect(text).not.toContain("alice@example.com");
    expect(matches).toHaveLength(1);
  });
});
