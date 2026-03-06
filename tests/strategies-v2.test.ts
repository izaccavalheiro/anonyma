/**
 * Tests for v2 strategies: encrypt, synthesize, mask preserveFormat
 */
import { describe, it, expect } from "vitest";
import { encrypt, decrypt } from "../src/strategies/encrypt.js";
import { synthesize } from "../src/strategies/synthesize.js";
import { mask } from "../src/strategies/mask.js";
import { EncryptionError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// mask() — preserveFormat option
// ---------------------------------------------------------------------------
describe("mask() preserveFormat", () => {
  it("alpha characters become X when preserveFormat: true", () => {
    const result = mask("AbCd", { preserveFormat: true });
    expect(result).toBe("XxXx");
  });

  it("digits become 0 when preserveFormat: true", () => {
    const result = mask("1234", { preserveFormat: true });
    expect(result).toBe("0000");
  });

  it("separators are preserved unchanged", () => {
    const result = mask("4111-1111-1111-1111", { preserveFormat: true });
    expect(result).toBe("0000-0000-0000-0000");
  });

  it("preserveFormat with keepTrailing leaves trailing digits intact", () => {
    const result = mask("4111-1111-1111-1111", {
      preserveFormat: true,
      keepTrailing: 4,
    });
    expect(result).toBe("0000-0000-0000-1111");
  });

  it("preserveFormat with keepLeading leaves leading chars intact", () => {
    const result = mask("(555) 867-5309", {
      preserveFormat: true,
      keepLeading: 5,
    });
    // leading 5 chars = "(555)" kept, rest masked
    expect(result.startsWith("(555)")).toBe(true);
  });

  it("preserveFormat: false is the default (uses maskChar)", () => {
    const result = mask("1234-5678", { maskChar: "#" });
    expect(result).toBe("#########");
  });

  it("uppercase alpha → 'X', lowercase alpha → 'x'", () => {
    const result = mask("HeLLo", { preserveFormat: true });
    expect(result).toBe("XxXXx");
  });

  it("mixed alphanumeric preserves format positions", () => {
    // "A1B2" → "X0X0"
    const result = mask("A1B2", { preserveFormat: true });
    expect(result).toBe("X0X0");
  });

  it("symbols/spaces are preserved as-is", () => {
    const result = mask("123 456", { preserveFormat: true });
    expect(result).toBe("000 000");
  });
});

// ---------------------------------------------------------------------------
// synthesize() — deterministic
// ---------------------------------------------------------------------------
describe("synthesize()", () => {
  it("returns a string", () => {
    expect(typeof synthesize("alice@example.com", "email")).toBe("string");
  });

  it("is deterministic — same input → same output", () => {
    const a = synthesize("alice@example.com", "email");
    const b = synthesize("alice@example.com", "email");
    expect(a).toBe(b);
  });

  it("different inputs → different outputs (usually)", () => {
    const a = synthesize("alice@example.com", "email");
    const b = synthesize("bob@example.com", "email");
    expect(a).not.toBe(b);
  });

  it("synthesized email looks like an email", () => {
    const result = synthesize("alice@example.com", "email");
    expect(result).toMatch(/^[^@]+@[^@]+\.[^@]+$/);
  });

  it("synthesized phone starts with a digit", () => {
    const result = synthesize("+1-800-555-0100", "phone");
    expect(result).toMatch(/^\+?\d/);
  });

  it("synthesized SSN has format NNN-NN-NNNN", () => {
    const result = synthesize("123-45-6789", "ssn");
    expect(result).toMatch(/^\d{3}-\d{2}-\d{4}$/);
  });

  it("synthesized credit card is 16 digits (with or without dashes)", () => {
    const result = synthesize("4111-1111-1111-1111", "credit-card");
    const digitsOnly = result.replace(/\D/g, "");
    expect(digitsOnly.length).toBe(16);
  });

  it("seed option changes output", () => {
    const a = synthesize("alice@example.com", "email", { seed: "seedA" });
    const b = synthesize("alice@example.com", "email", { seed: "seedB" });
    expect(a).not.toBe(b);
  });

  it("uses generic fallback for unknown categories", () => {
    const result = synthesize("some-value-123", "unknown-category" as "email");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("synthesized IPv4 looks like an IP", () => {
    const result = synthesize("192.168.1.1", "ip-address");
    expect(result).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  });

  it("synthesized URL looks like a URL", () => {
    const result = synthesize("https://example.com/path", "url");
    expect(result).toMatch(/^https?:\/\//);
  });

  it("synthesized name has at least two parts", () => {
    const result = synthesize("Alice Smith", "name");
    const parts = result.trim().split(/\s+/);
    expect(parts.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// encrypt() / decrypt()
// ---------------------------------------------------------------------------
describe("encrypt() / decrypt()", () => {
  const opts = { passphrase: "super-secret-password" };

  it("returns a colon-separated string (encoding:iv:ciphertext)", async () => {
    const result = await encrypt("hello world", opts);
    const parts = result.split(":");
    expect(parts.length).toBe(3);
    expect(parts[0]).toBe("base64");
  });

  it("decrypts back to original plaintext", async () => {
    const ciphertext = await encrypt("my secret value", opts);
    const plaintext = await decrypt(ciphertext, opts);
    expect(plaintext).toBe("my secret value");
  });

  it("different calls produce different ciphertexts (random IV)", async () => {
    const a = await encrypt("same", opts);
    const b = await encrypt("same", opts);
    expect(a).not.toBe(b);
  });

  it("decrypts are identical regardless of IV", async () => {
    const c1 = await encrypt("hello", opts);
    const c2 = await encrypt("hello", opts);
    expect(await decrypt(c1, opts)).toBe("hello");
    expect(await decrypt(c2, opts)).toBe("hello");
  });

  it("hex encoding works end-to-end", async () => {
    const hexOpts = { passphrase: "password", encoding: "hex" as const };
    const ciphertext = await encrypt("test value", hexOpts);
    expect(ciphertext.startsWith("hex:")).toBe(true);
    const plaintext = await decrypt(ciphertext, hexOpts);
    expect(plaintext).toBe("test value");
  });

  it("wrong passphrase throws EncryptionError on decrypt", async () => {
    const ciphertext = await encrypt("secret", { passphrase: "correctKey" });
    await expect(decrypt(ciphertext, { passphrase: "wrongKey" })).rejects.toThrow(
      EncryptionError,
    );
  });

  it("throws EncryptionError with operation: 'decrypt' on corrupt data", async () => {
    try {
      await decrypt("base64:AAAAAAAAAAAAAAAA:invalidCiphertext", opts);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e instanceof EncryptionError).toBe(true);
      expect((e as EncryptionError).operation).toBe("decrypt");
    }
  });

  it("encrypts empty string", async () => {
    const ciphertext = await encrypt("", opts);
    const plaintext = await decrypt(ciphertext, opts);
    expect(plaintext).toBe("");
  });

  it("encrypts unicode text", async () => {
    const input = "héllo wörld — αβγ 🔑";
    const ciphertext = await encrypt(input, opts);
    const plaintext = await decrypt(ciphertext, opts);
    expect(plaintext).toBe(input);
  });
});
