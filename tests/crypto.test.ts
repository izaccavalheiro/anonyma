/**
 * Tests for the `anonyma/crypto` subpath entry (`src/crypto.ts`).
 *
 * Importing from the re-export barrel is what drives coverage for that
 * file.  The suite also exercises every branch in the underlying
 * `strategies/encrypt.ts` implementation that the shared
 * `strategies-v2.test.ts` leaves uncovered:
 *
 *  - `keyBytes` (16- and 32-byte raw keys)
 *  - missing passphrase AND keyBytes → EncryptionError
 *  - invalid keyBytes length → EncryptionError
 *  - malformed ciphertext (decrypt) → EncryptionError
 *  - `CryptoNotAvailableError` when `crypto.subtle` is absent
 */

import { describe, it, expect, vi, afterEach } from "vitest";
// Import explicitly from `src/crypto.ts` (via the .js extension that the
// vitest ESM resolver remaps to .ts) so the barrel file itself is executed
// and counted by the coverage tool.
import { encrypt, decrypt } from "../src/crypto.js";
import { EncryptionError, CryptoNotAvailableError } from "../src/errors.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// Re-export surface smoke-test (covers the barrel file itself)
// ---------------------------------------------------------------------------
describe("crypto barrel (src/crypto.ts)", () => {
  it("exports encrypt as a function", () => {
    expect(typeof encrypt).toBe("function");
  });

  it("exports decrypt as a function", () => {
    expect(typeof decrypt).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// keyBytes path — 32-byte raw key
// ---------------------------------------------------------------------------
describe("encrypt/decrypt with keyBytes (32 bytes)", () => {
  const key32 = new Uint8Array(32).fill(0xab);

  it("encrypts and decrypts successfully with a 32-byte key", async () => {
    const ciphertext = await encrypt("hello raw key", { keyBytes: key32 });
    const parts = ciphertext.split(":");
    expect(parts.length).toBe(3);
    expect(parts[0]).toBe("base64");

    const plaintext = await decrypt(ciphertext, { keyBytes: key32 });
    expect(plaintext).toBe("hello raw key");
  });

  it("hex encoding works with a 32-byte key", async () => {
    const ciphertext = await encrypt("hello hex", {
      keyBytes: key32,
      encoding: "hex",
    });
    expect(ciphertext.startsWith("hex:")).toBe(true);

    const plaintext = await decrypt(ciphertext, { keyBytes: key32 });
    expect(plaintext).toBe("hello hex");
  });
});

// ---------------------------------------------------------------------------
// keyBytes path — 16-byte raw key
// ---------------------------------------------------------------------------
describe("encrypt/decrypt with keyBytes (16 bytes)", () => {
  const key16 = new Uint8Array(16).fill(0x42);

  it("encrypts and decrypts successfully with a 16-byte key", async () => {
    const ciphertext = await encrypt("aes-128 test", { keyBytes: key16 });
    const plaintext = await decrypt(ciphertext, { keyBytes: key16 });
    expect(plaintext).toBe("aes-128 test");
  });
});

// ---------------------------------------------------------------------------
// Invalid keyBytes length
// ---------------------------------------------------------------------------
describe("invalid keyBytes length", () => {
  it("throws EncryptionError for a 24-byte key (unsupported size)", async () => {
    const badKey = new Uint8Array(24).fill(0x01);
    await expect(encrypt("x", { keyBytes: badKey })).rejects.toThrow(EncryptionError);
  });

  it("throws EncryptionError on decrypt for a 24-byte key", async () => {
    // Produce a valid ciphertext first with a 32-byte key …
    const goodKey = new Uint8Array(32).fill(0xcc);
    const ciphertext = await encrypt("some value", { keyBytes: goodKey });
    // … then attempt to decrypt with a key of wrong size
    const badKey = new Uint8Array(24).fill(0x01);
    await expect(decrypt(ciphertext, { keyBytes: badKey })).rejects.toThrow(EncryptionError);
  });
});

// ---------------------------------------------------------------------------
// Missing key material — no passphrase AND no keyBytes
// ---------------------------------------------------------------------------
describe("missing key material", () => {
  it("encrypt throws EncryptionError when neither passphrase nor keyBytes given", async () => {
    // Force TypeScript to accept the intentionally incomplete options object.
    const opts = {} as Parameters<typeof encrypt>[1];
    await expect(encrypt("value", opts)).rejects.toThrow(EncryptionError);
  });

  it("decrypt throws EncryptionError when neither passphrase nor keyBytes given", async () => {
    // Build a valid ciphertext first so the 3-part check passes.
    const ciphertext = await encrypt("value", { passphrase: "pw" });
    const opts = {} as Parameters<typeof decrypt>[1];
    await expect(decrypt(ciphertext, opts)).rejects.toThrow(EncryptionError);
  });
});

// ---------------------------------------------------------------------------
// Malformed ciphertext
// ---------------------------------------------------------------------------
describe("malformed ciphertext", () => {
  it("throws EncryptionError when ciphertext does not have exactly 3 colon-separated parts", async () => {
    await expect(
      decrypt("onlytwoparts:here", { passphrase: "pw" }),
    ).rejects.toThrow(EncryptionError);
  });

  it("throws EncryptionError for a completely empty ciphertext string", async () => {
    await expect(decrypt("", { passphrase: "pw" })).rejects.toThrow(EncryptionError);
  });
});

// ---------------------------------------------------------------------------
// CryptoNotAvailableError — when globalThis.crypto.subtle is absent
// ---------------------------------------------------------------------------
describe("CryptoNotAvailableError", () => {
  it("encrypt throws CryptoNotAvailableError when crypto.subtle is not available", async () => {
    vi.stubGlobal("crypto", {});
    await expect(encrypt("value", { passphrase: "pw" })).rejects.toThrow(
      CryptoNotAvailableError,
    );
  });

  it("decrypt throws CryptoNotAvailableError when crypto.subtle is not available", async () => {
    vi.stubGlobal("crypto", {});
    await expect(decrypt("base64:iv:payload", { passphrase: "pw" })).rejects.toThrow(
      CryptoNotAvailableError,
    );
  });
});

// ---------------------------------------------------------------------------
// Outer catch in encrypt() — non-EncryptionError from subtle.encrypt
// ---------------------------------------------------------------------------
describe("encrypt() outer catch — wraps unexpected crypto errors", () => {
  it("wraps a non-EncryptionError thrown by subtle.encrypt into EncryptionError", async () => {
    // Spy on subtle.encrypt and make it throw a plain Error so the outer
    // catch block (lines 138-139 of encrypt.ts) is exercised.
    const spy = vi
      .spyOn(globalThis.crypto.subtle, "encrypt")
      .mockRejectedValueOnce(new Error("simulated crypto failure"));

    await expect(encrypt("value", { passphrase: "pw" })).rejects.toThrow(EncryptionError);
    spy.mockRestore();
  });
});
