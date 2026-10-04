/**
 * Tests for the error classes added with the engine, vault, audit and compliance modules.
 */
import { describe, expect, it } from "vitest";
import {
  AnonymaError,
  AsyncStrategyError,
  AuditIntegrityError,
  KeyManagementError,
  PolicyError,
  TokenVaultError,
} from "../src/errors.js";
import {
  fromBase64Url,
  fromUtf8,
  toBase32,
  toBase64Url,
  toHex,
  utf8,
} from "../src/internal/encoding.js";

describe("errors", () => {
  it("new error classes extend AnonymaError and carry a code, a name and their fields", () => {
    const cases: [AnonymaError, string, string][] = [
      [new AsyncStrategyError("email"), "AsyncStrategyError", "ASYNC_STRATEGY"],
      [
        new KeyManagementError("unknown key version", "k1"),
        "KeyManagementError",
        "KEY_MANAGEMENT_ERROR",
      ],
      [new KeyManagementError("no active version"), "KeyManagementError", "KEY_MANAGEMENT_ERROR"],
      [new TokenVaultError("collision"), "TokenVaultError", "TOKEN_VAULT_ERROR"],
      [
        new PolicyError([{ severity: "error", path: "/id", code: "invalid-id", message: "bad" }]),
        "PolicyError",
        "POLICY_ERROR",
      ],
      [new AuditIntegrityError("sink failed"), "AuditIntegrityError", "AUDIT_INTEGRITY_ERROR"],
    ];
    for (const [error, name, code] of cases) {
      expect(error).toBeInstanceOf(AnonymaError);
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe(name);
      expect(error.code).toBe(code);
      expect(error.message.length).toBeGreaterThan(0);
      expect(Object.getPrototypeOf(error).constructor.name).toBe(name);
    }
    expect(new AsyncStrategyError("email").category).toBe("email");
    expect(new KeyManagementError("x", "k1").keyId).toBe("k1");
    expect(new KeyManagementError("x", "k1").message).toContain('"k1"');
    expect(new KeyManagementError("x").keyId).toBe(undefined);
    expect(
      new PolicyError([{ severity: "warning", path: "/a", code: "c", message: "m" }]).issues,
    ).toHaveLength(1);
  });
});

describe("internal/encoding", () => {
  it("encodes and decodes UTF-8, rejecting invalid byte sequences", () => {
    expect(fromUtf8(utf8("héllo 😀"))).toBe("héllo 😀");
    expect(fromUtf8(new Uint8Array([0xff, 0xfe]))).toBe(undefined);
  });

  it("encodes hex, base64url and Crockford base32", () => {
    const bytes = new Uint8Array([0, 1, 254, 255]);
    expect(toHex(bytes)).toBe("0001feff");
    expect(toBase64Url(new Uint8Array([251, 255, 190]))).toBe("-_--");
    expect(toBase64Url(new Uint8Array([1]))).toBe("AQ");
    expect([...(fromBase64Url("-_--") ?? [])]).toEqual([251, 255, 190]);
    expect([...(fromBase64Url("AQ") ?? [])]).toEqual([1]);
    expect(fromBase64Url("A")).toBe(undefined);
    expect(fromBase64Url("not base64!")).toBe(undefined);
    expect(toBase32(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff]), 8)).toBe("ZZZZZZZZ");
    expect(toBase32(new Uint8Array([0, 0x44, 0x32, 0x14, 0xc7]), 8)).toBe("01234567");
    expect(toBase32(new Uint8Array([0xff]), 8)).toBe("Z");
  });

  it("encodes buffers larger than the engine's argument limit", () => {
    const big = new Uint8Array(300_000).fill(65);
    const encoded = toBase64Url(big);
    expect(encoded).toHaveLength(400_000);
    expect(fromBase64Url(encoded)?.length).toBe(300_000);
  });
});
