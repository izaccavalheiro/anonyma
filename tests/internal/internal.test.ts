/**
 * Tests for the helpers in src/internal/ that the public API reaches only in
 * rare cases: malformed bytes, numbers inside strings and runtimes without Web
 * Crypto.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeText } from "../../src/internal/encoding.js";
import { parseJsonLossless, stringifyJsonLossless } from "../../src/internal/json-numbers.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("internal/encoding", () => {
  describe("decodeText", () => {
    it("refuses bytes in the UTF-16 form whose length it cannot have produced", () => {
      // The marker byte followed by whole code units: always an odd length.
      expect(decodeText(new Uint8Array([0xff, 0x41]))).toBe(undefined);
      expect(decodeText(new Uint8Array([0xff, 0x41, 0x00]))).toBe("A");
    });
  });
});

describe("internal/json-numbers", () => {
  describe("parseJsonLossless", () => {
    it("does not read digits inside a string with escaped quotes as a number", () => {
      const text = '{"q":"say \\"12345678901234567890\\"","n":12345678901234567890}';
      const { value, marker } = parseJsonLossless(text);
      expect(marker).toBeDefined();
      expect(value).toEqual({
        q: 'say "12345678901234567890"',
        n: `${String(marker)}12345678901234567890`,
      });
    });

    it("makes a marker without a global Web Crypto object, as on Node.js 18", () => {
      vi.stubGlobal("crypto", undefined);
      const { value, marker = "" } = parseJsonLossless("[12345678901234567890]");
      expect(marker).toHaveLength(12);
      for (const ch of marker) expect(ch.charCodeAt(0)).toBeGreaterThanOrEqual(1);
      for (const ch of marker) expect(ch.charCodeAt(0)).toBeLessThanOrEqual(8);
      expect(stringifyJsonLossless(value, marker)).toBe("[12345678901234567890]");
    });
  });

  describe("stringifyJsonLossless", () => {
    it("writes null for a value that JSON cannot represent", () => {
      expect(stringifyJsonLossless(undefined, undefined)).toBe("null");
      expect(stringifyJsonLossless(() => 1, "marker")).toBe("null");
    });

    it("writes a marked string whose number was replaced as an ordinary string", () => {
      const { value, marker } = parseJsonLossless('{"card":4111111111111111111111}');
      expect(stringifyJsonLossless(value, marker)).toBe('{"card":4111111111111111111111}');
      expect(stringifyJsonLossless({ card: `${String(marker)}[REDACTED]` }, marker)).toBe(
        '{"card":"[REDACTED]"}',
      );
    });
  });
});

describe("internal/webcrypto", () => {
  describe("webCrypto", () => {
    afterEach(() => {
      vi.doUnmock("node:crypto");
      vi.resetModules();
    });

    it("throws CryptoNotAvailableError on a runtime with neither a global crypto nor node:crypto", async () => {
      vi.stubGlobal("crypto", undefined);
      vi.doMock("node:crypto", () => {
        throw new Error("no such module");
      });
      vi.resetModules();
      // Fresh instances, so that the fallback is looked up again and the error classes match.
      const { webCrypto } = await import("../../src/internal/webcrypto.js");
      const { CryptoNotAvailableError } = await import("../../src/errors.js");
      await expect(webCrypto()).rejects.toThrow(CryptoNotAvailableError);
    });
  });
});
