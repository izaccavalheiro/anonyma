/**
 * Tests for sanitizeJsonText() and sanitizeJsonTextAsync().
 */
import { describe, expect, it } from "vitest";
import { sanitizeJsonText, sanitizeJsonTextAsync } from "../../src/ai/index.js";
import { compilePipeline } from "../../src/engine/index.js";
import { ValidationError } from "../../src/errors.js";

const pipeline = compilePipeline({ categories: ["email"] });

describe("ai/json text", () => {
  describe("sanitizeJsonText", () => {
    it("sanitizes the strings of a JSON text and reports where", () => {
      const result = sanitizeJsonText('{"user":{"email":"alice@example.com"},"n":1}', { pipeline });
      expect(result.text).toBe('{"user":{"email":"[REDACTED]"},"n":1}');
      expect(result.replaced).toBe(1);
      expect(result.fields).toEqual([
        { path: "/user/email", category: "email", detector: "email", rule: "email", count: 1 },
      ]);
    });

    it("keeps every digit of numbers that a JavaScript number cannot hold", () => {
      const text =
        '{"id":12345678901234567890,"amount":0.123456789012345678901,"to":"bob@example.org"}';
      expect(sanitizeJsonText(text, { pipeline }).text).toBe(
        '{"id":12345678901234567890,"amount":0.123456789012345678901,"to":"[REDACTED]"}',
      );
    });

    it("returns the text unchanged, spacing included, when nothing is replaced", () => {
      const text = '{ "id" : 12345678901234567890,\n  "note": "fine" }';
      const result = sanitizeJsonText(text, { pipeline });
      expect(result.text).toBe(text);
      expect(result.replaced).toBe(0);
    });

    it("rejects a text that is not JSON", () => {
      expect(() => sanitizeJsonText("{nope", { pipeline })).toThrow(ValidationError);
      expect(() => sanitizeJsonText("", { pipeline })).toThrow(/JSON text/);
    });
  });

  describe("sanitizeJsonTextAsync", () => {
    it("works with asynchronous replacers and keeps large numbers", async () => {
      const hashing = compilePipeline({
        categories: ["email"],
        defaultStrategy: { strategy: "hash", pepper: "test-pepper" },
      });
      const result = await sanitizeJsonTextAsync('[12345678901234567890,"alice@example.com"]', {
        pipeline: hashing,
      });
      expect(result.text).toMatch(/^\[12345678901234567890,"[0-9a-f]+"\]$/);
      expect(result.replaced).toBe(1);
    });

    it("handles a text without large numbers", async () => {
      const result = await sanitizeJsonTextAsync('"alice@example.com"', { pipeline });
      expect(result.text).toBe('"[REDACTED]"');
    });

    it("rejects a text that is not JSON", async () => {
      await expect(sanitizeJsonTextAsync("[", { pipeline })).rejects.toThrow(ValidationError);
    });
  });
});
