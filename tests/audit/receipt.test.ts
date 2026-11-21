/**
 * Tests for signed anonymization receipts.
 */
import { describe, expect, it } from "vitest";
import { anonymize } from "../../src/anonymize.js";
import { createReceiptIssuer, sha256Hex } from "../../src/audit/index.js";
import type { AnonymaReceipt } from "../../src/audit/index.js";
import { compilePipeline } from "../../src/engine/index.js";
import { ValidationError } from "../../src/errors.js";
import { VERSION } from "../../src/version.js";

const SECRET = "receipt-test-key-0123456789abcdef0123456789abcdef";
const TEXT = "Mail ana@example.com or bob@example.org, card 4111 1111 1111 1111.";

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

describe("audit/receipt", () => {
  describe("issue", () => {
    it("counts the replaced values per category and digests the output", async () => {
      const result = compilePipeline({ categories: ["email", "credit-card"] }).transform(TEXT);
      const receipts = createReceiptIssuer({ key: SECRET, now: () => Date.UTC(2026, 10, 21) });
      const receipt = await receipts.issue(result);
      expect(receipt).toMatchObject({
        v: 1,
        timestamp: "2026-11-21T00:00:00.000Z",
        library: `anonyma@${VERSION}`,
        stats: { "credit-card": 1, email: 2 },
        total: 3,
        output: await sha256Hex(result.text),
        alg: "HMAC-SHA-256",
      });
      expect(Object.keys(receipt.stats)).toEqual(["credit-card", "email"]);
      expect(receipt.id).toMatch(/^[0-9a-f]{32}$/);
      expect(receipt.signature).toMatch(/^[0-9a-f]{64}$/);
      expect(Object.isFrozen(receipt)).toBe(true);
    });

    it("never contains a value from the input", async () => {
      const result = compilePipeline({ categories: ["email", "credit-card"] }).transform(TEXT);
      const receipt = await createReceiptIssuer({ key: SECRET }).issue(result, { input: TEXT });
      const serialised = JSON.stringify(receipt);
      for (const value of ["ana@example.com", "bob@example.org", "4111"]) {
        expect(serialised).not.toContain(value);
      }
    });

    it("accepts the matches of anonymize()", async () => {
      const result = anonymize(TEXT, { includeMatches: true });
      const receipt = await createReceiptIssuer({ key: SECRET }).issue(result);
      expect(receipt.stats).toEqual({ "credit-card": 1, email: 2 });
    });

    it("names the presets, policy and key it was told about", async () => {
      const receipt = await createReceiptIssuer({
        key: SECRET,
        keyId: "receipts-2026",
        presets: ["lgpd", "hipaa"],
        policy: { id: "clinic-policy", version: "3" },
      }).issue({ text: "", spans: [] });
      expect(receipt).toMatchObject({
        presets: ["lgpd", "hipaa"],
        policy: { id: "clinic-policy", version: "3" },
        keyId: "receipts-2026",
        stats: {},
        total: 0,
      });
      const single = await createReceiptIssuer({ key: SECRET, presets: "gdpr" }).issue({
        text: "",
        spans: [],
      });
      expect(single.presets).toEqual(["gdpr"]);
      expect(single).not.toHaveProperty("policy");
      expect(single).not.toHaveProperty("keyId");
      expect(single).not.toHaveProperty("input");
    });

    it("blanks a category label that looks like personal data", async () => {
      const receipt = await createReceiptIssuer({ key: SECRET }).issue({
        text: "",
        spans: [{ category: "ana@example.com" }, { category: "__proto__" }],
      });
      expect(Object.entries(receipt.stats)).toEqual([
        ["[GUARDED]", 1],
        ["__proto__", 1],
      ]);
      expect(Object.getPrototypeOf(receipt.stats)).toBe(Object.prototype);
      const custom = await createReceiptIssuer({ key: SECRET, guard: (v) => v === "x" }).issue({
        text: "",
        matches: [{ category: "x" }, { category: "y" }],
      });
      expect(custom.stats).toEqual({ "[GUARDED]": 1, y: 1 });
    });

    it("takes counts and an output digest in place of spans and text", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const digest = await sha256Hex("a large file");
      const receipt = await receipts.issue({
        outputDigest: digest,
        counts: { phone: 3, email: 2, ssn: 0 },
      });
      expect(receipt).toMatchObject({
        stats: { email: 2, phone: 3, ssn: 0 },
        total: 5,
        output: digest,
      });
      expect((await receipts.verify(receipt, { output: "a large file" })).valid).toBe(true);
      const guarded = await receipts.issue({
        outputDigest: digest,
        counts: { "ana@example.com": 1, email: 1 },
      });
      expect(guarded.stats).toEqual({ "[GUARDED]": 1, email: 1 });
    });

    it("rejects counts that are not counts and a digest that is not one", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const digest = await sha256Hex("x");
      await expect(receipts.issue({ outputDigest: digest, counts: { email: -1 } })).rejects.toThrow(
        /subject\.counts\.email/,
      );
      await expect(
        receipts.issue({ outputDigest: digest, counts: { email: 1.5 } }),
      ).rejects.toThrow(ValidationError);
      await expect(receipts.issue({ outputDigest: "ABC", counts: {} })).rejects.toThrow(
        /outputDigest/,
      );
      await expect(
        receipts.issue({ outputDigest: digest.toUpperCase(), counts: {} }),
      ).rejects.toThrow(ValidationError);
    });

    it("rejects a subject without text or without what was replaced", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      await expect(receipts.issue(null as unknown as { text: string })).rejects.toThrow(
        ValidationError,
      );
      await expect(receipts.issue({ text: 1 } as unknown as { text: string })).rejects.toThrow(
        /subject\.text/,
      );
      await expect(receipts.issue({ text: "x" })).rejects.toThrow(/includeMatches/);
      await expect(
        receipts.issue({ text: "x", counts: "1" as unknown as Record<string, number> }),
      ).rejects.toThrow(/counts/);
    });
  });

  describe("verify", () => {
    it("accepts a genuine receipt and the texts it names", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const result = compilePipeline({ categories: ["email"] }).transform(TEXT);
      const receipt = await receipts.issue(result, { input: TEXT });
      expect(await receipts.verify(receipt)).toEqual({ valid: true, receipt });
      expect(
        (
          await receipts.verify(JSON.parse(JSON.stringify(receipt)), {
            output: result.text,
            input: TEXT,
          })
        ).valid,
      ).toBe(true);
    });

    it("works with a CryptoKey", async () => {
      const key = await hmacKey(SECRET);
      const receipts = createReceiptIssuer({ key });
      const receipt = await receipts.issue({ text: "ok", spans: [] });
      expect((await receipts.verify(receipt)).valid).toBe(true);
      // The same secret as a string gives the same signatures.
      expect((await createReceiptIssuer({ key: SECRET }).verify(receipt)).valid).toBe(true);
    });

    it("detects an altered receipt", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const receipt = await receipts.issue({ text: "x", spans: [{ category: "email" }] });
      const altered: AnonymaReceipt = { ...receipt, stats: { email: 0 } };
      expect(await receipts.verify(altered)).toEqual({ valid: false, reason: "signature" });
      const extra = { ...receipt, note: "added" };
      expect(await receipts.verify(extra)).toEqual({ valid: false, reason: "signature" });
      const shorter = { ...receipt, signature: receipt.signature.slice(1) };
      expect(await receipts.verify(shorter)).toEqual({ valid: false, reason: "signature" });
    });

    it("detects a receipt signed with another key", async () => {
      const receipt = await createReceiptIssuer({ key: SECRET }).issue({ text: "x", spans: [] });
      const other = createReceiptIssuer({ key: `${SECRET}-other` });
      expect(await other.verify(receipt)).toEqual({ valid: false, reason: "signature" });
    });

    it("detects a receipt about another output or another input", async () => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const receipt = await receipts.issue({ text: "sent", spans: [] }, { input: "original" });
      expect(await receipts.verify(receipt, { output: "other" })).toEqual({
        valid: false,
        reason: "output",
      });
      expect(await receipts.verify(receipt, { input: "other" })).toEqual({
        valid: false,
        reason: "input",
      });
      const unbound = await receipts.issue({ text: "sent", spans: [] });
      expect(await receipts.verify(unbound, { input: "original" })).toEqual({
        valid: false,
        reason: "input",
      });
    });

    it.each<[string, (receipt: AnonymaReceipt) => unknown]>([
      ["null", () => null],
      ["an array", () => []],
      ["another version", (r) => ({ ...r, v: 2 })],
      ["a missing id", (r) => ({ ...r, id: undefined })],
      ["a missing timestamp", (r) => ({ ...r, timestamp: 1 })],
      ["a missing library", (r) => ({ ...r, library: null })],
      ["presets that are not names", (r) => ({ ...r, presets: [1] })],
      ["presets that are not a list", (r) => ({ ...r, presets: "gdpr" })],
      ["a policy without an id", (r) => ({ ...r, policy: { version: "1" } })],
      ["a policy that is not an object", (r) => ({ ...r, policy: "p" })],
      ["stats that are not counts", (r) => ({ ...r, stats: { email: 1.5 } })],
      ["stats that are not an object", (r) => ({ ...r, stats: [] })],
      ["a total that is not a count", (r) => ({ ...r, total: "3" })],
      ["an output that is not a digest", (r) => ({ ...r, output: "abc" })],
      ["an output that is not text", (r) => ({ ...r, output: 1 })],
      ["an input that is not a digest", (r) => ({ ...r, input: "abc" })],
      ["an input that is not text", (r) => ({ ...r, input: 1 })],
      ["another algorithm", (r) => ({ ...r, alg: "SHA-256" })],
      ["a key id that is not text", (r) => ({ ...r, keyId: 1 })],
      ["a missing signature", (r) => ({ ...r, signature: undefined })],
    ])("rejects %s as malformed", async (_label, change) => {
      const receipts = createReceiptIssuer({ key: SECRET });
      const receipt = await receipts.issue({ text: "x", spans: [] });
      expect(await receipts.verify(change(receipt))).toEqual({ valid: false, reason: "malformed" });
    });
  });

  it("rejects a missing or empty key", () => {
    expect(() => createReceiptIssuer({ key: "" })).toThrow(ValidationError);
    expect(() => createReceiptIssuer({} as { key: string })).toThrow(/key/);
  });
});
