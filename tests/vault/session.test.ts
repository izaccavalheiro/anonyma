import { describe, expect, it } from "vitest";
import { ValidationError } from "../../src/errors.js";
import { compilePipeline } from "../../src/engine/index.js";
import { createSessionTokenizer, restoreTokens, tokenizeWith } from "../../src/vault/index.js";

describe("vault/session", () => {
  describe("createSessionTokenizer", () => {
    it("numbers tokens per category in the order values are first seen", () => {
      const session = createSessionTokenizer();
      expect(session.tokenize("alice@example.com", { category: "email" })).toBe("[EMAIL_0001]");
      expect(session.tokenize("bob@example.com", { category: "email" })).toBe("[EMAIL_0002]");
      expect(session.tokenize("alice@example.com", { category: "email" })).toBe("[EMAIL_0001]");
      expect(session.tokenize("203.0.113.9", { category: "ipv4" })).toBe("[IPV4_0001]");
      expect(session.size()).toBe(3);
      expect(session).toMatchObject({ scheme: "session", reversible: true });
    });

    it("assigns tokens in document order when used through a pipeline", () => {
      const session = createSessionTokenizer();
      const pipeline = compilePipeline(
        { defaultStrategy: { strategy: "tokenize" } },
        { tokenization: session },
      );
      const text = "first a@example.com then b@example.com then a@example.com";
      expect(pipeline.transform(text).text).toBe(
        "first [EMAIL_0001] then [EMAIL_0002] then [EMAIL_0001]",
      );
      expect(session.restore(pipeline.transform(text).text).text).toBe(text);
    });

    it("keeps values that differ only in case apart", () => {
      const session = createSessionTokenizer();
      const text = "keys sk_live_ABCdef and sk_live_abcDEF";
      const a = session.tokenize("sk_live_ABCdef", { category: "api-key" });
      const b = session.tokenize("sk_live_abcDEF", { category: "api-key" });
      expect(a).not.toBe(b);
      expect(session.restore(`keys ${a} and ${b}`).text).toBe(text);
    });

    it("merges values under a caller-supplied normalisation", () => {
      const session = createSessionTokenizer({
        normalize: (value, category) => (category === "email" ? value.toLowerCase() : value),
      });
      const a = session.tokenize("Alice@Example.com", { category: "email" });
      expect(session.tokenize("alice@example.com", { category: "email" })).toBe(a);
      expect(session.detokenize(a)).toBe("Alice@Example.com");
    });

    it("supports the angle format, custom prefixes and custom categories", () => {
      const session = createSessionTokenizer({ format: "angle", prefixes: { email: "MAIL" } });
      expect(session.tokenize("a@example.com", { category: "email" })).toBe("<MAIL_1>");
      expect(session.tokenize("ACME-1", { category: "order-id" })).toBe("<ORDER_ID_1>");
      expect(session.tokenize("x", { category: "42 things!" })).toBe("<X_42_THINGS_1>");
      expect(session.tokenize("y", { category: "--" })).toMatch(/^<X[A-Z0-9]+_1>$/);
      expect(session.tokenize("z", { category: "constructor" })).toBe("<CONSTRUCTOR_1>");
      expect(session.restore("<MAIL_1> <ORDER_ID_1>").text).toBe("a@example.com ACME-1");
    });

    it("does not confuse token-shaped text with its own tokens when a tag is set", () => {
      const session = createSessionTokenizer({ tag: "k3Xf" });
      const token = session.tokenize("alice@example.com", { category: "email" });
      expect(token).toBe("[EMAIL_k3Xf_0001]");
      const result = session.restore(`Template says [EMAIL_0001]; real address is ${token}`);
      expect(result.text).toBe("Template says [EMAIL_0001]; real address is alice@example.com");
      expect(result).toMatchObject({ restored: 1, unresolved: [] });
    });

    it("reports tokens it cannot resolve and counts every restored occurrence", () => {
      const session = createSessionTokenizer();
      const token = session.tokenize("alice@example.com", { category: "email" });
      const result = session.restore(`${token} ${token} [PHONE_0009]`);
      expect(result).toEqual({
        text: "alice@example.com alice@example.com [PHONE_0009]",
        restored: 2,
        unresolved: ["[PHONE_0009]"],
      });
      expect(session.restore("no tokens")).toEqual({
        text: "no tokens",
        restored: 0,
        unresolved: [],
      });
    });

    it("restores tokens with digits in the prefix, which the 1.x pattern missed", () => {
      const session = createSessionTokenizer();
      const v4 = session.tokenize("203.0.113.9", { category: "ipv4" });
      const v6 = session.tokenize("2001:db8::1", { category: "ipv6" });
      expect(session.restore(`Block ${v4} and ${v6}`).text).toBe(
        "Block 203.0.113.9 and 2001:db8::1",
      );
    });

    it("is strict by default and tolerant of model rewrites when lenient", () => {
      const strict = createSessionTokenizer();
      const lenient = createSessionTokenizer({ lenient: true });
      for (const session of [strict, lenient]) {
        session.tokenize("alice@example.com", { category: "email" });
        session.tokenize("555-867-5309", { category: "phone" });
        session.tokenize("4111111111111111", { category: "credit-card" });
      }
      const rewrites = [
        "[EMAIL_1] / [PHONE_1]",
        "[email_0001] / [phone_0001]",
        "\\[EMAIL\\_0001\\] / \\[PHONE\\_0001\\]",
        "[ EMAIL_0001 ] / [PHONE_0001 ]",
        "<EMAIL_0001> / (PHONE_0001)",
        "\uff3bEMAIL_0001\uff3d / [PHONE_00001]",
      ];
      for (const text of rewrites) {
        expect(strict.restore(text).restored, text).toBe(0);
        expect(lenient.restore(text).text, text).toBe("alice@example.com / 555-867-5309");
      }
      expect(lenient.restore("[credit\\_card\\_1]").text).toBe("4111111111111111");
      expect(lenient.restore("[EMAIL_0007] (see note_1)")).toEqual({
        text: "[EMAIL_0007] (see note_1)",
        restored: 0,
        unresolved: ["[EMAIL_0007]"],
      });
    });

    it("is lenient about the tag as well", () => {
      const session = createSessionTokenizer({ tag: "k3Xf", lenient: true });
      session.tokenize("alice@example.com", { category: "email" });
      expect(session.restore("[email_K3XF_1]").text).toBe("alice@example.com");
      expect(session.restore("[EMAIL_0001]").restored).toBe(0);
    });

    it("forgets single tokens", () => {
      const session = createSessionTokenizer({ lenient: true });
      const token = session.tokenize("alice@example.com", { category: "email" });
      expect(session.forget(token)).toBe(true);
      expect(session.forget(token)).toBe(false);
      expect(session.detokenize(token)).toBe(undefined);
      expect(session.restore(token)).toMatchObject({ restored: 0, unresolved: [token] });
      // The number is not reused, so a stale token can never resolve to a different value.
      expect(session.tokenize("bob@example.com", { category: "email" })).toBe("[EMAIL_0002]");
    });

    it("forgets a token that came from a snapshot made with other prefixes", () => {
      const first = createSessionTokenizer({ prefixes: { email: "MAIL" } });
      const token = first.tokenize("alice@example.com", { category: "email" });
      const second = createSessionTokenizer({ snapshot: first.snapshot() });
      expect(second.forget(token)).toBe(true);
      // The value must get a fresh token, not the forgotten one that no longer resolves.
      const again = second.tokenize("alice@example.com", { category: "email" });
      expect(again).not.toBe(token);
      expect(second.detokenize(again)).toBe("alice@example.com");
    });

    it("round-trips through a snapshot and continues numbering", () => {
      const first = createSessionTokenizer({ format: "angle", tag: "ab12" });
      const a = first.tokenize("alice@example.com", { category: "email" });
      first.tokenize("555-867-5309", { category: "phone" });
      const snapshot = JSON.parse(JSON.stringify(first.snapshot())) as ReturnType<
        typeof first.snapshot
      >;
      expect(snapshot).toMatchObject({ v: 1, format: "angle", tag: "ab12" });

      const second = createSessionTokenizer({ snapshot });
      expect(second.detokenize(a)).toBe("alice@example.com");
      expect(second.tokenize("alice@example.com", { category: "email" })).toBe(a);
      expect(second.tokenize("bob@example.com", { category: "email" })).toBe("<EMAIL_ab12_2>");
      expect(createSessionTokenizer().snapshot()).toEqual({
        v: 1,
        format: "bracket",
        entries: [],
        counters: [],
      });
    });

    it("never reissues a forgotten number after continuing from a snapshot", () => {
      const first = createSessionTokenizer();
      first.tokenize("alice@example.com", { category: "email" });
      const bob = first.tokenize("bob@example.com", { category: "email" });
      expect(first.forget(bob)).toBe(true);

      const second = createSessionTokenizer({ snapshot: first.snapshot() });
      expect(second.tokenize("carol@example.com", { category: "email" })).toBe("[EMAIL_0003]");
      expect(second.restore(`write to ${bob}`)).toMatchObject({ restored: 0, unresolved: [bob] });

      for (const counters of [{}, [["EMAIL"]], [["EMAIL", 1.5]], [[1, 2]]]) {
        const snapshot = { ...first.snapshot(), counters } as unknown as ReturnType<
          typeof first.snapshot
        >;
        expect(() => createSessionTokenizer({ snapshot })).toThrow(ValidationError);
      }
    });

    it("derives a usable, distinct prefix for any category label", () => {
      const session = createSessionTokenizer({ lenient: true });
      // The cut at 38 characters lands right after a separator.
      const long = session.tokenize("x", {
        category: "emergency-contact-secondary-mobile-no-home",
      });
      expect(long).toBe("[EMERGENCY_CONTACT_SECONDARY_MOBILE_NO_0001]");
      expect(session.detokenize(long)).toBe("x");

      const name = session.tokenize("\u5c71\u7530", { category: "\u6c0f\u540d" });
      const address = session.tokenize("\u6771\u4eac", { category: "\u4f4f\u6240" });
      expect(name.slice(0, name.lastIndexOf("_"))).not.toBe(
        address.slice(0, address.lastIndexOf("_")),
      );
      // Ordinary notation is not mistaken for a token of such a category.
      const prose = "Let (x_1) and (x_2) be the roots.";
      expect(session.restore(prose).text).toBe(prose);
    });

    it("restores leniently in linear time", () => {
      const session = createSessionTokenizer({ lenient: true });
      session.tokenize("alice@example.com", { category: "email" });
      const started = performance.now();
      session.restore("[A_" + "0".repeat(200_000));
      session.restore("[" + "A_".repeat(100_000));
      session.restore("[".repeat(100_000));
      expect(performance.now() - started).toBeLessThan(5000);
      expect(session.restore("to [ email_1 ] and \\[EMAIL\\_0001\\]").text).toBe(
        "to alice@example.com and alice@example.com",
      );
    });

    it("rejects invalid options, snapshots and values", () => {
      expect(() => createSessionTokenizer({ format: "curly" as "angle" })).toThrow(ValidationError);
      expect(() => createSessionTokenizer({ tag: "x" })).toThrow(ValidationError);
      expect(() => createSessionTokenizer({ tag: "has space" })).toThrow(ValidationError);
      expect(() => createSessionTokenizer({ prefixes: { email: "lower" } })).toThrow(
        ValidationError,
      );
      expect(() => createSessionTokenizer({ prefixes: { email: "A".repeat(41) } })).toThrow(
        ValidationError,
      );
      expect(() => createSessionTokenizer({ prefixes: { email: 1 as unknown as string } })).toThrow(
        ValidationError,
      );
      const bad =
        (snapshot: unknown): (() => unknown) =>
        () =>
          createSessionTokenizer({
            snapshot: snapshot as ReturnType<ReturnType<typeof createSessionTokenizer>["snapshot"]>,
          });
      expect(bad({ v: 2, format: "bracket", entries: [] })).toThrow(ValidationError);
      expect(bad({ v: 1, format: "bracket", entries: "x" })).toThrow(ValidationError);
      expect(bad({ v: 1, format: "bracket", entries: [["[EMAIL_0001]", 1, "email"]] })).toThrow(
        ValidationError,
      );
      expect(bad({ v: 1, format: "bracket", entries: ["nope"] })).toThrow(ValidationError);
      expect(bad({ v: 1, format: "bracket", entries: [["<EMAIL_1>", "a", "email"]] })).toThrow(
        /does not belong/,
      );
      const session = createSessionTokenizer();
      expect(() => session.tokenize(1 as unknown as string, { category: "email" })).toThrow(
        ValidationError,
      );
      expect(() => session.restore(1 as unknown as string)).toThrow(ValidationError);
    });

    it("exposes patterns for stream hold-back", () => {
      const session = createSessionTokenizer();
      const token = session.tokenize("a@example.com", { category: "email" });
      expect(token.length).toBeLessThanOrEqual(session.maxTokenLength);
      expect(`x ${token} y`.match(session.tokenPattern)).toEqual([token]);
      for (let cut = 1; cut < token.length; cut++) {
        expect(
          session.partialTokenPattern?.test(`text ${token.slice(0, cut)}`),
          token.slice(0, cut),
        ).toBe(true);
      }
      expect(session.partialTokenPattern?.test("plain text")).toBe(false);
    });
  });

  describe("restoreTokens", () => {
    it("restores through the generic provider interface", async () => {
      const session = createSessionTokenizer();
      const token = session.tokenize("alice@example.com", { category: "email" });
      expect(await restoreTokens(`to ${token}, again ${token}, not [EMAIL_0009]`, session)).toEqual(
        {
          text: "to alice@example.com, again alice@example.com, not [EMAIL_0009]",
          restored: 2,
          unresolved: ["[EMAIL_0009]"],
        },
      );
      const untouched = "nothing to restore";
      expect((await restoreTokens(untouched, session)).text).toBe(untouched);
      await expect(restoreTokens(1 as unknown as string, session)).rejects.toThrow(ValidationError);
    });
  });

  describe("tokenizeWith", () => {
    it("passes the category, and the subject when given, to the provider", () => {
      const seen: unknown[] = [];
      const provider = {
        ...createSessionTokenizer(),
        tokenize: (value: string, context: unknown): string => {
          seen.push([value, context]);
          return "[T]";
        },
      };
      const context = {
        category: "email",
        detector: "email",
        confidence: 1,
        start: 0,
        end: 1,
        ordinal: 0,
        residual: false,
      };
      expect(tokenizeWith(provider)("v", context)).toBe("[T]");
      expect(tokenizeWith(provider, { subject: "user-1" })("v", context)).toBe("[T]");
      expect(seen).toEqual([
        ["v", { category: "email" }],
        ["v", { category: "email", subject: "user-1" }],
      ]);
    });
  });
});
