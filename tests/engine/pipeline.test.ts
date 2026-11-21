import { describe, expect, it } from "vitest";
import { AsyncStrategyError, ValidationError } from "../../src/errors.js";
import {
  constant,
  createPipeline,
  defineDetector,
  defineRegexDetector,
  redactWith,
  resolveSpans,
  spanText,
} from "../../src/engine/index.js";
import type { PipelineOptions, Replacer, SpanDetector } from "../../src/engine/index.js";

const email = defineRegexDetector({
  category: "email",
  pattern: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/,
  confidence: 0.99,
});
const url = defineRegexDetector({ category: "url", pattern: /https?:\/\/\S+/, confidence: 0.95 });
const card = defineRegexDetector({
  category: "credit-card",
  pattern: /\b\d{16}\b/,
  confidence: 0.97,
});
/** A greedy, low-confidence detector, like the 1.x address heuristic. */
const address = defineRegexDetector({
  category: "address",
  pattern: /is [^\n]{5,40}/,
  confidence: 0.82,
});

function pipeline(detectors: SpanDetector[], extra: Partial<PipelineOptions> = {}) {
  return createPipeline({ detectors, replace: { fallback: redactWith() }, ...extra });
}

describe("engine/pipeline", () => {
  describe("createPipeline", () => {
    it("rejects duplicate detector ids, bad thresholds, bad policies and bad replacers", () => {
      expect(() => pipeline([email, email])).toThrow(ValidationError);
      for (const minConfidence of [-0.1, 1.1, Number.NaN, "0.5" as unknown as number]) {
        expect(() => pipeline([email], { minConfidence })).toThrow(ValidationError);
      }
      expect(() => pipeline([email], { overlap: "union" as "cover" })).toThrow(ValidationError);
      expect(() =>
        createPipeline({ detectors: [email], replace: { fallback: "x" as unknown as Replacer } }),
      ).toThrow(ValidationError);
      expect(() =>
        createPipeline({
          detectors: [email],
          replace: { fallback: redactWith(), byCategory: { email: 1 as unknown as Replacer } },
        }),
      ).toThrow(ValidationError);
      expect(() => pipeline([email], { allow: [42 as unknown as string] })).toThrow(
        ValidationError,
      );
    });

    it("returns a frozen pipeline that exposes its detectors", () => {
      const p = pipeline([email, url]);
      expect(Object.isFrozen(p)).toBe(true);
      expect(p.detectors.map((d) => d.id)).toEqual(["email", "url"]);
    });
  });

  describe("scan", () => {
    it("returns spans in document order without the matched text", () => {
      const text = "see https://x.io then a@b.co";
      const spans = pipeline([email, url]).scan(text);
      expect(spans).toEqual([
        { start: 4, end: 16, category: "url", confidence: 0.95, detector: "url", residual: false },
        {
          start: 22,
          end: 28,
          category: "email",
          confidence: 0.99,
          detector: "email",
          residual: false,
        },
      ]);
      expect(spans.map((span) => spanText(text, span))).toEqual(["https://x.io", "a@b.co"]);
    });

    it("rejects input that is not a string", () => {
      expect(() => pipeline([email]).scan(42 as unknown as string)).toThrow(ValidationError);
    });

    it("skips a detector whose prefilter rejects the text", () => {
      let scans = 0;
      const gated = defineDetector({
        id: "gated",
        category: "c",
        prefilter: (text) => text.includes("#"),
        scan: () => {
          scans++;
        },
      });
      const p = pipeline([gated]);
      p.scan("plain");
      expect(scans).toBe(0);
      p.scan("with #");
      expect(scans).toBe(1);
    });

    it("names the detector that reports a span outside the text or with a bad confidence", () => {
      const bad = (start: number, end: number, confidence: number): SpanDetector =>
        defineDetector({
          id: "broken",
          category: "c",
          scan: (_t, emit) => emit(start, end, confidence),
        });
      for (const args of [
        [-1, 2, 0.5],
        [2, 2, 0.5],
        [0, 99, 0.5],
        [0.5, 2, 0.5],
        [0, 2, 1.5],
        [0, 2, Number.NaN],
      ] as const) {
        expect(() => pipeline([bad(...args)]).scan("abcdef")).toThrow(
          /"broken" reported an invalid span/,
        );
      }
    });
  });

  describe("overlap resolution", () => {
    const text = "My address is alice@example.com";

    it("cover: the higher-confidence hit wins and the loser keeps only what is left over", () => {
      const spans = pipeline([address, email]).scan(text);
      expect(spans.map((s) => [s.category, spanText(text, s), s.residual])).toEqual([
        ["address", "is", true],
        ["email", "alice@example.com", false],
      ]);
    });

    it("cover: no detected character survives when hits overlap partially", () => {
      // The 1.x engine kept the URL and dropped the card number, leaving it in the output.
      const input = "GET https://example.com/u/42 4111111111111111";
      const greedyCard = defineRegexDetector({
        category: "credit-card",
        pattern: /\b\d{2} \d{16}\b/,
        confidence: 0.97,
      });
      const out = pipeline([url, greedyCard]).transform(input).text;
      expect(out).not.toContain("4111111111111111");
      expect(out).toBe("GET [REDACTED][REDACTED]");
    });

    it("cover: ignores a whitespace-only remainder", () => {
      const padded = defineRegexDetector({
        category: "padded",
        pattern: / \d{16} /,
        confidence: 0.5,
      });
      const input = "n 4111111111111111 x";
      expect(pipeline([card, padded]).scan(input)).toHaveLength(1);
    });

    it("legacy: the earliest hit wins and overlapping hits are dropped whole", () => {
      const spans = pipeline([address, email], { overlap: "legacy" }).scan(text);
      expect(spans.map((s) => [s.category, s.residual])).toEqual([["address", false]]);
    });

    it("applies minConfidence before resolving, so a weak hit cannot shadow a strong one", () => {
      const out = pipeline([address, email], { minConfidence: 0.9 }).transform(text).text;
      expect(out).toBe("My address is [REDACTED]");
      // Same under the legacy overlap rule: the 1.x engine returned the text unchanged here.
      expect(
        pipeline([address, email], { minConfidence: 0.9, overlap: "legacy" }).transform(text).text,
      ).toBe("My address is [REDACTED]");
    });

    it("resolveSpans returns an empty list for no candidates", () => {
      expect(resolveSpans("", [], "cover")).toEqual([]);
      expect(resolveSpans("", [], "legacy")).toEqual([]);
    });

    it("resolveSpans orders equal-confidence overlaps by length, then position, then detector", () => {
      const candidates = [
        { start: 0, end: 4, confidence: 0.9, detector: 1, allowed: false },
        { start: 2, end: 9, confidence: 0.9, detector: 0, allowed: false },
        { start: 9, end: 12, confidence: 0.9, detector: 1, allowed: false },
        { start: 9, end: 12, confidence: 0.9, detector: 0, allowed: false },
      ];
      expect(resolveSpans("abcdefghijkl", candidates, "cover")).toEqual([
        { start: 0, end: 2, confidence: 0.9, detector: 1, residual: true },
        { start: 2, end: 9, confidence: 0.9, detector: 0, residual: false },
        { start: 9, end: 12, confidence: 0.9, detector: 0, residual: false },
      ]);
    });

    it("resolveSpans keeps both ends of a hit that a stronger hit splits in two", () => {
      const candidates = [
        { start: 0, end: 10, confidence: 0.5, detector: 0, allowed: false },
        { start: 3, end: 6, confidence: 0.9, detector: 1, allowed: false },
        { start: 5, end: 8, confidence: 0.7, detector: 2, allowed: false },
      ];
      expect(
        resolveSpans("abcdefghij", candidates, "cover").map((s) => [s.start, s.end, s.detector]),
      ).toEqual([
        [0, 3, 0],
        [3, 6, 1],
        [6, 8, 2],
        [8, 10, 0],
      ]);
    });
  });

  describe("allow rules", () => {
    const text = "Mail noreply@corp.com or Xnoreply@corp.com.br";

    it("matches strings against the whole value, case-insensitively by default", () => {
      expect(pipeline([email], { allow: ["NOREPLY@corp.com"] }).transform(text).text).toBe(
        "Mail noreply@corp.com or [REDACTED]",
      );
      expect(
        pipeline([email], { allow: ["NOREPLY@corp.com"], allowCaseSensitive: true }).transform(text)
          .text,
      ).toBe("Mail [REDACTED] or [REDACTED]");
    });

    it("gives the same answer on every call for a global or sticky RegExp rule", () => {
      const p = pipeline([email], { allow: [/^noreply@/g, /^never$/y] });
      const once = p.transform(text).text;
      expect(once).toBe("Mail noreply@corp.com or [REDACTED]");
      expect(p.transform(text).text).toBe(once);
      expect(p.transform(text).text).toBe(once);
    });

    it("passes the value and its span to a predicate", () => {
      const seen: unknown[] = [];
      const p = pipeline([email], {
        allow: [
          (value, span) => {
            seen.push([value, span.category, span.detector, span.residual]);
            return value.startsWith("noreply@");
          },
        ],
      });
      expect(p.transform(text).text).toBe("Mail noreply@corp.com or [REDACTED]");
      expect(seen[0]).toEqual(["noreply@corp.com", "email", "email", false]);
    });

    it("an allowed value keeps its place and overlapping weaker hits only cover the rest", () => {
      const input = "My address is alice@example.com";
      const p = pipeline([address, email], { allow: ["alice@example.com"] });
      expect(p.transform(input).text).toBe("My address [REDACTED] alice@example.com");
    });

    it("an allowed value that loses to a stronger hit is replaced with it and leaves no residue", () => {
      const weakMail = defineRegexDetector({
        id: "weak",
        category: "email",
        pattern: /\S+@\S+/,
        confidence: 0.4,
      });
      const input = "see https://x.io/a@b.co/p";
      expect(
        pipeline([url, weakMail], { allow: ["https://x.io/a@b.co/p"] }).transform(input).text,
      ).toBe(input);
      expect(pipeline([url, weakMail], { allow: ["a@b.co/p"] }).transform(input).text).toBe(
        "see [REDACTED]",
      );
    });

    it("legacy overlap: an allowed hit still shadows what it overlaps, as in 1.x", () => {
      const input = "My address is alice@example.com";
      const p = pipeline([address, email], { allow: ["is alice@example.com"], overlap: "legacy" });
      expect(p.transform(input).text).toBe(input);
    });
  });

  describe("test", () => {
    it("is true exactly when a transform would replace something", () => {
      const p = pipeline([email, card]);
      expect(p.test("nothing here")).toBe(false);
      expect(p.test("a@b.co")).toBe(true);
      expect(p.test("")).toBe(false);
    });

    it("stops at the first detector that reports a hit", () => {
      let reached = false;
      const spy = defineDetector({
        id: "spy",
        category: "c",
        scan: () => {
          reached = true;
        },
      });
      expect(pipeline([email, spy]).test("a@b.co")).toBe(true);
      expect(reached).toBe(false);
    });

    it("honours minConfidence and allow rules", () => {
      expect(pipeline([email], { minConfidence: 1 }).test("a@b.co")).toBe(false);
      expect(pipeline([email], { allow: ["a@b.co"] }).test("a@b.co")).toBe(false);
      expect(pipeline([email], { allow: ["a@b.co"] }).test("a@b.co c@d.co")).toBe(true);
    });
  });

  describe("transform", () => {
    it("returns the input string itself when nothing is detected", () => {
      const input = "nothing to see";
      const result = pipeline([email]).transform(input);
      expect(result.text).toBe(input);
      expect(result.spans).toEqual([]);
    });

    it("uses the per-category replacer, falls back otherwise, and reports output offsets", () => {
      const p = createPipeline({
        detectors: [email, card],
        replace: { fallback: constant("#"), byCategory: { email: constant("<mail>") } },
      });
      const result = p.transform("a@b.co 4111111111111111 c@d.co");
      expect(result.text).toBe("<mail> # <mail>");
      expect(result.spans.map((s) => [s.category, s.outStart, s.outEnd])).toEqual([
        ["email", 0, 6],
        ["credit-card", 7, 8],
        ["email", 9, 15],
      ]);
      for (const span of result.spans) {
        expect(result.text.slice(span.outStart, span.outEnd)).toMatch(/^(<mail>|#)$/);
      }
    });

    it("does not treat inherited object keys as categories", () => {
      const weird = defineRegexDetector({ category: "constructor", pattern: /X+/ });
      const p = createPipeline({
        detectors: [weird],
        replace: { fallback: constant("ok"), byCategory: {} },
      });
      expect(p.transform("XXX").text).toBe("ok");
    });

    it("calls replacers once per span, in document order, with full context", () => {
      const calls: unknown[] = [];
      const p = createPipeline({
        detectors: [email],
        replace: {
          fallback: (value, context) => {
            calls.push([value, context]);
            return `E${String(context.ordinal)}`;
          },
        },
      });
      expect(p.transform("x a@b.co y c@d.co").text).toBe("x E0 y E1");
      expect(calls).toEqual([
        [
          "a@b.co",
          {
            category: "email",
            detector: "email",
            confidence: 0.99,
            start: 2,
            end: 8,
            ordinal: 0,
            residual: false,
          },
        ],
        [
          "c@d.co",
          {
            category: "email",
            detector: "email",
            confidence: 0.99,
            start: 11,
            end: 17,
            ordinal: 1,
            residual: false,
          },
        ],
      ]);
    });

    it("throws AsyncStrategyError instead of falling back when a replacer is asynchronous", () => {
      const p = createPipeline({
        detectors: [email],
        replace: { fallback: () => Promise.resolve("x") },
      });
      expect(() => p.transform("a@b.co")).toThrow(AsyncStrategyError);
      const rejecting = createPipeline({
        detectors: [email],
        replace: { fallback: () => Promise.reject(new Error("boom")) },
      });
      expect(() => rejecting.transform("a@b.co")).toThrow(AsyncStrategyError);
    });

    it("rejects a replacer that does not return a string", () => {
      const p = createPipeline({
        detectors: [email],
        replace: { fallback: (() => 42) as unknown as Replacer },
      });
      expect(() => p.transform("a@b.co")).toThrow(ValidationError);
    });

    it("handles text with surrogate pairs and a very long input", () => {
      const p = pipeline([email]);
      expect(p.transform("😀 a@b.co 😀").text).toBe("😀 [REDACTED] 😀");
      const long = `${"lorem ipsum ".repeat(50_000)}a@b.co`;
      const out = p.transform(long).text;
      expect(out.endsWith("[REDACTED]")).toBe(true);
      expect(out.length).toBe(long.length - 6 + 10);
    });
  });

  describe("transformAsync", () => {
    it("awaits replacers one at a time in document order", async () => {
      const order: string[] = [];
      const p = createPipeline({
        detectors: [email],
        replace: {
          fallback: async (value, context) => {
            order.push(`start ${String(context.ordinal)}`);
            await new Promise((resolve) => setTimeout(resolve, context.ordinal === 0 ? 5 : 0));
            order.push(`end ${String(context.ordinal)}`);
            return value.toUpperCase();
          },
        },
      });
      const result = await p.transformAsync("a@b.co then c@d.co");
      expect(result.text).toBe("A@B.CO then C@D.CO");
      expect(order).toEqual(["start 0", "end 0", "start 1", "end 1"]);
      expect(result.spans.map((s) => [s.outStart, s.outEnd])).toEqual([
        [0, 6],
        [12, 18],
      ]);
    });

    it("accepts synchronous replacers and returns the input when nothing matches", async () => {
      const p = pipeline([email]);
      expect((await p.transformAsync("a@b.co")).text).toBe("[REDACTED]");
      const input = "nothing";
      expect((await p.transformAsync(input)).text).toBe(input);
    });

    it("propagates a rejection and rejects non-string replacements", async () => {
      const failing = createPipeline({
        detectors: [email],
        replace: { fallback: () => Promise.reject(new Error("boom")) },
      });
      await expect(failing.transformAsync("a@b.co")).rejects.toThrow("boom");
      const wrong = createPipeline({
        detectors: [email],
        replace: { fallback: (() => Promise.resolve(1)) as unknown as Replacer },
      });
      await expect(wrong.transformAsync("a@b.co")).rejects.toThrow(ValidationError);
    });
  });

  describe("replace", () => {
    it("runs the replacer configured for the category of the context", () => {
      const p = createPipeline({
        detectors: [email],
        replace: { fallback: constant("#"), byCategory: { email: constant("<mail>") } },
      });
      const context = {
        detector: "d",
        confidence: 1,
        start: 0,
        end: 1,
        ordinal: 0,
        residual: false,
      };
      expect(p.replace("v", { ...context, category: "email" })).toBe("<mail>");
      expect(p.replace("v", { ...context, category: "other" })).toBe("#");
    });
  });
});

describe("engine/resolve", () => {
  describe("resolveSpans", () => {
    it("resolves a hit that contains tens of thousands of others in linear time", () => {
      const inner = Array.from({ length: 40_000 }, (_unused, index) => ({
        start: index * 10,
        end: index * 10 + 8,
        confidence: 0.99,
        detector: 0,
        allowed: false,
      }));
      const outer = { start: 0, end: 400_000, confidence: 0.5, detector: 1, allowed: false };
      const text = "x".repeat(400_000);
      const started = performance.now();
      const spans = resolveSpans(text, [outer, ...inner], "cover");
      expect(performance.now() - started).toBeLessThan(5000);
      expect(spans).toHaveLength(80_000);
      expect(
        spans.every((span, index) => index === 0 || span.start >= (spans[index - 1]?.end ?? 0)),
      ).toBe(true);
    });
  });
});

describe("engine/pipeline", () => {
  describe("overlap resolution", () => {
    it("legacy: of two hits that start together, the more confident one wins", () => {
      const candidates = [
        { start: 0, end: 4, confidence: 0.5, detector: 0, allowed: false },
        { start: 0, end: 8, confidence: 0.9, detector: 1, allowed: false },
      ];
      expect(resolveSpans("abcdefgh", candidates, "legacy")).toEqual([
        { start: 0, end: 8, confidence: 0.9, detector: 1, residual: false },
      ]);
    });
  });
});
