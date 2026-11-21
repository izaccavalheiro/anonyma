/**
 * Tests for context proximity (withContext), checksum and context members of
 * declarative patterns, the validating national-ID detector in compiled
 * pipelines, and combined presets in compilePipeline().
 */
import { describe, expect, it } from "vitest";
import {
  compilePipeline,
  createChunkTransformer,
  createPipeline,
  defineDetector,
  defineRegexDetector,
  redactWith,
  withContext,
} from "../../src/engine/index.js";
import type { ContextOptions, SpanDetector } from "../../src/engine/index.js";
import { ValidationError } from "../../src/errors.js";

const sixDigits = defineRegexDetector({
  category: "employee-id",
  pattern: /\b\d{6}\b/,
  confidence: 0.5,
  maxMatchLength: 6,
});

function confidences(detector: SpanDetector, text: string): number[] {
  const out: number[] = [];
  detector.scan(text, (_start, _end, confidence) => out.push(confidence));
  return out;
}

describe("engine/context", () => {
  describe("withContext", () => {
    it("raises the confidence of a hit with a keyword before it", () => {
      const detector = withContext(sixDigits, { keywords: ["badge"], boost: 0.4 });
      expect(confidences(detector, "Badge number 123456; order 654321")).toEqual([0.9, 0.5]);
    });

    it("uses a boost of 0.15 and a window of three words by default", () => {
      const detector = withContext(sixDigits, { keywords: ["badge"] });
      expect(confidences(detector, "badge 123456")).toEqual([0.65]);
      expect(confidences(detector, "badge of the 123456")).toEqual([0.65]);
      expect(confidences(detector, "badge of the employee 123456")).toEqual([0.5]);
    });

    it("searches as many words back as the window says", () => {
      const detector = withContext(sixDigits, { keywords: ["badge"], window: 1 });
      expect(confidences(detector, "badge: 123456")).toEqual([0.65]);
      expect(confidences(detector, "badge no 123456")).toEqual([0.5]);
    });

    it("matches whole words, ignoring case, and phrases across spaces", () => {
      const detector = withContext(sixDigits, { keywords: ["employee  id"] });
      expect(confidences(detector, "EMPLOYEE\tID 123456")).toEqual([0.65]);
      expect(confidences(detector, "employees id 123456")).toEqual([0.5]);
    });

    it("treats keywords as text, not as patterns", () => {
      const detector = withContext(sixDigits, { keywords: ["a.b"] });
      expect(confidences(detector, "a.b 123456")).toEqual([0.65]);
      expect(confidences(detector, "axb 123456")).toEqual([0.5]);
    });

    it("never raises the confidence above 1", () => {
      const detector = withContext(
        defineRegexDetector({ category: "x", pattern: /\d{6}/, confidence: 0.95 }),
        { keywords: ["id"], boost: 0.5 },
      );
      expect(confidences(detector, "id 123456")).toEqual([1]);
    });

    it("drops hits without a keyword when one is required", () => {
      const detector = withContext(sixDigits, { keywords: ["badge"], required: true });
      expect(confidences(detector, "badge 123456 and the other 654321")).toEqual([0.65]);
    });

    it("skips texts without any keyword when one is required", () => {
      let scanned = 0;
      const counting = defineDetector({
        id: "counting",
        category: "x",
        scan: () => {
          scanned++;
        },
      });
      const detector = withContext(counting, { keywords: ["Badge Number"], required: true });
      expect(detector.prefilter?.("order 123456")).toBe(false);
      expect(detector.prefilter?.("badge 123456")).toBe(true);
      detector.scan("x", () => undefined);
      expect(scanned).toBe(1);
    });

    it("keeps the prefilter of the original detector", () => {
      const gated = defineDetector({
        id: "gated",
        category: "x",
        prefilter: (text) => text.includes("#"),
        scan: () => undefined,
      });
      expect(withContext(gated, { keywords: ["id"] }).prefilter?.("id 1")).toBe(false);
      const required = withContext(gated, { keywords: ["id"], required: true });
      expect(required.prefilter?.("id 1")).toBe(false);
      expect(required.prefilter?.("id #1")).toBe(true);
      expect(withContext(sixDigits, { keywords: ["id"] }).prefilter).toBeUndefined();
    });

    it("keeps the id and category, and lengthens maxMatchLength by the look-back", () => {
      const detector = withContext(sixDigits, { keywords: ["badge"], window: 2 });
      expect(detector.id).toBe("employee-id");
      expect(detector.category).toBe("employee-id");
      expect(detector.maxMatchLength).toBe(6 + 2 * 41);
      const unbounded = defineDetector({ id: "u", category: "u", scan: () => undefined });
      expect(withContext(unbounded, { keywords: ["x"] }).maxMatchLength).toBeUndefined();
    });

    it("lifts a weak detector over minConfidence only where the text says what the value is", () => {
      const pipeline = createPipeline({
        detectors: [withContext(sixDigits, { keywords: ["employee", "badge"], boost: 0.4 })],
        replace: { fallback: redactWith() },
        minConfidence: 0.8,
      });
      expect(pipeline.transform("Badge number 123456; order 654321").text).toBe(
        "Badge number [REDACTED]; order 654321",
      );
    });

    it("sees a keyword that arrived in an earlier chunk of a stream", () => {
      const pipeline = createPipeline({
        detectors: [withContext(sixDigits, { keywords: ["badge"], required: true })],
        replace: { fallback: redactWith() },
      });
      const chunks = createChunkTransformer(pipeline, { batch: 0 });
      const out =
        chunks.push("badge ") + chunks.push("123") + chunks.push("456 ok") + chunks.flush();
      expect(out).toBe("badge [REDACTED] ok");
    });

    it.each<[unknown, string]>([
      [null, "context"],
      [{ keywords: [] }, "context.keywords"],
      [{ keywords: [" "] }, "context.keywords"],
      [{ keywords: "id" }, "context.keywords"],
      [{ keywords: ["id"], window: 0 }, "context.window"],
      [{ keywords: ["id"], window: 1.5 }, "context.window"],
      [{ keywords: ["id"], boost: 2 }, "context.boost"],
      [{ keywords: ["id"], boost: "1" }, "context.boost"],
      [{ keywords: ["id"], required: "yes" }, "context.required"],
    ])("rejects invalid options %j", (options, field) => {
      expect(() => withContext(sixDigits, options as ContextOptions)).toThrow(ValidationError);
      try {
        withContext(sixDigits, options as ContextOptions);
      } catch (error) {
        expect((error as ValidationError).message).toContain(field);
      }
    });
  });

  describe("compilePipeline patterns", () => {
    it("discards matches that fail the named validator", () => {
      const pipeline = compilePipeline({
        categories: [],
        patterns: [
          { source: String.raw`\b\d{9}\b`, category: "routing", validator: "aba-routing" },
        ],
      });
      expect(pipeline.transform("011000015 and 011000016").text).toBe("[REDACTED] and 011000016");
    });

    it("applies context to a pattern", () => {
      const pipeline = compilePipeline({
        categories: [],
        minConfidence: 0.8,
        patterns: [
          {
            source: String.raw`\b\d{6}\b`,
            category: "employee-id",
            confidence: 0.5,
            context: { keywords: ["badge"], boost: 0.4 },
          },
        ],
      });
      expect(pipeline.transform("badge 123456, then order number 654321").text).toBe(
        "badge [REDACTED], then order number 654321",
      );
    });

    it("rejects an unknown validator", () => {
      expect(() =>
        compilePipeline({
          patterns: [{ source: "x", category: "x", validator: "nope" as "luhn" }],
        }),
      ).toThrow(/patterns\[0\]\.validator.*luhn/);
    });

    it("rejects invalid context", () => {
      expect(() =>
        compilePipeline({
          patterns: [{ source: "x", category: "x", context: { keywords: [] } }],
        }),
      ).toThrow(/patterns\[0\]\.context\.keywords/);
      expect(() =>
        compilePipeline({
          patterns: [{ source: "x", category: "x", context: null as unknown as ContextOptions }],
        }),
      ).toThrow(/patterns\[0\]\.context(?!\.)/);
    });
  });

  describe("validating national-ID detection", () => {
    it("replaces CPFs whose check digits hold and leaves the others", () => {
      const text = "CPF 529.982.247-25 / 529.982.247-26";
      expect(compilePipeline({ categories: ["national-id"] }).transform(text).text).toBe(
        "CPF [REDACTED] / 529.982.247-26",
      );
      expect(
        compilePipeline({ categories: ["national-id"], detection: "legacy" }).transform(text).text,
      ).toBe("CPF [REDACTED] / [REDACTED]");
    });
  });

  describe("combined presets", () => {
    it("detects the categories of every preset", () => {
      const pipeline = compilePipeline({ preset: ["pci-dss", "hipaa"] });
      const text = "Card 4111 1111 1111 1111, SSN 123-45-6789";
      const result = pipeline.transform(text);
      expect(result.spans.map((span) => span.category)).toEqual(["credit-card", "ssn"]);
    });

    it("gives a category the most protective strategy of the presets", () => {
      // PCI DSS masks cards to their last four digits; HIPAA redacts them.
      const text = "Card 4111 1111 1111 1111";
      expect(compilePipeline({ preset: "pci-dss" }).transform(text).text).toContain("1111");
      expect(compilePipeline({ preset: ["pci-dss", "hipaa"] }).transform(text).text).toBe(
        "Card [REDACTED]",
      );
    });
  });
});
