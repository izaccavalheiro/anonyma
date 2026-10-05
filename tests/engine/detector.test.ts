import { describe, expect, it } from "vitest";
import { ValidationError } from "../../src/errors.js";
import { detectEmail } from "../../src/detectors/email.js";
import { defineDetector, defineRegexDetector, fromLegacyDetector } from "../../src/engine/index.js";
import type { SpanDetector } from "../../src/engine/index.js";

function hits(detector: SpanDetector, text: string): [number, number, number][] {
  const out: [number, number, number][] = [];
  detector.scan(text, (start, end, confidence) => out.push([start, end, confidence]));
  return out;
}

describe("engine/detector", () => {
  describe("defineDetector", () => {
    const scan = (): void => undefined;

    it("returns a frozen copy of a valid definition", () => {
      const detector = defineDetector({ id: "x", category: "custom", scan, maxMatchLength: 8 });
      expect(Object.isFrozen(detector)).toBe(true);
      expect(detector).toMatchObject({ id: "x", category: "custom", maxMatchLength: 8 });
    });

    it("rejects an empty id, an empty category and a missing scan function", () => {
      expect(() => defineDetector({ id: "", category: "c", scan })).toThrow(ValidationError);
      expect(() => defineDetector({ id: "x", category: "", scan })).toThrow(ValidationError);
      expect(() =>
        defineDetector({ id: "x", category: "c", scan: "nope" as unknown as typeof scan }),
      ).toThrow(ValidationError);
    });

    it("rejects a maxMatchLength that is not a positive integer", () => {
      for (const bad of [0, -1, 1.5, Number.NaN]) {
        expect(() => defineDetector({ id: "x", category: "c", scan, maxMatchLength: bad })).toThrow(
          ValidationError,
        );
      }
    });
  });

  describe("defineRegexDetector", () => {
    it("reports every match with the default confidence and the category as id", () => {
      const detector = defineRegexDetector({ category: "order-id", pattern: /ACME-\d{3}/ });
      expect(detector.id).toBe("order-id");
      expect(hits(detector, "ACME-123 and ACME-456")).toEqual([
        [0, 8, 0.85],
        [13, 21, 0.85],
      ]);
    });

    it("gives the same result on repeated calls and for sticky or global source patterns", () => {
      for (const pattern of [/\d{2}/g, /\d{2}/y, /\d{2}/]) {
        const detector = defineRegexDetector({ category: "n", pattern });
        expect(hits(detector, "a 12 b 34")).toEqual(hits(detector, "a 12 b 34"));
        expect(hits(detector, "a 12 b 34")).toHaveLength(2);
      }
    });

    it("reports only the chosen capture group and skips matches where it did not participate", () => {
      const detector = defineRegexDetector({
        category: "name",
        pattern: /Dear (\w+)|Hello/g,
        group: 1,
        confidence: 0.7,
      });
      expect(hits(detector, "Dear Alice. Hello. Dear Bob")).toEqual([
        [5, 10, 0.7],
        [24, 27, 0.7],
      ]);
    });

    it("applies validate and a computed confidence", () => {
      const detector = defineRegexDetector({
        category: "even",
        pattern: /\d+/,
        validate: (value) => Number(value) % 2 === 0,
        confidence: (match) => (match[0].length > 2 ? 0.9 : 0.5),
      });
      expect(hits(detector, "7 12 1234")).toEqual([
        [2, 4, 0.5],
        [5, 9, 0.9],
      ]);
    });

    it("builds a prefilter from requires and passes maxMatchLength through", () => {
      const detector = defineRegexDetector({
        id: "acme/order",
        category: "order-id",
        pattern: /ACME-\d+/,
        requires: ["ACME-", "acme-"],
        maxMatchLength: 16,
      });
      expect(detector.id).toBe("acme/order");
      expect(detector.maxMatchLength).toBe(16);
      expect(detector.prefilter?.("nothing here")).toBe(false);
      expect(detector.prefilter?.("see ACME-1")).toBe(true);
      expect(defineRegexDetector({ category: "c", pattern: /x/, requires: [] }).prefilter).toBe(
        undefined,
      );
    });

    it("terminates on a pattern that can match the empty string", () => {
      const detector = defineRegexDetector({ category: "c", pattern: /\d*/ });
      expect(hits(detector, "ab12c")).toEqual([[2, 4, 0.85]]);
    });

    it("rejects a non-RegExp pattern and a negative group", () => {
      expect(() =>
        defineRegexDetector({ category: "c", pattern: "x" as unknown as RegExp }),
      ).toThrow(ValidationError);
      expect(() => defineRegexDetector({ category: "c", pattern: /x/, group: -1 })).toThrow(
        ValidationError,
      );
    });
  });

  describe("fromLegacyDetector", () => {
    it("reports exactly the matches of the wrapped function", () => {
      const detector = fromLegacyDetector("email", detectEmail);
      const text = "a@example.com, b@example.org";
      expect(hits(detector, text)).toEqual(
        detectEmail(text).map((m) => [m.start, m.end, m.confidence]),
      );
      expect(detector.id).toBe("email");
    });

    it("accepts an id, a prefilter and a length bound", () => {
      const prefilter = (text: string): boolean => text.includes("@");
      const detector = fromLegacyDetector("email", detectEmail, {
        id: "mail",
        prefilter,
        maxMatchLength: 320,
      });
      expect(detector).toMatchObject({ id: "mail", prefilter, maxMatchLength: 320 });
    });

    it("rejects a detector that is not a function", () => {
      expect(() => fromLegacyDetector("email", null as unknown as typeof detectEmail)).toThrow(
        ValidationError,
      );
    });
  });
});

describe("engine/detector", () => {
  describe("defineRegexDetector", () => {
    it("rejects a confidence outside 0 to 1", () => {
      for (const confidence of [5, -0.1, Number.NaN, "high" as unknown as number]) {
        expect(() => defineRegexDetector({ category: "c", pattern: /x/, confidence })).toThrow(
          ValidationError,
        );
      }
      expect(defineRegexDetector({ category: "c", pattern: /x/, confidence: 1 }).id).toBe("c");
    });
  });
});
