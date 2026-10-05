/**
 * Property-based tests for the engine (fast-check).
 */
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { detect } from "../../src/anonymize.js";
import {
  LEGACY_AGGRESSIVE_DETECTORS,
  LEGACY_DETECTORS,
  builtinDetectors,
  compilePipeline,
  constant,
  createChunkTransformer,
  createPipeline,
  redactWith,
} from "../../src/engine/index.js";
import type { SpanDetector } from "../../src/engine/index.js";

/** Values that the built-in detectors recognise, all clearly synthetic. */
const PII = [
  "alice@example.com",
  "bob.smith+tag@example.org",
  "123-45-6789",
  "4111 1111 1111 1111",
  "5555555555554444",
  "203.0.113.57",
  "2001:db8::8a2e:370:7334",
  "GB82 WEST 1234 5698 7654 32",
  "DE89370400440532013000",
  "(415) 555-0134",
  "+44 20 7946 0958",
  "https://example.com/users/42?ref=abc",
  "1990-04-15",
  "Dr. Jane Smith",
  // Assembled at run time: the literal would look like a live credential to a secret scanner.
  ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_"),
  "1HGCM82633A004352",
  "529.982.247-25",
];

const filler = fc.constantFrom(
  "the quick brown fox",
  "status=ok",
  "retry in 30s",
  "see section",
  "INFO request completed",
  "ref",
  "\n",
  " ",
  ", ",
  ": ",
  "😀",
  "é",
  '{"k":"v"}',
  "12",
  "v1.2.3",
);

/** Text made of filler with PII values woven in. */
const mixedText = fc
  .array(
    fc.oneof({ weight: 3, arbitrary: filler }, { weight: 2, arbitrary: fc.constantFrom(...PII) }),
    {
      maxLength: 14,
    },
  )
  .map((parts) => parts.join(" "));

/** Arbitrary text, including characters that stress regular expressions. */
const anyText = fc.oneof(
  mixedText,
  fc.string({ maxLength: 200 }),
  fc.string({ unit: "grapheme", maxLength: 80 }),
  fc.string({ unit: fc.constantFrom(..."0123456789 -.:@/abcXYZ\n"), maxLength: 120 }),
);

const runs = { numRuns: 300 };

describe("engine properties", () => {
  it("legacy detectors with the legacy overlap rule reproduce detect() exactly", () => {
    for (const [registry, aggressive] of [
      [LEGACY_DETECTORS, false],
      [LEGACY_AGGRESSIVE_DETECTORS, true],
    ] as const) {
      const pipeline = createPipeline({
        detectors: Object.values(registry),
        replace: { fallback: redactWith() },
        overlap: "legacy",
      });
      fc.assert(
        fc.property(anyText, (text) => {
          const expected = detect(text, undefined, undefined, aggressive).map((m) => [
            m.category,
            m.start,
            m.end,
            m.confidence,
          ]);
          const actual = pipeline.scan(text).map((s) => [s.category, s.start, s.end, s.confidence]);
          expect(actual).toEqual(expected);
        }),
        runs,
      );
    }
  });

  it("cover: spans are disjoint, ordered, in bounds, and cover every reported character", () => {
    const detectors = builtinDetectors(undefined, { aggressive: true });
    const pipeline = createPipeline({ detectors, replace: { fallback: redactWith() } });
    fc.assert(
      fc.property(anyText, (text) => {
        const spans = pipeline.scan(text);
        let cursor = 0;
        for (const span of spans) {
          expect(span.start).toBeGreaterThanOrEqual(cursor);
          expect(span.end).toBeGreaterThan(span.start);
          expect(span.end).toBeLessThanOrEqual(text.length);
          cursor = span.end;
        }
        // Every non-whitespace character that any detector reported lies inside a span.
        const covered = new Uint8Array(text.length);
        for (const span of spans) covered.fill(1, span.start, span.end);
        for (const detector of detectors as SpanDetector[]) {
          if (detector.prefilter?.(text) === false) continue;
          detector.scan(text, (start, end) => {
            for (let i = start; i < end; i++) {
              if (covered[i] !== 1)
                expect(/\s/.test(text.charAt(i)), `offset ${String(i)}`).toBe(true);
            }
          });
        }
      }),
      runs,
    );
  });

  it("redaction leaves none of the planted values in the output", () => {
    const pipeline = compilePipeline();
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom(...PII), { minLength: 1, maxLength: 6 }),
        filler,
        (values, glue) => {
          const text = values.join(` ${glue} `);
          const out = pipeline.transform(text).text;
          for (const value of values) expect(out).not.toContain(value);
        },
      ),
      runs,
    );
  });

  it("reports output offsets that locate every replacement, and test() agrees with transform()", () => {
    const pipeline = createPipeline({
      detectors: builtinDetectors(),
      replace: { fallback: constant("#") },
    });
    fc.assert(
      fc.property(anyText, (text) => {
        const result = pipeline.transform(text);
        for (const span of result.spans) {
          expect(result.text.slice(span.outStart, span.outEnd)).toBe("#");
        }
        const replaced = result.spans.reduce((sum, span) => sum + (span.end - span.start), 0);
        expect(result.text.length).toBe(text.length - replaced + result.spans.length);
        expect(result.spans.length > 0).toBe(pipeline.test(text));
      }),
      runs,
    );
  });

  it("chunked output equals whole-text output for any way of splitting the input", () => {
    const pipeline = compilePipeline();
    fc.assert(
      fc.property(
        mixedText,
        fc.array(fc.integer({ min: 1, max: 40 }), { minLength: 1, maxLength: 30 }),
        fc.constantFrom(0, 16, 4096),
        (text, sizes, batch) => {
          const transformer = createChunkTransformer(pipeline, { batch });
          let out = "";
          let at = 0;
          for (let i = 0; at < text.length; i++) {
            const size = sizes[i % sizes.length] ?? 1;
            out += transformer.push(text.slice(at, at + size));
            at += size;
          }
          out += transformer.flush();
          expect(out).toBe(pipeline.transform(text).text);
        },
      ),
      runs,
    );
  });

  it("chunked output equals whole-text output for lists of card numbers and for mixed dates", () => {
    const cards = [
      "4111 1111 1111 1111",
      "5500 0000 0000 0004",
      "4012 8888 8888 1881",
      "4242 4242 4242 4242",
      "5555 5555 5555 4444",
      "378282246310005",
    ];
    const dates = ["12/05/1987", "March 3, 2021", "2021-03-03", "born 03.04.1990"];
    const line = fc.oneof(
      { weight: 4, arbitrary: fc.constantFrom(...cards) },
      { weight: 1, arbitrary: fc.constantFrom(...dates) },
      { weight: 1, arbitrary: fc.constantFrom("Batch 2024", "ref 0042", "ok") },
    );
    const list = fc
      .tuple(
        fc.array(line, { minLength: 4, maxLength: 60 }),
        fc.constantFrom("\n", "\r\n", ", ", "\n\n"),
      )
      .map(([lines, separator]) => lines.join(separator));
    const pipelines = [
      compilePipeline(),
      compilePipeline({ preset: "pci-dss" }),
      compilePipeline({ categories: ["credit-card"] }),
      compilePipeline({ categories: ["credit-card", "iban"] }),
    ];
    fc.assert(
      fc.property(
        list,
        fc.integer({ min: 1, max: 40 }),
        fc.constantFrom(0, 16, 4096),
        fc.integer({ min: 0, max: pipelines.length - 1 }),
        (text, size, batch, which) => {
          const pipeline = pipelines[which] ?? pipelines[0];
          if (pipeline === undefined) return;
          const transformer = createChunkTransformer(pipeline, { batch });
          let out = "";
          for (let at = 0; at < text.length; at += size) {
            out += transformer.push(text.slice(at, at + size));
          }
          out += transformer.flush();
          expect(out).toBe(pipeline.transform(text).text);
          for (const card of cards) expect(out).not.toContain(card);
        },
      ),
      runs,
    );
  });

  it("prefilters never hide a hit", () => {
    const detectors = [
      ...builtinDetectors(undefined, { aggressive: true }),
      ...Object.values(LEGACY_DETECTORS),
    ];
    fc.assert(
      fc.property(anyText, (text) => {
        for (const detector of detectors) {
          if (detector.prefilter === undefined || detector.prefilter(text)) continue;
          let hits = 0;
          detector.scan(text, () => hits++);
          expect(hits, detector.id).toBe(0);
        }
      }),
      runs,
    );
  });
});
