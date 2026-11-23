/**
 * Batch fusion: detectBatch(), anonymizeBatch() and Pipeline.scanBatch() scan short entries joined
 * into one text. These tests check that every result equals the per-entry
 * call, at the boundaries between entries where fusion could change one, and
 * that the invariants fusion relies on still hold in the detectors' source.
 */
import { readFileSync, readdirSync } from "node:fs";
import fc from "fast-check";
import { afterEach, describe, expect, it } from "vitest";
import { anonymize, detect } from "../src/anonymize.js";
import { compilePipeline, createPipeline, defineRegexDetector } from "../src/engine/index.js";
import type { Pipeline, PipelineSpec } from "../src/engine/index.js";
import { FUSION_SEPARATOR } from "../src/internal/fusion.js";
import { anonymizeBatch, detectBatch } from "../src/batch.js";
import { DETECTOR_REGISTRY } from "../src/detectors/index.js";
import type { AnonymizeOptions, PiiCategory, PiiMatch } from "../src/types.js";
import { pixPayload } from "./fixtures/pix.js";

/** Labels that give a value nearby a higher confidence, or make it a match at all. */
const LABELS = [
  "Passport:",
  "passport number",
  "Address:",
  "shipped to",
  "Tax ID:",
  "VAT",
  "tracking number",
  "case no.",
  "docket #",
  "MRN:",
  "patient id",
  "Rx #",
  "NDC",
  "member id",
  "NHS number",
  "Discord ID",
  "api key =",
  "bearer",
  "routing number",
  "account number:",
  "pix key",
  "RG:",
  "national id",
  "DL #",
  "driver's license",
  "plate number",
  "registration no.",
  "company number",
  "ABN",
  "wallet address",
  "bitcoin",
  "Dear",
  "Mr.",
  // What the precise detectors look for before a value.
  "message-id: <abc",
  "version",
  "https://user:",
  "section",
  "release",
  "Table",
  "nginx/",
  "ssn",
  "social security number",
  "patient",
  "regarding",
];

/** Values that the built-in detectors recognise, all synthetic. */
const VALUES = [
  "A12345678",
  "AB123456",
  "123 Main Street",
  "Hauptstraße 5, 10115 Berlin",
  "12 rue de la Paix",
  "12-3456789",
  "912-70-1234",
  "1Z999AA10123456784",
  "940011189922385111111",
  "4111 1111 1111 1111",
  "4111111111111111",
  "**** **** **** 1111",
  "ana@example.com",
  "ana [at] example [dot] com",
  "192.0.2.1",
  "2001:db8::1",
  "+1 202 555 0102",
  "(202) 555-0102",
  "555-0102",
  "06 12 34 56 78",
  "Ana Example",
  "DE89370400440532013000",
  "GB82 WEST 1234 5698 7654 32",
  "123-45-6789",
  "123456789",
  "https://example.com/a/b?c=d#e",
  "1HGCM82633A004352",
  "AB12 CDE",
  "@example_user",
  "u/example_user",
  "linkedin.com/in/example-user",
  ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_"),
  "0x" + "ab".repeat(20),
  "13-cv-12345",
  "1990-04-15",
  "04/15/1990",
  "15 April 1990",
  "529.982.247-25",
  "12.345.678-9",
  "AB 12 34 56 C",
  "2345 6789 0124",
  "123456789012",
  "01-23-45",
  "021000021",
  "12345678-1234-1234-1234-123456789012",
  pixPayload(),
];

/** What may precede or follow a value inside an entry. */
const EDGES = ["", " ", "  ", "\t", "\n", ".", ". ", ", ", ":", "-", "x", "9"];

const ALL_CATEGORIES = Object.keys(DETECTOR_REGISTRY) as PiiCategory[];

/** The results of `detect` on each entry, the reference for detectBatch. */
function oneByOne(texts: readonly string[], categories?: readonly PiiCategory[]): PiiMatch[][] {
  return texts.map((text) => detect(text, categories));
}

/** detectBatch's matches, each entry required to succeed. */
function batched(texts: readonly string[], categories?: readonly PiiCategory[]): PiiMatch[][] {
  return detectBatch(texts, categories).map((result) => {
    if (!result.ok) throw result.error;
    return result.value;
  });
}

/** Results compared as JSON, so that the order of keys counts too. */
function expectSame(texts: readonly string[], categories?: readonly PiiCategory[]): void {
  expect(JSON.stringify(batched(texts, categories))).toBe(
    JSON.stringify(oneByOne(texts, categories)),
  );
}

/** Pipeline.scanBatch against scan on each entry, as JSON. */
function expectSameSpans(pipeline: Pipeline, texts: readonly string[]): void {
  expect(JSON.stringify(pipeline.scanBatch(texts))).toBe(
    JSON.stringify(texts.map((text) => pipeline.scan(text))),
  );
}

/** anonymizeBatch against anonymize on each entry. */
function expectSameAnonymized(texts: readonly string[], options: AnonymizeOptions): void {
  const reference = texts.map((text) => anonymize(text, options));
  const results = anonymizeBatch(texts, options).map((result) => {
    if (!result.ok) throw result.error;
    return result.value;
  });
  expect(JSON.stringify(results)).toBe(JSON.stringify(reference));
}

/** A label at the end of one entry and a value at the start of the next, with edges. */
function boundaryEntries(): string[] {
  const entries: string[] = [];
  for (const label of LABELS) {
    for (const value of VALUES) {
      for (const edge of ["", " ", "\n"]) {
        entries.push(`see ${label}${edge}`, `${value} done`);
        entries.push(`${value}`, `${edge}${label} ${value}`);
      }
    }
  }
  return entries;
}

describe("batch fusion", () => {
  describe("detectBatch()", () => {
    it("matches detect() when a label ends one entry and a value starts the next", () => {
      expectSame(boundaryEntries());
    }, 120_000);

    it("matches detect() for values at the very edges of entries", () => {
      const entries: string[] = [];
      for (const value of VALUES) {
        for (const before of EDGES) {
          for (const after of EDGES) entries.push(`${before}${value}${after}`);
        }
      }
      expectSame(entries);
      expectSame([...entries].reverse(), ["email", "phone", "credit-card", "ipv4", "ssn"]);
    });

    it("matches detect() on the labelled corpora", () => {
      const directory = new URL("./fixtures/corpus/", import.meta.url);
      const texts = readdirSync(directory).flatMap((file) => {
        const corpus = JSON.parse(readFileSync(new URL(file, directory), "utf8")) as {
          items: { text: string }[];
        };
        return corpus.items.map((item) => item.text);
      });
      expect(texts.length).toBeGreaterThan(500);
      expectSame(texts);
    });

    it("scans an entry that starts with a greeting alone, so ^ still anchors it", () => {
      const texts = ["Thanks.", "Dear Ana Example, welcome", "Hello Bea Example"];
      const results = batched(texts);
      expect(results[1]?.map((m) => m.value)).toContain("Ana Example");
      expect(results[2]?.map((m) => m.value)).toContain("Bea Example");
      expectSame(texts);
      // A greeting after leading space is no greeting for ^, fused or not.
      expectSame(["Thanks.", "  Dear Ana Example"]);
      // Without the name category, greetings are fused like any entry.
      expectSame(texts, ["email"]);
    });

    it("scans alone the entries it cannot fuse", () => {
      const long = "word ".repeat(2000) + "ana@example.com";
      const texts = ["a ana@example.com", long, "b\u0000ana@example.com", "c 192.0.2.1"];
      expectSame(texts);
      expect(batched(texts).map((matches) => matches.length)).toEqual([1, 1, 1, 1]);
    });

    it("splits a batch larger than one fused text into several", () => {
      const texts = Array.from(
        { length: 600 },
        (_, i) => `row ${String(i)}: user${String(i)}@example.com`,
      );
      expectSame(texts);
    });

    it("ends on a full fused text when the last entry fills it", () => {
      // Four entries of 8,150 units and their separators pass 32,768 with the last one.
      const texts = Array.from({ length: 4 }, (_, i) =>
        `user${String(i)}@example.com `.padEnd(8150, "z"),
      );
      expectSame(texts);
    });

    it("returns an error in place of a value that is not a string", () => {
      const texts = ["ana@example.com", 42, "bea@example.com"] as unknown as string[];
      const results = detectBatch(texts);
      expect(results.map((r) => r.ok)).toEqual([true, false, true]);
      expect(results[2]?.ok && results[2].value[0]?.value).toBe("bea@example.com");
    });

    it("fails every entry for an unknown category, as detect() does", () => {
      const results = detectBatch(["a", "b"], ["email", "nope" as PiiCategory]);
      expect(results.every((r) => !r.ok)).toBe(true);
    });

    it("handles a single entry and empty entries", () => {
      expectSame(["ana@example.com"]);
      expectSame(["", "ana@example.com", "", ""]);
    });

    describe("with a replaced registry entry", () => {
      const original = DETECTOR_REGISTRY.email;
      afterEach(() => {
        (DETECTOR_REGISTRY as Record<string, unknown>).email = original;
      });

      it("scans entry by entry, since fusion is proven for the built-in detectors only", () => {
        (DETECTOR_REGISTRY as Record<string, unknown>).email = (text: string): PiiMatch[] =>
          text.startsWith("x")
            ? [{ category: "email", value: text, start: 0, end: text.length, confidence: 1 }]
            : [];
        const results = batched(["x1", "y", "x2"], ["email"]);
        expect(results.map((m) => m.map((match) => match.value))).toEqual([["x1"], [], ["x2"]]);
      });
    });
  });

  describe("anonymizeBatch()", () => {
    const texts = boundaryEntries().slice(0, 1500);

    it("matches anonymize() with the default options", () => {
      expectSameAnonymized(texts, {});
    });

    it("matches anonymize() with a preset, matches, tokens and an allowlist", () => {
      expectSameAnonymized(texts, {
        preset: "gdpr",
        includeMatches: true,
        consistentTokens: true,
        allowlist: ["ana@example.com"],
        confidenceThreshold: 0.75,
      });
    });

    it("matches anonymize() with aggressive detectors and custom patterns", () => {
      expectSameAnonymized(texts, {
        aggressive: true,
        includeMatches: true,
        customPatterns: [{ pattern: /done/, replacement: "[DONE]" }],
      });
    });

    it("matches anonymize() with rules and enabled categories", () => {
      expectSameAnonymized(texts, {
        rules: [
          { category: "email", strategy: { strategy: "mask", keepTrailing: 4 } },
          { category: "name", strategy: { strategy: "pseudonymize" } },
        ],
      });
      expectSameAnonymized(texts, { enabledCategories: { phone: true, url: true } });
    });

    it("scans entry by entry with custom detectors", () => {
      expectSameAnonymized(["a@example.com", "b@example.com"], {
        customDetectors: {
          email: (text) => [{ category: "email", value: text, start: 0, end: 1, confidence: 1 }],
        },
      });
    });

    it("fails every entry with the error of invalid options", () => {
      const results = anonymizeBatch(["a", "b"], { globalReplacement: " " });
      expect(results.map((r) => r.ok)).toEqual([false, false]);
      const unknown = anonymizeBatch(["a", "b"], {
        rules: [{ category: "nope" as PiiCategory, strategy: { strategy: "redact" } }],
      });
      expect(unknown.map((r) => r.ok)).toEqual([false, false]);
    });

    it("keeps a failing entry's error to that entry", () => {
      const results = anonymizeBatch(["ana@example.com", "bea@example.com"], {
        customPatterns: [{ pattern: "bea" as unknown as RegExp, replacement: "x" }],
      });
      expect(results.map((r) => r.ok)).toEqual([false, false]);
      const mixed = anonymizeBatch(["ana@example.com", 7 as unknown as string, "x"]);
      expect(mixed.map((r) => r.ok)).toEqual([true, false, true]);
    });
  });

  describe("Pipeline.scanBatch()", () => {
    const specs: [string, PipelineSpec][] = [
      ["precise", {}],
      ["legacy", { detection: "legacy" }],
      ["aggressive", { aggressive: true }],
      ["a few categories", { categories: ["email", "ipv4", "credit-card", "ssn", "iban"] }],
      ["allow rules and a threshold", { allow: ["ana@example.com"], minConfidence: 0.8 }],
    ];

    it.each(specs)(
      "matches scan() at entry boundaries (%s)",
      (_name, spec) => {
        expectSameSpans(compilePipeline(spec), boundaryEntries());
      },
      120_000,
    );

    it("matches scan() for values at the edges of entries and on the corpora", () => {
      const entries: string[] = [];
      for (const value of VALUES) {
        for (const before of EDGES) {
          for (const after of EDGES) entries.push(`${before}${value}${after}`);
        }
      }
      const pipeline = compilePipeline({});
      expectSameSpans(pipeline, entries);
      const directory = new URL("./fixtures/corpus/", import.meta.url);
      expectSameSpans(
        pipeline,
        readdirSync(directory).flatMap((file) =>
          (
            JSON.parse(readFileSync(new URL(file, directory), "utf8")) as {
              items: { text: string }[];
            }
          ).items.map((item) => item.text),
        ),
      );
    });

    it("keeps the look-back of the precise detectors inside an entry", () => {
      const pipeline = compilePipeline({ categories: ["email", "ipv4"] });
      const texts = ["Message-ID: <abc", "ana@example.com", "version", "203.0.113.7 up"];
      const spans = pipeline.scanBatch(texts);
      expect(spans.map((found) => found.length)).toEqual([0, 1, 0, 1]);
      expectSameSpans(pipeline, texts);
    });

    it("scans entry by entry with a detector of its own", () => {
      const pipeline = createPipeline({
        detectors: [defineRegexDetector({ id: "x", category: "x", pattern: /x+/ })],
        replace: { fallback: () => "" },
      });
      expect(pipeline.scanBatch(["axx", "x"]).map((found) => found[0]?.start)).toEqual([1, 0]);
    });

    it("scans entry by entry with an allow rule that sees offsets", () => {
      const starts: number[] = [];
      const pipeline = compilePipeline({
        categories: ["email"],
        allow: [
          ((_value: string, span: { start: number }) => {
            starts.push(span.start);
            return false;
          }) as unknown as string,
        ],
      });
      pipeline.scanBatch(["a ana@example.com", "b bea@example.com"]);
      expect(starts).toEqual([2, 2]);
    });

    it("throws for a text that is not a string, as scan() does", () => {
      expect(() => compilePipeline({}).scanBatch(["a", 1 as unknown as string])).toThrow();
    });
  });

  describe("invariants of the detectors", () => {
    const sources = [
      ...readdirSync(new URL("../src/detectors/", import.meta.url))
        .filter((file) => file.endsWith(".ts"))
        .map((file) => `../src/detectors/${file}`),
      "../src/engine/precise.ts",
    ].map((path) => ({
      file: path.split("/").pop() ?? path,
      source: readFileSync(new URL(path, import.meta.url), "utf8"),
    }));

    it("finds nothing in the separator, with any detector", () => {
      expect(detect(FUSION_SEPARATOR)).toEqual([]);
      expect(compilePipeline({ aggressive: true }).scan(FUSION_SEPARATOR)).toEqual([]);
      expect(
        anonymize(FUSION_SEPARATOR, { aggressive: true, includeMatches: true }).matches,
      ).toEqual([]);
    });

    it("keeps every label window shorter than the separator", () => {
      const windows = sources.flatMap(({ source }) =>
        [...source.matchAll(/-\s*pos\s*<=\s*(\d+)/g)].map((m) => Number(m[1])),
      );
      expect(windows.length).toBeGreaterThanOrEqual(15);
      for (const window of windows) expect(window).toBeLessThan(FUSION_SEPARATOR.length - 1);
      // The precise detectors test longer look-backs with patterns that stop at the separator;
      // a new look-back is a new case for the boundary tests above.
      const lookBacks = sources.flatMap(({ source }) =>
        [...source.matchAll(/start\s*-\s*(\d+)\)/g)].map((m) => Number(m[1])),
      );
      expect(lookBacks.sort((a, b) => a - b)).toEqual([1, 2, 48, 96]);
    });

    it("anchors at the start of the text only in the greetings of the name detectors", () => {
      const anchored = sources.filter(({ source }) => /\(\?:\^\|/.test(source));
      expect(anchored.map(({ file }) => file)).toEqual(["name.ts"]);
      // The words GREETING_START tests are the greeting words of both patterns.
      const name = anchored[0]?.source ?? "";
      expect([...name.matchAll(/\^\|\\{1,2}\.\S*?\)\(\?:([a-z |]+)\)/g)].map((m) => m[1])).toEqual([
        "dear|hi|hello|greetings|hey there|hey",
        "dear|hi|hello|greetings|hey there|hey",
      ]);
    });

    it("uses no class that matches every character, nor the m or s flags", () => {
      for (const { file, source } of sources) {
        expect(source, file).not.toMatch(/\[\\s\\S\]|\[\\d\\D\]|\[\\w\\W\]|\[\^\]/);
        expect(source, file).not.toMatch(/\/[dgiuvy]*[ms][dgiuvy]*;|"[dgiuvy]*[ms][dgiuvy]*"\)/);
      }
    });
  });

  it("matches detect() on random entries built from labels, values and edges", () => {
    const piece = fc.constantFrom(...LABELS, ...VALUES, ...EDGES, " ", "\n");
    const entry = fc.array(piece, { maxLength: 6 }).map((parts) => parts.join(""));
    fc.assert(
      fc.property(fc.array(entry, { minLength: 2, maxLength: 12 }), (texts) => {
        expect(JSON.stringify(batched(texts))).toBe(JSON.stringify(oneByOne(texts)));
        expectSameSpans(compilePipeline({}), texts);
      }),
      { numRuns: 200 },
    );
  });

  it("covers every category", () => {
    expect(ALL_CATEGORIES).toHaveLength(27);
  });
});
