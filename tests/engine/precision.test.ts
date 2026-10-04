/**
 * Precision and recall of the validating detectors on the labelled corpora in
 * tests/fixtures/corpus, compared with the 1.x detectors they supersede.
 *
 * The corpora are deliberately hard: roughly half of every corpus is
 * look-alikes. Items the labeller marked "amb" (ambiguous) are not scored.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  creditCardDetector,
  emailDetector,
  ibanDetector,
  ipv4Detector,
  ipv6Detector,
  legacyCreditCardDetector,
  legacyEmailDetector,
  legacyIbanDetector,
  legacyIpv4Detector,
  legacyIpv6Detector,
  legacySsnDetector,
  ssnDetector,
} from "../../src/engine/index.js";
import type { SpanDetector } from "../../src/engine/index.js";

interface Item {
  id: string;
  kind: "pos" | "neg" | "amb";
  class: string;
  text: string;
  expected?: { value: string; start: number; end: number }[];
}

interface Score {
  exact: number;
  partial: number;
  missed: number;
  falsePositives: number;
  precision: number;
  recall: number;
  errors: string[];
}

function load(family: string): Item[] {
  const file = new URL(`../fixtures/corpus/corpus-${family}.json`, import.meta.url);
  return (JSON.parse(readFileSync(file, "utf8")) as { items: Item[] }).items;
}

function hits(detector: SpanDetector, text: string): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = [];
  if (detector.prefilter?.(text) === false) return out;
  detector.scan(text, (start, end) => out.push({ start, end }));
  return out;
}

function scanAll(detectors: SpanDetector[], text: string): { start: number; end: number }[] {
  return detectors.flatMap((detector) => hits(detector, text));
}

function score(detectors: SpanDetector[], items: Item[]): Score {
  let exact = 0;
  let partial = 0;
  let missed = 0;
  let falsePositives = 0;
  let positives = 0;
  const errors: string[] = [];
  for (const item of items) {
    if (item.kind === "amb") continue;
    const got = scanAll(detectors, item.text);
    const used = new Set<number>();
    for (const want of item.expected ?? []) {
      positives++;
      const same = got.findIndex(
        (g, i) => !used.has(i) && g.start === want.start && g.end === want.end,
      );
      if (same >= 0) {
        used.add(same);
        exact++;
        continue;
      }
      const overlapping = got.findIndex(
        (g, i) => !used.has(i) && g.start < want.end && g.end > want.start,
      );
      if (overlapping >= 0) {
        used.add(overlapping);
        partial++;
        errors.push(`partial ${item.id} [${item.class}] ${JSON.stringify(item.text)}`);
      } else {
        missed++;
        errors.push(`missed  ${item.id} [${item.class}] ${JSON.stringify(item.text)}`);
      }
    }
    const spurious = got.filter((_, i) => !used.has(i));
    falsePositives += spurious.length;
    for (const s of spurious) {
      errors.push(
        `false+  ${item.id} [${item.class}] ${JSON.stringify(item.text)} -> ${JSON.stringify(item.text.slice(s.start, s.end))}`,
      );
    }
  }
  return {
    exact,
    partial,
    missed,
    falsePositives,
    precision: exact / Math.max(1, exact + partial + falsePositives),
    recall: exact / Math.max(1, positives),
    errors,
  };
}

const FAMILIES: [string, SpanDetector, SpanDetector, number, number][] = [
  // family, legacy, precise, minimum precision, minimum recall
  ["email", legacyEmailDetector, emailDetector, 0.9, 0.9],
  ["ssn", legacySsnDetector, ssnDetector, 0.97, 0.95],
  ["iban", legacyIbanDetector, ibanDetector, 0.98, 0.98],
  ["ipv4", legacyIpv4Detector, ipv4Detector, 0.9, 0.98],
  ["ipv6", legacyIpv6Detector, ipv6Detector, 0.98, 0.98],
  ["card", legacyCreditCardDetector, creditCardDetector, 0.98, 0.98],
];

describe("engine/precise", () => {
  describe("labelled corpora", () => {
    const table: Record<string, unknown>[] = [];

    for (const [family, legacy, precise, minPrecision, minRecall] of FAMILIES) {
      it(`${family}: is at least as precise and as complete as the 1.x detector`, () => {
        // Items whose id contains "-A" are obfuscated or masked forms that only aggressive mode targets.
        const items = load(family).filter((item) => !item.id.includes("-A"));
        const before = score([legacy], items);
        const after = score([precise], items);
        table.push({
          family,
          "1.x precision": before.precision.toFixed(3),
          "1.x recall": before.recall.toFixed(3),
          precision: after.precision.toFixed(3),
          recall: after.recall.toFixed(3),
          exact: after.exact,
          partial: after.partial,
          missed: after.missed,
          "false+": after.falsePositives,
        });
        if (process.env["ANONYMA_PRECISION_REPORT"] === "1") {
          console.log(`\n## ${family}\n${after.errors.join("\n")}`);
        }
        expect(after.precision).toBeGreaterThanOrEqual(before.precision);
        expect(after.recall).toBeGreaterThanOrEqual(before.recall);
        expect(after.precision).toBeGreaterThanOrEqual(minPrecision);
        expect(after.recall).toBeGreaterThanOrEqual(minRecall);
      });
    }

    it("prints the comparison table", () => {
      if (process.env["ANONYMA_PRECISION_REPORT"] === "1") console.table(table);
      expect(table.length).toBe(FAMILIES.length);
    });
  });
});
