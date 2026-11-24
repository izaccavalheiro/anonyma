/**
 * The engine of anonyma-native returns what anonyma returns: the same values,
 * offsets and confidences, the same anonymized text, the same batch entries.
 * Needs the root build (npm run build at the repository root) and the addon
 * (npm run build here). Run with `npm test`.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import * as anonyma from "../../../dist/index.js";
import { makeText } from "../../../bench/corpus.mjs";
import { NativeOptionsError, coreVersion, createEngine } from "../lib/index.mjs";

const COMMON = ["email", "phone", "credit-card", "ipv4", "iban"];
// gdpr pseudonymizes some categories without a seed: random ids, compared as such.
const comparable = (text) => text.replace(/id_[0-9a-f]{16}/g, "id_<random>");
const near = (a, b) =>
  assert.deepEqual(
    a.map((m) => ({ ...m, confidence: Math.round(m.confidence * 1e9) })),
    b.map((m) => ({ ...m, confidence: Math.round(m.confidence * 1e9) })),
  );

const TEXTS = [
  "",
  "nothing here",
  "📧 ana@example.com, and 🙂 4111 1111 1111 1111 at 192.0.2.10",
  "Dear Ana Example, IBAN DE89370400440532013000",
  ...[1_000, 10_000, 100_000].flatMap((size) =>
    [1 / 200, 1 / 40].map((density) => makeText({ size, density, seed: 7 }).text),
  ),
];
const LINES = Array.from(
  { length: 500 },
  (_, i) => makeText({ size: 200, density: 1 / 200, seed: 1000 + i }).text,
);

describe("anonyma-native", () => {
  it("reports the core's version", () => {
    assert.match(coreVersion(), /^\d+\.\d+\.\d+/);
  });

  it("detects what anonyma detects, offsets in UTF-16", () => {
    const all = createEngine();
    const common = createEngine({ categories: COMMON });
    for (const text of TEXTS) {
      near(all.detect(text), anonyma.detect(text));
      near(common.detect(text), anonyma.detect(text, COMMON));
    }
  });

  it("anonymizes as anonymize() does with a preset", () => {
    for (const preset of ["gdpr", "pci-dss", "hipaa"]) {
      const engine = createEngine({ preset });
      for (const text of TEXTS) {
        const native = engine.anonymize(text, { includeMatches: true });
        const reference = anonyma.anonymize(text, { preset, includeMatches: true });
        assert.equal(comparable(native.text), comparable(reference.text), preset);
        assert.deepEqual(
          native.matches.map((m) => [m.category, m.start, m.end]),
          reference.matches.map((m) => [m.category, m.start, m.end]),
        );
      }
      assert.deepEqual(engine.anonymize(TEXTS[2] ?? "").matches, []);
    }
  });

  it("applies rules and a default strategy as anonymize() does", () => {
    const options = {
      rules: [{ category: "email", strategy: { strategy: "mask" } }],
      defaultStrategy: { strategy: "redact" },
    };
    const engine = createEngine(options);
    for (const text of TEXTS) {
      assert.equal(engine.anonymize(text).text, anonyma.anonymize(text, options).text);
    }
  });

  it("returns the batch entries of detectBatch() and anonymizeBatch()", () => {
    const engine = createEngine({ preset: "pci-dss" });
    const all = createEngine();
    const texts = [...LINES, 7, "ana@example.com"];
    const native = all.detectBatch(texts);
    const reference = anonyma.detectBatch(texts);
    assert.equal(native.length, reference.length);
    for (const [i, entry] of native.entries()) {
      const expected = reference[i];
      assert.equal(entry.index, i);
      assert.equal(entry.ok, expected?.ok);
      if (entry.ok && expected?.ok) near(entry.value, expected.value);
    }
    const anonymized = engine.anonymizeBatch(texts);
    const expected = anonyma.anonymizeBatch(texts, { preset: "pci-dss" });
    assert.deepEqual(
      anonymized.map((r) => (r.ok ? r.value.text : null)),
      expected.map((r) => (r.ok ? r.value.text : null)),
    );
    assert.deepEqual(engine.detectBatch([]), []);
  });

  it("refuses options it does not run, and texts that are not strings", () => {
    assert.throws(() => createEngine({ customPatterns: [] }), NativeOptionsError);
    assert.throws(() => createEngine({ allowlist: ["x"] }), /use anonyma/);
    assert.throws(() => createEngine({ bogus: 1 }), /unknown option bogus/);
    assert.throws(() => createEngine(null), NativeOptionsError);
    assert.throws(() => createEngine({ preset: "nope" }), Error);
    const engine = createEngine();
    assert.throws(() => engine.detect(7), TypeError);
    assert.throws(() => engine.detectBatch("x"), TypeError);
    engine.close();
    assert.throws(() => engine.detect("x"), /closed/);
  });
});
