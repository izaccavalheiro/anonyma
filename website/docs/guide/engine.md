---
title: Span engine
sidebar_position: 10
description: Compile a pipeline once — validating detectors, every strategy, overlap resolution, chunk-safe streams — and reuse it.
---

`anonyma/engine` is the engine for production use. A pipeline is compiled once from a specification
and reused for every text:

- **Validating detectors.** Email addresses, US SSNs, IBANs, IP addresses, payment cards and
  national IDs are confirmed by check digits, issuer ranges and allocation rules, so look-alikes —
  version strings, order numbers, a CPF with wrong check digits — are left alone. The other
  categories use the same detectors as `anonymize()`.
- **Nothing left behind.** Overlapping detections are resolved so that no detected character is
  left in the output.
- **Every strategy.** All eight strategies apply as rules, `tokenize`, `encrypt` and `synthesize`
  included.
- **Configuration as data.** A specification is plain JSON — it can live in a configuration file or
  a [policy](compliance.md) — and keys, peppers and seeds are passed next to it, never inside it.
- **A report without data.** The result lists what was replaced, with offsets, categories and
  detectors, and never the detected text: ready for an [audit record](audit.md).

The engine was added in 1.1.0, next to the functions of `anonyma`, which keep their 1.0 behaviour.
Both follow semantic versioning.

## Compile and run

```ts
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "hipaa" });

const { text, spans } = pipeline.transform("Patient jane@example.org, SSN 123-45-6789");
// text:  "Patient [REDACTED], SSN [REDACTED]"
// spans: offsets, categories and detectors, never the detected text

pipeline.test("nothing personal here"); // false: is there anything to replace?
```

Use `transformAsync()` when a rule hashes or encrypts.

## The specification

| Field             | What it does                                                                    |
| ----------------- | ------------------------------------------------------------------------------- |
| `preset`          | A preset or a list of presets to start from                                     |
| `categories`      | Built-in categories to detect; defaults to the preset's, or all of them         |
| `defaultStrategy` | The strategy of categories without a rule; defaults to the preset's, or redact  |
| `rules`           | Strategies by category, `{ email: { strategy: "mask" } }`; they override the preset's |
| `patterns`        | Your own formats, with check digits and keywords (below)                        |
| `minConfidence`   | Matches below this confidence are left alone                                    |
| `allow`           | Exact values to leave alone; `allowCaseSensitive` to compare case               |
| `aggressive`      | The permissive variants of the built-in detectors                               |
| `detection`       | `"precise"` (default, validating) or `"legacy"` (the detectors of `anonymize()`) |
| `overlap`         | How overlapping detections are resolved                                         |

The second argument carries what a configuration file must not:

```ts
const pipeline = compilePipeline(spec, {
  secrets: { hashPepper: env.PEPPER, pseudonymizeSeed: env.SEED },
  encryption: { passphrase: env.ENCRYPTION_PASSPHRASE },
  tokenization: session, // a tokenizer from anonyma/vault
});
```

## Your own formats

A pattern can require check digits and use the words around a match. Here a six-digit number is an
employee ID only after "badge" or "employee", and a nine-digit one is a routing number only when its
check digits hold:

```ts
const pipeline = compilePipeline({
  minConfidence: 0.8,
  patterns: [
    {
      source: String.raw`\b\d{6}\b`,
      category: "employee-id",
      confidence: 0.5,
      context: { keywords: ["badge", "employee"], boost: 0.4 }, // within 3 words before
    },
    { source: String.raw`\b\d{9}\b`, category: "routing", validator: "aba-routing" },
  ],
});
pipeline.transform("Badge 123456; your order number is 654321; routing 011000015").text;
// "Badge [REDACTED]; your order number is 654321; routing [REDACTED]"
```

`validator` takes any name in [Checksums](../reference/checksums.md). `withContext(detector, options)`
does the same as `context` for any detector; with `required: true`, matches without a keyword before
them are dropped.

## Build from parts

`createPipeline()` builds a pipeline from detectors and replacers imported one by one, so that a
bundler keeps only those:

```ts
import { createPipeline, emailDetector, ibanDetector, maskWith, redactWith } from "anonyma/engine";

const pipeline = createPipeline({
  detectors: [emailDetector, ibanDetector],
  replace: { fallback: redactWith(), byCategory: { iban: maskWith({ keepLeading: 4 }) } },
});
pipeline.transform("ana@example.com, GB82 WEST 1234 5698 7654 32").text;
// "[REDACTED], GB82***********************"
```

`defineRegexDetector()` turns a regular expression into a detector — see
[Detecting personal data](detection.md#add-your-own-formats).

## Streams

`createPipelineStream(pipeline)` is a `TransformStream<string, string>` that finds values split
between chunks. See [Batches and streams](batch-and-streaming.md#text-in-arbitrary-chunks).
