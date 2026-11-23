# anonyma-core

The engine of [anonyma](https://github.com/izaccavalheiro/anonyma) for every
language: PII detection, checksum validation, anonymization strategies,
reversible tokens with a vault, compliance presets and signed anonymization
receipts. The Python, Go, Node.js and WebAssembly bindings call it, and none
of them re-implements a detection rule.

```rust
use anonyma_core::{restore, AnonymaEngine, Category, InMemoryVault};

let engine = AnonymaEngine::builder()
    .categories([Category::Email, Category::Iban])
    .build()?;
let mut vault = InMemoryVault::new();
let shielded = engine.shield("Mail ana@example.com", &mut vault)?;
assert_eq!(shielded.text, "Mail {{EMAIL_1}}");
assert_eq!(restore("Sent to {{EMAIL_1}}", &vault).text, "Sent to ana@example.com");
```

## Parity with the TypeScript reference

The TypeScript package `anonyma` is the reference. This crate ports it
function by function and passes the shared conformance suite
(`packages/conformance`) for every capability `anonyma_core::capabilities()`
lists:

| Area        | Ported                                                                              |
| ----------- | ----------------------------------------------------------------------------------- |
| Detectors   | all 27                                                               |
| Validators  | all 22 of `CHECKSUMS`                                                                |
| Strategies  | `redact`, `mask`, `pseudonymize`                                                     |
| Tokens      | classic (`[EMAIL_0001]`) and vault (`{{EMAIL_1}}`) tokens, restoration              |
| Presets     | all eight definitions and their combination                                         |
| Receipts    | canonical JSON, SHA-256, HMAC-SHA-256 receipts: issue and verify                    |

Every category is ported. Should a future category reach the TypeScript package
first, an engine asked for it fails with `Error::UnsupportedCategories` rather
than skipping it silently; `EngineBuilder::allow_partial(true)` opts in to
partial detection.

## Two APIs

`AnonymaEngine` is the classic API of the reference (`detect()`, `anonymize()`, `tokenize()`).
`Pipeline` is its span engine (`compilePipeline(...).scan()` of `anonyma/engine`): precise
detectors where there is one, the redaction labels allow-listed, and overlaps resolved by
covering, so a weaker detection keeps the characters no stronger one claims as residual spans.
The precise IPv4, IPv6 and card detectors are not ported yet: a pipeline refuses those
categories in precise mode.

## Regular expressions

The reference's patterns are ECMAScript regular expressions; this crate runs
them on the `regex` crate, which guarantees linear-time matching. The module
`jsregex` translates what differs (`\b`, `\d`, `\s`, case folding) to
ECMAScript's meaning. The few lookarounds of the reference become post-filters
on captured groups. Offsets are UTF-8 byte offsets; `anonyma_core::offsets`
converts them to code points or UTF-16 units.
