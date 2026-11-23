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
| Detectors   | `email`, `phone`, `ipv4`, `ipv6`, `url`, `credit-card`, `ssn`, `iban`, `date-of-birth`, `tax-id`, `bank-account` in full; `national-id` for the Brazilian CPF only |
| Validators  | `luhn`, `verhoeff`, `iban`, `cpf`, `cnpj`, `aba-routing`, `pix`                       |
| Strategies  | `redact`, `mask`, `pseudonymize`                                                     |
| Tokens      | classic (`[EMAIL_0001]`) and vault (`{{EMAIL_1}}`) tokens, restoration              |
| Presets     | all eight definitions and their combination                                         |
| Receipts    | canonical JSON, SHA-256, HMAC-SHA-256 receipts: issue and verify                    |

An engine refuses a category it does not detect in full, and fails with
`Error::UnsupportedCategories` rather than skipping it silently. Opt in with
`EngineBuilder::allow_partial(true)`, and read `AnonymaEngine::undetected()`.

## Regular expressions

The reference's patterns are ECMAScript regular expressions; this crate runs
them on the `regex` crate, which guarantees linear-time matching. The module
`jsregex` translates what differs (`\b`, `\d`, `\s`, case folding) to
ECMAScript's meaning. The few lookarounds of the reference become post-filters
on captured groups. Offsets are UTF-8 byte offsets; `anonyma_core::offsets`
converts them to code points or UTF-16 units.
