# anonyma conformance suite

One JSON file of test cases, [`conformance-tests.json`](conformance-tests.json), that every
implementation of anonyma must pass: the TypeScript reference (`anonyma` on npm), the Rust core
(`crates/anonyma-core`) and each binding built on it (`bindings/*`). A binding re-implements no
detection rule, checksum or token format: it calls the Rust core. The suite proves it calls it
right, and that the Rust core behaves like the reference.

The suite is private to this repository; it is not published.

## Layout

```
packages/conformance/
├── conformance-tests.json         # the cases
├── conformance-tests.schema.json  # JSON Schema (draft 2020-12) of the file
├── src/index.ts                   # loader, comparison rules, runSuite() for TypeScript
├── src/typescript.ts              # adapter of the TypeScript reference
└── tests/                         # the reference must pass every case, skipping none
```

The other runners read the same file:

| Implementation         | Runner                                          |
| ---------------------- | ----------------------------------------------- |
| TypeScript (reference) | `packages/conformance/tests/typescript.test.ts` |
| Rust core              | `crates/anonyma-core/tests/conformance.rs`      |
| Python                 | `bindings/python/tests/test_conformance.py`     |
| Go                     | `bindings/go/conformance_test.go`               |

## A case

```json
{
  "id": "detect.national-id.cpf-invalid-strict",
  "description": "strict mode drops a CPF whose check digits fail",
  "op": "detect",
  "requires": ["detect:national-id/br-cpf", "detect:national-id+strict"],
  "input": { "text": "CPF 529.982.247-26", "categories": ["national-id"], "strict": true },
  "expected": { "matches": [] }
}
```

- `id` is stable: a case that changes meaning gets a new id.
- `description` says what the case checks. "Reference behaviour" marks a result that is surprising
  but is what the reference does; an implementation reproduces it, and a change to it is a change
  to the reference first.
- `requires` lists the capabilities an implementation needs to run the case (below).

## Capabilities

An implementation declares the capabilities it provides. A case whose `requires` are not all
provided is **skipped**, never failed; the runner reports it. The TypeScript reference provides
every capability and must skip nothing.

| Capability                     | Meaning                                                                                                                       |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `validate:<name>`              | the checksum validator `<name>` (the names of `CHECKSUMS` in `anonyma/validators`)                                            |
| `detect:<category>`            | the whole built-in detector of the category                                                                                   |
| `detect:<category>/<entry>`    | one entry of a composite detector, such as `national-id/br-cpf`: a case that needs only it uses inputs no other entry matches |
| `detect:<category>+aggressive` | the aggressive variant of the detector                                                                                        |
| `detect:<category>+strict`     | the strict variant, which verifies check digits (`national-id`)                                                               |
| `scan`, `scan:<category>`      | the engine's scan (`anonyma/engine`), and its detectors of the category in precise mode                                       |
| `tokenize`, `detokenize`       | classic tokens (`[EMAIL_0001]`) and their restoration                                                                         |
| `shield`, `restore`            | vault tokens (`{{EMAIL_1}}`) and their restoration from a vault                                                               |
| `anonymize`, `strategy:<name>` | one-way anonymization with the strategy `<name>`                                                                              |
| `preset`                       | preset definitions and their combination                                                                                      |
| `preset:<name>`                | anonymization with the preset: every category of the preset is detected in full                                               |
| `receipt`                      | canonical JSON, SHA-256 digests and HMAC-signed anonymization receipts                                                        |

A release of a binding states the capabilities it provides. Its release gate: no failed case,
and no skipped case among the capabilities it claims.

## Operations

Offsets are in **Unicode code points** from the start of the text (`"offsets": "code-points"`),
whatever the implementation's native unit: JavaScript counts UTF-16 code units, Rust counts UTF-8
bytes, Python counts code points. Each runner converts. Confidence values are equal within `1e-9`.

| `op`             | Input                                                               | Expected                                                                           |
| ---------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `validate`       | `validator`, `value`                                                | `valid`                                                                            |
| `detect`         | `text`, `categories`, `aggressive?`, `strict?`                      | `matches`: `category`, `value`, `start`, `end`, `confidence`, in document order    |
| `scan`           | `text`, `categories`, `detection?`, `aggressive?`, `minConfidence?` | `spans`: `category`, `detector`, `value`, `start`, `end`, `confidence`, `residual` |
| `tokenize`       | `text`, `categories`                                                | `text`, `mapping` (pairs, compared as a set)                                       |
| `detokenize`     | `text`, `mapping`                                                   | `text`, `replacedCount`, `unresolved`                                              |
| `shield`         | `text`, `categories`, `vault` (pairs it starts with)                | `text`, `vault` (every pair afterwards, compared as a set)                         |
| `restore`        | `text`, `vault`                                                     | `text`, `restored`, `unresolved`                                                   |
| `anonymize`      | `text`, and `preset` (names) or `rules`                             | `text`, or `textPattern` when the output is random                                 |
| `preset`         | `names`                                                             | `categories`, `defaultStrategy`, `rules`                                           |
| `canonicalize`   | `value`                                                             | `text`                                                                             |
| `digest`         | `text`                                                              | `hex`: SHA-256 of the UTF-8 encoding                                               |
| `receipt.sign`   | `key`, `body`                                                       | `signature`                                                                        |
| `receipt.verify` | `key`, `receipt`                                                    | `valid`, `reason?`                                                                 |
| `receipt.issue`  | `key`, `text`, `counts`, `presets?`, `timestamp`                    | `receipt`: the listed members; the receipt must verify                             |

The semantics are the reference's:

- **detect** is `detect(text, categories, customDetectors, aggressive)` of `anonyma`. Each
  category's detector runs in the order given; the matches are sorted by start, then by
  confidence, highest first (a stable sort), and a match that starts inside the previous kept one
  is dropped. `strict` replaces the `national-id` detector by its strict variant.
- **scan** is `compilePipeline({ categories, detection, aggressive, minConfidence }).scan(text)`
  of `anonyma/engine`: in precise mode (the default), the precise detectors of `email`, `ssn`,
  `iban`, `ipv4`, `ipv6`, `credit-card` and the strict `national-id`; the legacy detectors
  otherwise. A detection whose value is a redaction label in use (`[REDACTED]`, `REDACTED`, any
  case) is allow-listed. Overlaps are resolved by covering: within a cluster of overlapping
  detections, ordered by confidence, length, start and detector, each one claims the characters no
  stronger one has, and a partly covered one becomes residual spans of its unclaimed parts, trimmed
  of white space.
- **tokenize** is `tokenize(text, { categories, format: "bracket" })`. Tokens are assigned from the
  end of the text backwards, one counter per prefix, and values equal ignoring case share a token.
- **shield** is `tokenize(text, { categories, vault })` with an `InMemoryVault`: brace tokens
  numbered in document order, values compared exactly; a token the vault holds for the same value
  is reused, one it holds for another value is skipped.
- **restore** is `restore(text, vault)`: one left-to-right pass over every brace, bracket or angle
  token, each matched whole (`{{PERSON_1}}` never matches inside `{{PERSON_10}}`); a value is never
  restored again.
- **anonymize** is `anonymize(text, { preset } | { rules })`.
- **preset** is `combinePresets(names)`.
- **canonicalize** is the canonical JSON of the audit log: object members sorted by their names'
  UTF-16 code units, strings escaped as `JSON.stringify` escapes them, no white space. The suite
  uses integers only; other numbers are out of its scope.
- **receipt.sign** is HMAC-SHA-256, keyed with the UTF-8 bytes of `key`, over
  `"anonyma/receipt/v1\u0000"` followed by the canonical JSON of the body, in lower-case hex.
- **receipt.issue** leaves `id` (random), `library` (the implementation's name and version) and
  `signature` out of the comparison; the receipt must verify with the same key.

## Adding a case

1. Add it to `conformance-tests.json` with synthetic data only (`example.com` addresses,
   documentation IP ranges, test card numbers; `npm run check:privacy` checks e-mail addresses).
2. Run the reference: `npm run build && npm test --workspace anonyma-conformance`. A case the
   reference fails is wrong, or has found a bug in the reference.
3. Run the other runners. A case one of them fails is a bug in that implementation, unless the
   case needs a capability it does not claim.
