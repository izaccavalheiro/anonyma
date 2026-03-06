# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-06

### Added

---

#### Core API (`"anonyma"`)

- **`detect(text, categories?, customDetectors?, aggressive?)`** — Scan a string for PII
  and return a sorted, non-overlapping array of `PiiMatch` objects. An optional `categories`
  array restricts scanning to a subset; `customDetectors` override built-in detectors per
  category; `aggressive: true` switches to the expanded `AGGRESSIVE_DETECTOR_REGISTRY`.

- **`anonymize(text, options?)`** — Synchronous detect-and-replace pipeline. Applies the
  configured strategy to every match and returns `{ text, matches }`. Async strategies
  (`hash`, `encrypt`, `tokenize`, `synthesize`) fall back to a safe synchronous substitute
  and emit a `console.warn`; use `anonymizeAsync()` for those strategies.

- **`anonymizeAsync(text, options?)`** — Fully async variant of `anonymize()`. Supports all
  eight strategies natively, including `hash` (SHA-256), `encrypt` (AES-GCM), `tokenize`,
  and `synthesize`.

- **`anonymizeRecord(record, rules)`** — Field-level anonymization of plain objects. `rules`
  is a `FieldRuleMap` keyed by dot-notation paths (e.g. `"user.email"`); only the specified
  fields are processed and the rest of the object is cloned unchanged.

- **`anonymizeObject<T>(obj, options?)`** — Deep recursive anonymization of any
  JSON-serializable object tree. Walks arrays, nested objects, and mixed structures;
  all string leaves are passed through the full `anonymize()` pipeline. Returns a deep
  clone — the original is never mutated. Detects circular references and throws
  `ValidationError` with a clear message.

- **`hasPII(text, categories?, customDetectors?)`** — Boolean check for PII presence.
  Uses an early-exit optimisation: scanning stops immediately after the first detector
  returns a match, making this significantly faster than a full `detect()` call when
  the answer is `true`.

- **`createAnonymizer(config?)`** — Factory that produces a reusable `Anonymizer` instance
  with built-in configuration. Returned instances expose `anonymize()`, `anonymizeAsync()`,
  `detect()`, `anonymizeRecord()`, `anonymizeObject()`, `tokenize()`, and `hasPII()` — all
  pre-bound to the factory config and accepting per-call overrides.

---

#### Reversible Tokenization (`"anonyma"`)

- **`tokenize(text, options?)`** — Replace all detected PII with opaque, reversible tokens
  (`[EMAIL_0001]`, `[PHONE_0001]`, etc.). Returns `{ text, mapping, tokens }` where
  `mapping` is a `Map<token, originalValue>`. Supports `angle`, `bracket`, and `custom`
  token formats; a `tokenTemplate` function can fully control the token shape.

- **`tokenizeAsync(text, options?)`** — Async variant of `tokenize()`.

- **`detokenize(text, mapping)`** — Restore a tokenized string. Returns
  `{ text, replacedCount, unresolved }` — tokens absent from the mapping are left
  unchanged and listed in `unresolved` so callers can detect data loss.

---

#### LLM Pipeline Helpers (`"anonyma"`)

- **`sanitizeForLLM(text, options?)`** — Convenience wrapper around `tokenize()` with
  defaults tuned for large-language-model use (`format: "bracket"`, aggressive mode off
  to minimise false-positive noise in prompts). Returns a `TokenizeResult`; pass the
  `mapping` to `restoreFromLLM()`.

- **`restoreFromLLM(response, mapping)`** — Swap tokens back into the LLM's response text.
  Tokens use a safe character set (`[CATEGORY_NNNN]`) that language models rarely
  re-format, maximising round-trip fidelity.

---

#### Batch Processing (`"anonyma"`)

- **`anonymizeBatch(texts, options?)`** — Synchronously anonymize an array of strings.
  Each item is processed independently; a failure in one item does not abort the rest.
  Returns `BatchResult<AnonymizeResult>[]` with per-item `ok` / `error` discriminant.

- **`anonymizeBatchAsync(texts, options?, concurrency?)`** — Async batch anonymization.
  Items run in parallel via `Promise.allSettled`. An optional `concurrency` cap limits
  simultaneous in-flight items, controlling memory pressure for large datasets.

- **`tokenizeBatch(texts, options?)`** — Batch tokenization. Each item receives its own
  independent token counter sequence (tokens do not cross item boundaries).

- **`detectBatch(texts, categories?)`** — Batch PII detection. Returns
  `BatchResult<PiiMatch[]>[]`.

---

#### Compliance Presets (`"anonyma"`)

- **`getPreset(name)`** — Retrieve a `PresetConfig` by name. Throws `PresetNotFoundError`
  for unknown names.

- **`PRESET_REGISTRY`** — Read-only map of all six built-in presets keyed by name.

Six presets are available out of the box, each pre-configuring `enabledCategories` and
`defaultStrategy`:

| Preset | Default Strategy | Coverage |
|---|---|---|
| `"gdpr"` | `pseudonymize` | All personal data categories defined by the EU GDPR. |
| `"hipaa"` | `redact` | All 18 HIPAA Safe Harbor identifiers for PHI de-identification. |
| `"ccpa"` | `redact` | Consumer data categories defined by the California Consumer Privacy Act. |
| `"pci-dss"` | `redact` (card numbers: `mask` keepTrailing 4) | Cardholder and sensitive authentication data per PCI-DSS. |
| `"sox"` | `redact` | Financial records and corporate officer identifiers for SOX audit trails. |
| `"ferpa"` | `redact` | Student education records as defined by FERPA. |

---

#### Anonymization Strategies (`"anonyma"`)

Eight strategies are available. The first five are synchronous; the final three require
`anonymizeAsync()` (or the dedicated `encrypt`/`hash`/`synthesize` functions):

- **`mask(value, options?)`** — Replace inner characters with a mask character (default
  `"*"`). Options: `keepLeading`, `keepTrailing` (characters to leave visible),
  `maskChar` (single character), and `preserveFormat` (format-preserving masking: letters
  become `X`, digits become `0`, separators are preserved — e.g. `123-45-6789` →
  `000-00-0000`).

- **`redact(value, options?)`** — Replace the entire value with a configurable label.
  Default label: `[REDACTED]`.

- **`pseudonymize(value, options?)`** — Replace with a deterministic pseudo-identifier.
  When a `seed` is supplied, the same `(value, seed)` pair always produces the same
  pseudonym, enabling consistent replacement across a dataset. Without a seed, a random
  pseudonym is generated. A custom `prefix` (default `"id_"`) is prepended.

- **`generalize(value, options?)`** — Replace a numeric value with a bucket range.
  Default `bucketSize` of `10` turns `27` into `"20-29"`. Useful for age or year fields
  where relative ranges retain analytical utility.

- **`hash(value, options?)`** — Async SHA-256 hash (requires Web Crypto / Node ≥ 18).
  Options: `truncate` (number of hex characters to keep, default `16`) and `pepper`
  (a per-deployment secret mixed into the hash to prevent rainbow-table reversal).

- **`encrypt(value, options)` / `decrypt(ciphertext, options)`** — Async AES-256-GCM
  encryption (requires Web Crypto / Node ≥ 18). Provide either a `passphrase` (key
  derived via PBKDF2 + SHA-256, 100,000 iterations) or raw `keyBytes` (16 or 32 bytes
  for AES-128/256). Output format: `"<encoding>:<iv>:<ciphertext>"` where both IV and
  payload are encoded as `base64` (default) or `hex`. Also exported from the dedicated
  `"anonyma/crypto"` subpath.

- **`synthesize(value, options?)`** — Replace PII with structurally valid, format-
  preserving synthetic data. The generator is deterministic: the same `(value, seed)`
  pair always yields the same synthetic stand-in, preserving referential integrity across
  a dataset without retaining real PII. Synthetic generators are built in for `email`,
  `phone`, `ssn`, `credit-card`, `ipv4`, `ipv6`, `url`, `iban`, `date-of-birth`, `name`,
  `address`, `passport`, `drivers-license`, `national-id`, `bank-account`,
  `cryptocurrency`, `tax-id`, `medical-record`, `health-insurance`, `prescription`,
  `api-key`, `social-media`, `vin`, `license-plate`, `tracking-number` and `case-number`.

- **`tokenize` (as a strategy)** — When `strategy: "tokenize"` is supplied in a rule set,
  the value is replaced with a reversible opaque token. This is the same mechanism that
  powers the top-level `tokenize()` function.

---

#### PII Detectors (`"anonyma/detectors"`)

All detectors are pure functions `(text: string) => PiiMatch[]` and can be imported
individually for maximum tree-shaking. Twenty-seven categories are supported.

**Email, Network & Identity**

| Function | Confidence | Notes |
|---|---|---|
| `detectEmail` | 0.99 | RFC 5321 email addresses. |
| `detectEmailAggressive` | 0.75 | Obfuscated formats, e.g. `user [at] example [dot] com`. |
| `detectIpv4` | 0.98 | Dotted-decimal IPv4 with optional CIDR notation. |
| `detectIpv6` | 0.98 | Full and compressed IPv6 addresses. |
| `detectUrl` | 0.95 | http and https URLs with paths, query strings, and fragments. |
| `detectApiKey` | — | Common API key patterns (hex strings, Bearer tokens, `sk-`/`pk-`/`ghp_`-prefixed keys, etc.). |
| `detectSocialMedia` | — | Social media handles (`@username`) and profile URL patterns. |

**Phone & Identity Numbers**

| Function | Confidence | Notes |
|---|---|---|
| `detectPhone` | 0.90 | North American + E.164 international formats. |
| `detectPhoneAggressive` | 0.70 | 7-digit local formats (e.g. `555-1234`). |
| `detectSsn` | 0.95 | US Social Security Numbers with format and known-invalid range exclusions. |
| `detectSsnAggressive` | 0.80 | Expanded SSN pattern set. |

**Financial**

| Function | Confidence | Notes |
|---|---|---|
| `detectCreditCard` | 0.97 | 13–19 digit card numbers validated with the Luhn algorithm. |
| `detectCreditCardAggressive` | 0.80 | Also catches masked formats `****-****-****-1234`. |
| `detectIban` | 0.99 | IBAN strings validated with the ISO 13616 MOD-97 algorithm. |
| `detectBankAccount` | — | Common bank account number formats. |
| `detectCryptocurrency` | — | Bitcoin, Ethereum, and other common cryptocurrency wallet addresses. |
| `detectTaxId` | — | US EIN and common international tax identification number formats. |

**Personal Information**

| Function | Confidence | Notes |
|---|---|---|
| `detectName` | 0.75 | Heuristic: catches names preceded by greeting/salutation keywords (`Dear`, `Hi`, `Hello`, `To`, `From`, `Patient`, `Client`, `Defendant`, etc.). Not an NLP-based named-entity recogniser. |
| `detectNameAggressive` | 0.65 | Extends `detectName` with title-prefix patterns (`Mr.`, `Mrs.`, `Ms.`, `Dr.`, `Prof.`). |
| `detectDateOfBirth` | 0.78–0.88 | ISO 8601, US (`MM/DD/YYYY`), European (`DD/MM/YYYY`), and long-form date patterns. |
| `detectAddress` | — | Multi-line postal address patterns (street number, city, state/zip). |
| `detectPassport` | — | Passport number formats for major issuing countries. |
| `detectDriversLicense` | — | US and international driver's licence number patterns. |
| `detectNationalId` | — | National identity document numbers (SSN-adjacent, Aadhaar, NINO, etc.). |

**Healthcare**

| Function | Notes |
|---|---|
| `detectMedicalRecord` | Medical record number (MRN) patterns. |
| `detectHealthInsurance` | Health insurance member ID and policy number patterns. |
| `detectPrescription` | Prescription and DEA registration number patterns. |

**Vehicles & Transportation**

| Function | Notes |
|---|---|
| `detectVin` | 17-character Vehicle Identification Numbers validated with the ISO 3779 mod-11 checksum. |
| `detectVinAggressive` | Expanded VIN pattern set for partial or obfuscated VINs. |
| `detectLicensePlate` | Common licence plate formats across multiple countries. |
| `detectTrackingNumber` | Shipping tracking numbers (UPS, FedEx, USPS, DHL formats). |

**Government & Legal**

| Function | Notes |
|---|---|
| `detectCaseNumber` | Court case number formats (`YYYY-CV-NNNNN` and variants). |
| `detectCompanyRegistration` | Company registration and incorporation number formats. |

**Registries**

- **`DETECTOR_REGISTRY`** — Pre-assembled `Record<PiiCategory, Detector>` using all
  standard-confidence detectors. Keyed by `PiiCategory`.

- **`AGGRESSIVE_DETECTOR_REGISTRY`** — Pre-assembled registry using every available
  aggressive variant in place of its standard counterpart. Enables detection of
  obfuscated or partial PII at the cost of a higher false-positive rate.

---

#### `AnonymizeOptions` Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `rules` | `AnonymizationRule[]` | `[]` | Per-category strategy overrides. When non-empty, only listed categories are scanned. |
| `defaultStrategy` | `StrategyOptions` | `{ strategy: "redact" }` | Strategy applied to any category not covered by `rules`. |
| `includeMatches` | `boolean` | `false` | Include the `PiiMatch` array in the result. |
| `customDetectors` | `Partial<Record<PiiCategory, Detector>>` | — | Replace built-in detectors on a per-category basis. |
| `customPatterns` | `CustomPattern[]` | — | Ad-hoc `RegExp` patterns merged into the detection pipeline. Matches participate in standard overlap deduplication. |
| `globalReplacement` | `string` | — | Replace every detected entity with this exact string, overriding all strategy settings. |
| `consistentTokens` | `boolean` | `false` | Map repeated identical PII values to the same token within a single call (e.g. `EMAIL_1`, `EMAIL_1` for the same address appearing twice). Different values get different counters. |
| `aggressive` | `boolean` | `false` | Switch to `AGGRESSIVE_DETECTOR_REGISTRY` for all built-in categories. |
| `enabledCategories` | `Partial<Record<PiiCategory, boolean>>` | — | Convenience boolean map. Only categories set to `true` are active; `rules` takes precedence for categories it covers. |
| `allowlist` | `string[]` | `[]` | Exact values to never anonymize (case-insensitive by default). |
| `allowlistPatterns` | `RegExp[]` | `[]` | Regular expressions matched against detected values; matches are skipped. |
| `allowlistCaseSensitive` | `boolean` | `false` | Make `allowlist` string matching case-sensitive. |
| `confidenceThreshold` | `number` | `0` | Minimum confidence score `[0, 1]` for a match to be anonymized. |
| `preset` | `CompliancePreset` | — | Apply a compliance preset as the base configuration. Explicit `rules` and `defaultStrategy` take precedence. |
| `locales` | `Locale[]` | `["global"]` | Activate locale-specific detector patterns. Values: `"global"`, `"us"`, `"uk"`, `"eu"`, `"ca"`, `"au"`, `"br"`, `"in"`, `"cn"`, `"jp"`, `"kr"`, `"za"`. |

---

#### Error Classes (`"anonyma"`)

All errors extend `AnonymaError` and carry a machine-readable `code` string, enabling
precise `switch`/`instanceof` error handling.

| Class | Code | Extra Properties | When Thrown |
|---|---|---|---|
| `AnonymaError` | — | `code: string` | Base class; never thrown directly. |
| `ValidationError` | `VALIDATION_ERROR` | `field: string` | A function argument fails validation (wrong type, out-of-range value, etc.). |
| `UnsupportedStrategyError` | `UNSUPPORTED_STRATEGY` | `strategy: string` | An unrecognised strategy name is passed. |
| `UnknownCategoryError` | `UNKNOWN_CATEGORY` | `category: string` | A rule or config references an unknown PII category. |
| `CryptoNotAvailableError` | `CRYPTO_NOT_AVAILABLE` | — | `globalThis.crypto.subtle` is absent (Node < 18 or no polyfill). |
| `EncryptionError` | `ENCRYPTION_ERROR` | `operation: "encrypt" \| "decrypt"` | The underlying AES-GCM operation fails (wrong key, corrupt ciphertext, etc.). |
| `PresetNotFoundError` | `PRESET_NOT_FOUND` | `preset: string` | `getPreset()` is called with an unknown preset name. |
| `AllowlistMatchError` | `ALLOWLIST_MATCH_ERROR` | `field: string` | An allowlist configuration entry is malformed. |
| `BatchProcessingError` | `BATCH_PROCESSING_ERROR` | `succeeded`, `failed`, `total: number` | One or more items in a batch fail; carries partial result counts. |

---

#### Streaming API (`"anonyma/stream"`)

Requires the WHATWG Streams API: Node.js ≥ 18 (native global `TransformStream`) or a
browser with Streams API support. Throws `ValidationError` if `TransformStream` is
unavailable.

- **`createAnonymizeStream(options?)`** — Returns a `TransformStream<string, AnonymizeResult>`
  that anonymizes each string chunk synchronously. Input chunks must be complete strings
  (e.g. individual lines); partial-chunk reassembly is the caller's responsibility.

- **`createAnonymizeStreamAsync(options?)`** — Async variant that uses `anonymizeAsync()`
  internally. Supports `hash`, `encrypt`, and all other async strategies within a stream
  pipeline.

- **`createTokenizeStream(options?)`** — Returns a `TransformStream<string, TokenizeResult>`
  that tokenizes each chunk independently. Each chunk receives its own token counter
  sequence; for a shared token map across chunks, manage tokenization externally.

---

#### Checksum Validators (`"anonyma/validators"`)

Pure validation functions for PII checksum and format algorithms. All accept a string and
return `boolean`.

| Function | Algorithm / Standard | Notes |
|---|---|---|
| `luhn(digits)` | Luhn (ISO/IEC 7812) | Credit/debit card numbers and some national IDs. |
| `verhoeff(digits)` | Verhoeff | Indian Aadhaar numbers and some other national IDs. |
| `nhsMod11(value)` | NHS mod-11 | UK NHS 10-digit numbers (with or without spaces/hyphens). |
| `cpfChecksum(value)` | Brazilian CPF | 11-digit CPF with two check digits; rejects all-same-digit sequences. |
| `vinChecksum(vin)` | ISO 3779 mod-11 | 17-character Vehicle Identification Numbers. |
| `deaChecksum(value)` | DEA mod-10 | US Drug Enforcement Administration registration numbers. |
| `ibanMod97(value)` | ISO 13616 mod-97 | IBAN strings (15–34 characters, with or without spaces). |
| `ninoValid(value)` | UK NINO format | UK National Insurance Numbers; rejects invalid letter prefixes. |
| `aadhaarFormat(value)` | Aadhaar format | 12-digit Indian Aadhaar; does not start with `0` or `1`. |

---

#### Encryption Utilities (`"anonyma/crypto"`)

Standalone re-export of the AES-GCM primitives for callers that need raw
encrypt/decrypt access without the full anonymization pipeline.

- **`encrypt(value, options)`** — AES-256-GCM encryption. Accepts `passphrase` (PBKDF2-
  derived, `anonyma_kdf_v1` salt, 100,000 iterations) or raw `keyBytes` (16 or 32
  bytes). Output: `"<encoding>:<iv>:<ciphertext>"` (`base64` or `hex`).
- **`decrypt(ciphertext, options)`** — Decrypts a value produced by `encrypt()`. Must use
  the same `passphrase` or `keyBytes`.
- **`EncryptOptions`** type is also exported from this subpath.

---

#### Zod Schemas & AI / MCP Definitions (`"anonyma/schemas"`)

Requires `zod` as a peer dependency. Import from `"anonyma/schemas"`.

**Zod Schemas**

| Export | Validates |
|---|---|
| `PiiCategorySchema` | All 27 `PiiCategory` string literals. |
| `MaskOptionsSchema` | `MaskOptions` including `maskChar`, `keepLeading`, `keepTrailing`. |
| `RedactOptionsSchema` | `RedactOptions` with `label`. |
| `PseudonymizeOptionsSchema` | `PseudonymizeOptions` with `seed` and `prefix`. |
| `HashOptionsSchema` | `HashOptions` with `truncate` and `pepper`. |
| `GeneralizeOptionsSchema` | `GeneralizeOptions` with `bucketSize`. |
| `StrategyOptionsSchema` | Discriminated union of all strategy option shapes. |
| `PiiMatchSchema` | `PiiMatch` output object. |
| `AnonymizeResultSchema` | `AnonymizeResult` with `text` and `matches`. |
| `AnonymizationRuleSchema` | Single `{ category, strategy }` rule. |
| `CustomPatternSchema` | `CustomPattern` with `pattern` (RegExp instance), `category`, `confidence`, `label`. |
| `AnonymizeOptionsSchema` | Full `AnonymizeOptions` input object. |
| `FieldRuleSchema` | Single field-level `{ strategy }` rule. |
| `FieldRuleMapSchema` | `Record<string, FieldRule>` for `anonymizeRecord()`. |

**OpenAI / MCP Tool Definitions**

Pre-built `OpenAiFunctionDefinition` objects ready to pass to the OpenAI client's
`tools` array or an MCP server's tool registry:

- **`ANONYMIZE_TOOL_DEFINITION`** — Function definition for `anonymize()`.
- **`DETECT_TOOL_DEFINITION`** — Function definition for `detect()`.
- **`HAS_PII_TOOL_DEFINITION`** — Function definition for `hasPII()`.
- **`ANONYMIZE_OBJECT_TOOL_DEFINITION`** — Function definition for `anonymizeObject()`.

**Capability Manifest**

- **`ANONYMA_MANIFEST`** — Machine-readable `as const` object describing all capabilities,
  supported categories, strategy descriptions, and option keys. Intended for inclusion in
  AI agent system prompts so models can self-discover available tools.

**Inferred TypeScript Types**

All Zod schema input/output types are re-exported as TypeScript types:
`PiiCategoryInput`, `StrategyOptionsInput`, `AnonymizeOptionsInput`,
`AnonymizationRuleInput`, `CustomPatternInput`, `PiiMatchOutput`,
`AnonymizeResultOutput`, `FieldRuleInput`, `FieldRuleMapInput`.

---

#### TypeScript Types (`"anonyma"`)

All types are zero-cost, type-only exports (stripped by `tsc`; no runtime overhead).

| Type | Description |
|---|---|
| `PiiCategory` | Union of all 27 supported category string literals. |
| `PiiMatch` | `{ category, value, start, end, confidence }` — a single detected PII entity. |
| `CustomPattern` | `{ pattern: RegExp; category?; confidence?; label? }` — ad-hoc detection pattern. |
| `Locale` | `"global" \| "us" \| "uk" \| "eu" \| "ca" \| "au" \| "br" \| "in" \| "cn" \| "jp" \| "kr" \| "za"` |
| `CompliancePreset` | `"gdpr" \| "hipaa" \| "ccpa" \| "pci-dss" \| "sox" \| "ferpa"` |
| `StrategyName` | `"mask" \| "redact" \| "pseudonymize" \| "hash" \| "generalize" \| "tokenize" \| "encrypt" \| "synthesize"` |
| `StrategyOptions` | Discriminated union of all per-strategy option shapes. |
| `MaskOptions` | `{ maskChar?, keepLeading?, keepTrailing?, preserveFormat? }` |
| `RedactOptions` | `{ label? }` |
| `PseudonymizeOptions` | `{ seed?, prefix? }` |
| `HashOptions` | `{ truncate?, pepper? }` |
| `GeneralizeOptions` | `{ bucketSize? }` |
| `EncryptOptions` | `{ passphrase?, keyBytes?, encoding? }` |
| `SynthesizeOptions` | `{ seed?, locale? }` |
| `AnonymizationRule` | `{ category: PiiCategory, strategy: StrategyOptions }` |
| `AnonymizeOptions` | Full options accepted by `anonymize()` and `anonymizeAsync()`. |
| `AnonymizeResult` | `{ text: string, matches: ReadonlyArray<PiiMatch> }` |
| `TokenFormat` | `"angle" \| "bracket" \| "custom"` |
| `TokenizeOptions` | Options for `tokenize()` including `categories`, `format`, `tokenTemplate`, `deterministic`, `aggressive`, `locales`, `confidenceThreshold`, `allowlist`. |
| `TokenizeResult` | `{ text, mapping: ReadonlyMap<string, string>, tokens: TokenMatch[] }` |
| `DetokenizeResult` | `{ text, replacedCount, unresolved: string[] }` |
| `TokenMatch` | `{ token, original, category, start, end }` |
| `BatchResult<T>` | Discriminated union: `{ index, ok: true, value: T } \| { index, ok: false, error: Error }` |
| `FieldRule` | `{ strategy: StrategyOptions }` |
| `FieldRuleMap` | `Record<string, FieldRule>` — dot-notation paths for `anonymizeRecord()`. |
| `Detector` | `(text: string) => PiiMatch[]` — detector function signature. |
| `DetectorRegistry` | `Record<PiiCategory, Detector>` |
| `Anonymizer` | Interface returned by `createAnonymizer()`. |
| `AnonymizerConfig` | Config accepted by `createAnonymizer()`. |
| `AnonymaPlugin` | `{ name, detectors?, strategies?, validators? }` — plugin extension point. |
| `ValidatorFunction` | `(value: string) => boolean` |
| `StrategyFunction` | `(value: string, options?) => string` |
| `PresetConfig` | Full configuration shape for a compliance preset. |

---

#### Package & Infrastructure

- **Dual ESM + CJS output** via `tsup` with `sideEffects: false` for full tree-shaking
  support in all bundlers.
- **Full TypeScript declarations** — `.d.ts` + `.d.cts` files generated for every subpath.
- **Six subpath exports**: `"anonyma"`, `"anonyma/detectors"`, `"anonyma/schemas"`,
  `"anonyma/validators"`, `"anonyma/crypto"`, `"anonyma/stream"`.
- **Zero runtime dependencies** — the main package and all subpaths except
  `"anonyma/schemas"` have no external dependencies. `"anonyma/schemas"` requires `zod`
  as a peer dependency.
- **GitHub Actions CI** — lint (`eslint`), typecheck (`tsc --noEmit`), test, and build
  on Node.js 18, 20, and 22.
- **GitHub Actions Release** — automated npm publish with provenance on version tag push.
- **Vitest** test suite with ≥ 90% coverage target across statements, branches, and
  functions.
- **ESLint flat config (v9)** with strict TypeScript rules.
- **Prettier** code formatting.
- **MIT License**.

[1.0.0]: https://github.com/izaccavalheiro/anonyma/releases/tag/v1.0.0
