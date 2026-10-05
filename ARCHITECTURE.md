# ARCHITECTURE.md — anonyma System Architecture

> A deep-dive into the design decisions, module boundaries, data flows, and extension points of the **anonyma** library.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [High-Level Module Map](#2-high-level-module-map)
3. [Core Data Flow](#3-core-data-flow)
4. [Module Responsibilities](#4-module-responsibilities)
   - 4.1 [types.ts — The Type Layer](#41-typests--the-type-layer)
   - 4.2 [errors.ts — Error Hierarchy](#42-errorsts--error-hierarchy)
   - 4.3 [detectors/ — Detection Layer](#43-detectors--detection-layer)
   - 4.4 [strategies/ — Transformation Layer](#44-strategies--transformation-layer)
   - 4.5 [anonymize.ts — Core Engine](#45-anonymizets--core-engine)
   - 4.6 [tokenize.ts — Reversible Tokenization](#46-tokenizets--reversible-tokenization)
   - 4.7 [llm.ts — LLM Pipeline Helpers](#47-llmts--llm-pipeline-helpers)
   - 4.8 [batch.ts — Batch Processing](#48-batchts--batch-processing)
   - 4.9 [presets.ts — Compliance Presets](#49-presetsts--compliance-presets)
   - 4.10 [stream.ts — WHATWG Streaming](#410-streamts--whatwg-streaming)
   - 4.11 [validators.ts — Checksum Validators](#411-validatorsts--checksum-validators)
   - 4.12 [crypto.ts — Web Crypto Helpers](#412-cryptots--web-crypto-helpers)
   - 4.13 [schemas.ts — Zod Schemas & AI Definitions](#413-schematsts--zod-schemas--ai-definitions)
   - 4.14 [index.ts — Public API Barrel](#414-indexts--public-api-barrel)
   - 4.15 [engine/ — Span Engine](#415-engine--span-engine)
   - 4.16 [vault/ — Tokenization and Key Management](#416-vault--tokenization-and-key-management)
   - 4.17 [audit/ — Audit Log](#417-audit--audit-log)
   - 4.18 [compliance/ — Regulations and Policies](#418-compliance--regulations-and-policies)
   - 4.19 [ai/ — LLM and JSON Sanitization](#419-ai--llm-and-json-sanitization)
   - 4.20 [mcp/ — Model Context Protocol](#420-mcp--model-context-protocol)
   - 4.21 [middleware/ — HTTP Payload Scrubbing](#421-middleware--http-payload-scrubbing)
   - 4.22 [internal/ — Shared Helpers](#422-internal--shared-helpers)
5. [Detector Architecture](#5-detector-architecture)
6. [Strategy Architecture](#6-strategy-architecture)
7. [Anonymization Engine Deep-Dive](#7-anonymization-engine-deep-dive)
8. [Tokenization and Detokenization Flow](#8-tokenization-and-detokenization-flow)
9. [LLM Pipeline Integration Pattern](#9-llm-pipeline-integration-pattern)
10. [Compliance Preset System](#10-compliance-preset-system)
11. [Plugin Architecture](#11-plugin-architecture)
12. [Build System & Package Outputs](#12-build-system--package-outputs)
13. [Test Architecture](#13-test-architecture)
14. [Security Architecture](#14-security-architecture)
15. [Performance Characteristics](#15-performance-characteristics)
16. [Extension Points](#16-extension-points)

---

## 1. Design Philosophy

anonyma is built around six principles:

| Principle                         | Manifestation                                                                                                                                                                |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Zero runtime dependencies**     | `package.json` has an empty `dependencies` object; `zod` is a peer/optional                                                                                                  |
| **Strict type safety**            | `tsconfig.json` enables every strict flag + `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`                                                                         |
| **Pure, deterministic functions** | Detectors and most strategies are pure functions; async is confined to cryptographic operations                                                                              |
| **Tree-shakeable by design**      | Each detector and strategy is a standalone module; the barrel re-exports but does not merge namespaces                                                                       |
| **Separation of concerns**        | Detection (`detectors/`), transformation (`strategies/`), orchestration (`anonymize.ts`), and I/O (`stream.ts`, `batch.ts`) are fully decoupled                              |
| **Fail closed**                   | A built-in replacer redacts a value its strategy would leave unchanged; a synchronous transform throws on an asynchronous replacer; the audit logger stops when a sink fails |

---

## 2. High-Level Module Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Public API (index.ts)                        │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ re-exports
          ┌──────────────────────┼──────────────────────┐
          │                      │                       │
   ┌──────▼───────┐    ┌─────────▼────────┐    ┌────────▼────────┐
   │  anonymize.ts │    │   tokenize.ts    │    │    batch.ts     │
   │  (core engine)│    │  (reversible tok)│    │ (bulk processing│
   └──────┬───────┘    └─────────┬────────┘    └────────┬────────┘
          │                      │                       │
   ┌──────┴───────┐    ┌─────────┴────────┐             │
   │  detectors/  │    │    llm.ts        │             │
   │  (27 modules)│    │ (sanitize/restore│             │
   └──────┬───────┘    └─────────┬────────┘             │
          │                      │                       │
   ┌──────┴───────┐    ┌─────────┴────────┐    ┌────────┴────────┐
   │  strategies/ │    │   presets.ts     │    │   stream.ts     │
   │  (8 modules) │    │ (GDPR,HIPAA,...) │    │ (TransformStream│
   └──────┬───────┘    └──────────────────┘    └─────────────────┘
          │
   ┌──────┴───────────────────────────────────┐
   │            Support Modules               │
   │  types.ts · errors.ts · validators.ts    │
   │  crypto.ts · schemas.ts                  │
   └──────────────────────────────────────────┘
```

The subpath modules added in 1.1 form layers on top of this core. At runtime, a module uses
modules of its own layer or of the layers below, never of a layer above:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Integrations  middleware/   HTTP scrubbing: Fetch, Express, Hono         │
│               mcp/          Model Context Protocol server and tools      │
│               ai/           LLM guard, JSON sanitizer, stream restoring  │
├──────────────────────────────────────────────────────────────────────────┤
│ Services      vault/        tokenizers, key ring, token vault, rotation  │
│               audit/        hash-chained audit log without personal data │
│               compliance/   regulation profiles, policies, erasure       │
├──────────────────────────────────────────────────────────────────────────┤
│ Span engine   engine/       span detectors, overlap resolution,          │
│                             replacers, pipelines, chunk-safe streams     │
├──────────────────────────────────────────────────────────────────────────┤
│ 1.x core      detectors/ · strategies/ · presets.ts · validators.ts      │
└──────────────────────────────────────────────────────────────────────────┘
  internal/  Web Crypto lookup, byte encodings, lossless JSON numbers and allowlist matching, for every layer
```

The 1.x core does not depend on the subpath modules; only `errors.ts` imports a type from
`compliance/`. `engine/` and `vault/` share types and nothing else: the engine calls a
`TokenizationProvider` for the `tokenize` strategy, and the vault's tokenizers implement it.

---

## 3. Core Data Flow

### Synchronous anonymization (`anonymize`)

```
Input string
    │
    ▼
  detect()  ──────────────────────────────────────────────────────────────┐
    │  for each enabled PiiCategory:                                       │
    │    detector(text) → PiiMatch[]                                       │
    │  merge custom pattern matches                                        │
    │  apply confidence threshold filter                                   │
    │  apply allowlist filter                                              │
    │  sort + deduplicate (remove overlapping matches)                     │
    └──────────────────────────────────────────────────────────────────────┘
    │
    ▼
  resolveStrategy() ← AnonymizeOptions (preset, per-category rules, default)
    │  walk PiiMatch[] in reverse-index order
    │  call applyStrategy(match.value, strategyOptions) → replacement string
    │  splice replacement into text
    │
    ▼
 AnonymizeResult { text: string, matches: PiiMatch[] }
```

### Async anonymization (`anonymizeAsync`)

Same flow, except that a `hash` rule is awaited and produces a SHA-256 digest. Like `anonymize()`,
`anonymizeAsync()` redacts a value whose rule is `tokenize`, `encrypt` or `synthesize`, and prints a
warning; the span engine applies those strategies.

### Span engine (`pipeline.transform`)

```
Input string
    │
    ▼
  for each detector (skipped when its prefilter rules the text out):
    detector.scan(text, emit) → (start, end, confidence) hits, in any order
    │  drop hits below minConfidence
    │  mark hits matched by an allow rule: they take part in resolution, then stay untouched
    ▼
  resolveSpans(candidates, overlap)
    │  "cover" (default): accept by confidence, then length, then position, then detector
    │                     order; keep the uncovered parts of a losing hit as residual spans,
    │                     so no detected character is left in the output
    │  "legacy": the 1.x rule — the earliest start wins, losing hits are dropped
    ▼
  replacer per category (or the fallback), called in document order
    │  built-in replacers redact a value their strategy would leave unchanged
    │  transform(): a replacer that returns a promise → AsyncStrategyError
    │  transformAsync(): replacers awaited one at a time
    ▼
  one left-to-right pass assembles the output
    │
    ▼
 TransformResult { text, spans }   spans carry offsets and categories, never the matched text
```

`createChunkTransformer()` and `createPipelineStream()` run a pipeline over text that arrives in
chunks. They hold back the last `window` characters (by default the largest `maxMatchLength` of
the pipeline's detectors, or 256) and rescan them with left context, so that a value split across
chunks is replaced as if the text had arrived whole. An unbroken run of printable ASCII characters
of up to `tokenLimit` characters — a key, a token, a URL — is held back until it ends.

---

## 4. Module Responsibilities

### 4.1 `types.ts` — The Type Layer

Contains **only** TypeScript `interface`, `type`, and `enum` declarations. Zero runtime code. Because it is type-only, it is excluded from Vitest coverage and tree-shaken entirely from distribution builds.

Key types:

- `PiiCategory` — discriminated union of all 27 category string literals
- `PiiMatch` — readonly struct: `{ category, value, start, end, confidence }`
- `AnonymizeOptions` — full configuration surface for the core engine
- `AnonymizeResult` — `{ text, matches }`
- `StrategyOptions` — union of all per-strategy option objects
- `AnonymizationRule` — `{ category, strategy: StrategyOptions }`
- `Detector` / `DetectorRegistry` — function signatures for custom detectors
- `AnonymaPlugin` — hook interface for extending detectors, strategies, validators

### 4.2 `errors.ts` — Error Hierarchy

All library exceptions extend `AnonymaError` allowing callers to use a single `instanceof AnonymaError` guard:

```
AnonymaError (base)
├── ValidationError          (invalid arguments — carries field name)
├── UnsupportedStrategyError (unknown strategy name — carries strategy)
├── UnknownCategoryError     (unknown PII category — carries category)
├── CryptoNotAvailableError  (Web Crypto API absent)
├── EncryptionError          (AES-GCM operation failure)
├── PresetNotFoundError      (unknown preset name — carries preset)
├── AllowlistMatchError      (value matched allowlist — internal, not thrown publicly)
├── BatchProcessingError     (batch-level failure — carries index + cause)
├── AsyncStrategyError       (synchronous transform met an asynchronous replacer — carries category)
├── KeyManagementError       (unknown, destroyed or malformed key version — carries keyId)
├── TokenVaultError          (vault operation failed or would corrupt the vault)
├── PolicyError              (policy document rejected — carries every issue)
└── AuditIntegrityError      (audit chain cannot be extended or does not verify)
```

Every class is exported from `"anonyma"`. Because the build emits shared code once (see
[Build System](#12-build-system--package-outputs)), an error thrown by a subpath is an instance of
the class exported there.

Every error class calls `Object.setPrototypeOf(this, new.target.prototype)` to maintain correct prototype chains in transpiled environments.

### 4.3 `detectors/` — Detection Layer

Each file in `src/detectors/` is responsible for **one PII category**. The file exports:

- `detect<Category>(text: string): PiiMatch[]` — standard precision patterns
- `detect<Category>Aggressive(text: string): PiiMatch[]` — expanded, more permissive patterns (where applicable)

Detectors are **pure functions**: they accept a string, apply one or more `RegExp` patterns, and return an array of `PiiMatch` objects. They do not call external services, mutate state, or throw.

The `detectors/index.ts` barrel assembles two registries:

- `DETECTOR_REGISTRY: Record<PiiCategory, Detector>` — standard mode
- `AGGRESSIVE_DETECTOR_REGISTRY: Record<PiiCategory, Detector>` — aggressive mode

### 4.4 `strategies/` — Transformation Layer

Each file in `src/strategies/` implements one anonymization algorithm:

| File              | Strategy                                            | Sync     | Reversible |
| ----------------- | --------------------------------------------------- | -------- | ---------- |
| `mask.ts`         | Replace interior chars with mask char               | ✅       | ❌         |
| `redact.ts`       | Replace with static label e.g. `[REDACTED]`         | ✅       | ❌         |
| `pseudonymize.ts` | Deterministic seeded fake identifier                | ✅       | ❌         |
| `hash.ts`         | SHA-256 digest with optional pepper                 | ❌ async | ❌         |
| `generalize.ts`   | Range/bucket generalization (ages, dates)           | ✅       | ❌         |
| `encrypt.ts`      | AES-256-GCM via Web Crypto API                      | ❌ async | ✅         |
| `synthesize.ts`   | Format-preserving synthetic data replacement        | ✅       | ❌         |
| `tokenize.ts`     | Internal token store (used by `tokenize.ts` module) | ✅       | ✅         |

`encrypt.ts` uses **PBKDF2 + SHA-256** (100,000 iterations) for passphrase-based key derivation, or imports raw 16/32-byte keys directly. Output format: `"<encoding>:<iv_hex_or_b64>:<ciphertext>"`.

### 4.5 `anonymize.ts` — Core Engine

The largest and most complex module. Responsibilities:

- `detect()` — multi-category scan with allowlist, confidence filtering, overlap deduplication
- `anonymize()` — sync orchestration
- `anonymizeAsync()` — async orchestration (adds `hash`; `tokenize`, `encrypt` and `synthesize` are redacted, as in `anonymize()`)
- `anonymizeRecord()` — field-level anonymization of plain objects using dot-notation paths
- `anonymizeObject()` — deep recursive anonymization of arbitrary JSON trees
- `hasPII()` — optimised early-exit boolean scan
- `createAnonymizer()` — factory that closes over a reusable `AnonymizerConfig`

Internal overlap resolution: matches are sorted by `start` index, ties going to the higher confidence, then iterated. When a match's start index is inside the last consumed region, it is skipped (first wins).

### 4.6 `tokenize.ts` — Reversible Tokenization

Wraps `detect()` + the internal token store to produce a `TokenizeResult`:

```ts
{ text: string, mapping: ReadonlyMap<string, string> }
```

The `mapping` maps every token string (e.g. `"[EMAIL_0001]"`) back to the original PII value. `detokenize()` performs the inverse substitution.

Token formats (controlled by `TokenFormat`):

- `"bracket"` — `[EMAIL_0001]` (default, LLM-safe)
- `"angle"` — `<EMAIL_1>`
- `"custom"` — declared for a `tokenTemplate` function, which `tokenize()` does not apply; it produces the angle format

### 4.7 `llm.ts` — LLM Pipeline Helpers

Thin wrappers around `tokenize()` and `detokenize()` with LLM-optimised defaults (`format: "bracket"`, `aggressive: false`). The bracket format `[CATEGORY_NNNN]` is chosen because large language models rarely re-format content inside square brackets, ensuring token survival through the round-trip.

### 4.8 `batch.ts` — Batch Processing

Processes arrays of strings with per-item error isolation: a failure in item N does not abort items N+1..M. Each result is a discriminated union `{ index, ok: true, value } | { index, ok: false, error }`.

Functions:

- `anonymizeBatch()` — synchronous
- `anonymizeBatchAsync()` — async with `Promise.allSettled` semantics
- `tokenizeBatch()` — synchronous tokenization for all items
- `detectBatch()` — PII detection only for all items

### 4.9 `presets.ts` — Compliance Presets

Eight built-in regulatory presets:

| Preset    | Regulation           | Default Strategy                        | Focus                                               |
| --------- | -------------------- | --------------------------------------- | --------------------------------------------------- |
| `gdpr`    | EU GDPR              | pseudonymize                            | All personal data identifiers                       |
| `lgpd`    | Brazil LGPD          | redact                                  | Personal data, including the CPF                    |
| `pipeda`  | Canada PIPEDA        | redact                                  | Personal information, including the SIN             |
| `hipaa`   | US HIPAA Safe Harbor | redact                                  | The Safe Harbor identifiers detectable in text      |
| `ccpa`    | California CCPA/CPRA | redact                                  | Consumer identifiers, financial and health data     |
| `pci-dss` | PCI DSS v4           | redact; mask (last 4) for card and bank | Cardholder data                                     |
| `sox`     | US Sarbanes-Oxley    | redact                                  | Financial records and corporate officer identifiers |
| `ferpa`   | US FERPA             | redact                                  | Student education records                           |

A preset lists what the library can detect. The regulation profiles in `compliance/` (4.18) record,
for GDPR, LGPD, PIPEDA, CCPA, HIPAA and PCI DSS, the provision behind each category and the data
that no detector covers; a test checks every preset against its profile.

Each `PresetConfig` specifies the activated `categories[]`, a `defaultStrategy`, and optional per-category `rules[]` overrides. Presets are resolved at runtime in `anonymize.ts` via `getPreset()`.

### 4.10 `stream.ts` — WHATWG Streaming

Wraps the core engine in `TransformStream<string, AnonymizeResult>` / `TransformStream<string, TokenizeResult>`. Requires the global `TransformStream` (Node ≥ 18 / browsers). Each chunk is expected to be a complete string (e.g., a line or paragraph). Exported from the `"anonyma/stream"` subpath.

### 4.11 `validators.ts` — Checksum Validators

Stand-alone pure validation algorithms exported from `"anonyma/validators"`:

| Function        | Algorithm           | Used For                        |
| --------------- | ------------------- | ------------------------------- |
| `luhn`          | Luhn (ISO/IEC 7812) | Credit cards, some national IDs |
| `verhoeff`      | Verhoeff            | Indian Aadhaar                  |
| `nhsMod11`      | NHS Mod-11          | UK NHS numbers                  |
| `cpfChecksum`   | CPF                 | Brazilian tax ID                |
| `vinChecksum`   | VIN transliteration | Vehicle Identification Numbers  |
| `deaChecksum`   | DEA Mod-9           | US DEA registration numbers     |
| `ibanMod97`     | IBAN Mod-97         | International bank accounts     |
| `ninoValid`     | NINO format         | UK National Insurance Numbers   |
| `aadhaarFormat` | Verhoeff + format   | Indian Aadhaar (12-digit)       |

These validators are used internally by the corresponding detectors to reduce false positives.

### 4.12 `crypto.ts` — Web Crypto Helpers

Re-exports `encrypt()` and `decrypt()` from `strategies/encrypt.ts` (and the `EncryptOptions` type) under the `"anonyma/crypto"` subpath, for code that needs reversible encryption without the rest of the API.

### 4.13 `schemas.ts` — Zod Schemas & AI Definitions

**Requires `zod` as a peer dependency.** Exported from the `"anonyma/schemas"` subpath to keep the main bundle free of the Zod dependency.

Provides:

- `PiiCategorySchema` — Zod enum for all 27 categories
- `AnonymizeOptionsSchema` — Zod object schema with `.parse()` for runtime validation. It covers `rules`, `defaultStrategy`, `customPatterns`, `enabledCategories`, `globalReplacement`, `consistentTokens`, `aggressive` and `includeMatches`; `.parse()` removes the other options.
- Strategy, rule, match and field-rule schemas
- Function-calling tool definitions in the OpenAI format (`ANONYMIZE_TOOL_DEFINITION`, `DETECT_TOOL_DEFINITION`, `HAS_PII_TOOL_DEFINITION`, `ANONYMIZE_OBJECT_TOOL_DEFINITION`) and the `ANONYMA_MANIFEST` capability description

The Model Context Protocol declarations, with their JSON Schemas, live in `mcp/` (4.20).

### 4.14 `index.ts` — Public API Barrel

The single entry point for `import ... from "anonyma"`. Exports are organized by concern:

1. Core functions (`anonymize`, `detect`, `hasPII`, etc.)
2. Tokenization (`tokenize`, `detokenize`)
3. LLM helpers (`sanitizeForLLM`, `restoreFromLLM`)
4. Batch processing
5. Compliance presets
6. Individual strategies (tree-shakeable)
7. Error classes
8. TypeScript types (type-only `export type`)

### 4.15 `engine/` — Span Engine

Exported as `"anonyma/engine"`. Works on spans — offsets into the scanned text — rather than on
copied substrings. Contracts are in `engine/types.ts`.

| File           | Responsibility                                                                                                                                                                                              |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `detector.ts`  | `defineDetector()`, `defineRegexDetector()` (with prefilter substrings, validation and a maximum match length) and `fromLegacyDetector()` for 1.x `(text) => PiiMatch[]` functions                          |
| `precise.ts`   | Validating detectors for email, US SSN, IBAN, IPv4, IPv6 and payment cards: issuer ranges and Luhn, the ISO 13616 length table and mod-97, SSA allocation rules, the RFC 4291 grammar, look-alike rejection |
| `builtin.ts`   | The 27 1.x detectors as span detectors (`LEGACY_DETECTORS`, `LEGACY_AGGRESSIVE_DETECTORS`, `BUILTIN_CATEGORIES`), each a separate export                                                                    |
| `resolve.ts`   | `resolveSpans()`: the `cover` and `legacy` overlap policies                                                                                                                                                 |
| `pipeline.ts`  | `createPipeline()`: `scan`, `test`, `replace`, `transform`, `transformAsync`                                                                                                                                |
| `replacers.ts` | One factory per strategy (`maskWith()`, `hashWith()`, `encryptWith()`, …), `constant()`, and `strategyReplacer()` for a `StrategySpec`                                                                      |
| `compile.ts`   | `compilePipeline()`: a pipeline from a `PipelineSpec` — plain data, storable in a configuration file — and `CompileDependencies` (tokenization provider, encryption key, peppers and seeds)                 |
| `stream.ts`    | `createChunkTransformer()`, `createAsyncChunkTransformer()` and `createPipelineStream()`                                                                                                                    |

`compilePipeline()` uses the validating detectors by default (`detection: "precise"`) and the 1.x
detectors for the other categories; `detection: "legacy"` uses the 1.x detectors throughout.

### 4.16 `vault/` — Tokenization and Key Management

Exported as `"anonyma/vault"`.

| File              | Responsibility                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `keyring.ts`      | Versioned keys. Each version holds one secret from which purpose-bound, non-extractable keys are derived with HKDF-SHA-256; the manifest is authenticated with HMAC |
| `session.ts`      | `createSessionTokenizer()`: synchronous, in memory, tokens numbered per category (`[EMAIL_0001]`), snapshots to continue a session                                  |
| `keyed.ts`        | `createKeyedTokenizer()`: the token identifier is an HMAC-SHA-256 of category and value; with a vault the value is stored sealed with AES-256-GCM                   |
| `sealed.ts`       | `createSealedTokenizer()`: stateless; the token carries the value sealed with AES-256-GCM under a synthetic IV, so equal values give equal tokens                   |
| `memory-vault.ts` | `createMemoryVault()`: the reference `TokenVault`                                                                                                                   |
| `rotation.ts`     | `rewrapVault()` re-seals every record under the active key version without changing tokens; `shredKey()` destroys a version                                         |
| `restore.ts`      | `restoreTokens()` and `tokenizeWith()`, which connect a provider to text and to the engine                                                                          |

Erasure works per record (`forgetToken()`, `forgetSubject()`) or per key version (`shredKey()`):
without the key, nothing sealed under it can be recovered, not even from a backup of the vault.

### 4.17 `audit/` — Audit Log

Exported as `"anonyma/audit"`. A record describes what was done — fields, categories, detectors,
rules, counts — and has no member for values.

| File           | Responsibility                                                                                                                                       |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `logger.ts`    | `createAuditLogger()`: records sealed in call order, each hash covering the record and its predecessor (an HMAC with a key); stops when a sink fails |
| `canonical.ts` | Canonical JSON and digests, so that equal data always hashes the same; `inputChecksum()`                                                             |
| `fields.ts`    | `summarizeSpans()` and `jsonPointer()`, which turn engine results into field entries                                                                 |
| `sinks.ts`     | `memorySink()`, `lineSink()` and `parseAuditLog()`                                                                                                   |
| `verify.ts`    | `verifyAuditChain()`                                                                                                                                 |

Every caller-supplied string in a record (actor, source, policy reference, path segment, …) also
passes a guard — a pipeline — and is blanked if it looks like personal data.

### 4.18 `compliance/` — Regulations and Policies

Exported as `"anonyma/compliance"`. The profiles describe technical measures; they are not legal
advice.

| File             | Responsibility                                                                                                                                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `regulations.ts` | `REGULATIONS` for GDPR, LGPD, PIPEDA, CCPA/CPRA, HIPAA and PCI DSS: per category the provision and the protection a replacement must give, and the coverage gaps |
| `traits.ts`      | `describeStrategy()` (is a strategy reversible, keyed, deterministic, …) and `checkRequirement()`                                                                |
| `policy.ts`      | `parsePolicy()`: untrusted JSON to a checked `Policy`, or a `PolicyError` listing every issue; `checkPolicy()`, `policyToSpec()`, `regulationPolicy()`           |
| `erasure.ts`     | `planErasure()`: what honouring an erasure request takes, depending on how the data was transformed                                                              |

### 4.19 `ai/` — LLM and JSON Sanitization

Exported as `"anonyma/ai"`. The mapping between tokens and values never leaves the process.

| File         | Responsibility                                                                                                                                                             |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `json.ts`    | `sanitizeJson()` / `sanitizeJsonAsync()`: same nesting and array lengths; strings, long numbers, values under key rules and keys are sanitized; the input is never mutated |
| `guard.ts`   | `createLlmGuard()`: one exchange per model call sanitizes prompts and chat messages and restores the reply; `toLanguageModelMiddleware()` adapts it to the Vercel AI SDK   |
| `restore.ts` | Restoration in streamed output: a trailing fragment that could still become a token is held back; lenses read the text of SDK-specific chunk shapes                        |

### 4.20 `mcp/` — Model Context Protocol

Exported as `"anonyma/mcp"`.

| File             | Responsibility                                                                                                                                                                      |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `definitions.ts` | Tools (`anonyma_detect`, `anonyma_anonymize`, `anonyma_tokenize`, `anonyma_detokenize`, `anonyma_check_policy`), resources and resource templates, with JSON Schema (draft 2020-12) |
| `schema.ts`      | A validator for the subset of JSON Schema the declarations use, so arguments are checked against exactly what is advertised                                                         |
| `server.ts`      | `createMcpServer()`: transport-agnostic `handle()` for one JSON-RPC message; `serveStdio()` for newline-delimited streams                                                           |

Values behind tokens stay in server memory, per session. `anonyma_detokenize` is offered only when
the operator sets `allowDetokenize`, `anonyma_detect` reports positions rather than text, the model
cannot select strategies that need key material, and with an audit logger each call is recorded
without its content.

### 4.21 `middleware/` — HTTP Payload Scrubbing

Exported as `"anonyma/middleware"`, `"anonyma/middleware/express"` and `"anonyma/middleware/hono"`.
`core.ts` holds `createScrubber()`, which sanitizes JSON values, text, bodies by content type and
Fetch API responses, and records what it did in the audit log. `express.ts` and `hono.ts` adapt it;
they are typed against the few members of the request, response and context objects they use, so
neither depends on its framework.

### 4.22 `internal/` — Shared Helpers

Not exported. `webcrypto.ts` finds the Web Crypto API (the global, or `node:crypto` on Node.js 18),
`encoding.ts` converts between bytes and UTF-8, hex, base64url and Crockford base32 without
`Buffer`, and `json-numbers.ts` parses and writes JSON without rounding numbers a JavaScript number
cannot hold. `allowlist.ts` turns the `allowlist` and `allowlistPatterns` options of the 1.x
functions into one predicate: an entry matches a value equal to it, a pattern a value it finds a
match in.

---

## 5. Detector Architecture

### Contract

```ts
type Detector = (text: string) => PiiMatch[];
```

Every detector is:

- **Pure** — no side effects
- **Idempotent** — calling it twice with the same input yields the same result
- **Non-throwing** — errors are suppressed; on malformed regex the function returns `[]`

### Pattern Strategy

Most detectors apply one or more `RegExp` with the `g` flag. The regex is typically anchored with word boundaries (`\b`) or specific delimiters to reduce false positives. Confidence scores are hard-coded per category and variant (e.g., a 16-digit Luhn-valid number gets `0.97`; a 15/16-digit number without Luhn validation gets `0.85`).

### Aggressive Mode

Categories that benefit from broadened detection (email, phone, SSN, credit card, name, VIN) ship both a standard and an aggressive detector. The aggressive variant trades precision for recall — useful when PII may be obfuscated or in non-standard formats.

### Registry Pattern

```ts
const DETECTOR_REGISTRY: Record<PiiCategory, Detector> = {
  email: detectEmail,
  phone: detectPhone,
  // ...
};
```

The engine iterates `Object.entries(DETECTOR_REGISTRY)` filtered by `enabledCategories`. Users can override individual entries via `customDetectors` in `AnonymizeOptions`.

---

## 6. Strategy Architecture

### Sync Strategy Contract

```ts
(value: string, options: StrategyOptions) => string;
```

### Async Strategy Contract

```ts
(value: string, options: StrategyOptions) => Promise<string>;
```

The core engine calls strategies via `applyStrategySync()`, keyed by the `strategy` discriminant on the `StrategyOptions` union; `anonymizeAsync()` awaits `hash` itself. Unknown strategy names throw `UnsupportedStrategyError`. `applyStrategySync()` replaces a `hash` rule with a seeded pseudonym and redacts values whose rule is `tokenize`, `encrypt` or `synthesize`, with a warning. The span engine has a replacer for every strategy (`engine/replacers.ts`).

### Strategy Selection Priority

For any given PII match, the strategy is resolved in this order (highest priority first):

1. Per-match `rules` array entry matching that category
2. Preset-specific per-category rule (if a preset is active)
3. Preset's `defaultStrategy` (if a preset is active)
4. `AnonymizeOptions.defaultStrategy`
5. Built-in fallback: `{ strategy: "redact" }`

---

## 7. Anonymization Engine Deep-Dive

### `detect()` Algorithm

```
1. Build effective detector map:
   a. Start with DETECTOR_REGISTRY (or AGGRESSIVE_DETECTOR_REGISTRY if aggressive=true)
   b. Apply customDetectors overrides
   c. Filter to enabledCategories (if specified)

2. For each active detector:
   a. Run detector(text) → raw PiiMatch[]
   b. Filter: match.confidence >= threshold (default 0)
   c. Filter: match.value not in allowlist

3. Merge custom pattern matches (same filtering)

4. Run all matches through overlap deduplication:
   a. Sort by start index ascending; ties broken by confidence descending
   b. Walk sorted list keeping a "cursor" at the end of last accepted match
   c. Skip any match whose start < cursor (overlapping)
   d. Accept match, advance cursor to match.end

5. Return sorted, non-overlapping PiiMatch[]
```

### `anonymize()` Algorithm

```
1. Resolve active preset (if options.preset is set)
2. Call detect() to get matches[]
3. Walk matches in REVERSE order (right-to-left):
   - Reversing prevents index shifts from corrupting later splice operations
4. For each match:
   a. Resolve strategy for this category (see priority order above)
   b. Apply strategy (sync) → replacement
   c. If consistentTokens=true, assign deterministic token (e.g. EMAIL_1)
   d. Splice: text = text.slice(0,start) + replacement + text.slice(end)
5. Return { text, matches }
```

### `anonymizeObject()` Algorithm

Performs a deep clone while anonymizing all string leaves:

1. Detect and throw on circular references using a `WeakSet`.
2. Recurse into arrays (index by index) and plain objects (key by key).
3. Pass every `string` leaf through `anonymize()` or `anonymizeAsync()`.
4. Return deep clone — original is never mutated.

---

## 8. Tokenization and Detokenization Flow

```
tokenize(text, options)
    │
    ├─ detect(text, ...) → PiiMatch[]
    │
    ├─ Create TokenStore (Map<value, token> + counter per category)
    │
    ├─ Walk matches in REVERSE order:
    │    assignToken(store, category, value)
    │      → if value already mapped: return existing token (deduplication)
    │      → else: generate next token (e.g. "[EMAIL_0003]")
    │    splice token into text
    │
    └─ Return { text, mapping: Map<token, originalValue> }

detokenize(text, mapping)
    │
    ├─ For each (token, original) in mapping:
    │    Replace all occurrences of token in text with original
    │
    └─ Return { text, unresolved: string[] }
         (unresolved = tokens in text not found in mapping)
```

Token uniqueness is guaranteed per `tokenize()` call. The counter is category-scoped so `EMAIL_0001` and `PHONE_0001` can coexist without collision.

---

## 9. LLM Pipeline Integration Pattern

```
User Input
    │
    ▼
sanitizeForLLM(userText)
    │  → { text: sanitizedText, mapping }
    │
    ▼
callLLM(sanitizedText)     ← PII never leaves your system
    │
    ▼
LLM Response (contains tokens)
    │
    ▼
restoreFromLLM(llmResponse, mapping)
    │  → { text: restoredText, unresolved }
    │
    ▼
Deliver restoredText to user
```

Key properties:

- Tokens use the format `[CATEGORY_NNNN]` — LLMs treat bracket content as opaque and rarely rewrite it.
- `unresolved` in the result lets you detect when the LLM dropped or mutated a token (data loss detection).
- The `mapping` is a `ReadonlyMap` — it cannot be accidentally mutated between the sanitize and restore steps.

---

## 10. Compliance Preset System

Presets are loaded lazily via `getPreset(name)` which looks up `PRESET_REGISTRY[name]`. The registry is a plain `Record<CompliancePreset, PresetConfig>` — no dynamic imports or code splitting.

When a preset is active, `anonymize()`:

1. Restricts detection to `preset.categories`; `enabledCategories` is ignored.
2. Applies `preset.defaultStrategy` to all matches.
3. Applies `preset.rules` per-category overrides on top.
4. Gives user-supplied `options.rules` the highest precedence; as without a preset, only the categories they list are then processed.

A `PipelineSpec` for the span engine takes a preset as a starting point: its `categories`,
`defaultStrategy` and `rules` override the preset's, so a pipeline can add categories to a preset.

---

## 11. Plugin Architecture

The `AnonymaPlugin` interface describes a third-party extension:

```ts
interface AnonymaPlugin {
  name: string;
  detectors?: Record<string, Detector>;
  strategies?: Record<string, StrategyFunction>;
  validators?: Record<string, ValidatorFunction>;
}
```

It is declared only: `createAnonymizer()` accepts a `plugins` option but does not apply it. The
working extension points are `customDetectors` and `customPatterns` in the 1.x API, and span
detectors and replacers of your own in the span engine (see [Extension Points](#16-extension-points)).

---

## 12. Build System & Package Outputs

### Toolchain

| Tool       | Role                                                                |
| ---------- | ------------------------------------------------------------------- |
| `tsc`      | Type checking (`--noEmit`); not used for emit                       |
| `tsup`     | Bundler (wraps `esbuild`); produces ESM + CJS from each entry point |
| `vitest`   | Test runner with V8 coverage                                        |
| `eslint`   | Linting with `typescript-eslint`                                    |
| `prettier` | Code formatting                                                     |

### Entry Points & Output Files

```
tsup.config.ts defines 15 entry points, each built to .js (ESM), .cjs (CJS), .d.ts and .d.cts:
  src/index.ts               → dist/index.*
  src/schemas.ts             → dist/schemas.*
  src/validators.ts          → dist/validators.*
  src/crypto.ts              → dist/crypto.*
  src/stream.ts              → dist/stream.*
  src/detectors/index.ts     → dist/detectors/index.*
  src/engine/index.ts        → dist/engine/index.*
  src/vault/index.ts         → dist/vault/index.*
  src/audit/index.ts         → dist/audit/index.*
  src/compliance/index.ts    → dist/compliance/index.*
  src/ai/index.ts            → dist/ai/index.*
  src/mcp/index.ts           → dist/mcp/index.*
  src/middleware/index.ts    → dist/middleware/index.*
  src/middleware/express.ts  → dist/middleware/express.*
  src/middleware/hono.ts     → dist/middleware/hono.*
```

The `package.json` `exports` map routes each subpath to the correct file with proper `import`/`require` conditions and type declarations.

Code shared between entry points is emitted once, as `chunk-*.js` and `chunk-*.cjs` files
(`splitting: true`). Every entry point therefore uses the same module instances: one
`AnonymaError` class, one copy of each detector.

Before a release, CI checks the build from the outside: `publint` and `are-the-types-wrong`
validate the package and its type resolution, `scripts/check-size.mjs` holds each entry point to
the budget in `scripts/size-budget.json`, and `scripts/smoke.mjs` installs the packed tarball into
an empty project and uses every entry point through `import` and `require` on Node.js 18, 20, 22,
24 and 26.

### Tree-Shaking

`"sideEffects": false` in `package.json` informs bundlers that every module is safe to tree-shake. Strategies and detectors can be imported individually without pulling in the entire registry.

---

## 13. Test Architecture

### Structure

```
tests/
├── anonymize.test.ts      # Core engine: detect, anonymize, anonymizeObject, hasPII
├── batch.test.ts          # Batch processing
├── coverage-gaps.test.ts  # Targeted tests for hard-to-reach branches
├── crypto.test.ts         # Web Crypto encrypt/decrypt
├── detectors.test.ts      # All 27 detectors (standard + aggressive)
├── errors.test.ts         # Error classes and codes
├── errors-v2.test.ts      # Extended error scenario coverage
├── new-detectors.test.ts  # Detectors added in later releases
├── presets.test.ts        # All 8 compliance presets
├── strategies.test.ts     # All 8 strategies (sync + async)
├── strategies-v2.test.ts  # Edge cases for strategies
├── stream.test.ts         # TransformStream wrappers
├── tokenize.test.ts       # tokenize/detokenize round-trips
├── validators.test.ts     # All checksum validator functions
├── errors-v3.test.ts      # Error classes of the subpath modules, through the public entry points
├── version.test.ts        # package.json, the code and the changelog agree on the version
├── engine/                # Pipelines, detectors, overlap, replacers, chunked streams,
│                          # precision floors and property-based tests (fast-check)
├── vault/                 # Key ring, session and keyed tokenizers
├── audit/                 # Logger, sinks and chain verification
├── compliance/            # Profiles, citations, policies, erasure, presets against profiles
├── ai/                    # JSON sanitizer, LLM guard, stream restoration
├── mcp/                   # MCP server and declarations
├── middleware/            # Scrubber, and the adapters against real Express and Hono apps
└── fixtures/corpus/       # Labelled corpora for email, SSN, IBAN, IPv4, IPv6 and cards
```

### Vitest Configuration

```ts
coverage: {
  provider: "v8",
  thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
  exclude: ["src/index.ts", "src/schemas.ts", "src/types.ts", "src/**/types.ts"],
}
```

`src/index.ts` and the `types.ts` files are excluded because they contain only re-exports and zero-runtime type declarations respectively. `src/schemas.ts` is excluded because it depends on the optional `zod` peer.

### ESM Resolver Plugin

Vitest cannot natively resolve TypeScript files referenced with `.js` extensions (TypeScript `NodeNext` convention). A custom Vite plugin in `vitest.config.ts` intercepts relative `.js` imports and resolves them to their `.ts` counterparts on the file system.

---

## 14. Security Architecture

### AES-256-GCM Encryption

- Uses the **Web Crypto API** — no third-party crypto library. `internal/webcrypto.ts` finds it: the global `crypto` where the runtime defines one, `node:crypto`'s `webcrypto` on Node.js 18.
- Each `encrypt()` call generates a fresh **12-byte random IV** via `crypto.getRandomValues()`.
- Key derivation: **PBKDF2 + SHA-256 + 100,000 iterations** from passphrase strings.
- Raw key import: supports 16-byte (AES-128) and 32-byte (AES-256) `Uint8Array` keys.
- Output is self-contained: `"<encoding>:<iv>:<ciphertext>"` — decryption needs no external state.

### SHA-256 Hashing

- Also uses Web Crypto API.
- Supports an optional **pepper** (pre-pended to value before hashing) to prevent rainbow-table attacks.
- Output is not reversible.

### Tokenization Security Notes

- Tokens are deterministic within a single `tokenize()` call but not across calls (counters reset).
- The `mapping` Map should be treated as a secret: it contains the original PII values.
- `sanitizeForLLM` / `restoreFromLLM` is designed exclusively for server-side use — the mapping must never be sent to the client or the LLM.

### Key Ring and Tokens

- Each key version holds one secret: raw material (at least 32 bytes) or a passphrase stretched
  with PBKDF2-HMAC-SHA-256 (600,000 iterations by default, never fewer than 100,000) with a random
  32-byte salt per version.
- Keys are derived with HKDF-SHA-256; the `info` binds each key to its purpose and namespace.
  Derived keys are non-extractable `CryptoKey` objects.
- The manifest is authenticated with HMAC-SHA-256 under the active version, and an edited
  manifest (another active version, a lower iteration count, another salt) is refused.
- Keyed tokens are HMAC-SHA-256 identifiers; vault records and sealed tokens use AES-256-GCM. The
  sealed scheme derives its nonce from the value with a keyed PRF, so it is deterministic; rotate
  a key version well before 2^32 distinct values have been sealed under it.

### Audit Chain

- Records are canonical JSON; each hash covers the record and the previous hash, starting from
  `GENESIS_HASH`. With a key the hash is an HMAC-SHA-256, so rewriting the log needs the key;
  without one, store `head()` where the log writer cannot reach it.
- Records have no member for values, and caller-supplied strings are blanked when they look like
  personal data.

### Input Validation

All public functions validate their arguments and throw `ValidationError` with a human-readable message and `field` name. Callers should rely on `instanceof AnonymaError` checks.

---

## 15. Performance Characteristics

| Operation                    | Complexity             | Notes                                                       |
| ---------------------------- | ---------------------- | ----------------------------------------------------------- |
| `detect(text)`               | O(C × R × N)           | C = active categories, R = regex exec time, N = text length |
| `anonymize(text)`            | O(C × R × N + M)       | M = match count for reverse-splice                          |
| `hasPII(text)`               | O(C × R) early-exit    | Stops at first match found                                  |
| `anonymizeBatch(texts)`      | O(B × C × R × N)       | B = batch size; fully synchronous                           |
| `anonymizeBatchAsync(texts)` | O(B × C × R × N) async | Runs all items concurrently via `Promise.allSettled`        |
| `tokenize(text)`             | O(C × R × N + M)       | Same as anonymize                                           |
| `hash(value)`                | O(V) async             | V = value length; one SHA-256 digest                        |
| `encrypt(value)`             | O(V) async             | One PBKDF2 + one AES-GCM                                    |

Overlap deduplication adds an O(M log M) sort over matches but M is typically small.

The span engine is linear in the size of its input: detectors with a prefilter skip texts that
cannot contain a hit, overlap resolution sorts the hits once, and the output is assembled in a
single pass. The chunked transformer adds no more than `window + batch` characters of lag. The CI
`performance` job runs the benchmark and fails when an engine operation stops scaling linearly
(`scripts/check-bench.mjs` limits the log-log slope of time against input size to 1.15).

---

## 16. Extension Points

| Extension Point           | Mechanism                                              | Type                                       |
| ------------------------- | ------------------------------------------------------ | ------------------------------------------ |
| Custom PII patterns       | `customPatterns` in `AnonymizeOptions`                 | `CustomPattern[]`                          |
| Replace built-in detector | `customDetectors` in `AnonymizeOptions`                | `Partial<DetectorRegistry>`                |
| Additional categories     | a span detector with a category of its own (engine)    | `SpanDetector` (`Category` is any string)  |
| Skip known-safe values    | `allowlist`, `allowlistPatterns` in `AnonymizeOptions` | `string[]`, `RegExp[]`                     |
| Field-level control       | `anonymizeRecord(obj, FieldRuleMap)`                   | dot-notation paths                         |
| Runtime validation        | `"anonyma/schemas"` + Zod                              | `AnonymizeOptionsSchema.parse()`           |
| AI tool definitions       | `"anonyma/schemas"` tool definitions; `"anonyma/mcp"`  | OpenAI function / MCP tool (JSON Schema)   |
| Streaming ingestion       | `createAnonymizeStream()`                              | `TransformStream<string, AnonymizeResult>` |
| Span detector             | `defineDetector()`, `defineRegexDetector()`            | `SpanDetector`                             |
| Replacement               | a function in a `ReplacementPlan`                      | `Replacer`                                 |
| Pipeline as data          | `compilePipeline(spec, dependencies)`                  | `PipelineSpec`, `CompileDependencies`      |
| Token storage             | an implementation of the vault interface               | `TokenVault`                               |
| Tokenization scheme       | an implementation of the provider interface            | `TokenizationProvider`                     |
| Audit destination         | an implementation of the sink interface                | `AuditSink`                                |
| Organisation policy       | a policy document, checked by `parsePolicy()`          | `PolicyDocument`                           |
