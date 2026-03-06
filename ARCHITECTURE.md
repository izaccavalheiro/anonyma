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

anonyma is built around five immutable principles:

| Principle | Manifestation |
|---|---|
| **Zero runtime dependencies** | `package.json` has an empty `dependencies` object; `zod` is a peer/optional |
| **Strict type safety** | `tsconfig.json` enables every strict flag + `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` |
| **Pure, deterministic functions** | Detectors and most strategies are pure functions; async is confined to cryptographic operations |
| **Tree-shakeable by design** | Each detector and strategy is a standalone module; the barrel re-exports but does not merge namespaces |
| **Separation of concerns** | Detection (`detectors/`), transformation (`strategies/`), orchestration (`anonymize.ts`), and I/O (`stream.ts`, `batch.ts`) are fully decoupled |

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

Same flow but `applyStrategy` is awaited, enabling hash (SHA-256) and encrypt (AES-GCM) strategies that require the Web Crypto API.

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
└── BatchProcessingError     (batch-level failure — carries index + cause)
```

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

| File | Strategy | Sync | Reversible |
|---|---|---|---|
| `mask.ts` | Replace interior chars with mask char | ✅ | ❌ |
| `redact.ts` | Replace with static label e.g. `[REDACTED]` | ✅ | ❌ |
| `pseudonymize.ts` | Deterministic seeded fake identifier | ✅ | ❌ |
| `hash.ts` | SHA-256 digest with optional pepper | ❌ async | ❌ |
| `generalize.ts` | Range/bucket generalization (ages, dates) | ✅ | ❌ |
| `encrypt.ts` | AES-256-GCM via Web Crypto API | ❌ async | ✅ |
| `synthesize.ts` | Format-preserving synthetic data replacement | ✅ | ❌ |
| `tokenize.ts` | Internal token store (used by `tokenize.ts` module) | ✅ | ✅ |

`encrypt.ts` uses **PBKDF2 + SHA-256** (100,000 iterations) for passphrase-based key derivation, or imports raw 16/32-byte keys directly. Output format: `"<encoding>:<iv_hex_or_b64>:<ciphertext>"`.

### 4.5 `anonymize.ts` — Core Engine

The largest and most complex module. Responsibilities:
- `detect()` — multi-category scan with allowlist, confidence filtering, overlap deduplication
- `anonymize()` — sync orchestration
- `anonymizeAsync()` — async orchestration (all 8 strategies)
- `anonymizeRecord()` — field-level anonymization of plain objects using dot-notation paths
- `anonymizeObject()` — deep recursive anonymization of arbitrary JSON trees
- `hasPII()` — optimised early-exit boolean scan
- `createAnonymizer()` — factory that closes over a reusable `AnonymizerConfig`

Internal overlap resolution: matches are sorted by `start` index, then iterated. When a match's start index is inside the last consumed region, it is skipped (first-wins, longest-first tiebreaker).

### 4.6 `tokenize.ts` — Reversible Tokenization

Wraps `detect()` + the internal token store to produce a `TokenizeResult`:
```ts
{ text: string, mapping: ReadonlyMap<string, string> }
```
The `mapping` maps every token string (e.g. `"[EMAIL_0001]"`) back to the original PII value. `detokenize()` performs the inverse substitution.

Token formats (controlled by `TokenFormat`):
- `"bracket"` — `[EMAIL_0001]` (default, LLM-safe)
- `"angle"` — `<EMAIL_0001>`
- `"curly"` — `{EMAIL_0001}`
- `"plain"` — `EMAIL_0001`

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

Six built-in regulatory presets:

| Preset | Regulation | Primary Strategy | Focus |
|---|---|---|---|
| `gdpr` | EU GDPR | pseudonymize | All personal data identifiers |
| `hipaa` | US HIPAA Safe Harbor | redact | 18 PHI identifier classes |
| `ccpa` | California CCPA | mask | Personal + household data |
| `pci-dss` | PCI DSS v4 | mask | Payment card data |
| `sox` | US Sarbanes-Oxley | hash | Financial records + employee data |
| `ferpa` | US FERPA | redact | Student education records |

Each `PresetConfig` specifies the activated `categories[]`, a `defaultStrategy`, and optional per-category `rules[]` overrides. Presets are resolved at runtime in `anonymize.ts` via `getPreset()`.

### 4.10 `stream.ts` — WHATWG Streaming

Wraps the core engine in `TransformStream<string, AnonymizeResult>` / `TransformStream<string, TokenizeResult>`. Requires the global `TransformStream` (Node ≥ 18 / browsers). Each chunk is expected to be a complete string (e.g., a line or paragraph). Exported from the `"anonyma/stream"` subpath.

### 4.11 `validators.ts` — Checksum Validators

Stand-alone pure validation algorithms exported from `"anonyma/validators"`:

| Function | Algorithm | Used For |
|---|---|---|
| `luhn` | Luhn (ISO/IEC 7812) | Credit cards, some national IDs |
| `verhoeff` | Verhoeff | Indian Aadhaar |
| `nhsMod11` | NHS Mod-11 | UK NHS numbers |
| `cpfChecksum` | CPF | Brazilian tax ID |
| `vinChecksum` | VIN transliteration | Vehicle Identification Numbers |
| `deaChecksum` | DEA Mod-9 | US DEA registration numbers |
| `ibanMod97` | IBAN Mod-97 | International bank accounts |
| `ninoValid` | NINO format | UK National Insurance Numbers |
| `aadhaarFormat` | Verhoeff + format | Indian Aadhaar (12-digit) |

These validators are used internally by the corresponding detectors to reduce false positives.

### 4.12 `crypto.ts` — Web Crypto Helpers

Low-level utilities re-used by `strategies/encrypt.ts`. Exposes encoding helpers (`toBase64`, `fromBase64`, `toHex`, `fromHex`) and the key derivation pipeline. Exported from the `"anonyma/crypto"` subpath.

### 4.13 `schemas.ts` — Zod Schemas & AI Definitions

**Requires `zod` as a peer dependency.** Exported from the `"anonyma/schemas"` subpath to keep the main bundle free of the Zod dependency.

Provides:
- `PiiCategorySchema` — Zod enum for all 27 categories
- `AnonymizeOptionsSchema` — Full Zod object schema with `.parse()` for runtime validation
- `toJsonSchema()` — Converts Zod schemas to JSON Schema compatible with OpenAI function-calling and Anthropic tool definitions
- MCP (Model Context Protocol) tool definitions for `anonymize`, `detect`, and `tokenize`

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
(value: string, options: StrategyOptions) => string
```

### Async Strategy Contract

```ts
(value: string, options: StrategyOptions) => Promise<string>
```

The core engine calls strategies via `applyStrategy` (sync) or `applyStrategyAsync` (async), keyed by the `strategy` discriminant on the `StrategyOptions` union. Unknown strategy names throw `UnsupportedStrategyError`.

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
   a. Sort by start index ascending; ties broken by length descending
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

When a preset is active, the engine:
1. Restricts detection to `preset.categories` (unless `enabledCategories` further narrows it).
2. Applies `preset.defaultStrategy` to all matches.
3. Applies `preset.rules` per-category overrides on top.
4. User-supplied `options.rules` still take highest precedence within the preset.

---

## 11. Plugin Architecture

The `AnonymaPlugin` interface enables third-party extensions:

```ts
interface AnonymaPlugin {
  detectors?: Partial<DetectorRegistry>;
  strategies?: Record<string, StrategyFunction>;
  validators?: Record<string, ValidatorFunction>;
}
```

Plugins are applied at `createAnonymizer()` time and their entries extend (not replace) the built-in registries.

---

## 12. Build System & Package Outputs

### Toolchain

| Tool | Role |
|---|---|
| `tsc` | Type checking (`--noEmit`); not used for emit |
| `tsup` | Bundler (wraps `esbuild`); produces ESM + CJS from each entry point |
| `vitest` | Test runner with V8 coverage |
| `eslint` | Linting with `typescript-eslint` |
| `prettier` | Code formatting |

### Entry Points & Output Files

```
tsup.config.ts defines 6 entry points:
  src/index.ts          → dist/index.js (ESM) + dist/index.cjs (CJS) + .d.ts
  src/schemas.ts        → dist/schemas.js + dist/schemas.cjs + .d.ts
  src/validators.ts     → dist/validators.js + dist/validators.cjs + .d.ts
  src/crypto.ts         → dist/crypto.js + dist/crypto.cjs + .d.ts
  src/stream.ts         → dist/stream.js + dist/stream.cjs + .d.ts
  src/detectors/index.ts→ dist/detectors/index.js + .cjs + .d.ts
```

The `package.json` `exports` map routes each subpath to the correct file with proper `import`/`require` conditions and `.d.ts` type declarations.

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
├── presets.test.ts        # All 6 compliance presets
├── strategies.test.ts     # All 8 strategies (sync + async)
├── strategies-v2.test.ts  # Edge cases for strategies
├── stream.test.ts         # TransformStream wrappers
├── tokenize.test.ts       # tokenize/detokenize round-trips
└── validators.test.ts     # All checksum validator functions
```

### Vitest Configuration

```ts
coverage: {
  provider: "v8",
  thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
  exclude: ["src/index.ts", "src/schemas.ts", "src/types.ts"],
}
```

`src/index.ts` and `src/types.ts` are excluded because they contain only re-exports and zero-runtime type declarations respectively. `src/schemas.ts` is excluded because it depends on the optional `zod` peer.

### ESM Resolver Plugin

Vitest cannot natively resolve TypeScript files referenced with `.js` extensions (TypeScript `NodeNext` convention). A custom Vite plugin in `vitest.config.ts` intercepts relative `.js` imports and resolves them to their `.ts` counterparts on the file system.

---

## 14. Security Architecture

### AES-256-GCM Encryption

- Uses the **Web Crypto API** (`globalThis.crypto.subtle`) — no third-party crypto library.
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

### Input Validation

All public functions validate their arguments and throw `ValidationError` with a human-readable message and `field` name. Callers should rely on `instanceof AnonymaError` checks.

---

## 15. Performance Characteristics

| Operation | Complexity | Notes |
|---|---|---|
| `detect(text)` | O(C × R × N) | C = active categories, R = regex exec time, N = text length |
| `anonymize(text)` | O(C × R × N + M) | M = match count for reverse-splice |
| `hasPII(text)` | O(C × R) early-exit | Stops at first match found |
| `anonymizeBatch(texts)` | O(B × C × R × N) | B = batch size; fully synchronous |
| `anonymizeBatchAsync(texts)` | O(B × C × R × N) async | Runs all items concurrently via `Promise.allSettled` |
| `tokenize(text)` | O(C × R × N + M) | Same as anonymize |
| `hash(value)` | O(V) async | V = value length; one SHA-256 digest |
| `encrypt(value)` | O(V) async | One PBKDF2 + one AES-GCM |

Overlap deduplication adds an O(M log M) sort over matches but M is typically small.

---

## 16. Extension Points

| Extension Point | Mechanism | Type |
|---|---|---|
| Custom PII patterns | `customPatterns` in `AnonymizeOptions` | `CustomPattern[]` |
| Replace built-in detector | `customDetectors` in `AnonymizeOptions` | `Partial<DetectorRegistry>` |
| Additional categories | `customDetectors` + custom string category | `Record<string, Detector>` |
| Skip known-safe values | `allowlist` in `AnonymizeOptions` | `(string | RegExp)[]` |
| Field-level control | `anonymizeRecord(obj, FieldRuleMap)` | dot-notation paths |
| Full plugin | `createAnonymizer({ plugins })` | `AnonymaPlugin[]` |
| Runtime validation | `"anonyma/schemas"` + Zod | `AnonymizeOptionsSchema.parse()` |
| AI tool definitions | `"anonyma/schemas"` + `toJsonSchema()` | JSON Schema / OpenAI function |
| Streaming ingestion | `createAnonymizeStream()` | `TransformStream<string, AnonymizeResult>` |
