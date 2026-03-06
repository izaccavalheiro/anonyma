# AGENTS.md — AI Agent Guidelines for anonyma

> This file instructs autonomous AI coding agents (Codex, Claude, Gemini, GPT-4o, and similar) on how to work safely and effectively inside this repository.

---

## Project Identity

**anonyma** is a zero-dependency TypeScript library for PII detection and data anonymization. It is published as an npm package targeting Node.js ≥ 18 with full Dual ESM + CJS output. The library ships 27 PII detectors, 8 anonymization strategies, 6 compliance presets, reversible tokenization, LLM pipeline helpers, WHATWG streaming support, batch processing, checksum validators, and optional Zod/MCP schemas.

---

## Repository Layout

```
src/
├── index.ts              # Public API barrel — only file users import from "anonyma"
├── types.ts              # All TypeScript interfaces and type aliases (no runtime code)
├── errors.ts             # Typed error hierarchy rooted at AnonymaError
├── anonymize.ts          # Core engine: detect(), anonymize(), anonymizeAsync(), anonymizeObject()
├── tokenize.ts           # High-level tokenize() / detokenize() API
├── llm.ts                # sanitizeForLLM() / restoreFromLLM() wrappers
├── batch.ts              # anonymizeBatch(), anonymizeBatchAsync(), detectBatch(), tokenizeBatch()
├── presets.ts            # GDPR / HIPAA / CCPA / PCI-DSS / SOX / FERPA preset definitions
├── stream.ts             # WHATWG TransformStream wrappers (Node ≥ 18 / browsers)
├── crypto.ts             # Low-level Web Crypto helpers
├── validators.ts         # Checksum validators (Luhn, Verhoeff, NHS, CPF, IBAN, etc.)
├── schemas.ts            # Optional Zod schemas + OpenAI/MCP tool definitions
├── detectors/            # One file per PII category; each exports detect*() + detect*Aggressive()
│   └── index.ts          # Assembles DETECTOR_REGISTRY and AGGRESSIVE_DETECTOR_REGISTRY
└── strategies/           # One file per anonymization strategy
    ├── mask.ts, redact.ts, pseudonymize.ts, hash.ts, generalize.ts
    ├── encrypt.ts         # AES-GCM via Web Crypto API
    ├── synthesize.ts      # Format-preserving deterministic synthesis
    └── tokenize.ts        # Internal token store used by tokenize.ts and anonymize.ts
tests/                     # Vitest test suite — mirrors src/ structure
```

---

## Non-Negotiable Constraints

1. **Zero runtime dependencies.** `node_modules` must remain empty at install time (only `devDependencies` and optional peer `zod`). Never add a `dependencies` entry to `package.json`.
2. **Strict TypeScript.** `tsconfig.json` uses `"strict": true` plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`. Every change must compile with `tsc --noEmit` without error.
3. **No `any`.** Use proper type narrowing. Prefer `unknown` and type guards when the type cannot be determined statically.
4. **Pure functions.** Detectors and strategies are pure, deterministic, and side-effect-free unless they require async crypto (hash, encrypt).
5. **Coverage gates.** Vitest coverage thresholds are 90% lines/functions/statements and 85% branches. A PR that drops coverage below these gates must include new tests.
6. **ESM-first with `.js` extensions.** Source imports use `.js` extensions even though the files are `.ts` — this is required by TypeScript `NodeNext` module resolution.

---

## How to Run the Project

```bash
# Install dev dependencies (zero runtime deps)
npm install

# Type-check only (no emit)
npm run typecheck

# Lint
npm run lint

# Run full test suite
npm run test

# Run tests with coverage report
npm run test:coverage

# Build ESM + CJS output into dist/
npm run build
```

---

## Adding a New PII Detector

1. Create `src/detectors/<category>.ts` following the exact same contract as any existing detector.
2. Export two functions: `detect<Category>(text: string): PiiMatch[]` and, if a more permissive variant makes sense, `detect<Category>Aggressive(text: string): PiiMatch[]`.
3. Add the new category to `PiiCategory` in `src/types.ts`.
4. Register the detector in `DETECTOR_REGISTRY` (and `AGGRESSIVE_DETECTOR_REGISTRY` if applicable) in `src/detectors/index.ts`.
5. Add `TOKEN_PREFIX_MAP` entries in both `src/anonymize.ts` and `src/tokenize.ts`.
6. Add the category to `ALL_CATEGORIES` in `src/anonymize.ts`.
7. Write tests in `tests/detectors.test.ts` (and `tests/new-detectors.test.ts` for new additions).
8. Export from `src/detectors/index.ts`.

---

## Adding a New Anonymization Strategy

1. Create `src/strategies/<strategy>.ts` exporting a pure function (or async function for crypto-dependent strategies).
2. Add the strategy name to `StrategyName` in `src/types.ts` and add the corresponding `*Options` interface.
3. Register the strategy handler inside the `applyStrategy` / `applyStrategyAsync` switch in `src/anonymize.ts`.
4. Re-export from `src/strategies/index.ts` and from `src/index.ts`.
5. Add tests and update the `UnsupportedStrategyError` message.

---

## Adding or Modifying a Compliance Preset

- All presets live in `src/presets.ts`.
- A `PresetConfig` requires: `name`, `description`, `categories`, `defaultStrategy`, and optional per-category `rules`.
- Register the new preset in `PRESET_REGISTRY`.
- Write tests in `tests/presets.test.ts`.

---

## Code Style Rules (enforced by ESLint + Prettier)

- Tabs: 2-space indentation.
- Trailing commas: ES5.
- Single quotes for strings.
- JSDoc / TSDoc comments on every exported symbol.
- No `console.log` in source files (only `console.warn` for deprecations in specific, documented cases).
- Keep files focused — one primary concern per file.

---

## Testing Conventions

- Use Vitest globals (`describe`, `it`, `expect`) — no imports needed.
- Group tests with `describe("<module>")` → `describe("<function>")` → `it("<behaviour>")`.
- Prefer `it("returns X when Y")` descriptions over implementation-level names.
- Test edge cases: empty string, unicode, very long inputs, malformed values, boundary conditions.
- For async tests (hash, encrypt), use `await` and mark the callback `async`.
- Never mock internal modules; test through the public API as much as possible.
- Add coverage-gap tests to `tests/coverage-gaps.test.ts` when covering difficult branches.

---

## Commit Message Format

Follow Conventional Commits:

```
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`  
Scope examples: `detectors`, `strategies`, `presets`, `stream`, `batch`, `llm`, `schemas`

---

## What Agents Must NOT Do

- Do not add runtime `dependencies` to `package.json`.
- Do not introduce `any` types.
- Do not skip `Object.setPrototypeOf(this, new.target.prototype)` when subclassing `Error`.
- Do not mutate input objects or strings — always return new values.
- Do not use `console.log` in production source code.
- Do not break the dual ESM/CJS export map in `package.json`.
- Do not remove or weaken the test coverage thresholds in `vitest.config.ts`.
- Do not bypass the `prepublishOnly` gate (`tsc + lint + test + build`) before publishing.
- Do not import `zod` in any file outside `src/schemas.ts` — it is an optional peer dependency.

---

## Security Guidelines

- The `encrypt` strategy uses AES-256-GCM via the Web Crypto API. Do not substitute with a weaker algorithm.
- PBKDF2 with 100,000 iterations and SHA-256 is used for passphrase key derivation. Do not lower the iteration count.
- IV (initialization vector) is always freshly generated (12 random bytes) per `encrypt()` call.
- The `hash` strategy uses SHA-256 with an optional pepper. Never persist raw PII after anonymization.
- The `tokenize` / `sanitizeForLLM` flow is designed so that the token map never leaves the server — validate this in any integration.

---

## Useful Reference

| Concern | File |
|---|---|
| All public API types | `src/types.ts` |
| Error codes | `src/errors.ts` |
| Detector contract | `src/detectors/email.ts` (canonical example) |
| Strategy contract | `src/strategies/mask.ts` (canonical sync) · `src/strategies/hash.ts` (canonical async) |
| Preset definition | `src/presets.ts` |
| Token format | `src/tokenize.ts` + `src/strategies/tokenize.ts` |
| LLM integration | `src/llm.ts` |
| Streaming | `src/stream.ts` |
| Zod schemas + AI tool defs | `src/schemas.ts` |
| Validators | `src/validators.ts` |
