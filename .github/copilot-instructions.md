# GitHub Copilot Instructions — anonyma

## Project Overview

**anonyma** is a zero-dependency TypeScript library for PII detection and data anonymization. It targets Node.js ≥ 18, ships as Dual ESM + CJS, and provides 27 PII detectors, 8 anonymization strategies, 6 compliance presets, reversible tokenization, LLM pipeline helpers, WHATWG streaming, batch processing, checksum validators, and optional Zod/MCP schemas.

---

## Language and Framework

- **Language**: TypeScript 5.x with the strictest compiler settings
- **Module format**: ESM (`"type": "module"`) with `.js` extensions on relative imports in source
- **Build tool**: tsup (esbuild wrapper)
- **Test runner**: Vitest with V8 coverage
- **Linter**: ESLint 9 with `typescript-eslint`
- **Runtime target**: Node.js ≥ 18 (uses Web Crypto API, `TransformStream`, `structuredClone`)

---

## Absolute Rules — Always Follow

1. **Zero runtime dependencies.** Never suggest adding a package to `dependencies` in `package.json`. All runtime code must be self-contained. `zod` is a peer/optional dependency only.
2. **No `any` type.** Use `unknown` + type guards, generics, or specific union types instead.
3. **Strict TypeScript only.** All code must satisfy `tsc --noEmit` with the settings in `tsconfig.json` (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`).
4. **Pure functions.** Detectors and non-crypto strategies must be pure (no side effects, no global state mutation, deterministic output).
5. **Immutable inputs.** Never mutate function arguments or input strings. Always return new values.
6. **`.js` extensions in source imports.** TypeScript `NodeNext` resolution requires `import ... from "./foo.js"` even though the file is `foo.ts`.
7. **JSDoc on every export.** Every exported function, class, interface, and type alias requires a JSDoc/TSDoc comment with `@param`, `@returns`, and at least one `@example`.

---

## Code Generation Preferences

### General

- Use `const` by default; use `let` only when reassignment is necessary.
- Prefer `for...of` over `.forEach()` for side-effectful iteration.
- Use optional chaining `?.` and nullish coalescing `??` rather than explicit `null` checks.
- Avoid `try/catch` in hot paths; validate inputs upfront and throw typed `AnonymaError` subclasses.
- Use `readonly` on all interface properties and function parameters that should not be mutated.
- Avoid default parameter values that are complex objects — compute them inside the function body.

### TypeScript Specifics

- Use discriminated unions for strategy options (the `strategy` literal acts as the discriminant).
- Export types with `export type` when there is no runtime value.
- Use `satisfies` operator to validate literal objects against types without widening.
- Use `as const` for constant arrays/objects to get literal type inference.

### Error Handling

- All errors must extend `AnonymaError` from `src/errors.ts`.
- Include `Object.setPrototypeOf(this, new.target.prototype)` in every `Error` subclass constructor.
- Throw `ValidationError` for invalid arguments (include the field name and reason).
- Throw `UnsupportedStrategyError` for unknown strategy names.
- Never `throw` plain `Error` objects from library code.

### Async Code

- Only use `async` when calling Web Crypto API (`crypto.subtle.*`) or `Promise.allSettled`.
- Keep synchronous paths synchronous — do not add unnecessary `Promise` wrapping.
- For the `hash` and `encrypt` strategies, always `await` the Web Crypto call directly.

---

## File and Module Structure

### Adding a New Detector

```ts
// src/detectors/<category>.ts
import type { PiiMatch } from "../types.js";

const PATTERN = /<regex>/g;

export function detect<Category>(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const re = new RegExp(PATTERN.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    matches.push({
      category: "<category>",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      confidence: 0.9,
    });
  }
  return matches;
}
```

After creating the file:
1. Add the category to `PiiCategory` in `src/types.ts`
2. Register in `DETECTOR_REGISTRY` in `src/detectors/index.ts`
3. Add `TOKEN_PREFIX_MAP` entries in `src/anonymize.ts` and `src/tokenize.ts`
4. Add to `ALL_CATEGORIES` in `src/anonymize.ts`
5. Add tests in `tests/detectors.test.ts`

### Adding a New Strategy

```ts
// src/strategies/<strategy>.ts
import { ValidationError } from "../errors.js";
import type { <Strategy>Options } from "../types.js";

export function <strategy>(value: string, options: <Strategy>Options = {}): string {
  // validate inputs first
  // return transformed value
}
```

After creating the file:
1. Add the strategy name to `StrategyName` union in `src/types.ts`
2. Add `<Strategy>Options` interface in `src/types.ts`
3. Register in `applyStrategy` switch in `src/anonymize.ts`
4. Re-export from `src/strategies/index.ts` and `src/index.ts`

---

## Testing Conventions

- Use Vitest globals — no need to import `describe`, `it`, `expect`.
- Structure: `describe("<module-name>")` → `describe("<functionName>()")` → `it("<behaviour description>")`.
- Use `it.each` for table-driven tests with multiple inputs.
- Test at least: normal case, empty string, unicode/multibyte input, boundary values, and invalid inputs.
- For async strategies: mark callback `async` and use `await expect(...)`.
- Never mock internal modules; test through the public API surface.
- Coverage gates: 90% lines/functions/statements, 85% branches.

```ts
describe("detectEmail()", () => {
  it("returns a match for a standard email address", () => {
    const matches = detectEmail("hello@example.com");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("hello@example.com");
    expect(matches[0]?.category).toBe("email");
  });

  it("returns empty array for text with no email", () => {
    expect(detectEmail("no email here")).toHaveLength(0);
  });
});
```

---

## Naming Conventions

| Construct | Convention | Example |
|---|---|---|
| Detector function | `detect<Category>` camelCase | `detectCreditCard` |
| Aggressive variant | `detect<Category>Aggressive` | `detectEmailAggressive` |
| Strategy function | lowercase verb | `mask`, `redact`, `pseudonymize` |
| Error class | `<Reason>Error` PascalCase | `ValidationError` |
| Preset name | lowercase hyphenated string literal | `"pci-dss"` |
| PII category | lowercase hyphenated string literal | `"credit-card"` |
| Registry constant | SCREAMING_SNAKE_CASE | `DETECTOR_REGISTRY` |
| Internal helper | `_` prefix or unexported | `_deduplicateMatches` |

---

## What Copilot Should NOT Suggest

- Importing from `node:crypto` — use Web Crypto API (`globalThis.crypto.subtle`) instead.
- Using `Buffer` — use `Uint8Array` for binary data.
- Adding npm packages for string manipulation, UUID generation, or hashing.
- Using `JSON.parse` / `JSON.stringify` without null checks when working with unknown input.
- Ignoring TypeScript errors with `// @ts-ignore` or `// @ts-expect-error` without a specific documented reason.
- Exporting mutable state from any module.
- Using `process.env` in source files — this is a library, not an application.
- Using `console.log` in production source (only `console.warn` is permitted, in specific documented deprecation scenarios).
- Widening `PiiCategory` to `string` — always use the specific union type.
- Adding `@types/*` packages to `dependencies` — they belong in `devDependencies`.

---

## Subpath Exports Reference

| Import path | Contents |
|---|---|
| `"anonyma"` | Core API: `anonymize`, `detect`, `hasPII`, `tokenize`, strategies, errors, types |
| `"anonyma/detectors"` | Individual `detect*` functions + `DETECTOR_REGISTRY` |
| `"anonyma/schemas"` | Zod schemas + `toJsonSchema()` + MCP tool defs (requires `zod`) |
| `"anonyma/validators"` | `luhn`, `verhoeff`, `nhsMod11`, `cpfChecksum`, etc. |
| `"anonyma/crypto"` | Low-level Web Crypto helpers |
| `"anonyma/stream"` | `createAnonymizeStream`, `createTokenizeStream` |

---

## Compliance Context

When generating code related to:
- **HIPAA**: Use `redact` strategy; cover all 18 Safe Harbor identifiers.
- **GDPR**: Use `pseudonymize` strategy; cover all personal data including IP addresses.
- **PCI-DSS**: Use `mask` strategy; focus on credit card, bank account, CVV data.
- **CCPA**: Use `mask`; cover personal data + household data identifiers.
- **FERPA**: Use `redact`; focus on student education records and identifiers.
- **SOX**: Use `hash`; focus on financial records and employee identifying data.
