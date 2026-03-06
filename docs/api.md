# anonyma API Reference

> Zero-dependency TypeScript data anonymization and PII detection library.

---

## Contents

1. [Core Functions](#core-functions)
   - [detect](#detect)
   - [hasPII](#haspii)
   - [anonymize](#anonymize)
   - [anonymizeObject](#anonymizeobject)
   - [anonymizeRecord](#anonymizerecord)
   - [createAnonymizer](#createanonymizer)
2. [Strategies](#strategies)
   - [mask](#mask)
   - [redact](#redact)
   - [pseudonymize](#pseudonymize)
   - [hash](#hash)
   - [generalize](#generalize)
3. [Detectors](#detectors)
4. [Error Classes](#error-classes)
5. [AI / MCP Integration](#ai--mcp-integration)
6. [Types Reference](#types-reference)

---

## Core Functions

### `detect`

```ts
detect(
  text: string,
  categories?: PiiCategory[],
  customDetectors?: Partial<Record<PiiCategory, Detector>>,
  aggressive?: boolean
): PiiMatch[]
```

Scan `text` for PII and return a sorted, de-duplicated array of matches — without
modifying the input.

| Parameter         | Type                      | Default | Description                                          |
| ----------------- | ------------------------- | ------- | ---------------------------------------------------- |
| `text`            | `string`                  | required| The input string to scan.                            |
| `categories`      | `PiiCategory[]`           | all     | Restrict scanning to these categories.               |
| `customDetectors` | `Partial<Record<...>>`    | —       | Override or extend built-in detectors.               |
| `aggressive`      | `boolean`                 | `false` | Use expanded, more permissive patterns for each detector. |

**Returns:** `PiiMatch[]` — each entry includes `category`, `value`, `start`, `end`, `confidence`.

**Example:**

```ts
import { detect } from "anonyma";

detect("alice@example.com and 192.168.1.1");
// [
//   { category: "email", value: "alice@example.com", start: 0, end: 17, confidence: 0.99 },
//   { category: "ipv4",  value: "192.168.1.1",       start: 22, end: 33, confidence: 0.98 },
// ]
```

---

### `hasPII`

```ts
hasPII(
  text: string,
  categories?: PiiCategory[],
  customDetectors?: Partial<Record<PiiCategory, Detector>>
): boolean
```

Return `true` if `text` contains any detectable PII, `false` otherwise.
Stops scanning after the first match for performance (early-exit optimisation).

| Parameter         | Type                   | Default | Description                                  |
| ----------------- | ---------------------- | ------- | -------------------------------------------- |
| `text`            | `string`               | required| The input string to check.                   |
| `categories`      | `PiiCategory[]`        | all     | Restrict check to these categories.          |
| `customDetectors` | `Partial<Record<...>>` | —       | Override built-in detectors.                 |

**Example:**

```ts
import { hasPII } from "anonyma";

if (hasPII(commentText)) {
  return { error: "Comment contains personal information." };
}

hasPII("Call 555-867-5309");          // true
hasPII("No sensitive data here");     // false
hasPII("alice@example.com", ["phone"]); // false — email present but only checking phone
```

---

### `anonymize`

```ts
anonymize(text: string, options?: AnonymizeOptions): AnonymizeResult
```

Detect all PII in `text` and replace each match according to the configured strategy.
Operates in a single pass, applying replacements right-to-left to preserve offsets.

**Options (`AnonymizeOptions`):**

| Field                | Type                                          | Default                  | Description                                                              |
| -------------------- | --------------------------------------------- | ------------------------ | ------------------------------------------------------------------------ |
| `defaultStrategy`    | `StrategyOptions`                             | `{ strategy: "redact" }` | Strategy for all unmatched categories.                                   |
| `rules`              | `AnonymizationRule[]`                         | `[]`                     | Per-category strategy overrides.                                         |
| `includeMatches`     | `boolean`                                     | `false`                  | Populate `result.matches`.                                               |
| `customDetectors`    | `Partial<Record<PiiCategory, Detector>>`      | —                        | Override specific built-in detectors.                                    |
| `customPatterns`     | `CustomPattern[]`                             | —                        | Ad-hoc regex patterns matched alongside built-in detectors.              |
| `globalReplacement`  | `string`                                      | —                        | Replace ALL detected PII with this string, overriding strategies.        |
| `consistentTokens`   | `boolean`                                     | `false`                  | Same value → same token (`EMAIL_1`, `PHONE_2`, etc.) within a call.      |
| `aggressive`         | `boolean`                                     | `false`                  | Use expanded patterns to catch obfuscated PII (higher false-positive risk). |
| `enabledCategories`  | `Partial<Record<PiiCategory, boolean>>`       | —                        | Convenience map — only categories set to `true` are processed.           |

**Returns:** `AnonymizeResult` — `{ text: string; matches: PiiMatch[] }`

**Example:**

```ts
import { anonymize } from "anonyma";

// Default redact:
anonymize("Contact alice@example.com for help.").text;
// "Contact [REDACTED] for help."

// Global replacement — override all strategies:
anonymize("alice@example.com and 555-867-5309", { globalReplacement: "***" }).text;
// "*** and ***"

// Consistent token mapping:
anonymize("alice@example.com and alice@example.com", { consistentTokens: true }).text;
// "EMAIL_1 and EMAIL_1"

// Aggressive mode — catch obfuscated PII:
anonymize("user [at] example [dot] com", { aggressive: true }).text;
// "[REDACTED]"

// Enable only specific categories:
anonymize("alice@example.com — call 555-867-5309", {
  enabledCategories: { email: true },
}).text;
// "[REDACTED] — call 555-867-5309"

// Custom pattern:
anonymize("Order ACME-001234 confirmed.", {
  customPatterns: [{ pattern: /\bACME-\d{6}\b/g, label: "[ORDER_ID]" }],
  rules: [],
}).text;
// "Order [ORDER_ID] confirmed."
```

---

### `anonymizeObject`

```ts
anonymizeObject<T extends object>(obj: T, options?: AnonymizeOptions): T
```

Recursively walk every string value in a JSON-serializable object tree, applying
`anonymize()` to each one. Returns a **deep clone** — the input is never mutated.

Handles:
- Plain objects (nested to any depth)
- Arrays (including mixed-type arrays)
- `null`, `undefined`, numbers, booleans — passed through unchanged
- Circular references — throws `ValidationError`

| Parameter | Type            | Default  | Description                                     |
| --------- | --------------- | -------- | ----------------------------------------------- |
| `obj`     | `object`        | required | The root object to anonymize.                   |
| `options` | `AnonymizeOptions` | —     | Forwarded to `anonymize()` for each string.     |

**Example:**

```ts
import { anonymizeObject } from "anonyma";

anonymizeObject({
  user: { name: "Alice", email: "alice@example.com" },
  notes: ["Call 555-867-5309", "No PII here"],
  score: 42,
});
// {
//   user: { name: "Alice", email: "[REDACTED]" },
//   notes: ["[REDACTED]", "No PII here"],
//   score: 42,
// }

// Consistent tokens across all fields:
anonymizeObject(
  { a: "alice@example.com", b: "alice@example.com" },
  { consistentTokens: true },
);
// { a: "EMAIL_1", b: "EMAIL_1" }
```

---

### `anonymizeRecord`

```ts
anonymizeRecord<T extends Record<string, unknown>>(
  record: T,
  rules: FieldRuleMap
): T
```

Anonymize specific fields in a plain record/object. Supports dot-notation paths for
nested fields. Returns a **new** object — never mutates the input.

**Example:**

```ts
import { anonymizeRecord } from "anonyma";

anonymizeRecord(
  { name: "Alice", email: "alice@example.com", age: "27" },
  {
    email: { strategy: { strategy: "redact" } },
    age:   { strategy: { strategy: "generalize" } },
  }
);
// { name: "Alice", email: "[REDACTED]", age: "20-29" }

// Nested fields (dot notation):
anonymizeRecord(
  { user: { email: "alice@example.com", role: "admin" } },
  { "user.email": { strategy: { strategy: "mask" } } }
);
// { user: { email: "******************", role: "admin" } }
```

---

### `createAnonymizer`

```ts
createAnonymizer(config?: AnonymizerConfig): Anonymizer
```

Create a pre-configured, reusable anonymizer instance. Ideal for applications that
run many anonymization operations with the same settings.

**Config (`AnonymizerConfig`):**

| Field               | Type                                       | Default  | Description                                             |
| ------------------- | ------------------------------------------ | -------- | ------------------------------------------------------- |
| `categories`        | `PiiCategory[]`                            | all      | Categories to detect.                                   |
| `defaultStrategy`   | `StrategyOptions`                          | `redact` | Strategy applied to all matches.                        |
| `customDetectors`   | `Partial<Record<PiiCategory, Detector>>`   | —        | Override built-in detectors.                            |
| `customPatterns`    | `CustomPattern[]`                          | —        | Ad-hoc regex patterns.                                  |
| `globalReplacement` | `string`                                   | —        | Replace all PII with this string.                       |
| `consistentTokens`  | `boolean`                                  | `false`  | Enable consistent token mapping.                        |
| `aggressive`        | `boolean`                                  | `false`  | Use expanded detection patterns.                        |

**Anonymizer interface:**

| Method              | Signature                                                              | Description                                          |
| ------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------- |
| `anonymize`         | `(text, options?) → AnonymizeResult`                                   | Anonymize a string.                                  |
| `detect`            | `(text) → PiiMatch[]`                                                  | Detect PII without modifying.                        |
| `hasPII`            | `(text) → boolean`                                                     | Check for PII presence.                              |
| `anonymizeObject`   | `<T extends object>(obj: T, options?) → T`                             | Recursively anonymize an object tree.                |
| `anonymizeRecord`   | `<T extends Record<string, unknown>>(record: T, rules: FieldRuleMap) → T` | Field-level anonymization.                        |

**Example:**

```ts
import { createAnonymizer } from "anonyma";

const anonymizer = createAnonymizer({
  categories: ["email", "phone"],
  defaultStrategy: { strategy: "mask", keepLeading: 0, keepTrailing: 4 },
  consistentTokens: true,
});

anonymizer.anonymize("Call 555-867-5309 or email alice@example.com").text;
// "Call ****5309 or email ************.com"

anonymizer.hasPII("No PII here"); // false

anonymizer.anonymizeObject({ contact: "alice@example.com", score: 99 });
// { contact: "EMAIL_1", score: 99 }
```

---

## Strategies

### `mask`

```ts
mask(value: string, options?: MaskOptions): string
```

Replace interior characters with a mask character, optionally keeping visible
leading and/or trailing characters.

| Option        | Type     | Default | Description                               |
| ------------- | -------- | ------- | ----------------------------------------- |
| `maskChar`    | `string` | `"*"`   | Single-character mask. Must be length 1.  |
| `keepLeading` | `number` | `0`     | Characters to keep at the start.          |
| `keepTrailing`| `number` | `0`     | Characters to keep at the end.            |

```ts
import { mask } from "anonyma";

mask("alice@example.com");                               // "******************"
mask("alice@example.com", { keepLeading: 1, keepTrailing: 3 }); // "a**************com"
mask("4111-1111-1111-1111", { maskChar: "X", keepTrailing: 4 }); // "XXXXXXXXXXXXXXX1111"
```

---

### `redact`

```ts
redact(value: string, options?: RedactOptions): string
```

Replace the entire value with a label.

| Option  | Type     | Default        | Description                    |
| ------- | -------- | -------------- | ------------------------------ |
| `label` | `string` | `"[REDACTED]"` | The replacement text. Non-empty.|

```ts
import { redact } from "anonyma";

redact("alice@example.com");                      // "[REDACTED]"
redact("123-45-6789", { label: "[SSN REMOVED]" }); // "[SSN REMOVED]"
```

---

### `pseudonymize`

```ts
pseudonymize(value: string, options?: PseudonymizeOptions): string
```

Replace with a deterministic (seeded) or random pseudonym. Providing the same
`value + seed` always returns the same pseudonym.

> ⚠️ Not cryptographically secure. Use `hash` for irreversibility.

| Option   | Type     | Default  | Description                                    |
| -------- | -------- | -------- | ---------------------------------------------- |
| `seed`   | `string` | —        | When set, output is deterministic.             |
| `prefix` | `string` | `"id_"`  | Prepended to the pseudonym hex string.         |

```ts
import { pseudonymize } from "anonyma";

pseudonymize("alice@example.com", { seed: "my-secret" });
// "id_3a7f1c2b9e4d0f1a" (same on every run)

pseudonymize("alice@example.com");
// "id_e9a3f7d1..." (random on every run)
```

---

### `hash`

```ts
hash(value: string, options?: HashOptions): Promise<string>
```

One-way SHA-256 hash. Requires Node.js ≥ 18 or a Web Crypto polyfill.
Adding a `pepper` prevents rainbow-table attacks.

> ⚠️ **Sync pipeline fallback**: When used in the synchronous `anonymize()` pipeline,
> the hash strategy falls back to a deterministic pseudonym and emits a `console.warn`.
> Call `hash()` directly if you need true SHA-256 output.

| Option     | Type     | Default | Description                              |
| ---------- | -------- | ------- | ---------------------------------------- |
| `truncate` | `number` | `16`    | Number of hex chars to keep (1–64).      |
| `pepper`   | `string` | —       | Per-deployment secret mixed into hash.   |

```ts
import { hash } from "anonyma";

await hash("alice@example.com");
// "5f3e4b3a9c1d8f2a"
```

---

### `generalize`

```ts
generalize(value: string, options?: GeneralizeOptions): string
```

Replace a numeric value with a range bucket. Non-numeric values are passed through unchanged.

| Option       | Type     | Default | Description             |
| ------------ | -------- | ------- | ----------------------- |
| `bucketSize` | `number` | `10`    | Width of each bucket.   |

```ts
import { generalize } from "anonyma";

generalize("27");          // "20-29"
generalize("5", { bucketSize: 5 }); // "5-9"
```

---

## Detectors

Each detector is exported individually from `"anonyma/detectors"` for maximum tree-shaking.
Each category also has an `*Aggressive` variant with expanded patterns (lower confidence).

### Built-in Detectors

| Export              | Category        | Confidence | Method                        |
| ------------------- | --------------- | ---------- | ----------------------------- |
| `detectEmail`       | `email`         | 0.99       | Regex (RFC 5321)              |
| `detectPhone`       | `phone`         | 0.90       | Regex (multi-format)          |
| `detectSsn`         | `ssn`           | 0.95       | Regex + exclusions            |
| `detectCreditCard`  | `credit-card`   | 0.97       | Regex + Luhn                  |
| `detectIpv4`        | `ipv4`          | 0.98       | Regex                         |
| `detectIpv6`        | `ipv6`          | 0.98       | Regex                         |
| `detectUrl`         | `url`           | 0.95       | Regex (http/https only)       |
| `detectIban`        | `iban`          | 0.99       | Regex + MOD-97                |
| `detectDateOfBirth` | `date-of-birth` | 0.78–0.88  | Multi-pattern                 |
| `detectName`        | `name`          | 0.75       | Heuristic (greeting context)  |

> **Note on `detectName`:** Name detection is greeting-context only — it catches names
> preceded by keywords like `"Dear"`, `"Hi"`, `"Hello"`, etc. It is not an NLP-based
> named-entity recogniser. Single-word names and names without greeting context will
> not be detected in normal mode.

### Aggressive Variants

| Export                     | Adds over normal mode                              | Confidence |
| -------------------------- | -------------------------------------------------- | ---------- |
| `detectEmailAggressive`    | Obfuscated formats: `user [at] domain [dot] com`   | 0.75       |
| `detectPhoneAggressive`    | 7-digit local format: `555-1234`                   | 0.70       |
| `detectSsnAggressive`      | No-separator 9-digit: `123456789`                  | 0.80       |
| `detectCreditCardAggressive` | Masked format: `****-****-****-1234`             | 0.80       |
| `detectNameAggressive`     | Title prefixes: `Mr.`, `Mrs.`, `Dr.`, `Prof.`      | 0.65       |

### Registries

```ts
import { DETECTOR_REGISTRY, AGGRESSIVE_DETECTOR_REGISTRY } from "anonyma/detectors";

// Normal mode:
DETECTOR_REGISTRY.email("alice@example.com");

// Aggressive mode:
AGGRESSIVE_DETECTOR_REGISTRY.email("user [at] example [dot] com");
```

---

## Custom Patterns

Add arbitrary regex patterns to the detection pipeline alongside built-in detectors.

```ts
import { anonymize } from "anonyma";

anonymize("Order ACME-001234 confirmed.", {
  customPatterns: [
    {
      pattern: /\bACME-\d{6}\b/g,
      category: "order-id",   // optional label (defaults to "custom")
      confidence: 0.9,        // optional (defaults to 0.85)
      label: "[ORDER_ID]",    // replacement label (defaults to "[REDACTED]")
    },
  ],
  rules: [],
}).text;
// "Order [ORDER_ID] confirmed."
```

Custom pattern matches participate in the same overlap deduplication as built-in
detector matches. If the global flag is absent from the supplied `RegExp`, it is
added automatically.

---

## Error Classes

All errors extend `AnonymaError` and carry a `code` string for programmatic handling.

| Class                    | Code                    | When thrown                                          |
| ------------------------ | ----------------------- | ---------------------------------------------------- |
| `AnonymaError`           | (base class)            | Never thrown directly.                               |
| `ValidationError`        | `VALIDATION_ERROR`      | Invalid function argument (also exposes `.field`).   |
| `UnsupportedStrategyError`| `UNSUPPORTED_STRATEGY` | Unknown strategy name (also exposes `.strategy`).    |
| `UnknownCategoryError`   | `UNKNOWN_CATEGORY`      | Unknown PII category (also exposes `.category`).     |
| `CryptoNotAvailableError`| `CRYPTO_NOT_AVAILABLE`  | `globalThis.crypto.subtle` not available.            |

```ts
import { AnonymaError, ValidationError } from "anonyma";

try {
  mask("x", { keepLeading: -1 });
} catch (err) {
  if (err instanceof ValidationError) {
    console.error(`Bad field "${err.field}":`, err.message);
  }
}
```

---

## AI / MCP Integration

### OpenAI Function Calling

```ts
import {
  ANONYMIZE_TOOL_DEFINITION,
  DETECT_TOOL_DEFINITION,
  HAS_PII_TOOL_DEFINITION,
  ANONYMIZE_OBJECT_TOOL_DEFINITION,
} from "anonyma/schemas";
import OpenAI from "openai";

const client = new OpenAI();

const response = await client.chat.completions.create({
  model: "gpt-4o",
  tools: [
    { type: "function", function: ANONYMIZE_TOOL_DEFINITION },
    { type: "function", function: DETECT_TOOL_DEFINITION },
    { type: "function", function: HAS_PII_TOOL_DEFINITION },
    { type: "function", function: ANONYMIZE_OBJECT_TOOL_DEFINITION },
  ],
  messages: [{ role: "user", content: "Anonymize: 'Call me at 555-867-5309'" }],
});
```

### Runtime Validation with Zod

```ts
import { AnonymizeOptionsSchema } from "anonyma/schemas";
import { anonymize } from "anonyma";

// Validate untrusted input:
const parsed = AnonymizeOptionsSchema.parse(req.body);
const result = anonymize(req.body.text as string, parsed);
```

### Capability Manifest

```ts
import { ANONYMA_MANIFEST } from "anonyma/schemas";

// Provide to an AI system prompt for autonomous tool discovery:
const systemContext = JSON.stringify(ANONYMA_MANIFEST, null, 2);
```

---

## Types Reference

All types are exported from `"anonyma"` as type-only imports (zero runtime cost).

```ts
import type {
  PiiCategory,         // "email" | "phone" | "ssn" | ... | "name"
  PiiMatch,            // { category, value, start, end, confidence }
  StrategyOptions,     // Discriminated union of all strategy option shapes
  AnonymizeOptions,    // Options for anonymize()
  AnonymizeResult,     // { text: string; matches: PiiMatch[] }
  CustomPattern,       // { pattern: RegExp; category?; confidence?; label? }
  FieldRuleMap,        // Record<string, FieldRule>
  Anonymizer,          // Instance returned by createAnonymizer()
  AnonymizerConfig,    // Config for createAnonymizer()
  Detector,            // (text: string) => PiiMatch[]
} from "anonyma";
```



---

## Core Functions

### `detect`

```ts
detect(
  text: string,
  categories?: PiiCategory[],
  customDetectors?: Partial<Record<PiiCategory, Detector>>
): PiiMatch[]
```

Scan `text` for PII and return a sorted, de-duplicated array of matches — without
modifying the input.

| Parameter        | Type                      | Default       | Description                             |
| ---------------- | ------------------------- | ------------- | --------------------------------------- |
| `text`           | `string`                  | required      | The input string to scan.               |
| `categories`     | `PiiCategory[]`           | all           | Restrict scanning to these categories.  |
| `customDetectors`| `Partial<Record<...>>`    | —             | Override or extend built-in detectors.  |

**Returns:** `PiiMatch[]` — each entry includes `category`, `value`, `start`, `end`, `confidence`.

**Example:**

```ts
import { detect } from "anonyma";

detect("alice@example.com and 192.168.1.1");
// [
//   { category: "email", value: "alice@example.com", start: 0, end: 17, confidence: 0.99 },
//   { category: "ipv4",  value: "192.168.1.1",       start: 22, end: 33, confidence: 0.98 },
// ]
```

---

### `anonymize`

```ts
anonymize(text: string, options?: AnonymizeOptions): AnonymizeResult
```

Detect all PII in `text` and replace each match according to the configured strategy.
Operates in a single pass, applying replacements right-to-left to preserve offsets.

**Options (`AnonymizeOptions`):**

| Field             | Type                    | Default                      | Description                          |
| ----------------- | ----------------------- | ---------------------------- | ------------------------------------ |
| `defaultStrategy` | `StrategyOptions`       | `{ strategy: "redact" }`     | Strategy for all unmatched categories. |
| `rules`           | `AnonymizationRule[]`   | `[]`                         | Per-category strategy overrides.     |
| `includeMatches`  | `boolean`               | `false`                      | Populate `result.matches`.           |

**Returns:** `AnonymizeResult` — `{ text: string; matches: PiiMatch[] }`

**Example:**

```ts
import { anonymize } from "anonyma";

// Default redact:
anonymize("Contact alice@example.com for help.").text;
// "Contact [REDACTED] for help."

// Custom strategy per category:
anonymize("alice@example.com / 192.168.1.1", {
  rules: [
    { category: "email", strategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 } },
    { category: "ipv4",  strategy: { strategy: "redact", label: "[IP]" } },
  ],
}).text;
// "a***************com / [IP]"
```

---

### `anonymizeRecord`

```ts
anonymizeRecord<T extends Record<string, unknown>>(
  record: T,
  rules: FieldRuleMap
): T
```

Anonymize specific fields in a plain record/object. Supports dot-notation paths for
nested fields. Returns a **new** object — never mutates the input.

**Example:**

```ts
import { anonymizeRecord } from "anonyma";

anonymizeRecord(
  { name: "Alice", email: "alice@example.com", age: "27" },
  {
    email: { strategy: { strategy: "redact" } },
    age:   { strategy: { strategy: "generalize" } },
  }
);
// { name: "Alice", email: "[REDACTED]", age: "20-29" }

// Nested fields (dot notation):
anonymizeRecord(
  { user: { email: "alice@example.com", role: "admin" } },
  { "user.email": { strategy: { strategy: "mask" } } }
);
// { user: { email: "******************", role: "admin" } }
```

---

### `createAnonymizer`

```ts
createAnonymizer(config?: AnonymizerConfig): Anonymizer
```

Create a pre-configured, reusable anonymizer instance. Ideal for applications that
run many anonymization operations with the same settings.

**Config (`AnonymizerConfig`):**

| Field             | Type                              | Default         | Description                           |
| ----------------- | --------------------------------- | --------------- | ------------------------------------- |
| `categories`      | `PiiCategory[]`                   | all             | Categories to detect.                 |
| `defaultStrategy` | `StrategyOptions`                 | `redact`        | Strategy applied to all matches.      |
| `customDetectors` | `Partial<Record<PiiCategory, Detector>>` | —       | Override built-in detectors.          |

**Example:**

```ts
import { createAnonymizer } from "anonyma";

const anonymizer = createAnonymizer({
  categories: ["email", "phone"],
  defaultStrategy: { strategy: "mask", keepLeading: 0, keepTrailing: 4 },
});

anonymizer.anonymize("Call 555-867-5309 or email alice@example.com").text;
// "Call ****5309 or email ************.com"
```

---

## Strategies

### `mask`

```ts
mask(value: string, options?: MaskOptions): string
```

Replace interior characters with a mask character, optionally keeping visible
leading and/or trailing characters.

| Option        | Type     | Default | Description                               |
| ------------- | -------- | ------- | ----------------------------------------- |
| `maskChar`    | `string` | `"*"`   | Single-character mask. Must be length 1.  |
| `keepLeading` | `number` | `0`     | Characters to keep at the start.          |
| `keepTrailing`| `number` | `0`     | Characters to keep at the end.            |

```ts
import { mask } from "anonyma";

mask("alice@example.com");                               // "******************"
mask("alice@example.com", { keepLeading: 1, keepTrailing: 3 }); // "a**************com"
mask("4111-1111-1111-1111", { maskChar: "X", keepTrailing: 4 }); // "XXXXXXXXXXXXXXX1111"
```

---

### `redact`

```ts
redact(value: string, options?: RedactOptions): string
```

Replace the entire value with a label.

| Option  | Type     | Default        | Description                    |
| ------- | -------- | -------------- | ------------------------------ |
| `label` | `string` | `"[REDACTED]"` | The replacement text. Non-empty.|

```ts
import { redact } from "anonyma";

redact("alice@example.com");                      // "[REDACTED]"
redact("123-45-6789", { label: "[SSN REMOVED]" }); // "[SSN REMOVED]"
```

---

### `pseudonymize`

```ts
pseudonymize(value: string, options?: PseudonymizeOptions): string
```

Replace with a deterministic (seeded) or random pseudonym. Providing the same
`value + seed` always returns the same pseudonym.

> ⚠️ Not cryptographically secure. Use `hash` for irreversibility.

| Option   | Type     | Default  | Description                                    |
| -------- | -------- | -------- | ---------------------------------------------- |
| `seed`   | `string` | —        | When set, output is deterministic.             |
| `prefix` | `string` | `"id_"`  | Prepended to the pseudonym hex string.         |

```ts
import { pseudonymize } from "anonyma";

pseudonymize("alice@example.com", { seed: "my-secret" });
// "id_3a7f1c2b9e4d0f1a" (same on every run)

pseudonymize("alice@example.com");
// "id_e9a3f7d1..." (random on every run)
```

---

### `hash`

```ts
hash(value: string, options?: HashOptions): Promise<string>
```

One-way SHA-256 hash. Requires Node.js ≥ 18 or a Web Crypto polyfill.
Adding a `pepper` prevents rainbow-table attacks.

| Option     | Type     | Default | Description                              |
| ---------- | -------- | ------- | ---------------------------------------- |
| `truncate` | `number` | `16`    | Number of hex chars to keep (1–64).      |
| `pepper`   | `string` | —       | Per-deployment secret mixed into hash.   |

```ts
import { hash } from "anonyma";

await hash("alice@example.com");
// "5f3e4b3a9c1d8f2a"

await hash("alice@example.com", { truncate: 32, pepper: "my-pepper" });
// "5f3e4b3a..." (32 chars, pepper-salted)
```

---

### `generalize`

```ts
generalize(value: string, options?: GeneralizeOptions): string
```

Replace a numeric value with a range bucket. Non-numeric values are passed through unchanged.

| Option       | Type     | Default | Description             |
| ------------ | -------- | ------- | ----------------------- |
| `bucketSize` | `number` | `10`    | Width of each bucket.   |

```ts
import { generalize } from "anonyma";

generalize("27");          // "20-29"
generalize("72");          // "70-79"
generalize("5", { bucketSize: 5 }); // "5-9"
generalize("N/A");         // "N/A"  (passthrough)
```

---

## Detectors

Each detector is exported individually from `"anonyma/detectors"` for maximum tree-shaking.

| Export              | Category        | Confidence | Method            |
| ------------------- | --------------- | ---------- | ----------------- |
| `detectEmail`       | `email`         | 0.99       | Regex (RFC 5321)  |
| `detectPhone`       | `phone`         | 0.90       | Regex (multi-format)|
| `detectSsn`         | `ssn`           | 0.95       | Regex + exclusions|
| `detectCreditCard`  | `credit-card`   | 0.97       | Regex + Luhn      |
| `detectIpv4`        | `ipv4`          | 0.98       | Regex             |
| `detectIpv6`        | `ipv6`          | 0.98       | Regex             |
| `detectUrl`         | `url`           | 0.95       | Regex             |
| `detectIban`        | `iban`          | 0.99       | Regex + MOD-97    |
| `detectDateOfBirth` | `date-of-birth` | 0.78–0.88  | Multi-pattern     |
| `DETECTOR_REGISTRY` | all             | —          | Pre-built registry|

```ts
import { detectEmail, DETECTOR_REGISTRY } from "anonyma/detectors";

detectEmail("alice@example.com");
// [{ category: "email", value: "alice@example.com", ... }]

// Run all detectors:
const allMatches = Object.values(DETECTOR_REGISTRY)
  .flatMap(detector => detector("alice@example.com, IP: 10.0.0.1"));
```

---

## Error Classes

All errors extend `AnonymaError` and carry a `code` string for programmatic handling.

| Class                    | Code                    | When thrown                                          |
| ------------------------ | ----------------------- | ---------------------------------------------------- |
| `AnonymaError`           | (base class)            | Never thrown directly.                               |
| `ValidationError`        | `VALIDATION_ERROR`      | Invalid function argument (also exposes `.field`).   |
| `UnsupportedStrategyError`| `UNSUPPORTED_STRATEGY` | Unknown strategy name (also exposes `.strategy`).    |
| `UnknownCategoryError`   | `UNKNOWN_CATEGORY`      | Unknown PII category (also exposes `.category`).     |
| `CryptoNotAvailableError`| `CRYPTO_NOT_AVAILABLE`  | `globalThis.crypto.subtle` not available.            |

```ts
import { AnonymaError, ValidationError } from "anonyma";

try {
  mask("x", { keepLeading: -1 });
} catch (err) {
  if (err instanceof ValidationError) {
    console.error(`Bad field "${err.field}":`, err.message);
  }
}
```

---

## AI / MCP Integration

### OpenAI Function Calling

```ts
import { ANONYMIZE_TOOL_DEFINITION, DETECT_TOOL_DEFINITION } from "anonyma/schemas";
import OpenAI from "openai";

const client = new OpenAI();

const response = await client.chat.completions.create({
  model: "gpt-4o",
  tools: [
    { type: "function", function: ANONYMIZE_TOOL_DEFINITION },
    { type: "function", function: DETECT_TOOL_DEFINITION },
  ],
  messages: [
    { role: "user", content: "Anonymize: 'Call me at 555-867-5309'" },
  ],
});
```

### Runtime Validation with Zod

```ts
import { AnonymizeOptionsSchema } from "anonyma/schemas";
import { anonymize } from "anonyma";

// Validate untrusted input from an HTTP request body:
const parsed = AnonymizeOptionsSchema.parse(req.body);
const result = anonymize(req.body.text as string, parsed);
```

### Capability Manifest

```ts
import { ANONYMA_MANIFEST } from "anonyma/schemas";

// Provide to an AI system prompt for autonomous tool discovery:
const systemContext = JSON.stringify(ANONYMA_MANIFEST, null, 2);
```

---

## Types Reference

All types are exported from `"anonyma"` as type-only imports (zero runtime cost).

```ts
import type {
  PiiCategory,         // "email" | "phone" | "ssn" | ...
  PiiMatch,            // { category, value, start, end, confidence }
  StrategyOptions,     // Discriminated union of all strategy option shapes
  AnonymizeOptions,    // Options for anonymize()
  AnonymizeResult,     // { text: string; matches: PiiMatch[] }
  FieldRuleMap,        // Record<string, FieldRule>
  Anonymizer,          // Instance returned by createAnonymizer()
  AnonymizerConfig,    // Config for createAnonymizer()
  Detector,            // (text: string) => PiiMatch[]
} from "anonyma";
```
