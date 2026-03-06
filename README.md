# anonyma

> A modern, **zero-dependency** TypeScript library for PII detection and data anonymization — built for the AI era.

[![npm version](https://img.shields.io/npm/v/anonyma)](https://www.npmjs.com/package/anonyma)
[![CI](https://github.com/izaccavalheiro/anonyma/actions/workflows/ci.yml/badge.svg)](https://github.com/izaccavalheiro/anonyma/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)

---

## Features

- 🔍 **Detect 27 PII categories** — email, phone, SSN, credit card, IBAN, passport, address, VIN, API keys, crypto wallets, and more
- 🛡️ **8 anonymization strategies** — mask, redact, pseudonymize, hash (SHA-256), generalize, tokenize, encrypt (AES-GCM), synthesize
- 🔁 **Reversible tokenization** — `tokenize()` / `detokenize()` for round-trip fidelity
- 🤖 **LLM pipeline helpers** — `sanitizeForLLM()` / `restoreFromLLM()` for safe prompt injection with reversible tokens
- 📋 **Compliance presets** — built-in `gdpr`, `hipaa`, `ccpa`, `pci-dss`, `sox`, and `ferpa` presets
- 🌍 **Locale-aware detection** — locale flags for US, UK, EU, CA, AU, BR, IN, CN, JP, KR, ZA, and global
- ⚡ **Batch processing** — `anonymizeBatch()`, `anonymizeBatchAsync()`, `tokenizeBatch()`, `detectBatch()`
- 🌊 **Streaming support** — WHATWG `TransformStream` wrappers (`createAnonymizeStream()`, `createTokenizeStream()`)
- 🎯 **Field-level record anonymization** — dot-notation paths for nested objects
- 🌳 **Deep object anonymization** — `anonymizeObject()` recursively cleans entire JSON trees
- ✅ **PII presence check** — `hasPII()` with early-exit for fast gating
- 🔎 **Aggressive mode** — expanded, permissive patterns for obfuscated PII
- 🧩 **Custom patterns & detectors** — inject ad-hoc `RegExp` patterns or fully replace per-category detectors
- 🚫 **Allowlist support** — skip known-safe values by exact string or `RegExp` pattern
- 🔢 **Confidence threshold** — filter out low-confidence matches
- 🔌 **Plugin architecture** — extend detectors, strategies, and validators via `AnonymaPlugin`
- 🔒 **Encryption** — reversible AES-GCM `encrypt()` / `decrypt()` strategy (Web Crypto API)
- 🎭 **Synthesis** — format-preserving synthetic data replacement (deterministic, seeded)
- ✔️ **Checksum validators** — `luhn`, `verhoeff`, `nhsMod11`, `cpfChecksum`, `vinChecksum`, `deaChecksum`, `ibanMod97`, `ninoValid`, `aadhaarFormat` via `"anonyma/validators"`
- ⚡ **Zero runtime dependencies** — Zod is an optional peer dependency
- 🌲 **Tree-shakeable** — import only what you use
- 🤖 **AI-ready** — OpenAI/MCP tool definitions and Zod schemas included
- 📦 **Dual ESM + CJS** — works everywhere Node.js ≥ 18 runs
- 🔒 **Strict TypeScript** — no `any`, full declaration files

---

## Installation

```bash
npm install anonyma
# or
pnpm add anonyma
# or
yarn add anonyma
```

For runtime validation and AI schema features, also install the optional peer dependency:

```bash
npm install zod
```

---

## Quick Start

```ts
import {
  anonymize, anonymizeAsync, detect, hasPII,
  anonymizeObject, anonymizeRecord, createAnonymizer,
  tokenize, tokenizeAsync, detokenize, sanitizeForLLM, restoreFromLLM,
  anonymizeBatch, anonymizeBatchAsync,
} from "anonyma";

// ── Detect PII ─────────────────────────────────────────────────────────────
const matches = detect("Contact alice@example.com or call 555-867-5309.");
// [
//   { category: "email", value: "alice@example.com", start: 8,  end: 25, confidence: 0.99 },
//   { category: "phone", value: "555-867-5309",       start: 34, end: 46, confidence: 0.9  },
// ]

// ── Fast PII presence check (stops at first match) ─────────────────────────
if (hasPII(commentText)) {
  return { error: "Comment contains personal information." };
}

// ── Anonymize free text (default: redact all PII) ──────────────────────────
const { text } = anonymize("Contact alice@example.com or call 555-867-5309.");
// "Contact [REDACTED] or call [REDACTED]."

// ── Async anonymization (required for hash/encrypt strategies) ─────────────
const { text: hashed } = await anonymizeAsync("alice@example.com", {
  defaultStrategy: { strategy: "hash", pepper: "my-pepper" },
});
// "5f3e4b3a9c1d8f2a"

// ── Consistent token mapping ───────────────────────────────────────────────
anonymize("From alice@example.com (alice@example.com)", { consistentTokens: true }).text;
// "From EMAIL_1 (EMAIL_1)"

// ── Global replacement ─────────────────────────────────────────────────────
anonymize("alice@example.com — 555-867-5309", { globalReplacement: "***" }).text;
// "*** — ***"

// ── Aggressive mode — catch obfuscated PII ────────────────────────────────
anonymize("user [at] example [dot] com", { aggressive: true }).text;
// "[REDACTED]"

// ── Custom pattern ─────────────────────────────────────────────────────────
anonymize("Order ACME-001234 confirmed.", {
  customPatterns: [{ pattern: /\bACME-\d{6}\b/g, label: "[ORDER_ID]" }],
  rules: [],
}).text;
// "Order [ORDER_ID] confirmed."

// ── Deep object anonymization ──────────────────────────────────────────────
anonymizeObject({
  user: { email: "alice@example.com", phone: "555-867-5309" },
  notes: ["Call later", "IP: 192.168.1.1"],
});
// {
//   user: { email: "[REDACTED]", phone: "[REDACTED]" },
//   notes: ["Call later", "[REDACTED]"],
// }

// ── Custom strategy per category ───────────────────────────────────────────
const { text: masked } = anonymize("alice@example.com and 192.168.1.1", {
  rules: [
    { category: "email", strategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 } },
    { category: "ipv4",  strategy: { strategy: "redact", label: "[IP REMOVED]" } },
  ],
});
// "a***************com and [IP REMOVED]"

// ── Format-preserving mask ─────────────────────────────────────────────────
anonymize("123-45-6789", {
  rules: [{ category: "ssn", strategy: { strategy: "mask", preserveFormat: true } }],
}).text;
// "000-00-0000"

// ── Enable only specific categories ───────────────────────────────────────
anonymize("alice@example.com — call 555-867-5309", {
  enabledCategories: { email: true },
}).text;
// "[REDACTED] — call 555-867-5309"

// ── Allowlist — skip known-safe values ────────────────────────────────────
anonymize("noreply@company.com or alice@example.com", {
  allowlist: ["noreply@company.com"],
}).text;
// "noreply@company.com or [REDACTED]"

// ── Confidence threshold ──────────────────────────────────────────────────
anonymize("maybe a name here", { confidenceThreshold: 0.8 }).text;
// Low-confidence matches are left untouched

// ── Compliance presets ─────────────────────────────────────────────────────
anonymize(medicalNote, { preset: "hipaa" }).text;
anonymize(userData,    { preset: "gdpr"  }).text;

// ── Locale-aware detection ─────────────────────────────────────────────────
anonymize("NHS: 943 476 5919", { locales: ["uk"] }).text;
// "[REDACTED]"

// ── Anonymize object fields ─────────────────────────────────────────────────
anonymizeRecord(
  { name: "Alice", email: "alice@example.com", age: "27" },
  {
    email: { strategy: { strategy: "redact" } },
    age:   { strategy: { strategy: "generalize" } },  // 27 → "20-29"
  }
);
// { name: "Alice", email: "[REDACTED]", age: "20-29" }

// ── Reusable anonymizer ─────────────────────────────────────────────────────
const anonymizer = createAnonymizer({
  categories: ["email", "phone"],
  defaultStrategy: { strategy: "pseudonymize", seed: "my-secret" },
  consistentTokens: true,
});
anonymizer.anonymize("alice@example.com").text;
// "id_3a7f1c2b9e4d0f1a"
anonymizer.hasPII("no pii here"); // false

// ── Reversible tokenization ────────────────────────────────────────────────
const { text: tokenized, mapping } = tokenize("alice@example.com called 555-867-5309");
// text: "[EMAIL_0001] called [PHONE_0001]"
const { text: restored } = detokenize(tokenized, mapping);
// "alice@example.com called 555-867-5309"

// ── LLM pipeline — sanitize then restore ──────────────────────────────────
const { text: sanitized, mapping: llmMapping } = sanitizeForLLM("Send invoice to alice@example.com");
// "Send invoice to [EMAIL_0001]"
const llmResponse = await callLLM(sanitized);
const final = restoreFromLLM(llmResponse, llmMapping);
// Tokens in the LLM's response are swapped back to the original values

// ── Batch processing ───────────────────────────────────────────────────────
const results = anonymizeBatch(["alice@example.com", "192.0.2.1", "123-45-6789"]);
for (const r of results) {
  if (r.ok) console.log(r.value.text);
  else console.error(`Item ${r.index} failed:`, r.error.message);
}

// ── AES-GCM encryption (reversible) ───────────────────────────────────────
import { encrypt, decrypt } from "anonyma";
const ciphertext = await encrypt("alice@example.com", { passphrase: "s3cr3t" });
// "base64:<iv>:<ciphertext>"
const original = await decrypt(ciphertext, { passphrase: "s3cr3t" });
// "alice@example.com"

// ── Synthetic data replacement ────────────────────────────────────────────
anonymize("alice@example.com", {
  defaultStrategy: { strategy: "synthesize", seed: "project-x" },
}).text;
// "carol.smith42@example.com" (deterministic, structurally valid)
```

---

## Strategies

| Strategy       | Description                                                         | Async | Deterministic | Reversible |
|----------------|---------------------------------------------------------------------|:-----:|:-------------:|:----------:|
| `redact`       | Replace with `[REDACTED]` label (customizable)                      | ❌    | ✅            | ❌         |
| `mask`         | Replace inner chars with `*`; optional format-preserving mode       | ❌    | ✅            | ❌         |
| `pseudonymize` | Replace with a hex pseudonym (seeded or random)                     | ❌    | ✅†           | ❌         |
| `hash`         | SHA-256 one-way hash with optional pepper (Web Crypto)              | ✅    | ✅            | ❌         |
| `generalize`   | Replace numbers with a bucket range (e.g. `27` → `20-29`)          | ❌    | ✅            | ❌         |
| `tokenize`     | Replace with a reversible placeholder token                         | ❌    | ✅            | ✅         |
| `encrypt`      | AES-256-GCM encryption via passphrase or raw key (Web Crypto)       | ✅    | ❌‡           | ✅         |
| `synthesize`   | Format-preserving synthetic replacement (seeded, no real PII)       | ❌    | ✅†           | ❌         |

† Deterministic when `seed` is provided. ‡ Random IV per encryption; decryptable with the same key.

---

## Detected PII Categories

### Personal Information

| Category          | Examples                                    | Validator / Notes                   |
|-------------------|---------------------------------------------|-------------------------------------|
| `email`           | `alice@example.com`                         | RFC 5321 regex                      |
| `phone`           | `+1 (555) 867-5309`, `415.555.2671`         | Multi-format regex                  |
| `ssn`             | `123-45-6789`                               | Regex + exclusions                  |
| `name`            | `Dear Alice Smith`, `Patient: John Doe`     | Heuristic (greeting/title context)  |
| `date-of-birth`   | `1990-04-15`, `April 15, 1990`              | Multi-format regex                  |
| `address`         | `123 Main St, Springfield, IL 62701`        | Pattern + keyword heuristic         |
| `passport`        | `A12345678`, `P1234567`                     | Country-specific patterns           |
| `drivers-license` | `D123-4567-8901`, `F123-456-78-910-1`       | Multi-state/country patterns        |
| `national-id`     | Aadhaar, NHS number, NINO, CPF, etc.        | Country-specific patterns           |

### Financial

| Category           | Examples                                  | Validator / Notes                   |
|--------------------|-------------------------------------------|-------------------------------------|
| `credit-card`      | `4111 1111 1111 1111`                     | Luhn algorithm                      |
| `iban`             | `GB82 WEST 1234 5698 7654 32`             | MOD-97 (ISO 13616)                  |
| `bank-account`     | Routing + account number pairs            | Pattern regex                       |
| `cryptocurrency`   | BTC, ETH, XRP wallet addresses            | Format regex per chain              |
| `tax-id`           | EIN `12-3456789`, VAT `GB123456789`       | Multi-country patterns              |

### Healthcare

| Category          | Examples                                    | Validator / Notes                   |
|-------------------|---------------------------------------------|-------------------------------------|
| `medical-record`  | `MRN: 1234567`, `MR#00456789`               | Keyword + pattern                   |
| `health-insurance`| `Subscriber ID`, `Group/Member #`           | Pattern regex                       |
| `prescription`    | `Rx# 1234567`, DEA numbers                  | Pattern + DEA checksum              |

### Digital Identity

| Category       | Examples                                       | Validator / Notes            |
|----------------|------------------------------------------------|------------------------------|
| `ipv4`         | `192.168.1.1`, `10.0.0.0/8`                    | Octet-range regex            |
| `ipv6`         | `2001:0db8::8a2e:0370:7334`                    | Regex                        |
| `url`          | `https://example.com/path?q=1`                 | http/https (scheme-required) |
| `api-key`      | Bearer tokens, AWS keys, GitHub PATs, etc.     | Pattern regex per provider   |
| `social-media` | `@username`, profile URLs, handles             | Pattern regex                |

### Vehicles & Transportation

| Category          | Examples                              | Validator / Notes            |
|-------------------|---------------------------------------|------------------------------|
| `vin`             | `1HGCM82633A004352`                   | VIN checksum (pos 9)         |
| `license-plate`   | `ABC-1234`, `AB12CDE`                 | Multi-country patterns       |
| `tracking-number` | FedEx, UPS, USPS, DHL tracking codes  | Pattern regex per carrier    |

### Government & Legal

| Category              | Examples                              | Validator / Notes            |
|-----------------------|---------------------------------------|------------------------------|
| `case-number`         | `2023-CV-001234`, `CR-2022-5678`      | Pattern regex                |
| `company-registration`| EIN, CRN, SIREN, ABN, etc.            | Multi-country patterns       |

---

## Compliance Presets

Built-in presets pre-configure which categories are detected and which default strategy is applied.

| Preset     | Categories Covered                                                       | Default Strategy  |
|------------|--------------------------------------------------------------------------|-------------------|
| `gdpr`     | All personal, financial, healthcare, and digital identity categories     | `pseudonymize`    |
| `hipaa`    | All 18 HIPAA Safe Harbor PHI identifiers                                 | `redact`          |
| `ccpa`     | Consumer identifiers, financial data, online activity                    | `redact`          |
| `pci-dss`  | Credit card, cardholder name, bank account, address                      | `mask` (last 4)   |
| `sox`      | Financial identifiers for audit trails                                   | `redact`          |
| `ferpa`    | Student PII — name, SSN, DOB, address                                    | `redact`          |

```ts
import { anonymize, getPreset, PRESET_REGISTRY } from "anonyma";

// Apply a preset
anonymize(text, { preset: "hipaa" });

// Extend a preset — add API key detection on top of GDPR
anonymize(text, { preset: "gdpr", enabledCategories: { "api-key": true } });

// Inspect a preset's configuration
const hipaa = getPreset("hipaa");
console.log(hipaa.categories); // [...18 categories...]
```

---

## Reversible Tokenization

`tokenize()` replaces PII with opaque placeholder tokens and returns a mapping for lossless restoration.

```ts
import { tokenize, detokenize } from "anonyma";

const { text, mapping, tokens } = tokenize("alice@example.com called 555-867-5309", {
  format: "bracket",  // "[EMAIL_0001]", "[PHONE_0001]" (default)
  // format: "angle",   // "<Email_1>", "<Phone_1>" (LLM-friendly)
  // format: "custom", tokenTemplate: (cat, n) => `{{${cat}_${n}}}`,
  deterministic: true, // same value → same token (default: true)
});
// text: "[EMAIL_0001] called [PHONE_0001]"

const { text: restored } = detokenize(text, mapping);
// "alice@example.com called 555-867-5309"
```

---

## LLM Pipeline Helpers

Sanitize user input before sending it to a language model, then restore PII from the model's response.

```ts
import { sanitizeForLLM, restoreFromLLM } from "anonyma";

// 1. Replace PII with bracket tokens before the LLM sees it
const { text: prompt, mapping } = sanitizeForLLM("Send invoice to alice@example.com");
// prompt: "Send invoice to [EMAIL_0001]"

// 2. Call your LLM
const response = await callLLM(prompt);
// response: "I have sent the invoice to [EMAIL_0001]."

// 3. Restore original values in the LLM's response
const { text: final, unresolved } = restoreFromLLM(response, mapping);
// final: "I have sent the invoice to alice@example.com."
// unresolved: [] (any tokens the LLM dropped are reported here)
```

---

## Batch Processing

Process arrays of strings efficiently. Each item is independent — failures don't abort the batch.

```ts
import { anonymizeBatch, anonymizeBatchAsync, tokenizeBatch, detectBatch } from "anonyma";

// Sync batch
const results = anonymizeBatch(["alice@example.com", "192.0.2.1", "bad\x00input"]);
for (const r of results) {
  if (r.ok) console.log(r.value.text);
  else console.error(`Item ${r.index}:`, r.error.message);
}

// Async batch (supports hash/encrypt strategies, runs in parallel)
const asyncResults = await anonymizeBatchAsync(texts, {
  defaultStrategy: { strategy: "hash", pepper: "secret" },
  concurrency: 10,
});

// Batch tokenization
const tokenResults = tokenizeBatch(texts, { format: "bracket" });

// Batch detection only
const detections = detectBatch(texts);
```

---

## Streaming

Process data through WHATWG `TransformStream` pipelines (Node ≥ 18 / browsers with Streams API).

```ts
import {
  createAnonymizeStream,
  createAnonymizeStreamAsync,
  createTokenizeStream,
} from "anonyma/stream";

// Anonymize line by line
const readable = ReadableStream.from(lines);
const anonymized = readable.pipeThrough(
  createAnonymizeStream({ defaultStrategy: { strategy: "mask" } })
);
for await (const { text } of anonymized) {
  process.stdout.write(text + "\n");
}

// Async stream (for hash/encrypt strategies)
const asyncStream = createAnonymizeStreamAsync({ preset: "hipaa" });

// Tokenize stream
const tokenStream = createTokenizeStream({ format: "bracket" });
```

---

## Encryption Strategy

Reversible AES-256-GCM encryption using the Web Crypto API. Requires Node.js ≥ 18.

```ts
import { encrypt, decrypt } from "anonyma";

// Encrypt with a passphrase (key derived via PBKDF2)
const ciphertext = await encrypt("alice@example.com", { passphrase: "s3cr3t" });
// "base64:<iv>:<ciphertext>"

// Or supply raw key bytes (16 or 32 bytes for AES-128/256)
const ct = await encrypt("alice@example.com", { keyBytes: myKeyBytes, encoding: "hex" });

// Decrypt
const original = await decrypt(ciphertext, { passphrase: "s3cr3t" });
// "alice@example.com"

// Use as a strategy inside anonymize
const { text } = await anonymizeAsync("alice@example.com", {
  rules: [{ category: "email", strategy: { strategy: "encrypt", passphrase: "s3cr3t" } }],
});
```

---

## Synthesis Strategy

Replace PII with structurally valid, format-preserving synthetic data. Deterministic when a seed is provided.

```ts
import { synthesize } from "anonyma";
import { anonymize } from "anonyma";

synthesize("alice@example.com", { category: "email", seed: "project-x" });
// "carol.smith42@example.com"

anonymize("Call 555-867-5309 or email alice@example.com", {
  defaultStrategy: { strategy: "synthesize", seed: "my-seed" },
}).text;
// "Call +1-312-408-7291 or email bob.jones15@test.org"
```

---

## Validators

Standalone checksum and format validators are exported from `"anonyma/validators"`. They are used internally by detectors but can also be used directly.

```ts
import {
  luhn,         // Luhn (ISO/IEC 7812) — credit cards
  verhoeff,     // Verhoeff — Indian Aadhaar
  nhsMod11,     // NHS mod-11 — UK NHS numbers
  cpfChecksum,  // CPF — Brazilian tax IDs
  vinChecksum,  // VIN position-9 check digit
  deaChecksum,  // DEA number check — US prescriptions
  ibanMod97,    // MOD-97 — IBAN (ISO 13616)
  ninoValid,    // NINO format — UK National Insurance
  aadhaarFormat,// Aadhaar format — Indian national ID
} from "anonyma/validators";

luhn("4111111111111111");  // true
ibanMod97("GB82WEST12345698765432");  // true
nhsMod11("943-476-5919");   // true
```

---

## Plugin Architecture

Extend anonyma with custom detectors, strategies, and validators using `AnonymaPlugin`.

```ts
import { createAnonymizer } from "anonyma";
import type { AnonymaPlugin } from "anonyma";

const myPlugin: AnonymaPlugin = {
  name: "my-plugin",
  detectors: {
    // Override or add custom category detection
    "employee-id": (text) => {
      const matches = [];
      for (const m of text.matchAll(/\bEMP-\d{6}\b/g)) {
        matches.push({ category: "employee-id", value: m[0], start: m.index!, end: m.index! + m[0].length, confidence: 0.95 });
      }
      return matches;
    },
  },
};

const anonymizer = createAnonymizer({ plugins: [myPlugin] });
anonymizer.anonymize("Employee EMP-001234 called.").text;
// "Employee [REDACTED] called."
```

---

## AI Integration

### OpenAI / Anthropic Function Calling

```ts
import {
  ANONYMIZE_TOOL_DEFINITION,
  DETECT_TOOL_DEFINITION,
  HAS_PII_TOOL_DEFINITION,
  ANONYMIZE_OBJECT_TOOL_DEFINITION,
} from "anonyma/schemas";

// Pass directly to the tools array:
const response = await openai.chat.completions.create({
  model: "gpt-4o",
  tools: [
    { type: "function", function: ANONYMIZE_TOOL_DEFINITION },
    { type: "function", function: HAS_PII_TOOL_DEFINITION },
    { type: "function", function: ANONYMIZE_OBJECT_TOOL_DEFINITION },
  ],
  messages: [{ role: "user", content: "Anonymize: alice@example.com" }],
});
```

### MCP Tool Definition

```ts
import { ANONYMA_MANIFEST } from "anonyma/schemas";

// Use the capability manifest to let an AI agent discover anonyma's tools:
const manifest = ANONYMA_MANIFEST;
console.log(manifest.capabilities.anonymize.strategies);
```

### Runtime Validation with Zod

```ts
import { AnonymizeOptionsSchema } from "anonyma/schemas";
import { anonymize } from "anonyma";

// Validate untrusted input (e.g. from an HTTP request):
const opts = AnonymizeOptionsSchema.parse(req.body.options);
const result = anonymize(req.body.text as string, opts);
```

---

## Subpath Imports

| Import path              | Contents                                                                  |
|--------------------------|---------------------------------------------------------------------------|
| `"anonyma"`              | Core API — no Zod dependency                                              |
| `"anonyma/detectors"`    | All detectors + `DETECTOR_REGISTRY` + `AGGRESSIVE_DETECTOR_REGISTRY`     |
| `"anonyma/schemas"`      | Zod schemas, JSON schemas, AI/MCP tool definitions (requires `zod`)       |
| `"anonyma/validators"`   | Standalone checksum validators (Luhn, MOD-97, NHS, VIN, etc.)            |
| `"anonyma/stream"`       | WHATWG `TransformStream` wrappers (Node ≥ 18 / browsers)                 |
| `"anonyma/crypto"`       | Low-level Web Crypto utilities                                            |

---

## API Documentation

Full API reference: [docs/api.md](docs/api.md)

---

## Requirements

- **Node.js** ≥ 18 (for `hash`, `encrypt`, and streaming features — Web Crypto + `TransformStream`)
- TypeScript ≥ 5.0 (optional)
- Zod ≥ 3.23 (optional peer-dependency for `"anonyma/schemas"`)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
