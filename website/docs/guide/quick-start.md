---
title: Quick start
sidebar_position: 2
description: Find personal data, replace it, follow a regulation, clean objects and get values back, in ten minutes.
---

Everything on this page comes from the main entry point:

```ts
import { anonymize, detect, hasPII } from "anonyma";
```

## 1. Find personal data

`detect()` reports what it finds, with offsets and a confidence, and does not change the text:

```ts
detect("Contact alice@example.com or call 555-867-5309.");
// [
//   { category: "email", value: "alice@example.com", start: 8,  end: 25, confidence: 0.99 },
//   { category: "phone", value: "555-867-5309",      start: 34, end: 46, confidence: 0.9  },
// ]
```

`hasPII()` stops at the first match, which makes it a cheap gate — for a comment form, a log line or
a test fixture:

```ts
hasPII("Call me at 555-867-5309"); // true
hasPII("Build 1.2.3 passed"); // false
```

## 2. Replace it

`anonymize()` detects all 27 [categories](../reference/categories.md) and redacts them by default:

```ts
anonymize("Contact alice@example.com or call 555-867-5309.").text;
// "Contact [REDACTED] or call [REDACTED]."
```

## 3. Choose how each category is replaced

Give a [strategy](strategies.md) per category. **Only the categories listed in `rules` are then
replaced** — see [Per-category rules](strategies.md#per-category-rules) to keep the others covered.

```ts
anonymize("alice@example.com and 192.168.1.1", {
  rules: [
    { category: "email", strategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 } },
    { category: "ipv4", strategy: { strategy: "redact", label: "[IP REMOVED]" } },
  ],
}).text;
// "a*************com and [IP REMOVED]"
```

## 4. Follow a regulation

A [preset](presets.md) chooses the categories and the strategies for you. Combine presets when data
falls under several regulations; each category gets the most protective strategy:

```ts
anonymize("Mail ana@example.com, CPF 529.982.247-25", { preset: ["lgpd", "gdpr"] }).text;
// "Mail [REDACTED], CPF [REDACTED]"
```

## 5. Clean objects

`anonymizeObject()` walks a JSON tree and returns a cleaned copy; numbers, booleans and the shape
are kept:

```ts
import { anonymizeObject } from "anonyma";

anonymizeObject({
  user: { email: "alice@example.com", phone: "555-867-5309" },
  notes: ["Call later", "IP: 192.168.1.1"],
});
// {
//   user: { email: "[REDACTED]", phone: "[REDACTED]" },
//   notes: ["Call later", "IP: [REDACTED]"],
// }
```

## 6. Configure once, reuse everywhere

```ts
import { createAnonymizer } from "anonyma";

const anonymizer = createAnonymizer({
  categories: ["email", "phone"],
  defaultStrategy: { strategy: "pseudonymize", seed: "my-secret" },
});
anonymizer.anonymize("alice@example.com").text; // "id_a908a815c8327f0b"
anonymizer.hasPII("no pii here"); // false
```

## 7. Get the values back

Tokens replace values reversibly. The mapping stays in your process, so you can send the text to a
language model or a third party and restore the answer:

```ts
import { restoreFromLLM, sanitizeForLLM } from "anonyma";

const { text: prompt, mapping } = sanitizeForLLM("Send the invoice to alice@example.com");
// "Send the invoice to [EMAIL_0001]"

const answer = await callYourModel(prompt); // "I sent it to [EMAIL_0001]."
restoreFromLLM(answer, mapping).text; // "I sent it to alice@example.com."
```

See [Reversible tokenization](tokenization.md) and [LLMs and AI tools](llm.md).

## 8. Hash and encrypt

Hashing and encryption use Web Crypto, which is asynchronous: use `anonymizeAsync()`.

```ts
import { anonymizeAsync } from "anonyma";

const { text } = await anonymizeAsync("alice@example.com", {
  defaultStrategy: { strategy: "hash", pepper: "my-pepper" },
});
// "e2a233272b2a9f2b"
```

## Two ways to call the library

The functions above are the simplest way in. For production pipelines, `anonyma/engine` compiles a
specification once and reuses it:

```ts
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "pci-dss" });
pipeline.transform("Refund 4111 1111 1111 1111 to ana@example.com").text;
// "Refund ***************1111 to [REDACTED]"
```

| You need…                                                         | Use                          |
| ----------------------------------------------------------------- | ---------------------------- |
| One call on a string or an object                                 | `anonymize()` and friends    |
| Detectors that check digits and leave look-alikes alone           | `compilePipeline()`          |
| `tokenize`, `encrypt` or `synthesize` as rules                    | `compilePipeline()`          |
| Streams where a value may be split between chunks                 | `createPipelineStream()`     |
| A configuration file, a policy, an audit record of what was done  | `compilePipeline()`          |

Read [Span engine](engine.md) next, or pick a task from the [recipes](../guides/scrub-files.md).
