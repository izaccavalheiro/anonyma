---
title: Objects and records
sidebar_position: 5
description: Clean whole JSON trees, apply rules to named fields, and configure an anonymizer once.
---

## Whole objects

`anonymizeObject()` walks a JSON tree — objects, arrays, nested values — and returns a cleaned copy.
Strings are anonymized; numbers, booleans, `null` and the shape are kept. The input is not changed.

```ts
import { anonymizeObject } from "anonyma";

anonymizeObject({ id: 42, email: "ana@example.com", tags: ["vip"] });
// { id: 42, email: "[REDACTED]", tags: ["vip"] }
```

It takes the same options as `anonymize()`: presets, rules, allowlists and so on.

## Named fields

When you know where the personal data is, `anonymizeRecord()` applies a rule to each field you name,
with dot paths for nested fields. Fields you do not name are left as they are.

```ts
import { anonymizeRecord } from "anonyma";

anonymizeRecord(
  { user: { email: "ana@example.com", age: "34" }, plan: "pro" },
  {
    "user.email": { strategy: { strategy: "mask", keepTrailing: 11 } },
    "user.age": { strategy: { strategy: "generalize" } },
  },
);
// { user: { email: "****example.com", age: "30-39" }, plan: "pro" }
```

## A reusable anonymizer

`createAnonymizer()` holds a configuration — categories, strategies, a preset, [plugins](plugins.md)
— and gives the same functions bound to it. Create it once, at start-up:

```ts
import { createAnonymizer } from "anonyma";

export const anonymizer = createAnonymizer({ preset: ["lgpd", "hipaa"] });

anonymizer.anonymize(note).text;
anonymizer.anonymizeObject(payload);
anonymizer.hasPII(comment);
```

## JSON for language models and APIs

For JSON on its way to a model or out of an API, `sanitizeJson()` in `anonyma/ai` runs a
[pipeline](engine.md) over every string, replaces the values of keys you name whole (`keyRules`),
leaves keys such as `role` alone (`skipKeys`), sanitizes JSON held in strings such as tool-call
arguments (`jsonStringKeys`), and reports what it replaced where, without the values.
`sanitizeJsonText()` does the same on JSON text and keeps every number exact, so a 20-digit ID comes
out unchanged. See [LLMs and AI tools](llm.md#json) and [HTTP middleware](middleware.md).
