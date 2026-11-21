---
title: Plugins
sidebar_position: 16
description: Package detectors, strategies and validators of your own and give them to an anonymizer.
---

A plugin gives the anonymizer that `createAnonymizer()` creates detectors, strategies and validators
of its own:

- A **detector** replaces the built-in detector of its category. `customDetectors` take precedence
  over it.
- A **strategy** is named in rules and default strategies as `{ strategy, options }`, and receives
  the `options` as its second argument.
- A **validator** decides which matches of its category count: a match is anonymized only when every
  validator of its category accepts it.

```ts
import { createAnonymizer, type AnonymaPlugin } from "anonyma";
import { cpfChecksum } from "anonyma/validators";

const acme: AnonymaPlugin = {
  name: "acme",
  detectors: {
    "case-number": (text) =>
      [...text.matchAll(/\bACME-\d{6}\b/g)].map((m) => ({
        category: "case-number" as const,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence: 0.95,
      })),
  },
  strategies: {
    "keep-domain": (value, options) =>
      `${String(options?.["user"] ?? "[USER]")}@${value.slice(value.indexOf("@") + 1)}`,
  },
  validators: {
    // A CPF-shaped national ID counts only with the right check digits
    "national-id": (value) => !/^\d{3}\.\d{3}\.\d{3}-\d{2}$/.test(value) || cpfChecksum(value),
  },
};

const anonymizer = createAnonymizer({ plugins: [acme] });
anonymizer.anonymize("ACME-004211: alice@example.com, CPF 529.982.247-25, ref 529.982.247-26", {
  rules: [
    { category: "case-number", strategy: { strategy: "redact", label: "[CASE]" } },
    { category: "email", strategy: { strategy: "keep-domain" } },
    { category: "national-id", strategy: { strategy: "redact" } },
  ],
}).text;
// "[CASE]: [USER]@example.com, CPF [REDACTED], ref 529.982.247-26"
```

Plugins apply to the methods of their anonymizer only: `anonymize()` and the other standalone
functions do not use them. `createAnonymizer()` throws a `ValidationError` when two plugins have the
same name, register a detector for the same category or a strategy under the same name, or when a
strategy has the name of a built-in one.

For categories of your own, with their own names, use the [span engine](engine.md#your-own-formats).
