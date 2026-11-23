---
title: Anonymization strategies
sidebar_position: 4
description: The eight ways anonyma replaces a value, how to choose one, and where each one applies.
---

| Strategy       | Replaces a value with…                                         | Async | Deterministic | Reversible |
| -------------- | -------------------------------------------------------------- | :---: | :-----------: | :--------: |
| `redact`       | a label, `[REDACTED]` by default                               |  no   |      yes      |     no     |
| `mask`         | `*` in place of its characters, or format-preserving zeros     |  no   |      yes      |     no     |
| `pseudonymize` | a hex pseudonym, `id_…`                                        |  no   |   with seed   |     no     |
| `hash`         | a SHA-256 digest, with an optional pepper                      |  yes  |      yes      |     no     |
| `generalize`   | a range, `27` → `20-29`                                        |  no   |      yes      |     no     |
| `tokenize`     | a placeholder token, `[EMAIL_0001]`                            |  no   |      yes      |    yes     |
| `encrypt`      | an AES-256-GCM ciphertext                                      |  yes  | no (fresh IV) |  with key  |
| `synthesize`   | a realistic fake value of the same format                      |  no   |   with seed   |     no     |

## Which one to use

| When…                                                     | Use                       |
| --------------------------------------------------------- | ------------------------- |
| Nobody downstream needs the value                         | `redact`                  |
| A person needs a hint, such as the last four card digits  | `mask`                    |
| The text must still read naturally (demos, test data)     | `synthesize`              |
| Records must stay linkable without the value              | `pseudonymize` with a seed, or `hash` with a pepper |
| Ages, amounts and dates only matter as ranges             | `generalize`              |
| The value must come back later, as after an LLM call      | `tokenize`                |
| Someone authorised must be able to recover it             | `encrypt`                 |

Pseudonymized, hashed and tokenized data is usually still personal data under GDPR, since it can be
attributed with additional information. These strategies reduce risk; they do not take data out of
scope. The [regulation profiles](../reference/regulations.md) record which protection each
regulation requires of a strategy.

## Per-category rules

```ts
import { anonymize } from "anonyma";

anonymize("alice@example.com and 192.168.1.1", {
  rules: [
    { category: "email", strategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 } },
    { category: "ipv4", strategy: { strategy: "redact", label: "[IP REMOVED]" } },
  ],
}).text;
// "a*************com and [IP REMOVED]"
```

:::note

Without a preset, a non-empty `rules` list is also the list of categories to replace: a category
without a rule is left untouched, and `defaultStrategy` does not add categories. With a
[preset](presets.md), a rule changes the strategy of its category, or adds the category, and the
preset's other categories are still replaced:

```ts
anonymize("alice@example.com 555-867-5309", {
  preset: "gdpr",
  rules: [{ category: "email", strategy: { strategy: "mask" } }],
}).text;
// "***************** id_…" — the email masked, the phone pseudonymized by the preset
```

In 1.3.3 and earlier, the rules took the place of the preset's, and the phone was left in place.

:::

A few options change how values are written:

```ts
// Format-preserving mask: digits become 0, letters X or x, separators stay
anonymize("123-45-6789", {
  rules: [{ category: "ssn", strategy: { strategy: "mask", preserveFormat: true } }],
}).text;
// "000-00-0000"

// The same value gets the same placeholder
anonymize("From alice@example.com (alice@example.com)", { consistentTokens: true }).text;
// "From EMAIL_1 (EMAIL_1)"

// One replacement for everything
anonymize("alice@example.com — 555-867-5309", { globalReplacement: "***" }).text;
// "*** — ***"
```

## Where each strategy applies

The strategy functions — `mask()`, `redact()`, `pseudonymize()`, `hash()`, `generalize()`,
`encrypt()`, `synthesize()` — apply to a single value anywhere. As rules:

- **`compilePipeline()`** in `anonyma/engine` applies all eight. Use `transformAsync()` for `hash`
  and `encrypt`.
- **`anonymize()`** and the helpers built on it (`anonymizeObject()`, `anonymizeRecord()`,
  `createAnonymizer()`, the batch and stream functions) apply `redact`, `mask`, `pseudonymize` and
  `generalize`. `hash` applies in their asynchronous versions; the synchronous ones write a seeded
  pseudonym (`hsh_…`) instead. A value whose rule is `tokenize`, `encrypt` or `synthesize` is
  redacted, with a warning: use `tokenize()` or a pipeline.

## Hashing

```ts
import { anonymizeAsync } from "anonyma";

const { text } = await anonymizeAsync("alice@example.com", {
  defaultStrategy: { strategy: "hash", pepper: "my-pepper" },
});
// "e2a233272b2a9f2b"
```

Without a pepper, a hash of a value from a small set — a phone number, a national ID — can be
reversed by hashing every candidate. Keep the pepper secret, out of configuration files.

## Encryption

Reversible AES-256-GCM through Web Crypto. A passphrase is stretched with PBKDF2 (SHA-256, 100,000
iterations); every call draws a fresh 12-byte IV.

```ts
import { decrypt, encrypt } from "anonyma";

const ciphertext = await encrypt("alice@example.com", { passphrase: "s3cr3t" });
// "base64:<iv>:<ciphertext>"

// Or raw key bytes: 16 or 32 bytes for AES-128 or AES-256
const hex = await encrypt("alice@example.com", { keyBytes: myKeyBytes, encoding: "hex" });

await decrypt(ciphertext, { passphrase: "s3cr3t" }); // "alice@example.com"
```

In a pipeline, the key is passed apart from the specification, so the specification can live in a
configuration file:

```ts
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline(
  { rules: { email: { strategy: "encrypt" } } },
  { encryption: { passphrase: "s3cr3t" } },
);
const { text } = await pipeline.transformAsync("Mail alice@example.com");
// "Mail base64:<iv>:<ciphertext>"
```

To rotate keys and keep values recoverable by token instead, see [Keys and token vaults](vault.md).

## Synthesis

Replaces a value with a fake of the same kind and format, so that test data and demos keep reading
naturally. Where a reserved range exists, the fake comes from it: email addresses at `example.com`,
IPv4 addresses in `192.0.2.0/24`. Synthetic card numbers are not made to pass the Luhn check, so they
are not real cards. With a seed, the same input always gives the same output.

```ts
import { synthesize } from "anonyma";
import { compilePipeline } from "anonyma/engine";

synthesize("alice@example.com", "email", { seed: "project-y" });
// "olivia.williams47@example.com"

compilePipeline({ defaultStrategy: { strategy: "synthesize", seed: "project-z" } }).transform(
  "Call 555-867-5309 or email alice@example.com",
).text;
// "Call +1-297-841-6744 or email wendy.clark9@example.com"
```

## Your own strategies

A [plugin](plugins.md) can add strategies, named in rules like the built-in ones.
