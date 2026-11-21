---
title: Introduction
slug: /
sidebar_position: 1
---

**anonyma** finds personal data in text and JSON — e-mail addresses, phone numbers, card numbers,
national IDs and 23 other categories — and replaces it: with a label, a mask, a pseudonym, a
synthetic value, a hash, a ciphertext, or a reversible token that can be put back later.

It is a TypeScript library with **no runtime dependencies**. It runs in your process, on Node.js,
Bun, Deno, Cloudflare Workers and in browsers; nothing is sent anywhere. The
[playground](/playground) on this site is the library itself, running in your
browser.

```bash
npm install anonyma
```

```ts
import { anonymize } from "anonyma";

anonymize("Mail ana@example.com, CPF 529.982.247-25", { preset: ["lgpd", "gdpr"] }).text;
// "Mail [REDACTED], CPF [REDACTED]"
```

## What you can do with it

| You want to…                                         | Use                                                                         |
| ---------------------------------------------------- | --------------------------------------------------------------------------- |
| Clean a string or an object in one call              | `anonymize()`, `anonymizeObject()` — [Quick start](guide/quick-start.md)    |
| Follow a regulation, or several                      | presets, alone or combined — [Compliance presets](guide/presets.md)         |
| Send prompts to an LLM and get the real values back  | tokens and vaults — [Protect LLM prompts](guides/protect-llm-prompts.md)    |
| Clean logs, exports and data files; check them in CI | the `anonyma` command — [Scrub files](guides/scrub-files.md)                |
| Keep personal data out of API responses              | Express, Hono and Fetch middleware — [HTTP middleware](guide/middleware.md) |
| Build a pipeline once, reuse it, stream it           | `anonyma/engine` — [Span engine](guide/engine.md)                           |
| Keep data joinable, rotate keys, honour erasure      | keyed tokens — [Keys and token vaults](guide/vault.md)                      |
| Prove what was done                                  | audit chains and receipts — [Audit trail and receipts](guide/audit.md)      |

## Principles

- **The data stays where it is.** No network, file-system or process API in the library; CI checks
  it on every change, along with the absence of runtime dependencies.
- **Detection you can trust.** Validating detectors check digits (Luhn, mod-97, mod-11, CPF, CNPJ,
  …) and context, so version strings and order numbers are left alone, and no detected character is
  left in the output.
- **Edge first.** Web Crypto and WHATWG streams only; the build is tested on Bun, Deno and
  Cloudflare Workers.
- **Evidence without data.** Audit records and receipts say what was replaced, never what it was.

## Where next

- New to it: [Installation](guide/installation.md), then [Quick start](guide/quick-start.md).
- Have a task: the [recipes](guides/scrub-files.md).
- Learning a feature: the [library guide](guide/installation.md), topic by topic.
- Looking something up: the [API reference](reference/api.md), the [categories](reference/categories.md)
  and the [presets](reference/presets.md).
