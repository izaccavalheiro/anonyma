# anonyma

> Find personal data in text and JSON, and replace it before it leaks — into logs, LLM prompts, API
> responses or test fixtures.

[![npm version](https://img.shields.io/npm/v/anonyma)](https://www.npmjs.com/package/anonyma)
[![CI](https://github.com/izaccavalheiro/anonyma/actions/workflows/ci.yml/badge.svg)](https://github.com/izaccavalheiro/anonyma/actions/workflows/ci.yml)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](vitest.config.ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-site-blue)](https://izaccavalheiro.github.io/anonyma/)

anonyma is a TypeScript library with **no runtime dependencies**. It detects 27 kinds of personal
and sensitive data — email addresses, phone numbers, payment cards, IBANs, national and tax IDs of
many countries, health identifiers, API keys — and replaces them with a label, a mask, a pseudonym,
a hash, a ciphertext, a realistic fake, or a token you can turn back into the original value. It
runs in your process on Node.js, Bun, Deno, Cloudflare Workers and in browsers, and sends nothing
anywhere.

**[Documentation](https://izaccavalheiro.github.io/anonyma/docs)** ·
[Quick start](https://izaccavalheiro.github.io/anonyma/docs/guide/quick-start) ·
[Playground](https://izaccavalheiro.github.io/anonyma/playground) ·
[API reference](https://izaccavalheiro.github.io/anonyma/docs/reference/api) ·
[Releases](https://izaccavalheiro.github.io/anonyma/docs/project/releases) ·
[Changelog](CHANGELOG.md)

## Install

```bash
npm install anonyma
```

## Quick start

```ts
import { anonymize, detect } from "anonyma";

detect("Contact alice@example.com or call 555-867-5309.");
// [{ category: "email", value: "alice@example.com", start: 8, end: 25, confidence: 0.99 }, …]

anonymize("Contact alice@example.com or call 555-867-5309.").text;
// "Contact [REDACTED] or call [REDACTED]."

// Follow one or more regulations: GDPR, LGPD, HIPAA, PCI DSS, CCPA, PIPEDA, SOX, FERPA
anonymize("Mail ana@example.com, CPF 529.982.247-25", { preset: ["lgpd", "gdpr"] }).text;
// "Mail [REDACTED], CPF [REDACTED]"
```

## Where it helps

**Prompts to a language model.** Replace personal data with tokens before the prompt leaves, and
put the real values back in the answer. The mapping never leaves your process.

```ts
import { restoreFromLLM, sanitizeForLLM } from "anonyma";

const { text: prompt, mapping } = sanitizeForLLM("Send the invoice to alice@example.com");
// "Send the invoice to [EMAIL_0001]"

const answer = await callYourModel(prompt); // "I sent it to [EMAIL_0001]."
restoreFromLLM(answer, mapping).text; // "I sent it to alice@example.com."
```

**Logs, exports and fixtures.** The command line scrubs text, CSV and JSON Lines of any size in
constant memory, and fails a CI job when a file holds personal data.

```bash
npm install --global anonyma-cli anonyma

anonyma scrub app.log -o app.safe.log
anonyma scan fixtures/customers.csv --fail-on-pii
```

**And the rest of the day-to-day:**

| You need to…                                              | Use                                                                       |
| --------------------------------------------------------- | ------------------------------------------------------------------------- |
| Clean a JSON object, or named fields of a record          | [`anonymizeObject()`, `anonymizeRecord()`][objects]                       |
| Scrub API responses and request bodies                    | [Express, Hono and Fetch middleware][middleware]                          |
| Sanitize chat messages, tool calls and streamed answers   | [`anonyma/ai`][llm], [Vercel AI SDK middleware][vercel], [MCP proxy][mcp] |
| Keep test data realistic without real people in it        | the [`synthesize` strategy][strategies]                                   |
| Keep datasets joinable, rotate keys, honour erasure       | [keyed tokens and key rings][vault]                                       |
| Detect formats of your own, with check digits and context | [custom patterns and detectors][detection]                                |
| Prove what was anonymized, without keeping the data       | [hash-chained audit log and signed receipts][audit]                       |

[objects]: https://izaccavalheiro.github.io/anonyma/docs/guide/objects
[middleware]: https://izaccavalheiro.github.io/anonyma/docs/guide/middleware
[llm]: https://izaccavalheiro.github.io/anonyma/docs/guide/llm
[vercel]: https://izaccavalheiro.github.io/anonyma/docs/packages/vercel-ai
[mcp]: https://izaccavalheiro.github.io/anonyma/docs/packages/mcp
[strategies]: https://izaccavalheiro.github.io/anonyma/docs/guide/strategies
[vault]: https://izaccavalheiro.github.io/anonyma/docs/guide/vault
[detection]: https://izaccavalheiro.github.io/anonyma/docs/guide/detection
[audit]: https://izaccavalheiro.github.io/anonyma/docs/guide/audit

## Why anonyma

- **Your data stays where it is.** No network, file-system or process code, and no runtime
  dependencies; CI checks both on every change.
- **Detection you can trust.** The validating pipelines of `anonyma/engine` confirm card numbers,
  IBANs, CPFs and many national IDs by their check digits, so look-alikes such as version strings
  and order numbers are left alone.
- **One library for the whole job.** 27 categories, 8 strategies and 8 compliance presets that
  combine, plus reversible tokens, streams, batches and regulation profiles with citations.
- **Runs everywhere.** Web platform APIs only, tested on Node.js, Bun, Deno and Cloudflare Workers;
  ESM and CommonJS; tree-shakeable.
- **Strict TypeScript.** Full declarations, no `any`, and a 100% test coverage gate.

## Packages

| Package                                          | What it does                                                               |
| ------------------------------------------------ | -------------------------------------------------------------------------- |
| `anonyma`                                        | The library                                                                |
| [`anonyma-cli`](packages/cli#readme)             | The `anonyma` command: scrub and scan files as streams                     |
| [`anonyma-vercel-ai`](packages/vercel-ai#readme) | Vercel AI SDK middleware: prompts tokenized, answers restored              |
| [`anonyma-mcp`](packages/mcp#readme)             | A privacy proxy for any MCP server: tool results reach the model as tokens |
| [`anonyma-parallel`](packages/parallel#readme)   | The batch functions on a pool of worker threads: every core, same results  |
| [`anonyma-native`](bindings/node#readme)         | An opt-in engine on the Rust core for Node.js, faster on batches           |

Outside JavaScript, the same detectors run in Python (`pip install --pre anonyma`) and in Go
(`github.com/izaccavalheiro/anonyma-go`), on a Rust core that a shared conformance suite checks
against this library, and in any language over HTTP through the sidecar container
(`ghcr.io/izaccavalheiro/anonyma-sidecar`), which serves the library itself. See
[other languages](https://izaccavalheiro.github.io/anonyma/docs/guides/other-languages).

## Status

The library is stable: it has followed semantic versioning since 1.0.0, and the
[changelog](CHANGELOG.md) records every release with what changed and why. The companion packages
are at 0.x, where a minor version may change their API, and the Python and Go packages are alphas.
The [releases page](https://izaccavalheiro.github.io/anonyma/docs/project/releases) lists the latest
version of every package, the [blog](https://izaccavalheiro.github.io/anonyma/blog) walks through
the releases, and [history and decisions](docs/history.md) tells how the project got here, why it is
built the way it is, and what it learned on the way.

## Learn more

The [documentation site](https://izaccavalheiro.github.io/anonyma/) is the reference for everything
anonyma does: the [library guide](https://izaccavalheiro.github.io/anonyma/docs/guide/installation),
task-by-task [recipes](https://izaccavalheiro.github.io/anonyma/docs/guides/scrub-files), the
[API reference](https://izaccavalheiro.github.io/anonyma/docs/reference/api), a
[playground](https://izaccavalheiro.github.io/anonyma/playground) that runs the library in your
browser, and [benchmarks](https://izaccavalheiro.github.io/anonyma/benchmarks).

anonyma is a technical measure. It helps you protect personal data; it is not legal advice, and it
does not make a system compliant on its own.

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as
described in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
