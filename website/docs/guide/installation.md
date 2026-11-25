---
title: Installation
sidebar_position: 1
description: Install anonyma, check the requirements, and find the entry point for each feature.
---

```bash
npm install anonyma
# or
pnpm add anonyma
# or
yarn add anonyma
```

The package has no runtime dependencies. Zod is an optional peer dependency, needed only for the
schemas in `anonyma/schemas`:

```bash
npm install zod
```

## Requirements

- **A JavaScript runtime with the Web platform**: Node.js 18 or later, Bun, Deno, Cloudflare
  Workers or a browser. The library uses Web Crypto, WHATWG streams and `TextEncoder`, and no
  Node.js module. On Node.js 18, which has no global `crypto`, it loads `node:crypto` lazily. CI
  runs the same feature checks on every one of these runtimes; Workers run them without
  `nodejs_compat`.
- **TypeScript 5.0 or later** (optional). The package ships full declarations and is written
  without `any`.
- **Zod 3.25.4 or later, or Zod 4** (optional), for `anonyma/schemas`. It imports the `zod/v3`
  entry point that both provide, so its types are the same with either.

The package is published as ESM and CommonJS, and is tree-shakeable: import only what you use.

## Entry points

Start with `anonyma`. The other entry points add features you can adopt one at a time.

| Import                 | What it gives you                                                                          | Guide                                             |
| ---------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| `anonyma`              | `detect()`, `anonymize()`, objects, tokens, presets, batches, strategies, errors           | [Quick start](quick-start.md)                     |
| `anonyma/engine`       | Compiled pipelines with validating detectors, every strategy, chunk-safe streams           | [Span engine](engine.md)                          |
| `anonyma/vault`        | Session, keyed and sealed tokenizers, a key ring with rotation, token vaults               | [Keys and token vaults](vault.md)                 |
| `anonyma/ai`           | Chat-message and JSON sanitizers, restoration of complete and streamed model output        | [LLMs and AI tools](llm.md)                       |
| `anonyma/audit`        | A hash-chained audit log without personal data, signed receipts                            | [Audit trail and receipts](audit.md)              |
| `anonyma/compliance`   | Regulation profiles with citations, a policy parser, erasure planning                      | [Regulations and policies](compliance.md)         |
| `anonyma/middleware`   | Scrubbing of HTTP payloads; adapters in `anonyma/middleware/express` and `…/hono`          | [HTTP middleware](middleware.md)                  |
| `anonyma/mcp`          | A Model Context Protocol server without dependencies                                       | [LLMs and AI tools](llm.md#mcp-server)            |
| `anonyma/stream`       | WHATWG `TransformStream` wrappers around `anonymize()` and `tokenize()`                    | [Batches and streams](batch-and-streaming.md)     |
| `anonyma/validators`   | Checksum validators: Luhn, mod-97, mod-11, CPF, CNPJ and more                              | [Checksum validators](validators.md)              |
| `anonyma/detectors`    | Every detector, and the registries that hold them                                          | [Detecting personal data](detection.md)           |
| `anonyma/schemas`      | Zod schemas, function-calling tool definitions and a capability manifest (needs Zod)       | [LLMs and AI tools](llm.md#tool-definitions)      |
| `anonyma/crypto`       | Low-level Web Crypto helpers                                                               | [API reference](../reference/api.md)              |

## Companion packages

Five packages are published separately, each with a version of its own. The first four take
`anonyma` as a peer dependency:

- [`anonyma-cli`](../packages/cli.md) — the `anonyma` command, to scrub and scan files of any size;
- [`anonyma-vercel-ai`](../packages/vercel-ai.md) — middleware for the Vercel AI SDK;
- [`anonyma-mcp`](../packages/mcp.md) — a privacy proxy for any MCP server;
- [`anonyma-parallel`](../packages/parallel.md) — the batch functions on a pool of worker threads;
- [`anonyma-native`](../packages/native.md) — detection and anonymization on anonyma's Rust core,
  prebuilt for Linux, macOS and Windows: an opt-in engine, faster when every category is detected
  and on batches.

For Python, Go and other languages, see [Other languages](../guides/other-languages.md). The
[releases page](../project/releases.md) lists the latest version of every package.
