---
title: Run on the edge
sidebar_position: 4
description: Use anonyma in Cloudflare Workers, Deno, Bun, Vercel Edge and browsers.
---

The library uses only the Web platform — Web Crypto, WHATWG streams, `TextEncoder` — so the same
build runs everywhere. Every change is tested on Node.js, Bun, Deno and Cloudflare Workers (workerd,
without `nodejs_compat`).

## Cloudflare Workers

```ts
import { createScrubber } from "anonyma/middleware";

const scrubber = createScrubber({ spec: { preset: "gdpr" } });

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const upstream = await fetch(env.API_URL + new URL(request.url).pathname);
    return scrubber.response(upstream, "GET /api");
  },
};
```

JSON responses are scrubbed value by value, keeping their structure; text is scrubbed as a stream.

## Streams

```ts
import { compilePipeline, createPipelineStream } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "hipaa" });
const safe = response
  .body!.pipeThrough(new TextDecoderStream())
  .pipeThrough(createPipelineStream(pipeline));
```

A value split between two chunks is still found: the stream holds back a window long enough for
the longest value a detector can match.

## In the browser

Import it like any module. The [playground](/playground) is a page that does
exactly that, under a Content Security Policy that forbids every network connection.

## Keys on the edge

Hashing, encryption, HMAC and key derivation go through Web Crypto. Keys you derive with the key ring
of `anonyma/vault` are non-extractable `CryptoKey`s; keep their secrets in your platform's secret
store, never in configuration.
