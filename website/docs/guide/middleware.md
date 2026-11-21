---
title: HTTP middleware
sidebar_position: 14
description: Scrub personal data from API responses and request bodies in Express, Hono and any Fetch handler.
---

`anonyma/middleware` scrubs HTTP payloads with a [pipeline](engine.md): JSON value by value, keeping
its structure, and text as text. Neither adapter depends on its framework.

## Express

```ts
import express from "express";
import { anonymaExpress } from "anonyma/middleware/express";

const app = express();
app.use(express.json());

// Scrubs what res.json() and res.send() send and, with `request: true`, the parsed request body
app.use("/support", anonymaExpress({ spec: { preset: "gdpr" }, request: true }));
```

Enable `request` on routes that forward the body to a model, a log or a third party.

## Hono

`anonymaHono()` does the same on every runtime Hono supports. The scrubbed request body is available
as `c.get("anonymaBody")`:

```ts
import { Hono } from "hono";
import { anonymaHono } from "anonyma/middleware/hono";

const app = new Hono();
app.use("/support/*", anonymaHono({ spec: { preset: "gdpr" }, request: true }));

app.post("/support/tickets", (c) => c.json({ received: c.get("anonymaBody") }));
```

## Any Fetch handler

`createScrubber()` works on values, text and `Response` objects directly — in a Cloudflare Worker,
a Next.js route handler or a Deno server:

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

`scrubber.json(value, source)` and `scrubber.text(text, source)` scrub values you already hold. The
`source` names the route in audit records; use the route pattern (`/users/:id`), never the concrete
URL, which can itself hold personal data.

## Options

The adapters and `createScrubber()` take the same options:

| Option                  | What it does                                                          |
| ----------------------- | --------------------------------------------------------------------- |
| `spec` or `pipeline`    | What to detect and how to replace it                                  |
| `keyRules`              | Keys whose values are replaced whole, whatever they contain           |
| `keys`                  | `"replace"` (default) or `"flag"` object keys that hold personal data |
| `numberDigits`          | Integers with at least this many digits are scanned (default 12)      |
| `audit`, `actor`, `policyId` | Write an [audit record](audit.md) for each scrubbed payload      |
| `maxBodyLength`         | The largest text body, in characters (default 5,000,000); a larger one fails instead of passing unscrubbed |

For a step-by-step setup on the edge, see the recipe [Run on the edge](../guides/edge-runtimes.md).
