---
title: Audit trail and receipts
sidebar_position: 12
description: Record what was anonymized, under which policy, without recording the data — and prove it later.
---

`anonyma/audit` keeps evidence of what was done, never of what the data was.

- An **audit log** is a chain of records, one per operation, kept on your side.
- A **receipt** travels with the data: a signed statement that a text was anonymized.

## Audit log

A record says what was replaced — fields, categories, detectors, rules, counts — and never the
values. Each record's hash covers the one before it, so removing, reordering or editing a record
breaks the chain; with a key, the hash is an HMAC. When a sink fails, the logger stops rather than
leave a gap.

```ts
import { createAuditLogger, memorySink, summarizeSpans, verifyAuditChain } from "anonyma/audit";
import { compilePipeline } from "anonyma/engine";

const sink = memorySink();
const audit = createAuditLogger({ sinks: [sink] });

const { spans } = compilePipeline({ preset: "hipaa" }).transform(note);
await audit.record({
  operation: "anonymize",
  policy: { id: "hipaa" },
  fields: summarizeSpans(spans, { rule: "redact" }),
});

(await verifyAuditChain(sink.records())).ok; // true
```

`lineSink(write)` writes each record as a line of JSON wherever `write` sends it — a file, a log
service — and `parseAuditLog()` reads those lines back for verification.

## Receipts

A receipt says when a text was anonymized, under which presets and policy, and how many values of
each category were replaced, with a digest of the output. It holds counts and digests, never a
value, so it can be stored with the data or handed to an auditor. Its HMAC-SHA-256 signature fails
if anything in it changes, or if it was not issued with your key.

```ts
import { createReceiptIssuer } from "anonyma/audit";
import { compilePipeline } from "anonyma/engine";

const receipts = createReceiptIssuer({ key: env.RECEIPT_KEY, presets: "lgpd" });

const result = compilePipeline({ preset: "lgpd" }).transform(text);
const receipt = await receipts.issue(result, { input: text });
// { v: 1, id, timestamp: "2026-11-21T10:00:00.000Z", library: "anonyma@1.3.0",
//   presets: ["lgpd"], stats: { email: 2, "national-id": 1 }, total: 3,
//   output: <SHA-256 of result.text>, input: <HMAC of text>, alg: "HMAC-SHA-256", signature }

(await receipts.verify(receipt, { output: result.text })).valid; // true
```

The key is a `CryptoKey` or a string of at least 32 random bytes, encoded. The
[command line](../packages/cli.md) issues the same receipts with `--receipt`.
