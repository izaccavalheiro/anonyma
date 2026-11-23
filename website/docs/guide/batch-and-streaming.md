---
title: Batches and streams
sidebar_position: 9
description: Process arrays of texts without one failure stopping the rest, and anonymize streams of text.
---

## Batches

Each item is processed on its own: a failure is reported for that item and does not stop the batch.

```ts
import { anonymizeBatch, anonymizeBatchAsync, detectBatch, tokenizeBatch } from "anonyma";

const results = anonymizeBatch(["alice@example.com", "192.0.2.1", "123-45-6789"]);
for (const result of results) {
  if (result.ok) console.log(result.value.text);
  else console.error(`Item ${result.index} failed:`, result.error.message);
}

// Asynchronous strategies (hash), at most 10 items at a time
const hashed = await anonymizeBatchAsync(
  texts,
  { defaultStrategy: { strategy: "hash", pepper: "secret" } },
  10,
);

tokenizeBatch(texts, { format: "bracket" });
detectBatch(texts);
```

Without the third argument, `anonymizeBatchAsync()` processes every item at once.

### Many short texts

A call costs a fixed amount, whatever the length of the text. For log lines, rows or chat turns,
that fixed cost is most of the work, so pass them together rather than one call at a time:
`detectBatch()`, `anonymizeBatch()` and, in the span engine, `pipeline.scanBatch()` join texts under
8 KB, scan them once and split the results back by text. The results are exactly those of one call
per text, and short texts cost two to three times less.

```ts
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "gdpr" }); // compile once, reuse
const spans = pipeline.scanBatch(lines); // one array of spans per line, in order
```

`anonymizeBatchAsync()`'s third argument bounds how many asynchronous strategies run at once; the
detection itself runs on one thread either way.

## Streams

Which stream to use depends on how the text arrives.

### Text in arbitrary chunks

A network response, a file read in blocks, a model's streamed answer: a value can be split between
two chunks. `createPipelineStream()` from `anonyma/engine` holds back a window long enough for the
longest value a detector can match, so a split value is still found:

```ts
import { compilePipeline, createPipelineStream } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "hipaa" });
const safe = response
  .body!.pipeThrough(new TextDecoderStream())
  .pipeThrough(createPipelineStream(pipeline));
```

### Complete records

When every chunk is a whole record — a line of a log, a message from a queue — the streams of
`anonyma/stream` apply `anonymize()` or `tokenize()` to each chunk and emit its result:

```ts
import {
  createAnonymizeStream,
  createAnonymizeStreamAsync,
  createTokenizeStream,
} from "anonyma/stream";

const anonymized = ReadableStream.from(lines).pipeThrough(
  createAnonymizeStream({ defaultStrategy: { strategy: "mask" } }),
);
for await (const { text } of anonymized) console.log(text);

createAnonymizeStreamAsync({ preset: "hipaa" }); // asynchronous strategies
createTokenizeStream({ format: "bracket" }); // one mapping per chunk
```

These streams do not look across chunk boundaries: split text on line boundaries before piping it.

### Files

To scrub logs, CSV and JSON Lines files — gigabytes of them, in constant memory — use the
[command line](../packages/cli.md) or the recipe [Scrub logs and data files](../guides/scrub-files.md).
