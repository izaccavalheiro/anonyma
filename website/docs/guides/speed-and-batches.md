---
title: Speed and batches
sidebar_position: 6
description: Which call to use for one prompt, many short texts or a large file, in TypeScript, Python, Go and through the sidecar.
---

Every call to anonyma pays a fixed cost before it reads the first character: the detectors start,
check what they need, and resolve what they found. On a 200-character log line that fixed cost is
most of the work. On a long document it hardly counts. So the right call depends on the shape of
your data more than on the language.

| Your data                                     | Use                                                   |
| --------------------------------------------- | ----------------------------------------------------- |
| One prompt or message at a time               | the single-text call (`detect`, `anonymize`, `scan`)  |
| Many short texts: log lines, rows, chat turns | a batch call: one call for the whole list             |
| Megabytes of texts, on a machine with cores   | a batch on every core: the worker pool, or Python/Go  |
| One large document or a stream                | the single-text call, or a stream for unbounded input |

Batch calls give exactly the results of one call per text. Texts under 8 KB are joined, scanned
once and split back, so the fixed cost is paid once per batch instead of once per text.

## TypeScript

```ts
import { anonymizeBatch, detectBatch } from "anonyma";
import { compilePipeline } from "anonyma/engine";

const results = anonymizeBatch(lines, { preset: "gdpr" }); // one result per line, in order
const found = detectBatch(lines);

const pipeline = compilePipeline({ preset: "gdpr" }); // compile once, reuse
const spans = pipeline.scanBatch(lines);
const cleaned = pipeline.transformBatch(lines);
```

On short log lines, `detectBatch()` and `pipeline.scanBatch()` take two to three times less time
than one call per line. Build a pipeline with `compilePipeline()` once and reuse it: compiling is
cheap, but it is work every call would repeat.

### Every core: anonyma-parallel

The batch functions run in the calling thread. For large batches, the companion package
`anonyma-parallel` cuts the batch into chunks and runs them on a pool of worker threads (Node.js, Bun,
Deno), with the same results in the same order:

```ts
import { createPool } from "anonyma-parallel";

const pool = createPool(); // one worker per core but one; create it once and keep it
const results = await pool.anonymizeBatch(lines, { preset: "gdpr" });
const found = await pool.detectBatch(lines);
await pool.close();
```

A batch under 8 KB runs in the calling thread, where it costs less than the trip to a worker;
`pool.explain(lines)` tells how a batch would run. Options cannot hold functions (custom detectors,
plugins, allow callbacks): those stay with anonyma's own batch functions.

## Python

```python
from anonyma import Anonyma

engine = Anonyma(presets="gdpr")          # build once, reuse
clean = engine.anonymize_batch(lines)     # list of strings, in order
found = engine.detect_batch(lines)        # one list of matches per line
```

A batch runs in one call with the GIL released, and spreads over every core of the machine. A
batch of two texts already costs less than two calls.

For a column of a dataframe, the helpers call `anonymize_batch` once for the whole column and keep
its index, nulls and non-string rows:

```python
from anonyma import Anonyma
from anonyma.pandas import anonymize_series  # or anonyma.polars

df["note"] = anonymize_series(df["note"], Anonyma(presets="gdpr"))
```

## Go

```go
engine, err := anonyma.NewEngine(anonyma.Options{Presets: []string{"gdpr"}})
if err != nil {
	return err
}
defer engine.Close()

clean, err := engine.AnonymizeBatch(lines) // one result per line, in order
```

An `Engine` is built once and is safe for concurrent use. Its batch methods take many texts in one
cgo call and spread them over every core. `NewReader` already sends the lines it has read in
batches, and still returns each line of an interactive stream at once.

## The sidecar

A request over loopback costs a few hundred microseconds of HTTP, whatever its size: more than
detecting a short text. Send lists to the batch endpoints:

```sh
curl -s localhost:7878/v1/anonymize/batch \
  -H 'content-type: application/json' \
  -d '{"texts": ["Mail ana@example.com", "No data here"], "preset": "gdpr"}'
```

The answer holds `results` in the order of `texts`, each what a request for that text alone would
return.

## Measured

On a 4-core laptop (Intel Core i5-8265U, 8 threads, Windows 11), 10,000 synthetic log lines of
about 200 bytes, finding every category:

| Call                                              | Per line |
| ------------------------------------------------- | -------: |
| TypeScript `detect()`, one call per line          |   147 µs |
| TypeScript `detectBatch()`                        |    59 µs |
| TypeScript, `anonyma-parallel` pool of 8 workers  |    15 µs |
| Python `detect`, one call per line                |    50 µs |
| Python `detect_batch`                             |   9.7 µs |
| Go `Detect`, one call per line                    |    69 µs |
| Go `Engine.DetectBatch`                           |    17 µs |
| Sidecar, one request per line                     |   299 µs |
| Sidecar `/v1/detect/batch`, 1,000 lines a request |    49 µs |

Absolute numbers depend on the machine. The ratios between rows are what carry over. The
[benchmarks](/benchmarks) have every engine on the same corpus, with the cost of a call by text size
and the speed-up per thread.
