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

## Python

```python
from anonyma import Anonyma

engine = Anonyma(presets="gdpr")          # build once, reuse
clean = engine.anonymize_batch(lines)     # list of strings, in order
found = engine.detect_batch(lines)        # one list of matches per line
```

A batch runs in one call with the GIL released, and spreads over every core of the machine.

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

On a 4-core laptop (Intel Core i5-8265U, Windows 11), with synthetic log lines of about 200
characters:

| Call                                          | Per line     |
| --------------------------------------------- | ------------ |
| Go `Detect`, one call per line                | 63–88 µs     |
| Go `Engine.DetectBatch`, 1,000 lines per call | 15.5 µs      |
| Go `NewReader`, 10,000 lines                  | 13–25 µs     |
| Sidecar, one request per line                 | about 450 µs |
| Sidecar `/v1/detect/batch`, 1,000 lines       | 35 µs        |

Absolute numbers depend on the machine. The ratios between rows are what carry over. The
[benchmarks](/benchmarks) show the TypeScript engine's throughput and scaling in detail.
