# anonyma-parallel

Run [anonyma](https://github.com/izaccavalheiro/anonyma)'s batch functions on every core. A pool
of worker threads cuts a large batch into chunks of about 256 KB, runs each chunk with anonyma's own
batch function in a worker, and returns the results in input order: what the function returns in
one thread, faster on a machine with several cores.

```sh
npm install anonyma anonyma-parallel
```

```ts
import { createPool } from "anonyma-parallel";

const pool = createPool(); // one worker per core but one; workers start on first use
const results = await pool.anonymizeBatch(lines, { preset: "gdpr" }); // as anonymizeBatch()
const found = await pool.detectBatch(lines); // as detectBatch()
const spans = await pool.scanBatch(lines, { preset: "gdpr" }); // as compilePipeline(spec).scanBatch()
await pool.close();
```

- **The same results.** Each worker runs anonyma itself; entries keep their order and their `index`.
- **Options cross to the workers.** They must not hold functions: custom detectors, plugins and
  allow callbacks are refused with a `PoolOptionsError`; call anonyma directly for those.
- **Idle workers do not keep the process alive.** `close()` stops them.
- **Runtimes:** Node.js 18.3+, Bun and Deno (`node:worker_threads`). Cloudflare Workers and
  browsers have no threads: use anonyma's batch functions directly there.

## When the pool pays off

A batch under 8 KB runs in the calling thread: there it costs less than the round trip to a worker
(about 0.1 ms), and the result is the same. From there the pool wins, more with the batch's size.
`detectBatch()` of 200-character log lines on a 4-core laptop (Intel Core i5-8265U, 8 threads):

| Batch            | In one thread | Pool of 3 | Pool of 7 |
| ---------------- | ------------: | --------: | --------: |
| 64 lines, 13 KB  |        3.0 ms |    2.7 ms |    2.7 ms |
| 256 lines, 51 KB |         15 ms |    9.0 ms |    5.1 ms |
| 4,096, 0.8 MB    |        227 ms |    122 ms |     67 ms |
| 20,000, 4 MB     |         1.2 s |    0.58 s |    0.34 s |

The first call starts the workers, about 65 ms each on that machine: create one pool and keep it.
`pool.explain(texts)` tells how a batch would run, and `createPool({ inlineBelow })` moves the
threshold (`0` sends every batch to the workers, to keep the calling thread free).
