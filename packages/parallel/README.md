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

Use the pool for batches of about a megabyte or more. Below that, anonyma's own batch functions,
which already scan short texts together, cost less than sending the texts to another thread.
