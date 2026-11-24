#!/usr/bin/env node
/**
 * bench/matrix/ts-pool.mjs — the TypeScript engine on a pool of worker threads
 * (anonyma-parallel), on the matrix's entries, in the rows every harness
 * writes. Needs the root build and the package's (npm run build in both).
 *
 *   node bench/matrix/ts-pool.mjs <corpus dir> <out.jsonl>
 *
 * The pool runs batches only: its rows are "batch" cells, one per pool size,
 * timed with the workers already started.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { availableParallelism } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [dir, out] = process.argv.slice(2);
if (dir === undefined || out === undefined) {
  console.error("usage: node bench/matrix/ts-pool.mjs <corpus dir> <out.jsonl>");
  process.exit(2);
}
const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const { createPool } = await import(
  pathToFileURL(join(root, "packages", "parallel", "dist", "index.js")).href
);

/** Median milliseconds of one run of `run`, over at least 5 runs and 300 ms. */
async function median(run) {
  await run();
  const samples = [];
  const start = performance.now();
  while (samples.length < 5 || (performance.now() - start < 300 && samples.length < 50)) {
    const t = performance.now();
    await run();
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

const entries = JSON.parse(readFileSync(join(dir, "entries.json"), "utf8"));
const entrySize = Math.round(entries.reduce((n, e) => n + e.length, 0) / entries.length);
const cores = availableParallelism();
const rows = [];
for (const threads of [...new Set([2, 4, cores])].filter((n) => n <= cores)) {
  const pool = createPool({ threads });
  const matches = (await pool.detectBatch(entries)).reduce(
    (n, r) => n + (r.ok ? r.value.length : 0),
    0,
  );
  const medianMs = await median(() => pool.detectBatch(entries));
  await pool.close();
  rows.push({
    engine: "ts-pool",
    runtime: `node ${process.versions.node}, anonyma-parallel`,
    op: "detect",
    shape: "batch",
    entrySize,
    entries: entries.length,
    threads,
    medianMs,
    perEntryUs: (medianMs * 1000) / entries.length,
    matches,
  });
  console.log(JSON.stringify(rows.at(-1)));
}
writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
