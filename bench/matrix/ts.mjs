#!/usr/bin/env node
/**
 * bench/matrix/ts.mjs — the TypeScript engine's cells of the benchmark matrix,
 * on the built package (npm run build).
 *
 *   node bench/matrix/ts.mjs <corpus dir> <out.jsonl>
 *
 * Every harness of the matrix writes the same rows, one JSON object per line:
 * { engine, runtime, op, shape, entrySize, entries, threads, medianMs,
 *   perEntryUs, matches }. `shape` is "single" (one text), "each" (one call per
 * entry) or "batch" (one call for all entries); `medianMs` is the median time
 * of one run of the cell, `perEntryUs` that time divided by the entries.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [dir, out] = process.argv.slice(2);
if (dir === undefined || out === undefined) {
  console.error("usage: node bench/matrix/ts.mjs <corpus dir> <out.jsonl>");
  process.exit(2);
}
const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const lib = await import(pathToFileURL(join(root, "dist", "index.js")).href);

/** Median milliseconds of one run of `run`, over at least 5 runs and 300 ms. */
function median(run) {
  run();
  const samples = [];
  const start = performance.now();
  while (samples.length < 5 || (performance.now() - start < 300 && samples.length < 50)) {
    const t = performance.now();
    run();
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

const rows = [];
const row = (fields) => {
  const entries = fields.entries;
  rows.push({
    engine: "ts",
    runtime: `node ${process.versions.node}`,
    op: "detect",
    threads: 1,
    ...fields,
    perEntryUs: (fields.medianMs * 1000) / entries,
  });
  console.log(JSON.stringify(rows.at(-1)));
};

for (const name of ["1k", "100k", "1m"]) {
  const text = readFileSync(join(dir, `single-${name}.txt`), "utf8");
  const matches = lib.detect(text).length;
  row({
    shape: "single",
    entrySize: text.length,
    entries: 1,
    medianMs: median(() => lib.detect(text)),
    matches,
  });
}
const entries = JSON.parse(readFileSync(join(dir, "entries.json"), "utf8"));
const entrySize = Math.round(entries.reduce((n, e) => n + e.length, 0) / entries.length);
const each = entries.reduce((n, e) => n + lib.detect(e).length, 0);
row({
  shape: "each",
  entrySize,
  entries: entries.length,
  medianMs: median(() => entries.map((e) => lib.detect(e))),
  matches: each,
});
const batch = lib.detectBatch(entries).reduce((n, r) => n + (r.ok ? r.value.length : 0), 0);
row({
  shape: "batch",
  entrySize,
  entries: entries.length,
  medianMs: median(() => lib.detectBatch(entries)),
  matches: batch,
});

writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
