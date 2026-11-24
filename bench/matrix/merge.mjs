#!/usr/bin/env node
/**
 * bench/matrix/merge.mjs — merges the rows of every harness of the benchmark
 * matrix into bench/results/matrix.json, fits a cost model per engine into
 * bench/results/model.json, and prints the tables as Markdown.
 *
 *   node bench/matrix/merge.mjs <dir of *.jsonl> <results dir>
 *
 * The model is T(s) = C_call + C_byte × s^k per call on a text of s bytes,
 * fitted on one thread by least squares on the relative error over the single
 * texts and the entries called one by one: k, searched on a grid, captures a
 * cost per byte that changes with size (small texts stay in cache). Rows with
 * more threads give each engine's speed-up and parallel efficiency; for the
 * worker pool, which runs batches only, against TypeScript's batch in one
 * thread. Before it, every engine that runs `detect` must report TypeScript's matches on every cell; a difference is listed, not
 * hidden, and makes the script exit with code 1.
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { cpus, release, type } from "node:os";
import { join } from "node:path";

const [dir, results] = process.argv.slice(2);
if (dir === undefined || results === undefined) {
  console.error("usage: node bench/matrix/merge.mjs <dir of *.jsonl> <results dir>");
  process.exit(2);
}

const rows = readdirSync(dir)
  .filter((file) => file.endsWith(".jsonl"))
  .flatMap((file) =>
    readFileSync(join(dir, file), "utf8")
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line)),
  );
const environment = {
  cpu: cpus()[0]?.model.trim() ?? "unknown",
  threads: cpus().length,
  os: `${type()} ${release()}`,
  date: new Date().toISOString().slice(0, 10),
  runtimes: Object.fromEntries(rows.map((r) => [r.engine, r.runtime])),
};

// Correctness first: every `detect` engine against TypeScript, cell by cell.
const key = (r) => `${r.shape}/${r.entrySize}/${r.entries}`;
const reference = new Map(rows.filter((r) => r.engine === "ts").map((r) => [key(r), r.matches]));
const differences = rows
  .filter((r) => r.op === "detect" && r.engine !== "ts" && reference.has(key(r)))
  .filter((r) => r.matches !== reference.get(key(r)))
  .map((r) => ({ engine: r.engine, cell: key(r), matches: r.matches, ts: reference.get(key(r)) }));

/** Least squares on relative error, for a fixed exponent k: minimise Σ ((c + b·s^k − t) / t)². */
function fitWith(points, k) {
  let [aa, ab, bb, ya, yb] = [0, 0, 0, 0, 0];
  for (const [s, t] of points) {
    const [x1, x2] = [1 / t, s ** k / t];
    aa += x1 * x1;
    ab += x1 * x2;
    bb += x2 * x2;
    ya += x1;
    yb += x2;
  }
  const det = aa * bb - ab * ab;
  const c = (ya * bb - yb * ab) / det;
  const b = (aa * yb - ab * ya) / det;
  const errors = points.map(([s, t]) => (c + b * s ** k - t) / t);
  return {
    c,
    b,
    k,
    squares: errors.reduce((sum, e) => sum + e * e, 0),
    max: Math.max(...errors.map(Math.abs)),
  };
}

/** The best exponent on a grid from 0.7 to 1.5, then its coefficients. */
function fit(points) {
  // An engine that only runs batches (the worker pool) has no single-call cost to fit.
  if (points.length < 2) {
    return { cCallUs: null, cByteNs: null, exponent: null, maxRelativeError: null };
  }
  let best = fitWith(points, 1);
  for (let k = 0.7; k <= 1.5001; k += 0.005) {
    const candidate = fitWith(points, k);
    if (candidate.squares < best.squares && candidate.c >= 0 && candidate.b > 0) best = candidate;
  }
  return {
    cCallUs: best.c,
    cByteNs: best.b * 1000,
    exponent: Number(best.k.toFixed(3)),
    maxRelativeError: best.max,
  };
}

/** Microseconds of one call on `bytes`, by an engine's model. */
const predict = (model, bytes) => model.cCallUs + (model.cByteNs / 1000) * bytes ** model.exponent;

const engines = {};
for (const engine of [...new Set(rows.map((r) => r.engine))]) {
  const own = rows.filter((r) => r.engine === engine);
  const points = own
    .filter((r) => (r.shape === "single" || r.shape === "each") && r.threads === 1)
    .map((r) => [r.entrySize, r.perEntryUs]);
  const each = own.find((r) => r.shape === "each" && r.threads === 1);
  const threads = own
    .filter((r) => r.shape === "each" && r.threads > 1)
    .map((r) => ({
      threads: r.threads,
      speedup: each.medianMs / r.medianMs,
      efficiency: each.medianMs / r.medianMs / r.threads,
    }));
  const batch = own.find((r) => r.shape === "batch");
  // Several batch rows: one per pool size, each against TypeScript's batch in one thread.
  const tsBatch = rows.find((r) => r.engine === "ts" && r.shape === "batch");
  const pool = own.filter((r) => r.shape === "batch");
  if (pool.length > 1 && tsBatch !== undefined) {
    threads.push(
      ...pool.map((r) => ({
        threads: r.threads,
        speedup: tsBatch.medianMs / r.medianMs,
        efficiency: tsBatch.medianMs / r.medianMs / r.threads,
      })),
    );
  }
  engines[engine] = {
    op: own[0].op,
    ...fit(points),
    batchSpeedup: each && batch ? each.perEntryUs / batch.perEntryUs : null,
    batchThreads: batch?.threads ?? null,
    threads,
  };
}
// The text size from which each engine is faster than TypeScript, by the model: on a log
// grid over the measured sizes (the fit says nothing outside them), the smallest size from
// which it costs less at every larger size; null if it never does.
const ts = engines.ts;
const measured = rows.filter((r) => r.shape !== "batch").map((r) => r.entrySize);
const [smallest, largest] = [Math.min(...measured), Math.max(...measured)];
for (const model of Object.values(engines)) {
  let from = null;
  if (ts && model !== ts && model.cCallUs !== null) {
    for (let bytes = smallest; bytes <= largest * 1.0001; bytes *= 1.25) {
      if (predict(model, bytes) >= predict(ts, bytes)) from = null;
      else from ??= Math.round(bytes);
    }
  }
  model.fasterThanTsFromBytes = from;
}

writeFileSync(
  join(results, "matrix.json"),
  `${JSON.stringify({ environment, rows, differences }, null, 2)}\n`,
);
writeFileSync(
  join(results, "model.json"),
  `${JSON.stringify({ environment, engines }, null, 2)}\n`,
);

const f = (n, digits = 1) => (n === null || n === undefined ? "—" : n.toFixed(digits));
const names = Object.keys(engines);
const cell = (engine, shape, size) =>
  rows.find(
    (r) =>
      r.engine === engine &&
      r.shape === shape &&
      (shape !== "each" || r.threads === 1) &&
      (size === undefined || r.entrySize === size),
  );
const sizes = [...new Set(rows.filter((r) => r.shape === "single").map((r) => r.entrySize))].sort(
  (a, b) => a - b,
);
const lines = [
  `Measured ${environment.date} on ${environment.cpu} (${String(environment.threads)} threads), ${environment.os}.`,
  "",
  `| Engine | ${sizes.map((s) => `${f(s / 1000, 0)} KB (ms)`).join(" | ")} | entry one by one (µs) | batch (µs/entry) | batch speed-up |`,
  `| --- | ${sizes.map(() => "---:").join(" | ")} | ---: | ---: | ---: |`,
  ...names.map((e) => {
    const single = sizes.map((s) => f(cell(e, "single", s)?.medianMs, 3));
    return `| ${e} (${engines[e].op}) | ${single.join(" | ")} | ${f(cell(e, "each")?.perEntryUs)} | ${f(cell(e, "batch")?.perEntryUs)} | ${engines[e].batchSpeedup === null ? "—" : `${f(engines[e].batchSpeedup, 2)}×`} |`;
  }),
  "",
  "| Engine | C_call (µs) | C_byte (ns) | exponent k | predicted 200 B (µs) | predicted 1 MB (ms) | max error | faster than TS from |",
  "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  ...names.map((e) => {
    const m = engines[e];
    const from = m.fasterThanTsFromBytes;
    if (m.cCallUs === null) return `| ${e} | — | — | — | — | — | — | — |`;
    return `| ${e} | ${f(m.cCallUs)} | ${f(m.cByteNs, 2)} | ${f(m.exponent, 3)} | ${f(predict(m, 200))} | ${f(predict(m, 1e6) / 1000)} | ${f(m.maxRelativeError * 100, 0)}% | ${from === null ? "—" : `${String(from)} B`} |`;
  }),
  "",
  "| Engine | threads | speed-up | efficiency |",
  "| --- | ---: | ---: | ---: |",
  ...names.flatMap((e) =>
    engines[e].threads.map(
      (t) => `| ${e} | ${String(t.threads)} | ${f(t.speedup, 2)}× | ${f(t.efficiency, 2)} |`,
    ),
  ),
  "",
  differences.length === 0
    ? "Every `detect` engine reported TypeScript's matches on every cell."
    : `**Differences from TypeScript:** ${JSON.stringify(differences)}`,
];
console.log(lines.join("\n"));
// A difference in results fails the run; timings never do (shared runners are noisy).
if (differences.length > 0) process.exitCode = 1;
