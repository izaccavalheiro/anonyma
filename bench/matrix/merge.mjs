#!/usr/bin/env node
/**
 * bench/matrix/merge.mjs — merges the rows of every harness of the benchmark
 * matrix into bench/results/matrix.json, fits a cost model per engine into
 * bench/results/model.json, and prints the tables as Markdown.
 *
 *   node bench/matrix/merge.mjs <dir of *.jsonl> <results dir>
 *
 * The model is T(s) = C_call + s × C_byte per call on a text of s bytes, fitted
 * by least squares on the relative error over the single texts and the
 * entries called one by one. Before it, every engine that runs `detect` must
 * report TypeScript's matches on every cell; a difference is listed, not
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

/** Least squares on relative error: minimise Σ ((c + s·b − t) / t)². */
function fit(points) {
  let [aa, ab, bb, ya, yb] = [0, 0, 0, 0, 0];
  for (const [s, t] of points) {
    const [x1, x2] = [1 / t, s / t];
    aa += x1 * x1;
    ab += x1 * x2;
    bb += x2 * x2;
    ya += x1;
    yb += x2;
  }
  const det = aa * bb - ab * ab;
  const c = (ya * bb - yb * ab) / det;
  const b = (aa * yb - ab * ya) / det;
  const error = Math.max(...points.map(([s, t]) => Math.abs(c + s * b - t) / t));
  return { cCallUs: c, cByteNsPerB: b * 1000, maxRelativeError: error };
}

const engines = {};
for (const engine of [...new Set(rows.map((r) => r.engine))]) {
  const own = rows.filter((r) => r.engine === engine);
  const points = own
    .filter((r) => r.shape === "single" || r.shape === "each")
    .map((r) => [r.entrySize, r.perEntryUs]);
  const each = own.find((r) => r.shape === "each");
  const batch = own.find((r) => r.shape === "batch");
  engines[engine] = {
    op: own[0].op,
    ...fit(points),
    batchSpeedup: each && batch ? each.perEntryUs / batch.perEntryUs : null,
    batchThreads: batch?.threads ?? null,
  };
}
// The text size from which each engine is faster than TypeScript, by the model.
const ts = engines.ts;
for (const model of Object.values(engines)) {
  const crossover =
    ts && model !== ts && model.cByteNsPerB < ts.cByteNsPerB
      ? Math.max(0, ((model.cCallUs - ts.cCallUs) * 1000) / (ts.cByteNsPerB - model.cByteNsPerB))
      : null;
  model.fasterThanTsFromBytes = crossover;
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
    (r) => r.engine === engine && r.shape === shape && (size === undefined || r.entrySize === size),
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
    return `| ${e} (${engines[e].op}) | ${single.join(" | ")} | ${f(cell(e, "each")?.perEntryUs)} | ${f(cell(e, "batch")?.perEntryUs)} | ${f(engines[e].batchSpeedup, 2)}× |`;
  }),
  "",
  "| Engine | C_call (µs) | C_byte (ns/B) | max error | faster than TS from |",
  "| --- | ---: | ---: | ---: | ---: |",
  ...names.map((e) => {
    const m = engines[e];
    const from = m.fasterThanTsFromBytes;
    return `| ${e} | ${f(m.cCallUs)} | ${f(m.cByteNsPerB)} | ${f(m.maxRelativeError * 100, 0)}% | ${from === null ? "—" : `${f(from, 0)} B`} |`;
  }),
  "",
  differences.length === 0
    ? "Every `detect` engine reported TypeScript's matches on every cell."
    : `**Differences from TypeScript:** ${JSON.stringify(differences)}`,
];
console.log(lines.join("\n"));
// A difference in results fails the run; timings never do (shared runners are noisy).
if (differences.length > 0) process.exitCode = 1;
