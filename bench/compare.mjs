#!/usr/bin/env node
/**
 * bench/compare.mjs — times two builds of anonyma against each other on the
 * same machine, interleaved, and fails when the second is slower.
 *
 *   node bench/compare.mjs --base <dist> --head <dist> [--rounds 11] [--limit 1.10]
 *
 * Shared runners are too noisy for absolute budgets, but both builds run in one
 * process, cell by cell, in alternating order (base, head, head, base, ...), so
 * noise touches both. Each round gives a ratio head / base; a cell regresses
 * when even the lower quartile of its ratios is above the limit: the head is
 * slower by more than the limit beyond the run-to-run spread. A cell the base
 * cannot run (a function it does not have) is reported and skipped.
 *
 * Exit code 1 on a regression; the table goes to stdout and, in GitHub
 * Actions, to the job summary.
 */
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { makeLabelledText, makeText } from "./corpus.mjs";

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 && at + 1 < args.length ? args[at + 1] : fallback;
};
const baseDir = option("base");
const headDir = option("head");
if (baseDir === undefined || headDir === undefined) {
  console.error(
    "usage: node bench/compare.mjs --base <dist> --head <dist> [--rounds 11] [--limit 1.10]",
  );
  process.exit(2);
}
const ROUNDS = Number(option("rounds", "11"));
const LIMIT = Number(option("limit", "1.10"));

async function load(dir) {
  const url = (file) => pathToFileURL(resolve(dir, file)).href;
  return { core: await import(url("index.js")), engine: await import(url("engine/index.js")) };
}
const builds = { base: await load(baseDir), head: await load(headDir) };

const SPARSE = 1 / 200;
const text1k = makeText({ size: 1_000, density: SPARSE, seed: 7 }).text;
const text100k = makeText({ size: 100_000, density: SPARSE, seed: 7 }).text;
const dense1m = makeText({ size: 1_000_000, density: 1 / 40, seed: 7 }).text;
const labelled = makeLabelledText(100_000);
const lines = Array.from(
  { length: 2_000 },
  (_, i) => makeText({ size: 200, density: SPARSE, seed: 1000 + i }).text,
);

/** The gated cells: each makes, from a build, the call to time (or undefined if it lacks it). */
const CELLS = [
  [
    "detect, 1 KB",
    ({ core }) =>
      () =>
        core.detect(text1k),
  ],
  [
    "detect, 100 KB",
    ({ core }) =>
      () =>
        core.detect(text100k),
  ],
  [
    "detect, 1 MB dense",
    ({ core }) =>
      () =>
        core.detect(dense1m),
  ],
  [
    "detect, 100 KB of labels",
    ({ core }) =>
      () =>
        core.detect(labelled),
  ],
  [
    "anonymize gdpr, 100 KB",
    ({ core }) =>
      () =>
        core.anonymize(text100k, { preset: "gdpr" }),
  ],
  [
    "scan, 100 KB",
    ({ engine }) => {
      const pipeline = engine.compilePipeline({});
      return () => pipeline.scan(text100k);
    },
  ],
  [
    "detectBatch, 2,000 lines",
    ({ core }) =>
      typeof core.detectBatch === "function" ? () => core.detectBatch(lines) : undefined,
  ],
];

/** Milliseconds for `iterations` calls of `run`. */
function time(run, iterations) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) run();
  return performance.now() - start;
}

const quantile = (sorted, q) => {
  const at = (sorted.length - 1) * q;
  const low = Math.floor(at);
  const high = Math.ceil(at);
  return sorted[low] + (sorted[high] - sorted[low]) * (at - low);
};

const rows = [];
for (const [name, make] of CELLS) {
  const base = make(builds.base);
  const head = make(builds.head);
  if (base === undefined || head === undefined) {
    rows.push({ name, status: "skipped" });
    continue;
  }
  // Warm both, then pick an iteration count that makes one sample about 30 ms.
  base();
  head();
  const once = Math.max(time(head, 1), 0.001);
  const iterations = Math.max(1, Math.round(30 / once));
  const ratios = [];
  const ms = { base: [], head: [] };
  for (let round = 0; round < ROUNDS; round++) {
    const order = round % 2 === 0 ? ["base", "head"] : ["head", "base"];
    const sample = {};
    for (const which of order) {
      sample[which] = time(which === "base" ? base : head, iterations) / iterations;
      ms[which].push(sample[which]);
    }
    ratios.push(sample.head / sample.base);
  }
  ratios.sort((a, b) => a - b);
  const [low, median, high] = [0.25, 0.5, 0.75].map((q) => quantile(ratios, q));
  const medianOf = (values) =>
    quantile(
      [...values].sort((a, b) => a - b),
      0.5,
    );
  rows.push({
    name,
    status: low > LIMIT ? "SLOWER" : high < 1 / LIMIT ? "faster" : "ok",
    baseMs: medianOf(ms.base),
    headMs: medianOf(ms.head),
    median,
    low,
    high,
  });
}

const f = (n, digits = 3) => n.toFixed(digits);
const table = [
  `| Cell | Base (ms) | Head (ms) | Head / base | Quartiles | Status |`,
  `| --- | ---: | ---: | ---: | --- | --- |`,
  ...rows.map((r) =>
    r.status === "skipped"
      ? `| ${r.name} | — | — | — | — | not in the base |`
      : `| ${r.name} | ${f(r.baseMs)} | ${f(r.headMs)} | ${f(r.median, 2)} | ${f(r.low, 2)}–${f(r.high, 2)} | ${r.status} |`,
  ),
];
const summary = [
  `### TypeScript: head against base, ${String(ROUNDS)} interleaved rounds`,
  "",
  `A cell fails when the lower quartile of head / base is above ${f(LIMIT, 2)}.`,
  "",
  ...table,
  "",
].join("\n");
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY)
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
if (rows.some((r) => r.status === "SLOWER")) {
  console.error(`At least one cell is more than ${String(Math.round((LIMIT - 1) * 100))}% slower.`);
  process.exitCode = 1;
}
