#!/usr/bin/env node
/**
 * bench/run.mjs — latency, throughput, scaling and memory benchmark for anonyma.
 *
 * Zero dependencies. Measures a *built* package, so the same script can compare
 * builds:
 *
 *   node bench/run.mjs                          # measures ./dist
 *   node bench/run.mjs --dist /path/to/dist     # measures another build
 *   node bench/run.mjs --quick                  # smaller matrix
 *   node bench/run.mjs --filter anonymize       # only operations whose name contains the text
 *   node bench/run.mjs --json bench/results/baseline.json
 *
 * Method
 * ------
 * - Inputs come from bench/corpus.mjs and are a pure function of (size, density, seed).
 * - Each cell is warmed up, then sampled until both a minimum time and a minimum
 *   number of iterations are reached. The table reports the median and the 95th
 *   percentile of the samples.
 * - Scaling is the least-squares slope of log(time) against log(size): 1.0 means
 *   linear, 2.0 means quadratic.
 * - Memory is measured in a child process started with --expose-gc: gc(), then
 *   heapUsed before and immediately after one call (transient growth, which
 *   includes garbage the call left behind and is a lower bound when a scavenge
 *   ran during the call), then heapUsed after another gc() (retained).
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { makeObject, makeText, splitFixed, splitLines } from "./corpus.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const option = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
};

const DIST = resolve(option("dist", resolve(here, "../dist")));
const QUICK = flag("quick");
const FILTER = option("filter", "");
const JSON_OUT = option("json", "");
const MEMORY_CHILD = flag("memory-child");

const load = (file) => import(pathToFileURL(resolve(DIST, file)).href);
const lib = await load("index.js");
const stream = await load("stream.js");
const detectors = await load("detectors/index.js");
/** The span engine, present in builds that ship "anonyma/engine". */
const engine = existsSync(resolve(DIST, "engine/index.js")) ? await load("engine/index.js") : null;

const SIZES = QUICK ? [1_000, 10_000, 100_000] : [100, 1_000, 10_000, 100_000, 1_000_000];
const DENSITIES = [
  ["none", 0],
  ["sparse", 1 / 200],
  ["dense", 1 / 40],
];
const MIN_TIME_MS = QUICK ? 120 : 300;
const MIN_ITERATIONS = 5;
const MAX_ITERATIONS = 20_000;

// ---------------------------------------------------------------------------
// Measurement helpers
// ---------------------------------------------------------------------------

const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];

function summarise(samples, bytes) {
  const sorted = [...samples].sort((a, b) => a - b);
  const median = quantile(sorted, 0.5);
  return {
    iterations: sorted.length,
    medianMs: median,
    p95Ms: quantile(sorted, 0.95),
    opsPerSec: 1000 / median,
    mbPerSec: bytes / 1e6 / (median / 1000),
  };
}

function measureSync(fn, bytes) {
  fn();
  const samples = [];
  const started = performance.now();
  while (
    samples.length < MAX_ITERATIONS &&
    (samples.length < MIN_ITERATIONS || performance.now() - started < MIN_TIME_MS)
  ) {
    const t0 = performance.now();
    fn();
    samples.push(performance.now() - t0);
  }
  return summarise(samples, bytes);
}

async function measureAsync(fn, bytes) {
  await fn();
  const samples = [];
  const started = performance.now();
  while (
    samples.length < MAX_ITERATIONS &&
    (samples.length < MIN_ITERATIONS || performance.now() - started < MIN_TIME_MS)
  ) {
    const t0 = performance.now();
    await fn();
    samples.push(performance.now() - t0);
  }
  return summarise(samples, bytes);
}

/** Least-squares slope of ln(y) against ln(x). */
function logLogSlope(points) {
  const xs = points.map(([x]) => Math.log(x));
  const ys = points.map(([, y]) => Math.log(y));
  const mx = xs.reduce((a, b) => a + b, 0) / xs.length;
  const my = ys.reduce((a, b) => a + b, 0) / ys.length;
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i++) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  return den === 0 ? NaN : num / den;
}

async function drain(transform, chunks) {
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();
  const pump = (async () => {
    for (const chunk of chunks) await writer.write(chunk);
    await writer.close();
  })();
  let out = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    out += typeof value === "string" ? value.length : value.text.length;
  }
  await pump;
  return out;
}

const fmt = (n, digits = 3) =>
  Number.isFinite(n) ? (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(digits)) : "-";

// ---------------------------------------------------------------------------
// Memory child
// ---------------------------------------------------------------------------

async function memoryChild() {
  const gc = globalThis.gc;
  const heap = () => process.memoryUsage().heapUsed;
  const rows = [];
  for (const size of QUICK ? [10_000, 100_000] : [1_000, 10_000, 100_000, 1_000_000]) {
    const { text } = makeText({ size, density: 1 / 200, seed: "memory" });
    const enginePipeline = engine?.compilePipeline();
    for (const [name, fn] of [
      ["detect", () => lib.detect(text)],
      ["anonymize", () => lib.anonymize(text)],
      ["tokenize", () => lib.tokenize(text)],
      ...(enginePipeline ? [["engine", () => enginePipeline.transform(text)]] : []),
    ]) {
      fn();
      gc();
      const before = heap();
      const kept = fn();
      const after = heap();
      gc();
      const retained = heap();
      rows.push({
        op: name,
        size,
        transientBytes: after - before,
        retainedBytes: retained - before,
        keep: kept === undefined ? 0 : 1,
      });
    }
  }
  // Peak heap while streaming a large input in line-sized chunks.
  const totalBytes = QUICK ? 5_000_000 : 50_000_000;
  const block = splitLines(
    makeText({ size: 1_000_000, density: 1 / 200, seed: "stream-memory" }).text,
  );
  gc();
  const base = heap();
  let peak = base;
  let seen = 0;
  const transform = stream.createAnonymizeStream();
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();
  const consume = (async () => {
    for (;;) {
      const { done } = await reader.read();
      if (done) return;
    }
  })();
  const t0 = performance.now();
  while (seen < totalBytes) {
    for (const line of block) {
      await writer.write(line);
      seen += line.length;
    }
    peak = Math.max(peak, heap());
  }
  await writer.close();
  await consume;
  const elapsed = performance.now() - t0;
  gc();
  process.stdout.write(
    JSON.stringify({
      perCall: rows,
      stream: {
        bytes: seen,
        peakHeapGrowthBytes: peak - base,
        retainedBytes: heap() - base,
        mbPerSec: seen / 1e6 / (elapsed / 1000),
      },
    }),
  );
}

if (MEMORY_CHILD) {
  await memoryChild();
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main matrix
// ---------------------------------------------------------------------------

const results = [];
const wanted = (name) => FILTER === "" || name.includes(FILTER);

async function cell(op, sizeLabel, size, density, densityLabel, matches, run, isAsync = false) {
  if (!wanted(op)) return;
  const stats = isAsync ? await measureAsync(run, size) : measureSync(run, size);
  results.push({ op, size, sizeLabel, density: densityLabel, matches, ...stats });
}

const label = (n) =>
  n >= 1_000_000 ? `${n / 1_000_000}MB` : n >= 1000 ? `${n / 1000}KB` : `${n}B`;

for (const size of SIZES) {
  for (const [densityLabel, density] of DENSITIES) {
    const { text } = makeText({ size, density, seed: "main" });
    const matches = lib.detect(text).length;
    const sl = label(size);
    await cell("detect", sl, size, density, densityLabel, matches, () => lib.detect(text));
    await cell("hasPII", sl, size, density, densityLabel, matches, () => lib.hasPII(text));
    await cell("anonymize/redact", sl, size, density, densityLabel, matches, () =>
      lib.anonymize(text),
    );
    await cell("anonymize/mask", sl, size, density, densityLabel, matches, () =>
      lib.anonymize(text, { defaultStrategy: { strategy: "mask", keepTrailing: 4 } }),
    );
    await cell("anonymize/consistentTokens", sl, size, density, densityLabel, matches, () =>
      lib.anonymize(text, { consistentTokens: true }),
    );
    await cell("tokenize+detokenize", sl, size, density, densityLabel, matches, () => {
      const r = lib.tokenize(text);
      lib.detokenize(r.text, r.mapping);
    });
    if (size <= 100_000) {
      await cell(
        "anonymizeAsync/hash",
        sl,
        size,
        density,
        densityLabel,
        matches,
        () => lib.anonymizeAsync(text, { defaultStrategy: { strategy: "hash" } }),
        true,
      );
    }
    if (size >= 10_000) {
      const lines = splitLines(text);
      await cell(
        "stream/lines",
        sl,
        size,
        density,
        densityLabel,
        matches,
        () => drain(stream.createAnonymizeStream(), lines),
        true,
      );
      const blocks = splitFixed(text, 65_536);
      await cell(
        "stream/64KB",
        sl,
        size,
        density,
        densityLabel,
        matches,
        () => drain(stream.createAnonymizeStream(), blocks),
        true,
      );
    }
  }
}

// The span engine, when the build has it.
if (engine !== null) {
  const precise = engine.compilePipeline();
  const parity = engine.compilePipeline({ detection: "legacy", overlap: "legacy" });
  for (const size of SIZES) {
    for (const [densityLabel, density] of DENSITIES) {
      const { text } = makeText({ size, density, seed: "main" });
      const sl = label(size);
      const matches = precise.scan(text).length;
      await cell("engine/scan", sl, size, density, densityLabel, matches, () => precise.scan(text));
      await cell("engine/test", sl, size, density, densityLabel, matches, () => precise.test(text));
      await cell("engine/transform", sl, size, density, densityLabel, matches, () =>
        precise.transform(text),
      );
      await cell(
        "engine/transform(1.x detectors)",
        sl,
        size,
        density,
        densityLabel,
        parity.scan(text).length,
        () => parity.transform(text),
      );
      if (size >= 10_000) {
        const feed = (chunks) => () => {
          const transformer = engine.createChunkTransformer(precise);
          let out = 0;
          for (const chunk of chunks) out += transformer.push(chunk).length;
          return out + transformer.flush().length;
        };
        await cell(
          "engine/chunks/lines",
          sl,
          size,
          density,
          densityLabel,
          matches,
          feed(splitLines(text)),
        );
        await cell(
          "engine/chunks/64KB",
          sl,
          size,
          density,
          densityLabel,
          matches,
          feed(splitFixed(text, 65_536)),
        );
      }
    }
  }
}

// Structured payloads and batches (sparse density only).
for (const size of QUICK ? [10_000, 100_000] : [1_000, 10_000, 100_000, 1_000_000]) {
  const { obj: object, bytes } = makeObject({ size, density: 1 / 200, seed: "object" });
  await cell("anonymizeObject", label(size), bytes, 1 / 200, "sparse", -1, () =>
    lib.anonymizeObject(object),
  );
  const lines = splitLines(makeText({ size, density: 1 / 200, seed: "batch" }).text);
  await cell("anonymizeBatch", label(size), size, 1 / 200, "sparse", lines.length, () =>
    lib.anonymizeBatch(lines),
  );
}

// Key derivation cost of the encrypt strategy.
if (wanted("encrypt")) {
  const keyBytes = new Uint8Array(32).fill(7);
  const passphrase = await measureAsync(
    () => lib.encrypt("alice@example.com", { passphrase: "benchmark" }),
    17,
  );
  const raw = await measureAsync(() => lib.encrypt("alice@example.com", { keyBytes }), 17);
  results.push({
    op: "encrypt/passphrase",
    size: 17,
    sizeLabel: "17B",
    density: "-",
    matches: 1,
    ...passphrase,
  });
  results.push({
    op: "encrypt/keyBytes",
    size: 17,
    sizeLabel: "17B",
    density: "-",
    matches: 1,
    ...raw,
  });
}

// Per-detector share of detect() on 100 KB of sparse text.
const perDetector = [];
if (wanted("detector")) {
  const { text } = makeText({ size: 100_000, density: 1 / 200, seed: "per-detector" });
  for (const [category, detector] of Object.entries(detectors.DETECTOR_REGISTRY)) {
    const stats = measureSync(() => detector(text), text.length);
    perDetector.push({ category, medianMs: stats.medianMs, matches: detector(text).length });
  }
  const total = perDetector.reduce((a, r) => a + r.medianMs, 0);
  for (const row of perDetector) row.share = row.medianMs / total;
  perDetector.sort((a, b) => b.medianMs - a.medianMs);
}

// Scaling slopes: time against size at fixed density.
const scaling = [];
for (const op of [...new Set(results.map((r) => r.op))]) {
  for (const [densityLabel] of DENSITIES) {
    const points = results
      .filter((r) => r.op === op && r.density === densityLabel && r.size >= 1000)
      .map((r) => [r.size, r.medianMs]);
    if (points.length >= 3) scaling.push({ op, density: densityLabel, slope: logLogSlope(points) });
  }
}

// Scaling in the number of matches at a fixed size.
const matchScaling = [];
if (wanted("anonymize")) {
  const size = QUICK ? 100_000 : 400_000;
  const points = { detect: [], anonymize: [] };
  for (const density of [1 / 800, 1 / 400, 1 / 200, 1 / 100, 1 / 50, 1 / 25]) {
    const { text } = makeText({ size, density, seed: "match-scaling" });
    const matches = lib.detect(text).length;
    const d = measureSync(() => lib.detect(text), size).medianMs;
    const a = measureSync(() => lib.anonymize(text), size).medianMs;
    points.detect.push([matches, d]);
    points.anonymize.push([matches, a]);
    matchScaling.push({ size, matches, detectMs: d, anonymizeMs: a, replaceMs: a - d });
  }
  matchScaling.slopes = {
    detect: logLogSlope(points.detect),
    anonymize: logLogSlope(points.anonymize),
    replace: logLogSlope(matchScaling.map((r) => [r.matches, Math.max(r.replaceMs, 1e-6)])),
  };
}

// Memory, in a child with --expose-gc.
let memory = null;
if (wanted("memory")) {
  const child = spawnSync(
    process.execPath,
    [
      "--expose-gc",
      fileURLToPath(import.meta.url),
      "--memory-child",
      "--dist",
      DIST,
      ...(QUICK ? ["--quick"] : []),
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (child.status === 0) memory = JSON.parse(child.stdout);
  else process.stderr.write(`memory child failed: ${child.stderr}\n`);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const environment = {
  node: process.version,
  cpu: cpus()[0]?.model ?? "unknown",
  cores: cpus().length,
  dist: DIST,
  quick: QUICK,
};

console.log(
  `\nanonyma benchmark — ${environment.node}, ${environment.cpu} (${environment.cores} cores)`,
);
console.log(`build: ${DIST}\n`);
console.log(
  "operation                    size    density  matches   median ms     p95 ms       MB/s",
);
for (const r of results) {
  console.log(
    `${r.op.padEnd(28)} ${r.sizeLabel.padStart(5)}  ${String(r.density).padEnd(7)} ${String(r.matches).padStart(8)} ` +
      `${fmt(r.medianMs).padStart(11)} ${fmt(r.p95Ms).padStart(10)} ${fmt(r.mbPerSec).padStart(10)}`,
  );
}
console.log("\nscaling (log-log slope of time against size; 1.0 = linear)");
for (const s of scaling)
  console.log(`  ${s.op.padEnd(28)} ${s.density.padEnd(7)} ${fmt(s.slope, 2)}`);
if (matchScaling.length > 0) {
  console.log(`\nscaling in the number of matches at ${label(matchScaling[0].size)}`);
  for (const r of matchScaling) {
    console.log(
      `  matches=${String(r.matches).padStart(6)}  detect=${fmt(r.detectMs).padStart(8)} ms  anonymize=${fmt(r.anonymizeMs).padStart(8)} ms  replace=${fmt(r.replaceMs).padStart(8)} ms`,
    );
  }
  console.log(
    `  slopes: detect ${fmt(matchScaling.slopes.detect, 2)}, anonymize ${fmt(matchScaling.slopes.anonymize, 2)}, replace step ${fmt(matchScaling.slopes.replace, 2)}`,
  );
}
if (perDetector.length > 0) {
  console.log("\nper-detector cost on 100 KB of sparse text");
  for (const r of perDetector) {
    console.log(
      `  ${r.category.padEnd(22)} ${fmt(r.medianMs).padStart(8)} ms  ${(r.share * 100).toFixed(1).padStart(5)}%  matches=${r.matches}`,
    );
  }
}
if (memory !== null) {
  console.log("\nmemory per call (bytes of heap)");
  for (const r of memory.perCall) {
    console.log(
      `  ${r.op.padEnd(10)} ${label(r.size).padStart(5)}  transient=${String(r.transientBytes).padStart(10)}  retained=${String(r.retainedBytes).padStart(10)}`,
    );
  }
  console.log(
    `\nstream of ${(memory.stream.bytes / 1e6).toFixed(0)} MB in line chunks: peak heap growth ${(memory.stream.peakHeapGrowthBytes / 1e6).toFixed(1)} MB, ` +
      `retained ${(memory.stream.retainedBytes / 1e6).toFixed(2)} MB, ${fmt(memory.stream.mbPerSec)} MB/s`,
  );
}

if (JSON_OUT !== "") {
  const file = resolve(JSON_OUT);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(
    file,
    `${JSON.stringify({ environment, results, scaling, matchScaling: { rows: [...matchScaling], slopes: matchScaling.slopes }, perDetector, memory }, null, 2)}\n`,
  );
  console.log(`\nresults written to ${file}`);
}
