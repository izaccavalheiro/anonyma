#!/usr/bin/env node
/**
 * bench/core.mjs — the TypeScript engine against the Rust core (anonyma-core).
 *
 * Step 4 of docs/rfcs/0001-polyglot-core.md: a native engine is offered to the
 * npm package only where it wins. This script measures, on the corpus of
 * bench/corpus.mjs, the same operations through
 *
 *   ts      the built TypeScript package (./dist),
 *   native  the Node.js addon of the core (bindings/node, napi-rs),
 *   wasm    the WebAssembly build of the core (bindings/wasm, wasm-bindgen's
 *           Node.js glue): the engine Cloudflare Workers would run, on the same V8.
 *
 *   node bench/core.mjs --native anonyma_native.node --wasm pkg/anonyma_wasm.js
 *   node bench/core.mjs ... --quick --json out.json --markdown out.md
 *
 * The core is called through its JSON API, as an npm integration would call it,
 * so every Rust timing includes serializing the input and parsing the answer.
 * Offsets are requested in UTF-16, the unit of JavaScript strings.
 *
 * Before timing, each Rust engine's results are compared with TypeScript's on
 * every input up to 100,000 characters: same spans (category, start, end) for
 * detect and scan, same text for anonymize. A difference is reported, never
 * hidden: a speed-up that changes the results is not a speed-up.
 *
 * Zero dependencies; an engine whose file is not given is left out.
 */

import { existsSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { makeText } from "./corpus.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const option = (name, fallback = "") => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
};
const QUICK = argv.includes("--quick");
const DIST = resolve(option("dist", resolve(here, "../dist")));
const require = createRequire(import.meta.url);

const SIZES = QUICK ? [1_000, 10_000, 100_000] : [1_000, 10_000, 100_000, 1_000_000];
const DENSITIES = [
  ["none", 0],
  ["sparse", 1 / 200],
  ["dense", 1 / 40],
];
const COMMON = ["email", "phone", "credit-card", "ssn", "ipv4"];
/** Inputs up to this size are compared between engines before timing. */
const COMPARE_UP_TO = 100_000;
const MIN_MS = QUICK ? 150 : 400;
const MIN_SAMPLES = 5;
const MAX_SAMPLES = 200;

// ---------------------------------------------------------------------------
// Engines
// ---------------------------------------------------------------------------

/** Loads an engine and reports how long its module took to load. */
async function timed(load) {
  const start = performance.now();
  const value = await load();
  return { value, loadMs: performance.now() - start };
}

const span = (m) => [m.category, m.start, m.end];

async function typescript() {
  const { value, loadMs } = await timed(async () => ({
    lib: await import(pathToFileURL(resolve(DIST, "index.js")).href),
    engine: await import(pathToFileURL(resolve(DIST, "engine/index.js")).href),
  }));
  const pipelines = new Map();
  const pipeline = (categories) => {
    const key = categories ? categories.join() : "*";
    if (!pipelines.has(key)) {
      pipelines.set(key, value.engine.compilePipeline(categories ? { categories } : {}));
    }
    return pipelines.get(key);
  };
  return {
    name: "ts",
    loadMs,
    detect: (text, categories) => value.lib.detect(text, categories).map(span),
    scan: (text, categories) =>
      pipeline(categories)
        .scan(text)
        .map((s) => [...span(s), s.residual === true]),
    anonymize: (text, preset) => value.lib.anonymize(text, { preset }).text,
  };
}

/** An engine over the JSON API of the core: `call(op, json) -> json`. */
function core(name, loadMs, call) {
  const run = (op, input) => {
    const answer = JSON.parse(call(op, JSON.stringify({ ...input, offsets: "utf-16" })));
    if (answer.error !== undefined) throw new Error(`${name} ${op}: ${answer.error}`);
    return answer.ok;
  };
  const withCategories = (text, categories) => (categories ? { text, categories } : { text });
  return {
    name,
    loadMs,
    detect: (text, categories) => run("detect", withCategories(text, categories)).matches.map(span),
    scan: (text, categories) =>
      run("scan", withCategories(text, categories)).spans.map((s) => [...span(s), s.residual]),
    anonymize: (text, preset) => run("anonymize", { text, preset }).text,
  };
}

async function native(file) {
  const { value, loadMs } = await timed(() => require(resolve(file)));
  return core("native", loadMs, value.call);
}

async function wasm(file) {
  const { value, loadMs } = await timed(() => require(resolve(file)));
  return core("wasm", loadMs, value.call);
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

const WORKLOADS = [
  { name: "detect (all categories)", run: (e, text) => e.detect(text, undefined) },
  { name: "detect (5 common)", run: (e, text) => e.detect(text, COMMON) },
  { name: "scan (all categories)", run: (e, text) => e.scan(text, undefined) },
  { name: "anonymize (gdpr)", run: (e, text) => e.anonymize(text, ["gdpr"]) },
];

function measure(fn) {
  for (let i = 0; i < 2; i++) fn();
  const samples = [];
  const start = performance.now();
  while (
    samples.length < MIN_SAMPLES ||
    (performance.now() - start < MIN_MS && samples.length < MAX_SAMPLES)
  ) {
    const t = performance.now();
    fn();
    samples.push(performance.now() - t);
  }
  samples.sort((a, b) => a - b);
  return samples[Math.floor(samples.length / 2)];
}

/** The first difference between two results, or null. */
function difference(expected, actual) {
  const a = JSON.stringify(expected);
  const b = JSON.stringify(actual);
  if (a === b) return null;
  if (Array.isArray(expected) && Array.isArray(actual)) {
    const length = Math.max(expected.length, actual.length);
    for (let i = 0; i < length; i++) {
      if (JSON.stringify(expected[i]) !== JSON.stringify(actual[i])) {
        return `#${i} of ${expected.length} vs ${actual.length}: ts ${JSON.stringify(expected[i])}, core ${JSON.stringify(actual[i])}`;
      }
    }
  }
  const at = [...a].findIndex((c, i) => c !== b[i]);
  return `text differs at ${at}: ts …${a.slice(Math.max(0, at - 30), at + 30)}…, core …${b.slice(Math.max(0, at - 30), at + 30)}…`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const engines = [await typescript()];
for (const [flag, load] of [
  ["native", native],
  ["wasm", wasm],
]) {
  const file = option(flag);
  if (file && existsSync(file)) engines.push(await load(file));
  else if (file) console.warn(`${flag}: ${file} not found, left out`);
}
const [ts, ...cores] = engines;

// The first call compiles each engine's patterns: report it apart from the steady state.
const firstInput = makeText({ size: 1_000, density: 1 / 200, seed: 7 });
const firstCall = Object.fromEntries(
  engines.map((engine) => {
    const start = performance.now();
    engine.detect(firstInput, undefined);
    return [engine.name, performance.now() - start];
  }),
);

const rows = [];
const differences = [];
for (const workload of WORKLOADS) {
  for (const size of SIZES) {
    for (const [density, value] of DENSITIES) {
      const text = makeText({ size, density: value, seed: 42 });
      if (size <= COMPARE_UP_TO) {
        const expected = workload.run(ts, text);
        for (const engine of cores) {
          const diff = difference(expected, workload.run(engine, text));
          if (diff)
            differences.push({ engine: engine.name, workload: workload.name, size, density, diff });
        }
      }
      const row = { workload: workload.name, size, density, ms: {} };
      for (const engine of engines) row.ms[engine.name] = measure(() => workload.run(engine, text));
      rows.push(row);
      const cells = engines.map((e) => `${e.name} ${row.ms[e.name].toFixed(3)} ms`).join(" · ");
      console.log(
        `${workload.name.padEnd(24)} ${String(size).padStart(9)} ${density.padEnd(6)} ${cells}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const environment = {
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  cpu: cpus()[0]?.model ?? "unknown",
  cores: cpus().length,
  quick: QUICK,
};
const speedup = (row, name) => row.ms.ts / row.ms[name];
const fmt = (ms) => (ms >= 100 ? ms.toFixed(0) : ms >= 1 ? ms.toFixed(2) : ms.toFixed(3));
const mbps = (size, ms) => ((size * 2) / 1e6 / (ms / 1e3)).toFixed(1);

const lines = [
  "## TypeScript engine vs Rust core",
  "",
  `Node.js ${environment.node} on ${environment.platform}, ${environment.cpu} (${environment.cores} cores).`,
  "Median of each cell; × is the speed-up over TypeScript (above 1: the core is faster).",
  "MB/s counts the input as UTF-16, two bytes a character.",
  "",
  "| engine | load (ms) | first detect, 1,000 chars (ms) |",
  "| --- | ---: | ---: |",
  ...engines.map((e) => `| ${e.name} | ${fmt(e.loadMs)} | ${fmt(firstCall[e.name])} |`),
  "",
];
for (const workload of WORKLOADS) {
  lines.push(`### ${workload.name}`, "");
  lines.push(
    `| size | density | ts (ms) | ts MB/s | ${cores.map((e) => `${e.name} (ms) | ${e.name} ×`).join(" | ")} |`,
    `| ---: | --- | ---: | ---: | ${cores.map(() => "---: | ---:").join(" | ")} |`,
  );
  for (const row of rows.filter((r) => r.workload === workload.name)) {
    const cells = cores.map((e) => `${fmt(row.ms[e.name])} | ${speedup(row, e.name).toFixed(2)}`);
    lines.push(
      `| ${row.size.toLocaleString("en")} | ${row.density} | ${fmt(row.ms.ts)} | ${mbps(row.size, row.ms.ts)} | ${cells.join(" | ")} |`,
    );
  }
  lines.push("");
}
const compared = rows.filter((r) => r.size <= COMPARE_UP_TO).length * cores.length;
lines.push("### Same results", "");
if (differences.length === 0) {
  lines.push(`Every Rust result matched TypeScript's (${compared} comparisons).`);
} else {
  lines.push(`${differences.length} of ${compared} comparisons differ:`, "");
  for (const d of differences.slice(0, 40)) {
    lines.push(
      `- ${d.engine}, ${d.workload}, ${d.size} ${d.density}: ${d.diff.replace(/\|/g, "\\|")}`,
    );
  }
}
const markdown = `${lines.join("\n")}\n`;
console.log(`\n${markdown}`);

const markdownOut = option("markdown");
if (markdownOut) writeFileSync(markdownOut, markdown);
const jsonOut = option("json");
if (jsonOut) {
  const load = Object.fromEntries(engines.map((e) => [e.name, e.loadMs]));
  writeFileSync(
    jsonOut,
    `${JSON.stringify({ environment, load, firstCall, rows, differences }, null, 2)}\n`,
  );
}
