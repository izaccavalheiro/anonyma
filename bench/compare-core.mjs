#!/usr/bin/env node
/**
 * bench/compare-core.mjs — times two builds of the Rust core's matrix harness
 * (crates/anonyma-core/examples/matrix.rs) against each other, in alternating
 * runs on one corpus, and fails when the second is slower.
 *
 *   node bench/compare-core.mjs --base <binary> --head <binary> --corpus <dir> [--runs 5] [--limit 1.10]
 *
 * Each pair of runs (in alternating order) gives a ratio head / base per cell
 * of one thread; a cell regresses when even the lower quartile of its ratios
 * is above the limit, as in bench/compare.mjs.
 */
import { execFileSync } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 && at + 1 < args.length ? args[at + 1] : fallback;
};
const binaries = { base: option("base"), head: option("head") };
const corpus = option("corpus");
if (binaries.base === undefined || binaries.head === undefined || corpus === undefined) {
  console.error(
    "usage: node bench/compare-core.mjs --base <binary> --head <binary> --corpus <dir> [--runs 5] [--limit 1.10]",
  );
  process.exit(2);
}
const RUNS = Number(option("runs", "5"));
const LIMIT = Number(option("limit", "1.10"));
const scratch = mkdtempSync(join(tmpdir(), "anonyma-compare-"));

/** The rows of one run of a harness, by cell, on one thread. */
function run(which, n) {
  const out = join(scratch, `${which}-${String(n)}.jsonl`);
  execFileSync(binaries[which], [corpus, out], { stdio: ["ignore", "ignore", "inherit"] });
  const cells = new Map();
  for (const line of readFileSync(out, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const row = JSON.parse(line);
    // Rows on several threads measure the machine's cores more than the code.
    if (row.threads !== 1 && row.shape !== "batch") continue;
    cells.set(`${row.shape} ${String(row.entrySize)} B × ${String(row.entries)}`, row.medianMs);
  }
  return cells;
}

const ratios = new Map();
const ms = new Map();
for (let n = 0; n < RUNS; n++) {
  const order = n % 2 === 0 ? ["base", "head"] : ["head", "base"];
  const got = {};
  for (const which of order) got[which] = run(which, n);
  for (const [cell, head] of got.head) {
    const base = got.base.get(cell);
    if (base === undefined) continue;
    ratios.set(cell, [...(ratios.get(cell) ?? []), head / base]);
    const pair = ms.get(cell) ?? { base: [], head: [] };
    pair.base.push(base);
    pair.head.push(head);
    ms.set(cell, pair);
  }
}

const quantile = (values, q) => {
  const sorted = [...values].sort((a, b) => a - b);
  const at = (sorted.length - 1) * q;
  const low = Math.floor(at);
  const high = Math.ceil(at);
  return sorted[low] + (sorted[high] - sorted[low]) * (at - low);
};
const f = (n, digits = 3) => n.toFixed(digits);
const rows = [...ratios].map(([cell, values]) => {
  const [low, median, high] = [0.25, 0.5, 0.75].map((q) => quantile(values, q));
  const pair = ms.get(cell);
  return {
    cell,
    baseMs: quantile(pair.base, 0.5),
    headMs: quantile(pair.head, 0.5),
    low,
    median,
    high,
    status: low > LIMIT ? "SLOWER" : high < 1 / LIMIT ? "faster" : "ok",
  };
});
const summary = [
  `### Rust core: head against base, ${String(RUNS)} alternating runs`,
  "",
  `A cell fails when the lower quartile of head / base is above ${f(LIMIT, 2)}.`,
  "",
  "| Cell | Base (ms) | Head (ms) | Head / base | Quartiles | Status |",
  "| --- | ---: | ---: | ---: | --- | --- |",
  ...rows.map(
    (r) =>
      `| ${r.cell} | ${f(r.baseMs)} | ${f(r.headMs)} | ${f(r.median, 2)} | ${f(r.low, 2)}–${f(r.high, 2)} | ${r.status} |`,
  ),
  "",
].join("\n");
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY)
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
if (rows.length === 0) {
  console.error("No cell is common to both runs.");
  process.exitCode = 1;
} else if (rows.some((r) => r.status === "SLOWER")) {
  console.error(`At least one cell is more than ${String(Math.round((LIMIT - 1) * 100))}% slower.`);
  process.exitCode = 1;
}
