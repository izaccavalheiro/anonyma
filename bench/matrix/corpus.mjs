#!/usr/bin/env node
/**
 * bench/matrix/corpus.mjs — writes the corpus every engine of the matrix reads,
 * so that TypeScript, the Rust core, Python, Go and the sidecar time the same
 * bytes. Every value is synthetic (bench/corpus.mjs).
 *
 *   node bench/matrix/corpus.mjs <dir>
 *
 * Files: single-1k.txt, single-100k.txt, single-1m.txt (one text each, one value
 * per 200 characters) and entries.json (10,000 log lines of ~200 characters, a
 * JSON array of strings).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { makeText } from "../corpus.mjs";

const dir = process.argv[2];
if (dir === undefined) {
  console.error("usage: node bench/matrix/corpus.mjs <dir>");
  process.exit(2);
}
mkdirSync(dir, { recursive: true });
const DENSITY = 1 / 200;
for (const [name, size] of [
  ["1k", 1_000],
  ["100k", 100_000],
  ["1m", 1_000_000],
]) {
  writeFileSync(
    join(dir, `single-${name}.txt`),
    makeText({ size, density: DENSITY, seed: 7 }).text,
  );
}
const entries = Array.from(
  { length: 10_000 },
  (_, i) => makeText({ size: 200, density: DENSITY, seed: 1000 + i }).text,
);
writeFileSync(join(dir, "entries.json"), JSON.stringify(entries));
console.log(`corpus written to ${dir}`);
