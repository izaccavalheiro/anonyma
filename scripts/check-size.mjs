#!/usr/bin/env node
/**
 * Size budget for the built package.
 *
 * For every entry point of the export map, adds up the gzip size of the entry
 * file and of every chunk it imports, and compares the total with the budget
 * in scripts/size-budget.json. An entry point over its budget, or without
 * one, fails the check: growth has to be a decision, not an accident.
 *
 * Usage: node scripts/check-size.mjs        (after `npm run build`)
 */

import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const budgets = JSON.parse(readFileSync(join(root, "scripts", "size-budget.json"), "utf8"));

/** The entry file and every file it imports, directly or through a chunk. */
function closure(file, seen = new Set()) {
  if (seen.has(file)) return seen;
  seen.add(file);
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(/(?:from|import)\s*["'](\.{1,2}\/[^"']+)["']/g)) {
    closure(join(dirname(file), match[1]), seen);
  }
  return seen;
}

const rows = [];
let failed = false;
for (const [subpath, target] of Object.entries(pkg.exports)) {
  if (subpath === "./package.json") continue;
  const entry = join(root, target.import.default);
  let bytes = 0;
  for (const file of closure(entry)) bytes += gzipSync(readFileSync(file)).length;
  const budget = budgets[subpath];
  const ok = typeof budget === "number" && bytes <= budget * 1024;
  if (!ok) failed = true;
  rows.push({
    subpath,
    kilobytes: (bytes / 1024).toFixed(1),
    budget: typeof budget === "number" ? budget.toFixed(1) : "none",
    status: ok ? "ok" : typeof budget === "number" ? "OVER BUDGET" : "NO BUDGET",
  });
}

const lines = [
  "| Entry point | gzip (KB) | Budget (KB) | Status |",
  "| --- | ---: | ---: | --- |",
  ...rows.map((row) => `| \`${row.subpath}\` | ${row.kilobytes} | ${row.budget} | ${row.status} |`),
];
console.log(lines.join("\n"));
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Package size\n\n${lines.join("\n")}\n`);
}
if (failed) {
  console.error(
    "\nAn entry point is over its budget or has none. If the growth is intended, raise the figure in scripts/size-budget.json in the same change.",
  );
  process.exit(1);
}
