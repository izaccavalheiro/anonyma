#!/usr/bin/env node
/**
 * Complexity guard for the benchmark.
 *
 * Absolute timings depend on the machine, so they are not compared. What is
 * compared is how time grows with input size: the log-log slope that
 * bench/run.mjs reports (1.0 is linear, 2.0 quadratic). A slope above the
 * limit means an operation of the span engine, label-heavy detection or a
 * batch function stopped being linear.
 *
 * Usage: node scripts/check-bench.mjs <results.json> [limit]
 */

import { appendFileSync, readFileSync } from "node:fs";

const [file, limitArgument] = process.argv.slice(2);
if (file === undefined) {
  console.error("usage: node scripts/check-bench.mjs <results.json> [limit]");
  process.exit(2);
}
const limit = Number(limitArgument ?? 1.15);
const results = JSON.parse(readFileSync(file, "utf8"));

/**
 * The operations held to linear scaling: the span engine's, detection on
 * label-heavy text (a label check that grows with labels × candidates), and
 * the batch functions (fusion).
 */
const enforced = (op) =>
  op.startsWith("engine/") ||
  op.startsWith("labelled/") ||
  op === "detectBatch" ||
  op === "anonymizeBatch";
const guarded = results.scaling.filter((row) => enforced(row.op));
if (guarded.length === 0) {
  console.error(
    "The results hold no engine operations: was the benchmark run against a current build?",
  );
  process.exit(1);
}

const lines = [
  "| Operation | Density | Slope | Limit | Status |",
  "| --- | --- | ---: | ---: | --- |",
  ...results.scaling.map((row) => {
    const gated = enforced(row.op);
    const status = !gated ? "reported" : row.slope <= limit ? "ok" : "NOT LINEAR";
    return `| \`${row.op}\` | ${row.density} | ${row.slope.toFixed(2)} | ${gated ? limit.toFixed(2) : "-"} | ${status} |`;
  }),
];
console.log(lines.join("\n"));
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    `### Scaling (log-log slope of time against input size)\n\n${lines.join("\n")}\n`,
  );
}

const offenders = guarded.filter((row) => !(row.slope <= limit));
if (offenders.length > 0) {
  console.error(
    `\nNot linear: ${offenders.map((row) => `${row.op} (${row.density}) ${row.slope.toFixed(2)}`).join(", ")}`,
  );
  process.exit(1);
}
