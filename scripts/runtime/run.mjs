#!/usr/bin/env node
/**
 * Runs the runtime-neutral feature checks against dist/ in the JavaScript
 * runtime that executes this file.
 *
 * Usage (after `npm run build`):
 *   node scripts/runtime/run.mjs
 *   bun scripts/runtime/run.mjs
 *   deno run scripts/runtime/run.mjs
 */

import { formatResults, runChecks } from "./checks.mjs";

const runtime =
  globalThis.Deno !== undefined
    ? `Deno ${globalThis.Deno.version.deno}`
    : globalThis.Bun !== undefined
      ? `Bun ${globalThis.Bun.version}`
      : `Node.js ${globalThis.process.version}`;

const report = await runChecks();
console.log(`${runtime}:\n${formatResults(report).join("\n")}`);
// A top-level throw ends every runtime with a non-zero exit code.
if (!report.ok) throw new Error(`the feature checks failed on ${runtime}`);
