#!/usr/bin/env node
/**
 * Runs the runtime-neutral feature checks inside workerd, the runtime of
 * Cloudflare Workers, through Miniflare.
 *
 * The worker is bundled with esbuild first, as `wrangler deploy` does, so the
 * check also proves that a bundler targeting Workers can bundle the package:
 * it must not try to resolve the `node:crypto` fallback that only Node.js 18
 * reaches. The worker gets no `nodejs_compat` flag: what passes here needs
 * nothing but the Web platform.
 *
 * Miniflare is not a development dependency (it brings a large native
 * binary); install it for the run. esbuild comes with tsup.
 *
 *   npm run build
 *   npm install --no-save miniflare
 *   node scripts/runtime/workerd.mjs
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));

let Miniflare;
try {
  ({ Miniflare } = await import("miniflare"));
} catch {
  console.error("Miniflare is not installed: run `npm install --no-save miniflare` first.");
  process.exit(1);
}

const bundle = await build({
  entryPoints: [join(here, "worker.mjs")],
  bundle: true,
  format: "esm",
  platform: "browser",
  conditions: ["workerd", "worker", "browser"],
  target: "es2022",
  write: false,
  logLevel: "warning",
});
const [output] = bundle.outputFiles;

const worker = new Miniflare({
  modules: [{ type: "ESModule", path: "worker.mjs", contents: output.text }],
  compatibilityDate: "2025-09-01",
});

let report;
try {
  const response = await worker.dispatchFetch("http://localhost/");
  report = await response.json();
} finally {
  await worker.dispose();
}

console.log(
  `Cloudflare Workers (workerd), bundle of ${(output.contents.length / 1024).toFixed(0)} KB:`,
);
for (const result of report.results) {
  console.log(result.ok ? `  ok    ${result.name}` : `  FAIL  ${result.name}: ${result.error}`);
}
process.exit(report.ok ? 0 : 1);
