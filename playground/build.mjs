#!/usr/bin/env node
/**
 * Build the playground into playground/dist: a static page that runs anonyma
 * in the browser. With --serve, rebuild on change and serve it on
 * http://localhost:8000.
 *
 * It bundles the library from src/, so it needs no build of the package. esbuild
 * comes with tsup.
 */

import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, context } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "dist");
const serve = process.argv.includes("--serve");

const options = {
  entryPoints: [join(here, "src", "main.ts"), join(here, "src", "main.css")],
  outdir: out,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: !serve,
  sourcemap: true,
  legalComments: "none",
  // Only Node.js 18 reaches it, through Web Crypto's fallback; a browser has Web Crypto.
  external: ["node:crypto"],
  logLevel: "warning",
};

await mkdir(out, { recursive: true });
await copyFile(join(here, "index.html"), join(out, "index.html"));

if (serve) {
  const ctx = await context(options);
  await ctx.watch();
  const { port } = await ctx.serve({ servedir: out, port: 8000 });
  console.log(`Playground on http://localhost:${String(port)}`);
} else {
  await build(options);
  console.log(`Playground built in ${out}`);
}
