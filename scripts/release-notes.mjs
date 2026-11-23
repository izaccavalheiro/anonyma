#!/usr/bin/env node
/**
 * Print the section of a changelog that belongs to one version, for the body
 * of a GitHub release. Fails when the changelog has no such section, so a
 * version cannot be released without notes.
 *
 * Usage: node scripts/release-notes.mjs <version> [--changelog <path>]
 *
 * The changelog is CHANGELOG.md at the root unless --changelog names another,
 * relative to the root (bindings/python/CHANGELOG.md, packages/sidecar/CHANGELOG.md).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const option = args.indexOf("--changelog");
const changelog = option >= 0 ? args[option + 1] : "CHANGELOG.md";
const version = args.find(
  (arg, index) => !arg.startsWith("--") && (option < 0 || index !== option + 1),
);
if (version === undefined || changelog === undefined) {
  console.error("usage: node scripts/release-notes.mjs <version> [--changelog <path>]");
  process.exit(2);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(join(root, changelog), "utf8").split("\n");
const start = lines.findIndex((line) => line.startsWith(`## [${version}]`));
if (start < 0) {
  console.error(`${changelog} has no section for ${version}`);
  process.exit(1);
}
let end = lines.findIndex((line, index) => index > start && line.startsWith("## ["));
if (end < 0) end = lines.length;
const body = lines
  .slice(start + 1, end)
  .join("\n")
  .replace(/\n---\s*$/, "")
  .trim();
if (body.length === 0) {
  console.error(`The section for ${version} in ${changelog} is empty`);
  process.exit(1);
}
console.log(body);
