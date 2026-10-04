#!/usr/bin/env node
/**
 * Print the section of CHANGELOG.md that belongs to one version, for the body
 * of a GitHub release. Fails when the changelog has no such section, so a
 * version cannot be released without notes.
 *
 * Usage: node scripts/release-notes.mjs <version>
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [version] = process.argv.slice(2);
if (version === undefined) {
  console.error("usage: node scripts/release-notes.mjs <version>");
  process.exit(2);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split("\n");
const start = lines.findIndex((line) => line.startsWith(`## [${version}]`));
if (start < 0) {
  console.error(`CHANGELOG.md has no section for ${version}`);
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
  console.error(`The section for ${version} in CHANGELOG.md is empty`);
  process.exit(1);
}
console.log(body);
