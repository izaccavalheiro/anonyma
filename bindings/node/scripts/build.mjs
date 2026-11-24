#!/usr/bin/env node
/**
 * Builds the addon of this machine with cargo and copies it next to the
 * package as anonyma-native.<platform>-<arch>.node, where lib/load.cjs looks
 * first. `--target <triple>` builds for another target (CI); `--out <file>`
 * writes the addon there instead.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const option = (name) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : undefined;
};
const here = dirname(dirname(fileURLToPath(import.meta.url)));
const root = join(here, "..", "..");
const target = option("target");
execFileSync(
  "cargo",
  ["build", "-p", "anonyma-node", "--release", ...(target ? ["--target", target] : [])],
  { cwd: root, stdio: "inherit" },
);
const name = {
  win32: "anonyma_node.dll",
  darwin: "libanonyma_node.dylib",
}[process.platform] ?? "libanonyma_node.so";
const built = join(root, "target", ...(target ? [target] : []), "release", name);
const out = option("out") ?? join(here, `anonyma-native.${process.platform}-${process.arch}.node`);
copyFileSync(built, out);
console.log(`built ${out}`);
