#!/usr/bin/env node
/**
 * Publish the companion packages (packages/*) whose version is not on the
 * registry yet. The Release workflow runs it after anonyma itself has been
 * published, so a release tag publishes every package that has a new version.
 *
 * For each package it
 *
 * 1. skips it when `<name>@<version>` is already on the registry;
 * 2. requires a published anonyma that satisfies the package's peer range
 *    (anonyma is published first, in the same release);
 * 3. packs it into the output directory and publishes the tarball, public,
 *    under `next` for a prerelease version and `latest` otherwise.
 *
 * The packages must have been built (`npm run build:packages`).
 *
 * Usage: node scripts/publish-packages.mjs [--dry-run] [--out <dir>]
 *
 * With --dry-run nothing is published, and a peer range that no published
 * anonyma satisfies yet is reported instead of failing: a rehearsal runs
 * before the release that publishes it. Without it, the peer check is retried
 * for a few minutes, because the registry answers queries for a version some
 * time after it was published.
 */

import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const outIndex = args.indexOf("--out");
const out = resolve(outIndex === -1 ? join(root, "dist-packages") : args[outIndex + 1]);
const windows = process.platform === "win32";
const npm = windows ? "npm.cmd" : "npm";

/** Run npm and return its standard output; throw with its standard error. */
function runNpm(npmArgs, cwd = root) {
  return execFileSync(npm, npmArgs, {
    cwd,
    encoding: "utf8",
    shell: windows,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

/**
 * The versions of `spec` on the registry, or an empty list when the package
 * or a matching version does not exist. Any other failure is thrown.
 */
function published(spec) {
  try {
    const output = runNpm(["view", spec, "version", "--json"]);
    if (output === "") return [];
    const parsed = JSON.parse(output);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (error) {
    const stderr = String(error.stderr ?? "");
    if (/E404|ETARGET|No match found/i.test(stderr)) return [];
    throw new Error(`npm view ${spec} failed:\n${stderr}`);
  }
}

/** Seconds to wait before each retry of the peer check: about three minutes in all. */
const PEER_RETRIES = [10, 20, 30, 60, 60];

/** Whether a published anonyma satisfies `range`, retrying while the registry catches up. */
async function peerPublished(range) {
  for (const delay of dryRun ? [] : PEER_RETRIES) {
    if (published(`anonyma@${range}`).length > 0) return true;
    console.log(`anonyma@${range} is not on the registry yet; checking again in ${delay} s`);
    await new Promise((done) => setTimeout(done, delay * 1000));
  }
  return published(`anonyma@${range}`).length > 0;
}

/** The message of a failed command, with what to check when npm refused a publish. */
function describe(error) {
  const message = error instanceof Error ? error.message : String(error);
  const stderr = String(error?.stderr ?? "");
  if (/E404/.test(stderr) && /\bPUT\b/.test(stderr)) {
    return (
      "npm refused the publish (404). Check that this package has a trusted publisher for " +
      "the Release workflow (release.yml, environment npm); a package that was never " +
      "published needs its first version published by hand."
    );
  }
  return `${message}${stderr === "" ? "" : `\n${stderr}`}`;
}

const packages = readdirSync(join(root, "packages"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => join(root, "packages", entry.name))
  .filter((dir) => existsSync(join(dir, "package.json")))
  .map((dir) => ({ dir, pkg: JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) }))
  .filter(({ pkg }) => pkg.private !== true);

mkdirSync(out, { recursive: true });
const rows = [];
let failed = false;

for (const { dir, pkg } of packages) {
  const spec = `${pkg.name}@${pkg.version}`;
  try {
    if (published(spec).length > 0) {
      rows.push([spec, "already published"]);
      continue;
    }

    const peer = pkg.peerDependencies?.anonyma;
    if (peer !== undefined && !(await peerPublished(peer))) {
      if (!dryRun) throw new Error(`no published anonyma satisfies its peer range ${peer}`);
      rows.push([spec, `would publish once anonyma ${peer} is released`]);
      continue;
    }

    if (!existsSync(join(dir, "dist"))) {
      throw new Error("it has not been built: run `npm run build:packages` first");
    }
    const [{ filename }] = JSON.parse(
      runNpm(["pack", "--ignore-scripts", "--json", "--pack-destination", out], dir),
    );
    const tarball = join(out, filename);
    const tag = pkg.version.includes("-") ? "next" : "latest";
    const publishArgs = ["publish", tarball, "--access", "public", "--tag", tag];
    // Provenance comes from the workflow's OpenID Connect token, which a dry run does not use.
    if (!dryRun) publishArgs.push("--provenance");
    else publishArgs.push("--dry-run");
    runNpm(publishArgs);
    rows.push([spec, dryRun ? `would publish (${tag})` : `published (${tag})`]);
  } catch (error) {
    failed = true;
    rows.push([spec, `FAILED: ${describe(error)}`]);
  }
}

const lines = [
  "| Package | Result |",
  "| --- | --- |",
  ...rows.map(([spec, result]) => `| \`${spec}\` | ${result.replaceAll("\n", " ")} |`),
];
console.log(lines.join("\n"));
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Packages\n\n${lines.join("\n")}\n`);
}
if (process.env.GITHUB_OUTPUT) {
  const any = readdirSync(out).some((name) => name.endsWith(".tgz"));
  appendFileSync(process.env.GITHUB_OUTPUT, `packed=${String(any)}\n`);
}
process.exit(failed ? 1 : 0);
