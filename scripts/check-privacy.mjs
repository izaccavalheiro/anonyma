#!/usr/bin/env node
/**
 * Privacy-by-design invariants (GDPR Art. 25, LGPD Art. 46).
 *
 * A library that handles personal data makes promises that no unit test of a
 * single function can keep. This script checks them for the repository as a
 * whole:
 *
 * 1. No third-party code runs on the data: no runtime dependencies, and the
 *    only peer dependency is optional.
 * 2. The data stays in the process: the source uses no network, file-system,
 *    child-process or dynamic-code API.
 * 3. The built package imports nothing but its own files and the optional
 *    peer dependency.
 * 4. Only the built package is published: no test data, fixtures or sources.
 * 5. The repository holds synthetic data only: every e-mail address in a
 *    tracked file is under a domain reserved for documentation (RFC 2606,
 *    RFC 6761) or one listed in scripts/synthetic-domains.json.
 *
 * Usage: node scripts/check-privacy.mjs [--require-dist]
 */

import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const requireDist = process.argv.includes("--require-dist");
const windows = process.platform === "win32";
const results = [];

function check(name, problems, note = "") {
  results.push({ name, problems, note });
}

function walk(directory, accept, out = []) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) walk(path, accept, out);
    else if (accept(path)) out.push(path);
  }
  return out;
}

/** Source code without its comments, so that examples in documentation are not flagged. */
function withoutComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}

// ---------------------------------------------------------------------------
// 1. Dependencies
// ---------------------------------------------------------------------------
{
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const problems = [];
  for (const name of Object.keys(pkg.dependencies ?? {})) {
    problems.push(`runtime dependency "${name}"`);
  }
  for (const name of Object.keys(pkg.optionalDependencies ?? {})) {
    problems.push(`optional dependency "${name}"`);
  }
  for (const name of Object.keys(pkg.peerDependencies ?? {})) {
    if (pkg.peerDependenciesMeta?.[name]?.optional !== true) {
      problems.push(`peer dependency "${name}" is not optional`);
    }
  }
  if (pkg.scripts?.postinstall !== undefined || pkg.scripts?.install !== undefined) {
    problems.push("the package runs a script when it is installed");
  }
  check("No third-party code runs on the data (zero runtime dependencies)", problems);
}

// ---------------------------------------------------------------------------
// 2. Source: the data stays in the process
// ---------------------------------------------------------------------------
{
  const builtin =
    "(?:node:)?(?:http|https|http2|net|dgram|tls|dns|child_process|fs|fs/promises|worker_threads|cluster)";
  const forbidden = [
    [/\bfetch\s*\(/, "fetch()"],
    [/\b(?:XMLHttpRequest|WebSocket|EventSource)\b/, "a network API"],
    [/\bsendBeacon\b/, "navigator.sendBeacon"],
    [
      new RegExp(`(?:from|import\\s*\\(|require\\s*\\()\\s*["']${builtin}["']`),
      "a network, file-system or process module",
    ],
    [/\beval\s*\(/, "eval()"],
    [/\bnew\s+Function\s*\(/, "new Function()"],
    [/\bprocess\.env\b/, "process.env"],
  ];
  const problems = [];
  for (const file of walk(join(root, "src"), (path) => path.endsWith(".ts"))) {
    const code = withoutComments(readFileSync(file, "utf8"));
    for (const [index, line] of code.split("\n").entries()) {
      for (const [pattern, label] of forbidden) {
        if (pattern.test(line)) {
          problems.push(`${relative(root, file)}:${String(index + 1)} uses ${label}`);
        }
      }
    }
  }
  check(
    "The data stays in the process (no network, file-system or dynamic-code API in src/)",
    problems,
  );
}

// ---------------------------------------------------------------------------
// 3. Built package: nothing imported but its own files and the optional peer
// ---------------------------------------------------------------------------
{
  const dist = join(root, "dist");
  if (!existsSync(dist)) {
    check(
      "The built package imports only its own files",
      requireDist ? ["dist/ does not exist: run `npm run build` first"] : [],
      "skipped: no build",
    );
  } else {
    const problems = [];
    const specifier = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"']+)["']/g;
    for (const file of walk(dist, (path) => /\.(?:js|cjs)$/.test(path))) {
      const name = relative(dist, file);
      for (const match of withoutComments(readFileSync(file, "utf8")).matchAll(specifier)) {
        const target = match[1];
        if (target.startsWith(".")) continue;
        if (target === "zod" && /^schemas\.(?:js|cjs)$/.test(name)) continue;
        problems.push(`dist/${name} imports "${target}"`);
      }
    }
    check("The built package imports only its own files", problems);
  }
}

// ---------------------------------------------------------------------------
// 4. Published files
// ---------------------------------------------------------------------------
{
  const problems = [];
  let note = "";
  if (!existsSync(join(root, "dist"))) {
    note = "skipped: no build";
    if (requireDist) problems.push("dist/ does not exist: run `npm run build` first");
  } else {
    const output = execFileSync(
      windows ? "npm.cmd" : "npm",
      ["pack", "--dry-run", "--json", "--ignore-scripts"],
      { cwd: root, encoding: "utf8", shell: windows, stdio: ["ignore", "pipe", "ignore"] },
    );
    const [{ files }] = JSON.parse(output);
    const allowed = /^(?:dist\/|package\.json$|README\.md$|LICENSE$|CHANGELOG\.md$)/;
    for (const { path } of files) {
      if (!allowed.test(path)) problems.push(`"${path}" would be published`);
    }
    note = `${String(files.length)} files`;
  }
  check("Only the built package is published (no fixtures, tests or sources)", problems, note);
}

// ---------------------------------------------------------------------------
// 5. Synthetic data only
// ---------------------------------------------------------------------------
{
  const reserved = /(?:^|\.)(?:example|test|invalid|localhost)(?:\.|$)/;
  const accepted = new Set(
    JSON.parse(readFileSync(join(root, "scripts", "synthetic-domains.json"), "utf8")).domains,
  );
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter((path) => /\.(?:ts|mts|cts|js|mjs|cjs|json|md|yml|yaml|txt|csv)$/.test(path))
    .filter((path) => path !== "package-lock.json" && existsSync(join(root, path)));
  const address = /[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b/g;
  const unknown = new Map();
  for (const path of tracked) {
    for (const match of readFileSync(join(root, path), "utf8").matchAll(address)) {
      const domain = match[1].toLowerCase();
      if (reserved.test(domain) || accepted.has(domain)) continue;
      if (!unknown.has(domain)) unknown.set(domain, path);
    }
  }
  check(
    "The repository holds synthetic data only (e-mail domains)",
    [...unknown].map(([domain, path]) => `"${domain}" in ${path}`),
    `${String(tracked.length)} tracked files scanned`,
  );
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const lines = ["| Invariant | Result |", "| --- | --- |"];
let failed = false;
for (const { name, problems, note } of results) {
  if (problems.length > 0) failed = true;
  const result =
    problems.length > 0
      ? `**${String(problems.length)} problem(s)**`
      : note.startsWith("skipped")
        ? note
        : "holds";
  lines.push(
    `| ${name} | ${result}${problems.length === 0 && note !== "" && !note.startsWith("skipped") ? ` (${note})` : ""} |`,
  );
}
console.log(lines.join("\n"));
for (const { name, problems } of results) {
  if (problems.length === 0) continue;
  console.error(`\n${name}:`);
  for (const problem of problems.slice(0, 40)) console.error(`  - ${problem}`);
  if (problems.length > 40) console.error(`  - and ${String(problems.length - 40)} more`);
}
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    `### Privacy invariants\n\n${lines.join("\n")}\n`,
  );
}
if (failed) {
  console.error(
    "\nUse a domain reserved for documentation (example.com, example.org, *.example, *.test) in new fixtures, or add a made-up domain to scripts/synthetic-domains.json with the change that needs it.",
  );
  process.exit(1);
}
