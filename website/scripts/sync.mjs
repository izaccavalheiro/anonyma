#!/usr/bin/env node
/**
 * Write the pages of the site that come from the repository itself, so that
 * the site never says something the repository does not:
 *
 * - docs/packages/   the READMEs of packages/*;
 * - docs/reference/  docs/api.md, ARCHITECTURE.md, bench/README.md, and tables
 *                    generated from the built library (categories, presets,
 *                    regulations, checksums);
 * - docs/project/    CHANGELOG.md, SECURITY.md, CONTRIBUTING.md;
 * - src/data/        the benchmark results.
 *
 * The rest of docs/ — the introduction, the library guide (docs/guide/), the
 * recipes and the FAQ — is written in website/ and is the main documentation
 * of the library; README.md is a short overview that links to it.
 *
 * Links between these files become links between pages, links to a page under
 * website/docs/ become links to that page, and links to anything else in the
 * repository point to GitHub. The library must have been built
 * (`npm run build` at the root): the reference tables are read from dist/.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, posix, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const site = join(dirname(fileURLToPath(import.meta.url)), "..");
const root = join(site, "..");
const docs = join(site, "docs");
const REPOSITORY = "https://github.com/izaccavalheiro/anonyma";

// ---------------------------------------------------------------------------
// What goes where
// ---------------------------------------------------------------------------

/** Whole files: repository path → [page, title, sidebar position]. */
const FILES = {
  "docs/api.md": ["reference/api.md", "API reference", 1],
  "ARCHITECTURE.md": ["reference/architecture.md", "Architecture", 6],
  "bench/README.md": ["reference/benchmark-method.md", "Benchmark method", 7],
  "packages/cli/README.md": ["packages/cli.md", "Command line (anonyma-cli)", 1],
  "packages/vercel-ai/README.md": ["packages/vercel-ai.md", "Vercel AI SDK (anonyma-vercel-ai)", 2],
  "packages/mcp/README.md": ["packages/mcp.md", "MCP (anonyma-mcp)", 3],
  "CHANGELOG.md": ["project/changelog.md", "Changelog", 1],
  "SECURITY.md": ["project/security.md", "Security policy", 2],
  "CONTRIBUTING.md": ["project/contributing.md", "Contributing", 3],
};

/** Repository paths that are pages of the site. */
const pageOf = new Map([["README.md", "intro.md"]]);
for (const [path, [page]] of Object.entries(FILES)) {
  pageOf.set(path, page);
  if (path.startsWith("packages/")) pageOf.set(dirname(path), page);
}
/** The page that a repository path is, if it is one: generated, or written under website/docs/. */
function pageFor(repoPath) {
  const mapped = pageOf.get(repoPath);
  if (mapped !== undefined) return mapped;
  const written = /^website\/docs\/(.+\.mdx?)$/.exec(repoPath);
  return written !== null && existsSync(join(root, repoPath)) ? written[1] : undefined;
}

// ---------------------------------------------------------------------------
// Markdown helpers
// ---------------------------------------------------------------------------

/** Lines of `text` outside fenced code blocks, with a flag for each. */
function* linesOf(text) {
  let fence = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) {
      fence = !fence;
      yield { line, code: true };
      continue;
    }
    yield { line, code: fence };
  }
}

function frontMatter(fields) {
  const lines = Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(
      ([key, value]) =>
        `${key}: ${typeof value === "string" ? JSON.stringify(value) : String(value)}`,
    );
  return `---\n${lines.join("\n")}\n---\n\n`;
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/** Rewrite the links of `text`, which came from `source` and becomes the page `page`. */
function rewriteLinks(text, source, page) {
  const sourceDir = posix.dirname(source);
  const pageDir = posix.dirname(page);
  const out = [];
  for (const { line, code } of linesOf(text)) {
    if (code) {
      out.push(line);
      continue;
    }
    out.push(
      line.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)\)/g, (whole, bang, label, target) => {
        if (/^(?:[a-z]+:|\/\/)/i.test(target)) {
          // A remote image cannot load under the site's Content Security Policy: link to it.
          return bang === "!" ? `[${label}](${target})` : whole;
        }
        const [path, hash] = target.split("#");
        if (path === "") return whole;
        const repoPath = posix.normalize(posix.join(sourceDir, path)).replace(/\/$/, "");
        const mapped = pageFor(repoPath);
        if (mapped !== undefined) {
          const anchor = hash === undefined || hash === "readme" ? "" : `#${hash}`;
          return `[${label}](${posix.relative(pageDir, mapped)}${anchor})`;
        }
        const onDisk = join(root, repoPath);
        if (!existsSync(onDisk)) throw new Error(`${source}: broken link to ${target}`);
        const kind = statSync(onDisk).isDirectory() ? "tree" : "blob";
        return `${bang}[${label}](${REPOSITORY}/${kind}/main/${repoPath}${hash ? `#${hash}` : ""})`;
      }),
    );
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

const written = [];

function write(page, content) {
  const path = join(docs, page);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  written.push(page);
}

function category(dir, label, position, description) {
  const path = join(docs, dir, "_category_.json");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    `${JSON.stringify({ label, position, link: { type: "generated-index", description } }, null, 2)}\n`,
  );
}

for (const dir of ["packages", "reference", "project"]) {
  rmSync(join(docs, dir), { recursive: true, force: true });
}
rmSync(join(site, "src", "data"), { recursive: true, force: true });

// --- Whole files --------------------------------------------------------------
for (const [source, [page, title, position]] of Object.entries(FILES)) {
  let text = readFileSync(join(root, source), "utf8");
  // The title is the page's; badges and the first heading go.
  text = text.replace(/^(?:\[!\[[^\n]*\n)+/m, "").replace(/^# [^\n]*\n+/, "");
  write(
    page,
    frontMatter({
      title,
      sidebar_position: position,
      custom_edit_url: `${REPOSITORY}/edit/main/${source}`,
    }) +
      rewriteLinks(text, source, page) +
      "\n",
  );
}
category(
  "packages",
  "Companion packages",
  4,
  "Published separately; each takes anonyma as a peer dependency.",
);
category("project", "Project", 6, "Releases, security and how to contribute.");

// --- Reference tables from the built library ---------------------------------
const dist = join(root, "dist");
if (!existsSync(join(dist, "index.js"))) {
  throw new Error("Build the library first: npm run build (at the repository root)");
}
const load = (path) => import(pathToFileURL(join(dist, path)).href);
const core = await load("index.js");
const engine = await load("engine/index.js");
const compliance = await load("compliance/index.js");
const validators = await load("validators.js");

function strategyLabel(strategy) {
  if (strategy.strategy === "mask") {
    const kept = [];
    if (strategy.keepLeading) kept.push(`first ${String(strategy.keepLeading)}`);
    if (strategy.keepTrailing) kept.push(`last ${String(strategy.keepTrailing)}`);
    return kept.length > 0 ? `mask (${kept.join(", ")} kept)` : "mask";
  }
  return strategy.strategy;
}

const presetNames = Object.keys(core.PRESET_REGISTRY);
const header = (cells) => `| ${cells.join(" | ")} |\n| ${cells.map(() => "---").join(" | ")} |\n`;
const generatedNote = (what) =>
  `:::note\n\nGenerated from ${what} of anonyma ${core.VERSION}, so it is always what the code does.\n\n:::\n\n`;

{
  let body = generatedNote("the detectors");
  body +=
    "Every category is detected without configuration. In the validating pipelines of `anonyma/engine` " +
    "(the default of `compilePipeline()`), some categories use detectors that verify what they find — " +
    "check digits, issuer ranges, allocation rules — and leave look-alikes alone.\n\n";
  body += header(["Category", "Validating pipeline", "Presets that detect it"]);
  for (const name of engine.BUILTIN_CATEGORIES) {
    const [first] = engine.builtinDetectors([name]);
    const validating = first !== engine.LEGACY_DETECTORS[name];
    const presets = presetNames.filter((preset) =>
      core.PRESET_REGISTRY[preset].categories.includes(name),
    );
    body += `| \`${name}\` | ${validating ? "validates" : "pattern and context"} | ${presets.map((p) => `\`${p}\``).join(", ") || "—"} |\n`;
  }
  write(
    "reference/categories.md",
    frontMatter({ title: "Categories", sidebar_position: 2 }) + body,
  );
}

{
  let body = generatedNote("the presets");
  body +=
    'What each preset detects and how it replaces it. A list of presets (`preset: ["lgpd", "hipaa"]`) ' +
    "detects every category of every preset; each category gets the most protective of their strategies. " +
    "See [Compliance presets](../guide/presets.md).\n\n";
  body += header(["Category", ...presetNames.map((name) => `\`${name}\``)]);
  for (const name of engine.BUILTIN_CATEGORIES) {
    const cells = presetNames.map((preset) => {
      const config = core.PRESET_REGISTRY[preset];
      if (!config.categories.includes(name)) return "";
      const rule =
        config.rules?.find((r) => r.category === name)?.strategy ?? config.defaultStrategy;
      return strategyLabel(rule);
    });
    if (cells.some((cell) => cell !== "")) body += `| \`${name}\` | ${cells.join(" | ")} |\n`;
  }
  body += "\n## Descriptions\n\n";
  for (const name of presetNames)
    body += `- **\`${name}\`** — ${core.PRESET_REGISTRY[name].description}\n`;
  write("reference/presets.md", frontMatter({ title: "Presets", sidebar_position: 3 }) + body);
}

{
  let body = generatedNote("the regulation profiles of `anonyma/compliance`");
  body +=
    "Each profile maps categories to the provisions that name them, says which protection a strategy " +
    "must give, and lists the data the regulation names that no detector covers. Policies that extend a " +
    "profile are checked against it.\n\n";
  for (const regulation of Object.values(compliance.REGULATIONS)) {
    body += `## ${regulation.name}\n\n${regulation.jurisdiction} · ${regulation.edition} · id \`${regulation.id}\`\n\n`;
    body += header(["Category", "Recommended", "Provision"]);
    for (const rule of regulation.rules) {
      const reference = rule.references[0];
      const citation =
        reference === undefined
          ? ""
          : reference.url
            ? `[${reference.citation}](${reference.url})`
            : reference.citation;
      body += `| \`${rule.category}\` | ${strategyLabel(rule.recommended)} | ${citation} |\n`;
    }
    if (regulation.gaps.length > 0) {
      body += "\nNot covered by a detector:\n\n";
      for (const gap of regulation.gaps) body += `- **${gap.element}** — ${gap.mitigation}\n`;
    }
    body += "\n";
  }
  write(
    "reference/regulations.md",
    frontMatter({ title: "Regulations", sidebar_position: 4 }) + body,
  );
}

{
  let body = generatedNote("`CHECKSUMS` in `anonyma/validators`");
  body +=
    "A declarative pattern names the check digits its matches must pass, " +
    '`{ source: "\\\\b\\\\d{9}\\\\b", category: "routing", validator: "aba-routing" }`, ' +
    "and every validator can be imported on its own.\n\n";
  body += header(["Name in a pattern", "Function"]);
  for (const [name, check] of Object.entries(validators.CHECKSUMS)) {
    body += `| \`${name}\` | ${check.name && check.name !== name ? `\`${check.name}()\`` : "—"} |\n`;
  }
  write("reference/checksums.md", frontMatter({ title: "Checksums", sidebar_position: 5 }) + body);
}
category(
  "reference",
  "Reference",
  5,
  "The API, generated tables, the architecture and the benchmark method.",
);

// --- Benchmark results --------------------------------------------------------
mkdirSync(join(site, "src", "data"), { recursive: true });
for (const name of ["baseline", "current"]) {
  const results = JSON.parse(readFileSync(join(root, "bench", "results", `${name}.json`), "utf8"));
  // Where the build lay on the measuring machine says nothing about the results.
  delete results.environment.dist;
  writeFileSync(join(site, "src", "data", `bench-${name}.json`), `${JSON.stringify(results)}\n`);
}
writeFileSync(
  join(site, "src", "data", "library.json"),
  `${JSON.stringify({ version: core.VERSION, categories: engine.BUILTIN_CATEGORIES.length, presets: presetNames })}\n`,
);

console.log(`sync: ${String(written.length)} pages from the repository (${relative(root, docs)})`);
