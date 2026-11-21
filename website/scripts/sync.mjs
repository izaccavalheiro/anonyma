#!/usr/bin/env node
/**
 * Write the pages of the site that come from the repository itself, so that
 * the site never says something the repository does not:
 *
 * - docs/guide/      the sections of README.md, one topic per page;
 * - docs/packages/   the READMEs of packages/*;
 * - docs/reference/  docs/api.md, ARCHITECTURE.md, bench/README.md, and tables
 *                    generated from the built library (categories, presets,
 *                    regulations, checksums);
 * - docs/project/    CHANGELOG.md, SECURITY.md, CONTRIBUTING.md;
 * - src/data/        the benchmark results.
 *
 * Links between these files become links between pages; links to anything
 * else in the repository point to GitHub. The library must have been built
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

/** README sections, grouped into guide pages. Every section must be placed or skipped. */
const GUIDE = [
  ["installation", "Installation", ["Installation", "Requirements", "Subpath Imports"]],
  ["quick-start", "Quick start", ["Quick Start"]],
  ["detection", "Detecting personal data", ["Detected PII Categories", "Custom Detectors"]],
  ["validators", "Checksum validators", ["Validators"]],
  [
    "strategies",
    "Anonymization strategies",
    ["Strategies", "Encryption Strategy", "Synthesis Strategy"],
  ],
  ["presets", "Compliance presets", ["Compliance Presets"]],
  ["tokenization", "Reversible tokenization", ["Reversible Tokenization"]],
  ["llm", "LLMs and AI tools", ["LLM Pipeline Helpers", "AI Integration"]],
  ["batch-and-streaming", "Batches and streams", ["Batch Processing", "Streaming"]],
  ["plugins", "Plugins", ["Plugins"]],
  [
    "modules",
    "Engine, vault, audit and AI modules",
    ["Span Engine, Tokenization, Audit and AI Modules"],
  ],
  ["errors", "Errors", ["Errors"]],
];
/** README sections the site covers elsewhere: the home page, the reference, the project pages. */
const SKIPPED = ["Features", "API Documentation", "Companion Packages", "Contributing", "License"];

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

/** Repository paths that are pages of the site; filled as pages are planned. */
const pageOf = new Map([["README.md", "intro.md"]]);
for (const [path, [page]] of Object.entries(FILES)) {
  pageOf.set(path, page);
  if (path.startsWith("packages/")) pageOf.set(dirname(path), page);
}
for (const [slug] of GUIDE) pageOf.set(`#guide/${slug}`, `guide/${slug}.md`);

// ---------------------------------------------------------------------------
// Markdown helpers
// ---------------------------------------------------------------------------

/** The id Docusaurus gives a heading (github-slugger, without the de-duplication suffix). */
function slug(heading) {
  return heading
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/`/g, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

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

function headings(text) {
  const out = [];
  for (const { line, code } of linesOf(text)) {
    const match = !code && /^#{1,6}\s+(.*)$/.exec(line);
    if (match) out.push(slug(match[1]));
  }
  return out;
}

/** Split a Markdown file into its `## ` sections: [title, body without the heading][]. */
function sections(text) {
  const out = [];
  let current;
  for (const { line, code } of linesOf(text)) {
    const match = !code && /^## (.*)$/.exec(line);
    if (match) {
      current = { title: match[1].trim(), lines: [] };
      out.push(current);
    } else if (current !== undefined) {
      current.lines.push(line);
    }
  }
  return out.map(({ title, lines }) => [
    title,
    lines
      .join("\n")
      .replace(/\n---\s*$/, "")
      .trim(),
  ]);
}

/** Raise every heading of `text` by `levels` (`### ` becomes `## ` for 1). */
function promote(text, levels) {
  if (levels === 0) return text;
  const out = [];
  for (const { line, code } of linesOf(text)) {
    out.push(!code && /^#{3,6}\s/.test(line) ? line.slice(levels) : line);
  }
  return out.join("\n");
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

/** Anchor → page, for links to an anchor of README.md that now lives on a guide page. */
const anchors = new Map();

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
        if (path === "") {
          const owner = anchors.get(hash);
          if (owner === undefined || owner === page) return whole;
          return `[${label}](${posix.relative(pageDir, owner)}#${hash})`;
        }
        const repoPath = posix.normalize(posix.join(sourceDir, path)).replace(/\/$/, "");
        const mapped = pageOf.get(repoPath);
        if (mapped !== undefined) {
          const anchor = hash === undefined || hash === "readme" ? "" : `#${hash}`;
          // An anchor of README.md may now be on a guide page.
          const owner =
            repoPath === "README.md" && hash !== undefined ? anchors.get(hash) : undefined;
          return `[${label}](${posix.relative(pageDir, owner ?? mapped)}${anchor})`;
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

for (const dir of ["guide", "packages", "reference", "project"]) {
  rmSync(join(docs, dir), { recursive: true, force: true });
}
rmSync(join(site, "src", "data"), { recursive: true, force: true });

// --- README, one topic per page ----------------------------------------------
const readme = readFileSync(join(root, "README.md"), "utf8");
const readmeSections = new Map(sections(readme));
const placed = new Set([...SKIPPED, ...GUIDE.flatMap(([, , names]) => names)]);
for (const name of readmeSections.keys()) {
  if (!placed.has(name)) {
    throw new Error(
      `README.md section "${name}" has no page: add it to GUIDE or SKIPPED in scripts/sync.mjs`,
    );
  }
}
const guidePages = GUIDE.map(([file, title, names], index) => {
  const parts = names.map((name) => {
    const body = readmeSections.get(name);
    if (body === undefined) throw new Error(`README.md has no section "${name}"`);
    return [name, body];
  });
  const body =
    parts.length === 1
      ? promote(parts[0][1], 1)
      : parts.map(([name, part]) => `## ${name}\n\n${part}`).join("\n\n");
  const page = `guide/${file}.md`;
  for (const id of headings(body)) if (!anchors.has(id)) anchors.set(id, page);
  for (const [name] of parts) anchors.set(slug(name), page);
  return { page, title, position: index + 1, body };
});
for (const { page, title, position, body } of guidePages) {
  write(
    page,
    frontMatter({
      title,
      sidebar_position: position,
      custom_edit_url: `${REPOSITORY}/edit/main/README.md`,
    }) +
      rewriteLinks(body, "README.md", page) +
      "\n",
  );
}
category("guide", "Library guide", 3, "How to use anonyma, topic by topic.");

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
