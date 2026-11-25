#!/usr/bin/env node
/**
 * Write the pages of the site that come from the repository itself, so that
 * the site never says something the repository does not:
 *
 * - docs/packages/   the READMEs of the published packages: packages/* and bindings/*;
 * - docs/reference/  docs/api.md, ARCHITECTURE.md, bench/README.md, the conformance
 *                    suite's README, and tables generated from the built library
 *                    (categories, presets, regulations, checksums);
 * - docs/project/    CHANGELOG.md, docs/history.md, RFC 0001, SECURITY.md,
 *                    CONTRIBUTING.md, the changelog of every other package, and a
 *                    table of releases read from all the changelogs;
 * - src/data/        the benchmark results, the matrix of engines and its cost model.
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
/** The site's own address: links to it from the repository's files become links between pages. */
const SITE = "https://izaccavalheiro.github.io/anonyma";

// ---------------------------------------------------------------------------
// What goes where
// ---------------------------------------------------------------------------

/**
 * Every published package: its README, its changelog, where it is published
 * and how to install it. The package pages, the changelogs and the releases
 * table are all made from this list.
 */
const PACKAGES = [
  {
    name: "anonyma",
    slug: "anonyma",
    title: "anonyma",
    readme: undefined,
    changelog: "CHANGELOG.md",
    where: "npm",
    install: "npm install anonyma",
  },
  {
    name: "anonyma-cli",
    slug: "cli",
    title: "Command line (anonyma-cli)",
    readme: "packages/cli/README.md",
    changelog: "packages/cli/CHANGELOG.md",
    where: "npm",
    install: "npm install --global anonyma-cli anonyma",
  },
  {
    name: "anonyma-vercel-ai",
    slug: "vercel-ai",
    title: "Vercel AI SDK (anonyma-vercel-ai)",
    readme: "packages/vercel-ai/README.md",
    changelog: "packages/vercel-ai/CHANGELOG.md",
    where: "npm",
    install: "npm install anonyma-vercel-ai anonyma ai",
  },
  {
    name: "anonyma-mcp",
    slug: "mcp",
    title: "MCP (anonyma-mcp)",
    readme: "packages/mcp/README.md",
    changelog: "packages/mcp/CHANGELOG.md",
    where: "npm",
    install: "npm install anonyma-mcp anonyma",
  },
  {
    name: "anonyma-parallel",
    slug: "parallel",
    title: "Worker pool (anonyma-parallel)",
    readme: "packages/parallel/README.md",
    changelog: "packages/parallel/CHANGELOG.md",
    where: "npm",
    install: "npm install anonyma anonyma-parallel",
  },
  {
    name: "anonyma-native",
    slug: "native",
    title: "Rust engine for Node.js (anonyma-native)",
    readme: "bindings/node/README.md",
    changelog: "bindings/node/CHANGELOG.md",
    where: "npm",
    install: "npm install anonyma-native",
  },
  {
    name: "anonyma for Python",
    slug: "python",
    title: "Python",
    readme: "bindings/python/README.md",
    changelog: "bindings/python/CHANGELOG.md",
    where: "PyPI",
    install: "pip install --pre anonyma",
  },
  {
    name: "anonyma for Go",
    slug: "go",
    title: "Go",
    readme: "bindings/go/README.md",
    changelog: "bindings/go/CHANGELOG.md",
    where: "Go modules",
    install: "go get github.com/izaccavalheiro/anonyma-go@latest",
  },
  {
    name: "anonyma-sidecar",
    slug: "sidecar",
    title: "Sidecar (any language)",
    readme: "packages/sidecar/README.md",
    changelog: "packages/sidecar/CHANGELOG.md",
    where: "GitHub Container Registry",
    install: "docker pull ghcr.io/izaccavalheiro/anonyma-sidecar",
  },
];

/** The page of a package's README, and of its changelog. */
const readmePage = (pkg) => (pkg.readme === undefined ? "intro.md" : `packages/${pkg.slug}.md`);
const changelogPage = (pkg) =>
  pkg.readme === undefined ? "project/changelog.md" : `project/changelogs/${pkg.slug}.md`;

/** Whole files: repository path → [page, title, sidebar position]. */
const FILES = {
  "docs/api.md": ["reference/api.md", "API reference", 1],
  "ARCHITECTURE.md": ["reference/architecture.md", "Architecture", 6],
  "bench/README.md": ["reference/benchmark-method.md", "Benchmark method", 7],
  "packages/conformance/README.md": ["reference/conformance.md", "Conformance suite", 8],
  "CHANGELOG.md": ["project/changelog.md", "Changelog", 2],
  "docs/history.md": ["project/history.md", "History and decisions", 3],
  "docs/rfcs/0001-polyglot-core.md": ["project/rfc-0001-polyglot-core.md", "RFC 0001: one core", 4],
  "SECURITY.md": ["project/security.md", "Security policy", 6],
  "CONTRIBUTING.md": ["project/contributing.md", "Contributing", 7],
};
PACKAGES.forEach((pkg, index) => {
  if (pkg.readme === undefined) return;
  FILES[pkg.readme] = [readmePage(pkg), pkg.title, index];
  FILES[pkg.changelog] = [changelogPage(pkg), pkg.name, index];
});

/** Repository paths that are pages of the site. */
const pageOf = new Map([["README.md", "intro.md"]]);
for (const [path, [page]] of Object.entries(FILES)) {
  pageOf.set(path, page);
  // A link to a package's folder is a link to its README.
  if (posix.basename(path) === "README.md") pageOf.set(posix.dirname(path), page);
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
        if (target === SITE || target.startsWith(`${SITE}/`)) {
          // A link to the site itself becomes a link between its pages, which the build checks.
          return `${bang}[${label}](${target.slice(SITE.length) || "/"})`;
        }
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
  "Packages",
  4,
  "Published separately from anonyma, each with its own version: the companion packages on npm, " +
    "and anonyma for Python, Go and, through the sidecar, any language.",
);
category(
  "project",
  "Project",
  6,
  "Releases, history and decisions, the security policy, and how to contribute.",
);
category(
  "project/changelogs",
  "Package changelogs",
  5,
  "The changelog of every package besides anonyma. Each package is versioned on its own.",
);

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
  "The API, generated tables, the architecture, the benchmark method and the conformance suite.",
);

// --- Releases of every package, from the changelogs ---------------------------

/** The id Docusaurus gives a heading (github-slugger): punctuation goes, spaces become hyphens. */
function headingId(text) {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, "")
    .replace(/ /g, "-");
}

/** Every released version of a changelog, newest first, from headings like `## [1.5.2] — 2026-11-24`. */
function releasesIn(changelog) {
  const releases = [];
  for (const { line, code } of linesOf(readFileSync(join(root, changelog), "utf8"))) {
    const heading = code ? null : /^## \[(\d[^\]]*)\] — (\d{4}-\d{2}-\d{2})\s*$/.exec(line);
    if (heading !== null) {
      releases.push({ version: heading[1], date: heading[2], anchor: headingId(line.slice(3)) });
    }
  }
  if (releases.length === 0) throw new Error(`${changelog} has no released version`);
  return releases;
}

/** What a version promises: semantic versioning, the 0.x rule, or none yet. */
function stageOf(version) {
  const prerelease = /^\d+\.\d+\.\d+(.*)$/.exec(version)?.[1] ?? "";
  if (/^-?(?:a|alpha)/.test(prerelease)) return "alpha";
  if (/^-?(?:b|beta)/.test(prerelease)) return "beta";
  if (prerelease !== "") return "pre-release";
  return version.startsWith("0.") ? "0.x" : "stable";
}

{
  const fromReleases = (page, anchor) =>
    `${posix.relative("project", page)}${anchor === undefined ? "" : `#${anchor}`}`;
  const every = [];
  let body =
    ":::note\n\nGenerated from the changelogs in the repository, so it lists exactly what was released.\n\n:::\n\n";
  body +=
    "Every package of the project, with its latest release. Each package is versioned on its own, " +
    "and its changelog records every release with what changed and why.\n\n";
  body += header(["Package", "Published on", "Latest", "Released", "First release", "Stage"]);
  for (const pkg of PACKAGES) {
    const releases = releasesIn(pkg.changelog);
    const latest = releases[0];
    const first = releases[releases.length - 1];
    body +=
      `| [${pkg.name}](${fromReleases(readmePage(pkg))}) | ${pkg.where} ` +
      `| [${latest.version}](${fromReleases(changelogPage(pkg), latest.anchor)}) ` +
      `| ${latest.date} | ${first.date} | ${stageOf(latest.version)} |\n`;
    for (const release of releases) every.push({ ...release, pkg });
  }
  body += "\n";
  body +=
    "- **stable**: semantic versioning. A change that breaks code written for an earlier version " +
    "needs a new major version.\n" +
    "- **0.x**: a minor version may change the API, a patch version may not.\n" +
    "- **alpha**: a pre-release. The API may change in any release; Python's pip needs `--pre`.\n\n";

  body += "## Install\n\n";
  body += header(["Package", "Command"]);
  for (const pkg of PACKAGES) body += `| ${pkg.name} | \`${pkg.install}\` |\n`;

  body += "\n## How a release is made\n\n";
  body +=
    "Every package is published by a workflow from a version tag, never from a developer's machine, " +
    "and its release on GitHub carries the section of its changelog.\n\n";
  body += header(["Tag", "Publishes", "Workflow"]);
  body +=
    "| `v<version>` | `anonyma` to npm, and every package in `packages/` whose version is new | " +
    "[`release.yml`](" +
    `${REPOSITORY}/blob/main/.github/workflows/release.yml) |\n`;
  for (const [tag, what] of [
    ["native-v<version>", "`anonyma-native` and its five platform packages to npm"],
    ["python-v<version>", "the wheels and the source distribution to PyPI"],
    ["go-v<version>", "the Go module with its prebuilt libraries to `anonyma-go`"],
    ["sidecar-v<version>", "the container image to `ghcr.io/izaccavalheiro/anonyma-sidecar`"],
  ]) {
    body += `| \`${tag}\` | ${what} | [\`polyglot-release.yml\`](${REPOSITORY}/blob/main/.github/workflows/polyglot-release.yml) |\n`;
  }

  body += "\n## Every release\n\n";
  body += `${String(every.length)} releases of ${String(PACKAGES.length)} packages, newest first.\n\n`;
  body += header(["Date", "Package", "Version"]);
  every.sort((a, b) => b.date.localeCompare(a.date));
  for (const release of every) {
    body += `| ${release.date} | ${release.pkg.name} | [${release.version}](${fromReleases(changelogPage(release.pkg), release.anchor)}) |\n`;
  }
  write(
    "project/releases.md",
    frontMatter({
      title: "Releases",
      sidebar_position: 1,
      description: "The latest release of every anonyma package, and every release so far.",
    }) + body,
  );
}

// --- Benchmark results --------------------------------------------------------
mkdirSync(join(site, "src", "data"), { recursive: true });
for (const name of ["baseline", "current"]) {
  const results = JSON.parse(readFileSync(join(root, "bench", "results", `${name}.json`), "utf8"));
  // Where the build lay on the measuring machine says nothing about the results.
  delete results.environment.dist;
  writeFileSync(join(site, "src", "data", `bench-${name}.json`), `${JSON.stringify(results)}\n`);
}
// The benchmark matrix: every engine on one corpus, and the cost model fitted on it.
for (const name of ["matrix", "model"]) {
  const results = readFileSync(join(root, "bench", "results", `${name}.json`), "utf8");
  writeFileSync(
    join(site, "src", "data", `bench-${name}.json`),
    `${JSON.stringify(JSON.parse(results))}\n`,
  );
}
writeFileSync(
  join(site, "src", "data", "library.json"),
  `${JSON.stringify({ version: core.VERSION, categories: engine.BUILTIN_CATEGORIES.length, presets: presetNames })}\n`,
);

console.log(`sync: ${String(written.length)} pages from the repository (${relative(root, docs)})`);
