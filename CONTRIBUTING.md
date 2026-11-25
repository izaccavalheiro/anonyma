# Contributing to anonyma

Thank you for investing your time in contributing to anonyma! This document covers
everything you need to get started.

---

## Code of Conduct

Be respectful. We follow the [Contributor Covenant](https://www.contributor-covenant.org/)
Code of Conduct. Harassment or discrimination of any kind will not be tolerated.

---

## Ways to Contribute

- **Bug reports** — Open an issue with a minimal reproduction.
- **Feature requests** — Open an issue describing the use case and expected behaviour.
- **Pull requests** — For bug fixes and small improvements. For large features, open
  an issue first to align on design.
- **Documentation** — Improvements to the documentation site (`website/docs/`), the API docs, or
  inline TSDoc are always welcome.

---

## Development Setup

### Prerequisites

- **Node.js** ≥ 22.22 for development (`.nvmrc` pins the version CI uses). The
  development tooling needs it; the package itself supports Node.js ≥ 18, which
  CI checks by installing the packed tarball on every supported line.
- **npm** ≥ 10

### Getting Started

```bash
git clone https://github.com/izaccavalheiro/anonyma.git
cd anonyma
npm install         # also installs the git hooks
npm run typecheck   # Verify TypeScript compilation
npm run lint        # Lint with ESLint
npm run test        # Run test suite
npm run build       # Build ESM + CJS output
npm run validate    # Everything CI runs, in one command
```

### Git hooks

`npm install` sets up three hooks (Husky):

| Hook         | What it does                                                             |
| ------------ | ------------------------------------------------------------------------ |
| `pre-commit` | Lints and formats the staged files (lint-staged).                        |
| `commit-msg` | Checks the message against Conventional Commits (commitlint).            |
| `pre-push`   | Type check, lint, privacy invariants and the test suite, before pushing. |

Set `HUSKY=0` to skip them for one command. CI runs the same checks regardless.

### Synthetic data only

This library exists to protect personal data, so its repository must not hold
any. Tests, fixtures, benchmarks, issues and pull requests use made-up values
only: addresses under `example.com`, `example.org` or `*.example`, the
documentation IP ranges, the published test card numbers. `npm run check:privacy`
fails on an e-mail address under a domain that is neither reserved for
documentation nor listed in `scripts/synthetic-domains.json`.

---

## Project Structure

```
src/
├── index.ts              # Public API barrel
├── types.ts              # All TypeScript interfaces and types
├── errors.ts             # Typed error classes
├── anonymize.ts          # Core engine: detect(), anonymize(), anonymizeRecord()
├── schemas.ts            # Zod schemas and AI/MCP tool definitions
├── detectors/            # One file per PII category
│   ├── email.ts
│   ├── phone.ts
│   └── ...
├── strategies/           # One file per anonymization strategy
│   ├── mask.ts
│   ├── redact.ts
│   └── ...
├── engine/               # "anonyma/engine": span detectors, pipelines, replacers, streams
├── vault/                # "anonyma/vault": key ring, tokenizers, token vault, rotation
├── audit/                # "anonyma/audit": hash-chained audit log
├── compliance/           # "anonyma/compliance": regulation profiles, policies, erasure
├── ai/                   # "anonyma/ai": JSON and chat-message sanitizers, LLM guard
├── mcp/                  # "anonyma/mcp": MCP declarations and server
├── middleware/           # "anonyma/middleware": HTTP payload scrubbing, Express, Hono
└── internal/             # Helpers shared by the modules above; not exported
tests/                    # Mirrors src/, with a folder per subpath module
├── detectors.test.ts
├── strategies.test.ts
├── anonymize.test.ts
├── errors.test.ts
├── engine/
├── ...
└── fixtures/corpus/      # Labelled detector corpora (precision and recall floors)
packages/                 # npm workspaces, each versioned on its own
├── cli/                  # anonyma-cli: the `anonyma` command
├── vercel-ai/            # anonyma-vercel-ai: Vercel AI SDK middleware
├── mcp/                  # anonyma-mcp: MCP guard and proxy
├── parallel/             # anonyma-parallel: a pool of worker threads for the batch functions
├── conformance/          # private: the conformance suite every implementation passes
└── sidecar/              # the sidecar: a local HTTP and MCP service, shipped as an image
crates/                   # The Rust core (anonyma-core) and its JSON API and C ABI (anonyma-ffi)
bindings/                 # Python, Go, Node.js (anonyma-native) and WebAssembly, on the core
bench/                    # Benchmark and corpus generator (`npm run bench`), engine matrix
scripts/                  # Checks run by CI: smoke test, size budget, privacy, scaling
website/                  # The documentation site (Docusaurus)
docs/
├── api.md                # API reference of the core functions
├── history.md            # History and decisions
└── rfcs/                 # Design records, such as RFC 0001 (one Rust core)
```

The Rust core and the bindings have their own toolchains (Cargo, maturin, Go). A change to a
detector, validator, token format, preset or receipt is a change for every language: give it a case
in `packages/conformance/conformance-tests.json` first, as
[RFC 0001](docs/rfcs/0001-polyglot-core.md) describes.

---

## Engineering Standards

All PRs must satisfy these requirements before merge:

### TypeScript

- **No `any`** — Use `unknown` + type guards, or proper discriminated unions.
- **No `@ts-ignore`** — Fix the root cause instead.
- Strict mode passes with zero errors: `npm run typecheck`.

### Testing

- Every new code path requires at least one test in the `tests/` directory.
- Tests live in `tests/` and use [Vitest](https://vitest.dev/).
- Run the full suite: `npm run test:coverage` — coverage must stay at 100%.

### Code Style

- Code is formatted with Prettier (`npm run format`) and linted with ESLint (`npm run lint`).
- CI will fail if formatting or lint checks do not pass.

### Continuous integration

Every push and pull request runs the `CI` workflow. Each job answers one question:

| Job            | Question                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------- |
| `static`       | Does the code type-check, lint and follow the format? Are the commit messages conventional?  |
| `test`         | Do the tests pass on Node.js 22, 24 and 26, and on Linux, macOS and Windows?                 |
| `coverage`     | Is the code covered above the thresholds in `vitest.config.ts`?                              |
| `package`      | Is the build a valid dual ESM/CJS package (publint, are-the-types-wrong), within its budget? |
| `smoke`        | Does the packed tarball work for a consumer on Node.js 18, 20, 22, 24 and 26?                |
| `runtimes`     | Does the built package work on Bun, Deno and Cloudflare Workers?                             |
| `packages`     | Do the companion packages (`packages/*`) type-check, pass their tests and pack?              |
| `site`         | Does the site (`website/`) type-check and build, with no broken link?                        |
| `performance`  | Is the span engine still linear in the size of its input?                                    |
| `privacy`      | Do the privacy invariants and the compliance suites hold (GDPR, LGPD)?                       |
| `supply-chain` | Are the dependencies free of known vulnerabilities and correctly signed?                     |

The `Polyglot` workflow runs the conformance suite in every language on every pull request: the
TypeScript reference, the Rust core on Linux, macOS and Windows, Python, Go on five platforms, and
the WebAssembly and Node.js builds. The `Performance comparison` workflow times a pull request
against its base on the same runner. CodeQL analyses the source and the workflows on every push, and
Dependabot proposes dependency updates weekly. A new size budget, a new made-up domain in
a fixture or a new entry point belongs in the same pull request as the change
that needs it.

### Documentation

- All exported functions, classes, and interfaces must have TSDoc annotations.
- Usage examples in TSDoc are required for public API symbols.

### The site

The site at <https://izaccavalheiro.github.io/anonyma/> (`website/`, Docusaurus) is the main
documentation of the library, published from `main` by the **Site** workflow. `README.md` is a short
overview for GitHub and npm that links to it: document a feature on the site, and mention it in the
README only if it changes what a newcomer should know.

| On the site                                   | Comes from                                          |
| --------------------------------------------- | --------------------------------------------------- |
| Introduction, library guide, recipes, FAQ     | `website/docs/` (written there)                     |
| Home page, playground, blog                   | `website/src/`, `website/blog/`                     |
| Packages                                      | `packages/*/README.md`, `bindings/*/README.md`      |
| API reference, architecture, benchmark method | `docs/api.md`, `ARCHITECTURE.md`, `bench/README.md` |
| Conformance suite                             | `packages/conformance/README.md`                    |
| Categories, presets, regulations, checksums   | the built library (`dist/`)                         |
| Changelog, security, contributing             | the files of the same name                          |
| History and decisions, RFC 0001               | `docs/history.md`, `docs/rfcs/`                     |
| Package changelogs, releases table            | the `CHANGELOG.md` of every package                 |
| Benchmarks page                               | `bench/results/*.json`                              |

A new package goes into `PACKAGES` in `website/scripts/sync.mjs`, which gives it a page, a changelog
page and a row on the releases page. A minor release of `anonyma` gets a post on the blog
(`website/blog/`) that says what changed, why, and what to check when upgrading.

`website/scripts/sync.mjs` generates the pages that come from other files; they are git-ignored, so
edit their sources. Every example on a guide page shows real output: run it against the build
before you commit it.

```bash
npm ci --prefix website   # once
npm run site              # build the library, then serve the site with live reload
npm run build:site        # what CI runs: type check and production build
```

The build fails on a broken link or anchor. The site's Content Security Policy
(`website/docusaurus.config.ts`) allows one other origin, its analytics service, for scripts and
connections, and nothing else; the playground's own code opens no connection.
`npm run check:privacy` fails if the policy is loosened any further.

---

## Adding a New PII Detector

1. Create `src/detectors/<category>.ts`.
2. Export a single named function `detect<Category>(text: string): PiiMatch[]`.
3. Re-export it from `src/detectors/index.ts` and add it to `DETECTOR_REGISTRY`.
4. Add `"<category>"` to the `PiiCategory` union in `src/types.ts`, to `ALL_CATEGORIES` and
   `TOKEN_PREFIX_MAP` in `src/anonymize.ts`, and to `TOKEN_PREFIX_MAP` in `src/tokenize.ts`.
5. Wrap it for the span engine in `src/engine/builtin.ts` (`LEGACY_DETECTORS`,
   `BUILTIN_CATEGORIES` and a named export), and add it to `PiiCategorySchema` in
   `src/schemas.ts`.
6. Write tests in `tests/detectors.test.ts`.
7. Add its cases to the conformance suite (`detect:<category>`), and port it to
   `crates/anonyma-core` or leave the capability out there, so the other languages refuse the
   category instead of skipping it.

---

## Adding a New Strategy

1. Create `src/strategies/<strategy>.ts`.
2. Export a named function with a typed options interface.
3. Re-export from `src/strategies/index.ts`.
4. Handle the new case in `applyStrategySync()` in `src/anonymize.ts`.
5. Handle it in `strategyReplacer()` in `src/engine/replacers.ts`, and describe the protection it
   gives in `describeStrategy()` in `src/compliance/traits.ts`.
6. Add the new option shape to the `StrategyOptions` discriminated union in `src/types.ts`.
7. Add a Zod schema in `src/schemas.ts`.
8. Write tests in `tests/strategies.test.ts`.

---

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

Examples:
feat(detectors): add passport number detector
fix(mask): handle empty string input correctly
docs(readme): add AI integration example
test(strategies): increase hash coverage
chore(deps): bump typescript to 5.5
```

| Type       | When to use                     |
| ---------- | ------------------------------- |
| `feat`     | New feature                     |
| `fix`      | Bug fix                         |
| `docs`     | Documentation only              |
| `test`     | Tests only                      |
| `refactor` | Code change without fix/feature |
| `perf`     | Performance improvement         |
| `chore`    | Build process, deps, tooling    |
| `ci`       | CI/CD changes                   |

---

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, ensuring all checks pass locally.
3. Open a PR against `main` with a clear description and link to any related issues.
4. A maintainer will review your PR. Feedback will be constructive and timely.
5. After approval and CI green, the PR will be squash-merged.

---

## Versioning

anonyma follows **Semantic Versioning (SemVer)**:

- **Patch** (`x.x.PATCH`): Backward-compatible bug fixes.
- **Minor** (`x.MINOR.x`): New features, no breaking changes.
- **Major** (`MAJOR.x.x`): Breaking API changes.

Widening a type that the library returns (a new member of a union in a result)
is a minor change; say so in the changelog, since an exhaustive `switch` over it
needs a new case. Removing or narrowing anything public is a major change.

The companion packages in `packages/` are versioned independently of
`anonyma`, each with its own `CHANGELOG.md`:

- While a package is at `0.x`, a minor version may change its API and a patch
  version may not.
- A package names the lowest `anonyma` it needs as a caret peer range
  (`^1.2.0`). Raise it when the package starts relying on a newer release, and
  release that `anonyma` first.
- A change to `anonyma` that a package depends on goes into the `anonyma`
  changelog; the package's changelog records the new peer range.

---

## Releasing

Releases are published by GitHub Actions, never from a local machine.

1. Set the version in `package.json` (and `package-lock.json`) and in
   `src/version.ts`, and give `CHANGELOG.md` a section `## [<version>]`. A test
   fails when the version the code reports differs from `package.json`.
2. Merge into `main`, then push a tag `v<version>` on the merged commit. A
   pre-release may be tagged on its release branch instead; the workflow
   refuses a stable version whose commit is not on `main`.
3. The `Release` workflow runs the whole CI pipeline on the tag, publishes to
   npm with a provenance attestation, and creates the GitHub release with the
   changelog section, the tarball and an SBOM. A version with a prerelease
   suffix (`1.2.0-beta.0`) is published under the `next` dist-tag, any other
   under `latest`.

The same tag also publishes the companion packages. After anonyma, the
workflow runs `scripts/publish-packages.mjs`, which publishes every package in
`packages/` whose version is not on the registry yet, provided a published
anonyma satisfies its peer range. To release a package, raise its version and
add its changelog section; it goes out with the next release tag. A package's
version can also be released alone by tagging an anonyma patch release.

Trusted publishing is configured per package on npm. A new package needs a
trusted publisher for the `Release` workflow (`release.yml`, environment `npm`)
before its first release. npm only configures packages that already exist, so
the first version of a new package is published once by hand, from a clean
checkout of the tagged commit (`npm run build && npm run build:packages`, then
`npm publish --access public` in its directory), and the trusted publisher is
added after it.

npm trusts the `Release` workflow as a publisher (trusted publishing through
OpenID Connect), so there is no npm token to store or rotate. Running the
workflow by hand from the Actions tab rehearses all of it without publishing.

The packages built on the Rust core are released by the `Polyglot` workflow
(`polyglot-release.yml`) from tags of their own, each with a section in its own
changelog: `native-v<version>` (`bindings/node`, to npm), `python-v<version>`
(`bindings/python`, to PyPI), `go-v<version>` (`bindings/go`, to the
`anonyma-go` repository) and `sidecar-v<version>` (`packages/sidecar`, to the
GitHub Container Registry). Their GitHub releases never take the "Latest"
badge, which stays with `anonyma`; keep their entries out of the root
`CHANGELOG.md`, whose sections are the npm release notes. Push at most three
tags at a time: GitHub starts no workflow for a push of more tags than that.

---

## Questions?

Open an issue: questions are welcome there as well as bug reports. The
[site](https://izaccavalheiro.github.io/anonyma/) answers most of them, and
[history and decisions](docs/history.md) explains why the project is built the way it is.
