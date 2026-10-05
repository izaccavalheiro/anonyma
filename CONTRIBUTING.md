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
- **Documentation** — Improvements to README, API docs, or inline TSDoc are always welcome.

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
bench/                    # Benchmark and corpus generator (`npm run bench`)
scripts/                  # Checks run by CI: smoke test, size budget, privacy, scaling
docs/
└── api.md
```

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
- Run the full suite: `npm run test:coverage` — maintain ≥ 90% coverage.

### Code Style

- Code is formatted with Prettier (`npm run format`) and linted with ESLint (`npm run lint`).
- CI will fail if formatting or lint checks do not pass.

### Continuous integration

Every push and pull request runs the `CI` workflow. Each job answers one question:

| Job            | Question                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------- |
| `static`       | Does the code type-check, lint and follow the format? Are the commit messages conventional?  |
| `test`         | Do the tests pass on Node.js 20, 22, 24 and 26, and on Linux, macOS and Windows?             |
| `coverage`     | Is the code covered above the thresholds in `vitest.config.ts`?                              |
| `package`      | Is the build a valid dual ESM/CJS package (publint, are-the-types-wrong), within its budget? |
| `smoke`        | Does the packed tarball work for a consumer on Node.js 18, 20, 22, 24 and 26?                |
| `performance`  | Is the span engine still linear in the size of its input?                                    |
| `privacy`      | Do the privacy invariants and the compliance suites hold (GDPR, LGPD)?                       |
| `supply-chain` | Are the dependencies free of known vulnerabilities and correctly signed?                     |

CodeQL analyses the source and the workflows on every push, and Dependabot
proposes dependency updates weekly. A new size budget, a new made-up domain in
a fixture or a new entry point belongs in the same pull request as the change
that needs it.

### Documentation

- All exported functions, classes, and interfaces must have TSDoc annotations.
- Usage examples in TSDoc are required for public API symbols.

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

---

## Releasing

Releases are published by GitHub Actions, never from a local machine.

1. Set the version in `package.json` (and `package-lock.json`), and give
   `CHANGELOG.md` a section `## [<version>]`. A test fails when the version
   the code reports differs from `package.json`.
2. Merge into `main`, then push a tag `v<version>` on the merged commit. A
   pre-release may be tagged on its release branch instead; the workflow
   refuses a stable version whose commit is not on `main`.
3. The `Release` workflow runs the whole CI pipeline on the tag, publishes to
   npm with a provenance attestation, and creates the GitHub release with the
   changelog section, the tarball and an SBOM. A version with a prerelease
   suffix (`1.2.0-beta.0`) is published under the `next` dist-tag, any other
   under `latest`.

npm trusts the `Release` workflow as a publisher (trusted publishing through
OpenID Connect), so there is no npm token to store or rotate. Running the
workflow by hand from the Actions tab rehearses all of it without publishing.

---

## Questions?

Open an issue or start a GitHub Discussion. We are happy to help.
