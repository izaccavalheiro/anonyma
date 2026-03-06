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

- **Node.js** ≥ 18
- **npm** ≥ 9

### Getting Started

```bash
git clone https://github.com/izaccavalheiro/anonyma.git
cd anonyma
npm install
npm run typecheck   # Verify TypeScript compilation
npm run lint        # Lint with ESLint
npm run test        # Run test suite
npm run build       # Build ESM + CJS output
```

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
└── strategies/           # One file per anonymization strategy
    ├── mask.ts
    ├── redact.ts
    └── ...
tests/
├── detectors.test.ts
├── strategies.test.ts
├── anonymize.test.ts
└── errors.test.ts
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

### Documentation

- All exported functions, classes, and interfaces must have TSDoc annotations.
- Usage examples in TSDoc are required for public API symbols.

---

## Adding a New PII Detector

1. Create `src/detectors/<category>.ts`.
2. Export a single named function `detect<Category>(text: string): PiiMatch[]`.
3. Re-export it from `src/detectors/index.ts` and add it to `DETECTOR_REGISTRY`.
4. Add `"<category>"` to the `PiiCategory` union in `src/types.ts`.
5. Write tests in `tests/detectors.test.ts`.

---

## Adding a New Strategy

1. Create `src/strategies/<strategy>.ts`.
2. Export a named function with a typed options interface.
3. Re-export from `src/strategies/index.ts`.
4. Handle the new case in `applyStrategySync()` in `src/anonymize.ts`.
5. Add the new option shape to the `StrategyOptions` discriminated union in `src/types.ts`.
6. Add a Zod schema in `src/schemas.ts`.
7. Write tests in `tests/strategies.test.ts`.

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

| Type       | When to use                              |
|------------|------------------------------------------|
| `feat`     | New feature                              |
| `fix`      | Bug fix                                  |
| `docs`     | Documentation only                       |
| `test`     | Tests only                               |
| `refactor` | Code change without fix/feature          |
| `perf`     | Performance improvement                  |
| `chore`    | Build process, deps, tooling             |
| `ci`       | CI/CD changes                            |

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

## Questions?

Open an issue or start a GitHub Discussion. We are happy to help.
