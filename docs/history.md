# History and decisions

How anonyma got where it is: what each release line changed, why it changed, and what the project
learned on the way. The [changelog](../CHANGELOG.md) records every change, release by release; this
page tells the story and keeps the reasons, so that a decision can be revisited with the facts that
led to it.

## Where it stands

As of November 2026:

- **`anonyma` 1.5** is the library: 27 categories of personal data, 8 strategies, 8 compliance
  presets that combine, reversible and keyed tokens, and the modules for pipelines, vaults, audit
  trails, regulations, LLMs, MCP and HTTP. It is stable: it has followed semantic versioning since
  1.0.0, and it has no runtime dependencies.
- **Five companion npm packages**, each versioned on its own and still at 0.x: the command line
  (`anonyma-cli`), the Vercel AI SDK middleware (`anonyma-vercel-ai`), the MCP proxy
  (`anonyma-mcp`), a pool of worker threads (`anonyma-parallel`) and an engine on the Rust core
  (`anonyma-native`).
- **Other languages**: a Python package and a Go module, both alpha, run on one Rust core that
  ports the TypeScript library, and pass the same conformance suite of 284 cases as the library
  itself. A sidecar container serves the TypeScript library to any language over HTTP.

The [releases page](https://izaccavalheiro.github.io/anonyma/docs/project/releases) lists the
latest version of every package, read from their changelogs.

## Timeline

### 1.0: the library (March 2026)

`detect()`, `anonymize()`, `anonymizeObject()` and reversible `tokenize()`, eight strategies from
redaction to AES-GCM encryption, six compliance presets, WHATWG streams, batches, checksum
validators and optional Zod schemas, with no runtime dependencies from the first commit.

### 1.1: an engine to build on (October 2026)

1.1 added seven entry points without changing what the 1.0 functions did:

- `anonyma/engine`, a span engine. Pipelines are compiled once, overlapping detections are resolved
  so that no detected character is left in the output, validating detectors confirm card numbers,
  IBANs and SSNs, every strategy is applied, and streams catch values split across chunks.
- `anonyma/vault` (keyed tokens and key rings with rotation), `anonyma/audit` (a hash-chained log
  without personal data), `anonyma/compliance` (regulation profiles with citations), `anonyma/ai`,
  `anonyma/mcp` and `anonyma/middleware`.
- The `lgpd` and `pipeda` presets, and releases built by GitHub Actions with provenance and an SBOM.

**Why:** the 1.0 functions could not be changed without breaking their users, and they had limits
that an application handling personal data should not live with: a strategy they could not apply
was replaced by redaction with a warning, and of two overlapping detections only the more confident
was kept. The engine is where those limits are lifted; the 1.0 API stays as it is.

1.1.0 also listed under "Known limitations" what the 1.0 documentation had promised and the code
did not do. 1.1.1 then fixed `allowlist`, which matched substrings: an entry for `bob@example.com`
also exempted `jimbob@example.com`.

### 1.2: plugins, vaults and the edge (November 2026)

Plugins for `createAnonymizer()` ([#6](https://github.com/izaccavalheiro/anonyma/issues/6)), token
vaults with `{{EMAIL_1}}` tokens for LLM prompts, the same feature checks on Node.js, Bun, Deno and
Cloudflare Workers in CI, support for zod 4, and the first two companion packages:
`anonyma-vercel-ai` and `anonyma-mcp`.

### 1.3: check digits, several regulations at once, receipts

- Thirteen national-ID formats are verified by their check digits in the validating pipelines, and
  `withContext()` lets a keyword before a value raise its confidence or be required.
- Brazilian and European formats: CNPJ (including the alphanumeric CNPJ issued from July 2026), RG,
  PIX, and the phone numbers and street addresses of several European countries.
- A list of presets (`["lgpd", "hipaa"]`) gives each category the most protective strategy of the
  presets.
- Signed receipts say what a run replaced without holding a single value.
- `anonyma-cli` scrubs and scans files of any size as streams.

The patch releases that followed published [the documentation site](../website/docs/intro.md)
(1.3.1), fixed the MCP proxy on Windows (1.3.2), and made `anonymize()` and `tokenize()` linear in
the length of the text (1.3.3).

### Beyond JavaScript: one Rust core (November 2026)

[RFC 0001](rfcs/0001-polyglot-core.md) set the plan: one engine in Rust (`crates/anonyma-core`)
that ports the TypeScript library, thin bindings on top of it, a sidecar for every other language
in the meantime, and one conformance suite that every implementation must pass. Within days the
core detected all 27 categories with every validator and preset, and the Python package (on PyPI),
the Go module (`github.com/izaccavalheiro/anonyma-go`) and the sidecar (a container image on GHCR)
had their first alphas.

### 1.4: rules that add to a preset

`rules` given with a preset now adjust the preset instead of replacing it. Before 1.4,
`preset: "gdpr"` with a single rule for `email` left phone numbers in the text, because the rule
took the place of every rule of the preset
([#47](https://github.com/izaccavalheiro/anonyma/issues/47)). The fix changes the output of calls
that combined the two, so it is a minor release, and the changelog says so first. Two detector
fixes keep card numbers whole ([#48](https://github.com/izaccavalheiro/anonyma/issues/48),
[#49](https://github.com/izaccavalheiro/anonyma/issues/49)).

### 1.5: batches, and every core

- 1.5.0 scans the short texts of a batch together: entries under 8 KB are joined with a separator no
  detector matches across, scanned once and split back, with the results of one call per entry.
  745 lines of 100 KB take 44 ms instead of 113. Detectors also skip the patterns that need a label
  when the text has none.
- 1.5.1 finds the label before a value by binary search, so text with many labels and many values
  no longer costs labels × values.
- 1.5.2 published `anonyma-parallel`, a pool of worker threads for the batch functions.
- `anonyma-native` 0.1.0 runs detection and anonymization on the Rust core from Node.js, with
  anonyma's results: 2.4 to 2.9 times faster on single texts, 7 times on batches.

**Why:** most real input is many short texts (log lines, rows, chat turns), and on a short text the
fixed cost of a call is most of the work. The [speed guide](../website/docs/guides/speed-and-batches.md)
says which call to use for which shape of data.

## Decisions, and why

**No runtime dependencies, and the Web platform only.** A library that handles personal data should
be auditable on its own. The source uses no network, file-system or child-process API, and CI
checks that on every change, together with the absence of dependencies. It is written against Web
Crypto and WHATWG streams, so the same build runs on Node.js, Bun, Deno, Cloudflare Workers and in
browsers.

**TypeScript stays the reference, and other languages call one Rust core.** Porting the rules by
hand to every language would run them on different regular-expression engines, and the copies would
drift where no reviewer looks. A change of behaviour lands in TypeScript first, with its
conformance case; a binding never re-implements a rule; and a core that lacks a category fails
instead of skipping it ([RFC 0001](rfcs/0001-polyglot-core.md)).

**The npm package keeps its TypeScript engine; the Rust engine is opt-in.** The first benchmark of
the core from Node.js (November 2026) found WebAssembly slower almost everywhere and the native
addon less than twice as fast where it won, which did not justify a native binary per platform in a
package without dependencies. After the core's speed work, the addon reached 2.2 to 2.9 times on
`anonymize()` with a preset and was published as `anonyma-native`. `anonyma` never imports it, and
keeps the span engine, custom detectors and plugins, which `anonyma-native` does not offer.

**A list of presets instead of a package per preset.** The plan for 1.3 proposed `preset-lgpd`,
`preset-gdpr` and `preset-hipaa`. Every preset and the detectors it needs were already in `anonyma`,
so separate packages would only add versions to keep in step.

**Unscoped package names.** The companion packages were announced as `@anonyma/vercel-ai` and
`@anonyma/mcp`, but the `@anonyma` scope is not available on npm: they were published as
`anonyma-vercel-ai` and `anonyma-mcp`, and every later package followed.

**Evidence without data.** Audit records and receipts hold categories, counts and digests, never a
value. Receipts are signed with HMAC-SHA-256 and never with a plain hash, which anyone could forge.

**Releases only from CI.** Packages are published by workflows from version tags, with provenance
attestations, never from a developer's machine; npm and PyPI trust the workflows directly, so there
is no token to store. The one exception is the first version of a new npm package, which npm
accepts only by hand. A stable version of `anonyma` is released only from a commit on `main`.

**The site is the documentation.** The README is a short overview. The site generates its reference
pages, package pages and changelogs from the repository and the build, so it cannot say something
the code does not.

## What we learned

**Benchmarks find bugs that tests do not.** Comparing the Rust core with the TypeScript engine found
three costs that grew with the length of the text times the number of matches: two in the core
([#78](https://github.com/izaccavalheiro/anonyma/pull/78),
[#80](https://github.com/izaccavalheiro/anonyma/pull/80)) and one in `anonymize()` and `tokenize()`
([#79](https://github.com/izaccavalheiro/anonyma/pull/79)), where 1,000,000 characters took up to
8 s. Every result was right, so no test could see them. Since then, CI checks that the span engine
stays linear, and every pull request to `main` is timed against its base.

**Write down what the code does.** The 1.0 documentation described behaviour the functions did not
have, and an allowlist "match" turned out to be a substring match. Since 1.1 the documentation
describes what the code does, and lists its limits where they exist. Every example on the site is
checked against the build, and the reference tables are generated from it.

**A fix that changes output is a change.** The allowlist fix (1.1.1) and the rules fix (1.4.0) both
made the library do what its documentation said, and both changed what some callers got back. Each
release says so in its first lines, so that nobody learns it from their output.

**Measure, decide, and measure again.** The native addon was turned down when it was less than twice
as fast, and published once the core was faster. The decision recorded its numbers, so it could be
reopened when they changed.

**A test that depends on chance fails by chance.** A test that looked for the digits `4111` in a
serialized receipt failed about once in a thousand runs, when a random identifier contained them; it
failed one release's verification. Tests now look for values that random data cannot produce, and
every branch has an example-based test, so that coverage never depends on random inputs.

**Regular-expression engines are not interchangeable.** `\b`, `\d`, `\s` and case folding mean
different things in ECMAScript and in Rust's `regex` crate. The core translates them in one module,
and the conformance suite checks every rule in every language.

## Still open

- `anonyma-core` on crates.io, once its API settles.
- A gRPC listener for the sidecar, which publishes the contract only.
- Bindings for the JVM and .NET, through the sidecar until there is demand for native ones.
- Prebuilt libraries for musl systems such as Alpine, for the Go module and `anonyma-native`.
- The WebAssembly build of the core, which CI builds and the core benchmark measures, but which is
  not published.
- Stable releases of the Python and Go packages, whose APIs may change until then.
