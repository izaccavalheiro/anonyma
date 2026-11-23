# RFC 0001: One Rust core, thin bindings, a sidecar

- Status: accepted, first slice implemented
- Scope: `crates/`, `bindings/`, `packages/conformance`, `packages/sidecar`,
  `.github/workflows/polyglot-release.yml`

## Problem

anonyma is a TypeScript library. Teams that write Python, Go, Java or C# want
the same detectors, token format, presets and receipts. Porting the library by
hand to each language would multiply every detection rule, checksum and token
format by the number of languages. Each copy would also run on a different
regular-expression engine (ECMAScript, Python `re`, Go RE2, Java), so the
copies would drift in ways no reviewer sees: one language reports a card
number that another misses, and the token formats stop agreeing.

## Decision

1. **One engine, in Rust** (`crates/anonyma-core`): detectors, checksum
   validators, strategies, vault tokens, presets, canonical JSON and signed
   receipts. Every binding calls it. No binding contains a detection rule.
2. **One test suite for every implementation** (`packages/conformance`): a
   JSON file of cases with their expected results. The TypeScript reference
   must pass all of them. Rust, Python and Go must pass every case whose
   capabilities they declare.
3. **Thin bindings**: PyO3 for Python, napi-rs for Node.js, wasm-bindgen for
   browsers and edge runtimes, and a C ABI (`crates/anonyma-ffi`) for Go and
   anything else with a C foreign function interface.
4. **A sidecar now** (`packages/sidecar`): a local HTTP and MCP service, as a
   container image. Every language can use all 27 detectors today, before its
   native binding catches up.

The TypeScript package stays the reference while the core catches up: a
change of behaviour lands there first, together with its conformance case.

## How it fits the repository

The audit before the change found an npm workspace (`package.json`
`workspaces: ["packages/*"]`, one `package-lock.json`). The companion packages
(`anonyma-vercel-ai`, `anonyma-mcp`, `anonyma-cli`) are unscoped, because the
`@anonyma` npm scope is not available. There was no Rust, Python or Go yet.

```
anonyma/
├── package.json, src/, tests/    the TypeScript reference (npm: anonyma), unchanged
├── packages/                     npm workspaces
│   ├── vercel-ai/ mcp/ cli/      unchanged
│   ├── conformance/              the suite, its schema and the TypeScript runner (private)
│   └── sidecar/                  HTTP + MCP service, Dockerfile, gRPC contract (private)
├── Cargo.toml                    Rust workspace, separate from npm
├── crates/
│   ├── anonyma-core/             the engine (crates.io: anonyma-core)
│   └── anonyma-ffi/              JSON API + C ABI (include/anonyma.h); Rust conformance runner
└── bindings/
    ├── python/                   PyO3 + maturin (PyPI: anonyma), integrations, pytest runner
    ├── node/                     napi-rs (not published yet)
    ├── wasm/                     wasm-bindgen (not published yet)
    └── go/                       cgo over the C ABI, io.Reader, net/http middleware, Go runner
```

- The Rust workspace and the npm workspace do not know about each other. They
  meet only in `packages/conformance/conformance-tests.json`, which every
  runner reads. Nothing in `src/` changes, and the npm packages are built,
  tested and released as before.
- No pnpm or Turborepo: the repository uses npm workspaces and one lockfile.
  Moving to another tool would gain nothing for four Rust crates, which Cargo
  builds.
- `bindings/` is outside `packages/*`, so npm never treats a binding as a
  workspace. The two new workspaces are `private`, so the release script
  publishes neither.
- The root scripts run workspace scripts with `--if-present`, so a workspace
  without a build step (`anonyma-conformance`) does not break
  `npm run build:packages`.

## The conformance suite

Each case names an operation (`validate`, `detect`, `tokenize`, `detokenize`,
`shield`, `restore`, `anonymize`, `preset`, `canonicalize`, `digest`,
`receipt.sign`, `receipt.verify`, `receipt.issue`), its input, the expected
result and the **capabilities** it needs (`detect:email`,
`detect:national-id/br-cpf`, `preset:lgpd`, ...). An implementation declares
its capabilities. A case it cannot run is skipped and reported, never passed
silently. The release gate of a binding: no failed case, and no skipped case
among the capabilities it claims.

The first version holds 121 cases. They cover the detectors the plan named
(e-mail, IPv4/IPv6, cards, SSN, IBAN, CPF, CNPJ, PIX), each with checksum
failures that must not be reported, and tokens and their restoration,
including `{{PERSON_1}}` next to `{{PERSON_10}}`. They also cover presets
alone and combined, and canonical JSON, digests and receipts. Several cases
record surprising behaviour of the reference, such as the separator kept after
a card number followed by a word, or `2001:db8::1` matched without its last
group. The suite makes such behaviour visible, so it can be changed
deliberately, in every language at once.

Offsets are Unicode code points: Python's unit, and the only one shared by
every language. Each runner converts from its native unit.

## Trade-offs

### Regular expressions: ECMAScript vs the `regex` crate

The `regex` crate is chosen because it matches in linear time: no input can
make a detector take exponential time (ReDoS). It differs from ECMAScript (no
`u` flag) where it matters:

| ECMAScript                   | `regex` crate                   | Mitigation (`jsregex.rs`)                                                            |
| ---------------------------- | ------------------------------- | ------------------------------------------------------------------------------------ |
| `\b`, `\w` ASCII             | Unicode                         | `(?-u:\b)`, `[A-Za-z0-9_]`                                                           |
| `\d` = `[0-9]`               | any Unicode digit               | `[0-9]`                                                                              |
| `\s`: 25 fixed code points   | Unicode `White_Space`           | the 25 code points, spelled out                                                      |
| `i` folds ASCII only         | folds `ſ`→`s`, `K` (Kelvin)→`k` | patterns in lower case on an ASCII-lower-cased haystack                              |
| lookahead, lookbehind        | none                            | captured groups checked afterwards; a rejected candidate resumes one character later |
| leftmost-first, backtracking | leftmost-first, automata        | same match for every pattern without lookaround                                      |

The translation is unit-tested. The conformance suite then checks the result
end to end, including texts with accented letters and characters outside the
Basic Multilingual Plane.

### Offsets and lengths

JavaScript counts UTF-16 units, Rust UTF-8 bytes, Python code points. The core
reports bytes. `offsets.rs` converts, and the JSON API takes `"offsets":
"code-points" | "utf-16" | "bytes"`. Two places in the reference measure
lengths, and the core reproduces their unit: `mask` counts UTF-16 units, and
the 30-character label windows of the composite detectors count UTF-16 units.

### The cost of the boundary

The C ABI, WebAssembly and Node.js bindings exchange JSON: one copy of the text
into JSON and one out, plus the parsing. That costs microseconds for a prompt
and matters only for megabytes. Python avoids it on its hot paths: `detect`,
`anonymize`, `tokenize` and `shield` take a native `str` and return tuples,
and they release the GIL while the core scans. A future binary format for the
C ABI would remove the copy for Go if profiles show it matters.

### Partial ports must fail closed

A privacy tool that silently skips a category it was asked to protect fails
open. `anonyma-core` detects some categories in full, and `national-id` only
in part (the CPF entry). An engine asked for anything it does not detect in
full refuses to build (`UnsupportedCategories`) unless the caller opts in
with `allow_partial`. In Python, `Anonyma(presets=["lgpd"])` therefore raises
and names the missing categories. Until the port is complete, the sidecar
serves every category.

### Dependencies

`anonyma` on npm keeps zero runtime dependencies. The Rust core depends on
`regex`, `sha2`, `hmac` and `getrandom`: the standard, audited crates for
matching, hashing and randomness, which would be riskier to write by hand.
The Python package has no runtime dependency, and LangChain support is an
extra. The sidecar depends on `anonyma` alone, and serves gRPC only as a
published contract until a listener justifies its first dependency.

## Roadmap

| Tier | What                               | State                                                                                       |
| ---- | ---------------------------------- | ------------------------------------------------------------------------------------------- |
| 0    | Sidecar (HTTP, MCP; gRPC contract) | implemented; image built in CI, published on `sidecar-v*` tags                              |
| 1    | Python (`anonyma` on PyPI)         | alpha: wheels built and published on `python-v*` tags                                       |
| 1B   | WebAssembly, Node.js               | scaffolds that build in CI; not published                                                   |
| 2    | Go                                 | cgo package with tests and the suite; needs prebuilt static libraries before `go get` works |
| 3    | JVM, .NET                          | through the sidecar; generated bindings (UniFFI) when there is demand                       |
| 4    | `anonyma-core` on crates.io        | packaged in CI; published once the API settles                                              |

Next steps, in order:

1. Port the remaining detectors, starting with those every preset needs
   (`phone`, `name`, `address`, `date-of-birth`, `url`), each with its
   conformance cases first. Each one turns `preset:<name>` capabilities on.
2. Port the precise detectors of the span engine (`anonyma/engine`) and give
   the suite an engine-level `detect` operation.
3. Publish prebuilt `libanonyma_ffi.a` per platform for Go.
4. Benchmark the Rust core against the TypeScript engine (`bench/`), on Node.js
   through napi-rs and on Workers through WebAssembly. A native engine for the
   npm package is offered only where it wins. Its public API stays unchanged,
   and it falls back to TypeScript where native modules cannot load.

## Releases

`.github/workflows/polyglot-release.yml` runs the suite in every language on
every pull request: TypeScript, Rust (Linux, macOS, Windows), Python 3.10 and
3.13, Go, and the WebAssembly and Node.js builds. It also builds the sidecar
image and calls it. Tags release:

- `python-v<version>`: abi3 wheels for manylinux x86_64/aarch64, macOS
  x86_64/arm64 and Windows x64, and an sdist, published to PyPI through
  trusted publishing (environment `pypi`). The version must match the tag.
- `sidecar-v<version>`: a multi-architecture image (`linux/amd64`,
  `linux/arm64`) pushed to `ghcr.io/<owner>/anonyma-sidecar`, with provenance,
  an SBOM and an attestation.

Each release needs a section for its version in its own changelog
(`bindings/python/CHANGELOG.md`, `packages/sidecar/CHANGELOG.md`), and nothing is published
without one. The release then gets a GitHub release with those notes. These GitHub releases never
take the "Latest" badge, which stays with the npm package. The npm packages keep their own
workflow and changelog (`release.yml`, tags `v<version>`, `CHANGELOG.md`).

Before the first Python release, the PyPI project `anonyma` needs a trusted
publisher (this repository, `polyglot-release.yml`, environment `pypi`) and
the repository an environment `pypi`.
