# Changelog

All notable changes to the Go package of anonyma (`github.com/izaccavalheiro/anonyma-go`)
are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- National-id detection reads a long text 1.7 times faster with the same results: its twenty formats
  are tried only where one can start (a word boundary and a run of digits or capitals long enough),
  instead of each scanning the whole text.

## [0.1.0-alpha.3] — 2026-11-23

An `Engine` built once with batches on every core, `NewReader` in batches, links with current Go
releases again, and a fix for long texts with capital letters, which took quadratic time.

### Added

- `NewEngine(opts)` builds an `Engine` once for many calls: `Detect`, `Anonymize`, and
  `DetectBatch`/`AnonymizeBatch`, which take many texts in one cgo call and scan short ones
  together. On 200-byte log lines: 37–40 µs per text in a batch, against 63–88 µs for `Detect`.
  An `Engine` is safe for concurrent use; `Close` frees it.
- `NewReader` and `Middleware` build one engine each instead of one per line or request.
- `NewReader` anonymizes lines in batches: every complete line already read, up to 4,096 lines or
  1 MiB, cut as soon as no complete line is waiting, so an interactive stream still gets each line
  back at once. 10,000 log lines cost 13–25 µs each instead of 64–118. A strategy error now fails
  the batch it is in, where it used to fail at its line.
- `DetectBatch()` and `AnonymizeBatch()` spread a batch over every core inside the one cgo call
  (rayon; `RAYON_NUM_THREADS` sets the number of threads): on 4 cores, 200-byte texts cost about
  15 µs each in a batch of 1,000, against 37–40 µs on one core.

### Changed

- Each call encodes its input in one buffer that the core reads in place, and decodes the answer
  in one pass without copying it: the Go side of a call costs 1.9 µs instead of 11.7 µs, and a
  `Detect` call allocates 17 times instead of 37. `NewReader` and `Middleware` encode their
  options once, not once per line or request.
- Detection skips the patterns that count only after a label (generic account, member and record
  numbers, ten national-id formats, ...) when the text holds no such label. Results are unchanged;
  a call on a 200-character text without labels takes about 30% less time.

### Fixed

- Options that `encoding/json` cannot encode (a strategy holding a channel or a function) are
  now an error. They were dropped, so the call detected every category with its default strategy.
- Detecting addresses, names, phone numbers, IBANs, IPv4 addresses and US SSNs in a text with
  capital letters took time and memory proportional to the length of the text times the number of
  candidates: each candidate lower-cased the whole text again. A 119 KB text with 1,000 labelled
  addresses allocated 240 MB; it now allocates a few times its own size. Long untrusted text can
  no longer make detection quadratic this way.
- The package links again with Go 1.26.11, 1.27.4 and later releases, which refused the prebuilt
  library ("disallowed LTO section", golang/go#83126). The library no longer holds the LLVM
  bitcode sections that Rust's standard library put in it; the linker never used them. Building
  the library from source (`go generate`) now needs rustup's `llvm-tools` component.
- With presets, a rule for a category the presets do not cover now adds that category; it was
  ignored. The rules of the other categories still override the presets' strategies
  ([#47](https://github.com/izaccavalheiro/anonyma/issues/47)).
- Card numbers written in groups no longer include the space or hyphen after them when a word
  follows ([#48](https://github.com/izaccavalheiro/anonyma/issues/48)).
- Twelve digits in groups of four that are part of a longer number written in groups (a card number)
  are no longer reported as an Aadhaar number
  ([#49](https://github.com/izaccavalheiro/anonyma/issues/49)).

## [0.1.0-alpha.2] — 2026-11-23

### Fixed

- `Anonymize` took time proportional to the length of the text times the number of matches,
  seconds for a megabyte with thousands of values: every replacement moved the rest of the text.
  It now takes one pass over the text.

## [0.1.0-alpha.1] — 2026-11-23

First release: cgo bindings of the Rust core of anonyma, with its static library
prebuilt for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64,
so `go get` needs no Rust toolchain.

### Added

- `Detect`, `Anonymize` and `Call`, the JSON API of the core, with byte offsets.
- `Scan`, the span engine: precise detectors and overlaps resolved by covering.
- `Vault`: `Shield` and `Restore` for LLM prompts, with the tokens kept in the process.
- `Validate` and the checksum validators of the core.
- `NewReader`, an `io.Reader` that anonymizes text line by line, and `Middleware`, which
  anonymizes the bodies of text and JSON requests and refuses (413) one too large to scrub.
- All 27 detection categories, every preset and every strategy of the conformance suite.
