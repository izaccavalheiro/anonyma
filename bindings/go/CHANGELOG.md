# Changelog

All notable changes to the Go package of anonyma (`github.com/izaccavalheiro/anonyma-go`)
are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- With presets, a rule for a category the presets do not cover now adds that category; it was
  ignored. The rules of the other categories still override the presets' strategies
  ([#47](https://github.com/izaccavalheiro/anonyma/issues/47)).
- Card numbers written in groups no longer include the space or hyphen after them when a word
  follows ([#48](https://github.com/izaccavalheiro/anonyma/issues/48)).

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
