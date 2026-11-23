# Changelog

All notable changes to `anonyma-cli` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`; while it is
at 0.x, a minor version may change its API or its command line.

## [Unreleased]

## [0.1.1] — 2026-11-23

Requires `anonyma` ^1.3.0.

### Fixed

- `anonyma scrub -o <file>` no longer leaves a `<file>.partial-<pid>` file behind when it fails
  right after it starts, as it could on Windows: the partial file was removed before the stream
  that creates it had opened it, and the open then created it again. The removal now waits for
  the stream to close.

## [0.1.0] — 2026-11-21

First release. Requires `anonyma` ^1.3.0.

### Added

- `anonyma scrub`: replaces the personal data of a text, JSON Lines or CSV file, read and written
  as streams in constant memory, with presets, policies, strategies and column selection. The
  output file appears only once complete. `--receipt` writes a signed receipt of the run.
- `anonyma scan`: reports personal data by line and column, JSON Pointer or CSV column, never by
  value, as a summary, a list or JSON; `--fail-on-pii` exits with status 1 when any is found.
- gzip input and output, standard input and output.
- `run()`, `CsvReader` and `formatCsvRecord()` for programs.
