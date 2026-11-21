# Changelog

All notable changes to `anonyma-cli` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`; while it is
at 0.x, a minor version may change its API or its command line.

## [0.1.0] — unreleased

First release. Requires `anonyma` ^1.3.0.

### Added

- `anonyma scrub`: replaces the personal data of a text, JSON Lines or CSV file, read and written
  as streams in constant memory, with presets, policies, strategies and column selection. The
  output file appears only once complete. `--receipt` writes a signed receipt of the run.
- `anonyma scan`: reports personal data by line and column, JSON Pointer or CSV column, never by
  value, as a summary, a list or JSON; `--fail-on-pii` exits with status 1 when any is found.
- gzip input and output, standard input and output.
- `run()`, `CsvReader` and `formatCsvRecord()` for programs.
