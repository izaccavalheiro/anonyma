# Changelog

All notable changes to `anonyma-parallel` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`.

## [Unreleased]

### Added

- `createPool()`: a pool of worker threads with `detectBatch()`, `anonymizeBatch()` and
  `scanBatch()`, which return what anonyma's batch functions return, in input order.
- Batches under 8 KB (`inlineBelow`) run in the calling thread, where they cost less; `explain()`
  tells how a batch would run.
