# Changelog

All notable changes to `anonyma-native` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`.

## [Unreleased]

## [0.1.0] — 2026-11-24

anonyma on its Rust core, for Node.js: the same results, 2.4 to 2.9 times faster on single texts and
7 times on batches.

### Added

- `createEngine(options)`: `detect`, `anonymize`, `detectBatch` and `anonymizeBatch` on the Rust
  core, with anonyma's result shapes and offsets in UTF-16 code units; options the core does not
  run throw a `NativeOptionsError`.
- `call()` and `Vault`: the core's JSON API.
