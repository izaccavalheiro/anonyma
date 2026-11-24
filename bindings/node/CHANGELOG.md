# Changelog

All notable changes to `anonyma-native` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`.

## [Unreleased]

### Added

- `createEngine(options)`: `detect`, `anonymize`, `detectBatch` and `anonymizeBatch` on the Rust
  core, with anonyma's result shapes and offsets in UTF-16 code units; options the core does not
  run throw a `NativeOptionsError`.
- `call()` and `Vault`: the core's JSON API.
