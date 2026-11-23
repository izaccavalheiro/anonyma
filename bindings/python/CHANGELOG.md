# Changelog

All notable changes to `anonyma` for Python are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of the npm package
`anonyma`, and is released from tags `python-v<version>`. While it is at 0.x, a minor version may
change its API.

## [Unreleased]

### Added

- Detection of `phone` (North American, international, and the national formats of Brazil,
  France, the United Kingdom, Spain, Italy and German-speaking countries; seven-digit numbers in
  aggressive mode), `url` and `date-of-birth`, ported to the Rust core and conformance-tested.

## [0.1.0a1] — 2026-11-23

First release, an alpha. Wheels for CPython 3.10 and later (stable ABI) on Linux (x86_64,
aarch64), macOS (x86_64, arm64) and Windows (x64). No runtime dependencies.

### Added

- `Anonyma`: detection and anonymization on the Rust core (`anonyma-core`), configured with
  presets (`Anonyma(presets=["lgpd", "hipaa"])`, combined by protection), categories, a strategy
  per category (`redact`, `mask`, `pseudonymize`), aggressive and strict detection.
- `shield_prompt()` and `restore()`: vault tokens (`{{EMAIL_1}}`) for LLM prompts, numbered across
  the turns of a conversation, restored whole (`{{PERSON_1}}` never inside `{{PERSON_10}}`).
- `Anonyma.tokenize()` and `detokenize()`: classic tokens (`[EMAIL_0001]`) with their mapping.
- `validate()`: the checksums `luhn`, `verhoeff`, `iban`, `cpf`, `cnpj` (numeric and
  alphanumeric), `aba-routing` and `pix`.
- `ReceiptIssuer`: anonymization receipts signed with HMAC-SHA-256, holding category counts and
  digests, never the data; `canonicalize()` and `sha256_hex()`.
- Integrations: `anonyma.integrations.chat` (OpenAI and Anthropic message lists),
  `anonyma.integrations.openai` (`shielded_chat_completions()`), and
  `anonyma.integrations.langchain` (`shield_and_restore()`, with `pip install 'anonyma[langchain]'`).
- Type hints throughout (`py.typed`); offsets in code points.

### Known limitations

- The Rust core detects `email`, `ipv4`, `ipv6`, `credit-card`, `ssn`, `iban`, `tax-id` and
  `bank-account` in full, and the CPF of `national-id`. Other categories (`name`, `phone`,
  `address`, ...) are not ported yet: asking for one raises `UnsupportedCategoriesError` unless
  `allow_partial=True`, so data is never let through silently. This is why every preset needs
  `allow_partial=True` for now.
- It passes 116 of the 121 cases of the conformance suite; the 5 it skips anonymize with a whole
  preset.
