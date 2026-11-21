# Changelog

All notable changes to `anonyma-vercel-ai` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`; while it is
at 0.x, a minor version may change its API.

## [0.1.0] — 2026-11-21

First release. Requires `ai` ^7 and `anonyma` ^1.2.0.

### Added

- `anonymaMiddleware()`: a `LanguageModelMiddleware` (specification `v4`) that tokenizes prompts
  and restores tokens in complete and streamed responses — text, reasoning and tool-call
  arguments.
- `withAnonyma(model)`: a wrapped model; a model id string is resolved like the AI SDK does,
  through `AI_SDK_DEFAULT_PROVIDER` or the AI Gateway.
- `createAnonymaAI()`: drop-in `generateText()` and `streamText()` that wrap every model they are
  given, sharing one middleware.
- `onSanitized`: the account of each prompt, which can stop a request by throwing.
