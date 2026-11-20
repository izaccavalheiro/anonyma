# Changelog

All notable changes to `@anonyma/mcp` are documented in this file. The package follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`; while it is
at 0.x, a minor version may change its API or the command line of `anonyma-mcp-proxy`.

## [0.1.0] — 2026-11-20

First release. Requires `anonyma` ^1.2.0.

### Added

- `createMcpGuard()`: the privacy guard of one MCP connection. Tool results, resources, prompts,
  errors, sampling requests and log messages from the server are tokenized; tool and prompt
  arguments, resource URIs and sampling answers from the client get the original values back.
- `anonyma-mcp-proxy` and `runStdioProxy()`: any stdio MCP server behind the guard. A message
  that cannot be processed is answered with a JSON-RPC error and never forwarded as it is; the
  log holds counts, never content.
- `guardMcpClient()`: `callTool`, `readResource` and `getPrompt` of an MCP SDK client, guarded.
