# Changelog

All notable changes to `anonyma-sidecar` are documented in this file. The sidecar follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) independently of `anonyma`, and its
container image is released from tags `sidecar-v<version>` to
`ghcr.io/izaccavalheiro/anonyma-sidecar`. While it is at 0.x, a minor version may change its
endpoints or settings.

## [0.1.0] — 2026-11-23

First release, built on `anonyma` 1.3.2.

### Added

- HTTP endpoints over `localhost` for any language: `POST /v1/detect`, `/v1/anonymize`,
  `/v1/shield` and `/v1/restore`, `DELETE /v1/sessions/{id}`, `GET /v1/info` and `/healthz`. All 27
  detectors, every strategy and preset, offsets in code points.
- Vault sessions for LLM conversations: `/v1/shield` returns a session whose vault keeps the
  tokens across turns; `/v1/restore` puts the values back. Sessions are bounded in number and
  lifetime, and emptied when they expire or the process stops.
- MCP at `POST /mcp`: the tools of `anonyma/mcp` over JSON-RPC.
- Optional bearer-token authentication (`ANONYMA_SIDECAR_TOKEN`); request body limit; JSON-only
  requests, so a browser cannot post without a CORS preflight. Nothing is logged.
- Container image for `linux/amd64` and `linux/arm64`: distroless, non-root, base images pinned
  by digest, with provenance, an SBOM and an attestation.
- The gRPC contract of the same operations (`proto/anonyma/sidecar/v1/sidecar.proto`), for
  generated clients; the sidecar does not serve gRPC yet.
