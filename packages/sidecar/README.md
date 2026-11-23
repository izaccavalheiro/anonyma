# anonyma-sidecar

A local service that scrubs personal data for applications in any language:
Java, C#, Go, Ruby, PHP, Python, anything that speaks HTTP or MCP. It runs
next to your application (a container in the same pod, or a process on the
same host). Your application sends text to `localhost`, and the text never
leaves the machine.

It serves the TypeScript reference implementation of anonyma: all 27 detectors
and every strategy and preset, plus vault tokens that you restore in a model's
answer. When the Rust core detects every category, the sidecar can switch to it
without changing its interface (docs/rfcs/0001-polyglot-core.md).

## Run it

```sh
# From the repository root
docker build -f packages/sidecar/Dockerfile -t anonyma-sidecar .
docker run --rm -p 127.0.0.1:7878:7878 anonyma-sidecar

# Or with Node.js 20+, after npm run build at the root and in packages/sidecar
node packages/sidecar/dist/bin.js --port 7878
```

| Setting                        | Flag             | Default                              |
| ------------------------------ | ---------------- | ------------------------------------ |
| `ANONYMA_SIDECAR_HOST`         | `--host`         | `127.0.0.1` (`0.0.0.0` in the image) |
| `ANONYMA_SIDECAR_PORT`         | `--port`         | `7878`                               |
| `ANONYMA_SIDECAR_TOKEN`        | environment only | none: no authentication              |
| `ANONYMA_SIDECAR_MAX_BODY`     | `--max-body`     | 1048576 bytes                        |
| `ANONYMA_SIDECAR_SESSION_TTL`  | `--session-ttl`  | 1800 seconds after last use          |
| `ANONYMA_SIDECAR_MAX_SESSIONS` | `--max-sessions` | 1000 (least recently used dropped)   |
| `ANONYMA_SIDECAR_MCP=off`      | `--no-mcp`       | MCP served at `POST /mcp`            |

Set `ANONYMA_SIDECAR_TOKEN` whenever another host or container can reach the
port. Every request except `GET /healthz` then needs
`Authorization: Bearer <token>`.

## Endpoints

Bodies are JSON (`Content-Type: application/json`). Offsets are Unicode code
points. Errors are `{"error": "<message>"}` with a 4xx status, and their
messages never quote the text.

| Endpoint                   | Body                                                                            | Answer                                                |
| -------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `GET /healthz`             |                                                                                 | `{"status": "ok"}`                                    |
| `GET /v1/info`             |                                                                                 | version, categories, presets                          |
| `POST /v1/detect`          | `text`, `categories?`, `preset?`, `aggressive?`, `detection?`, `minConfidence?` | `matches`: category, value, start, end, confidence    |
| `POST /v1/anonymize`       | as detect, plus `defaultStrategy?`, `rules?` (a strategy per category)          | `text`, `counts` per category                         |
| `POST /v1/detect/batch`    | as detect, with `texts` (a list) in place of `text`                             | `results`: one `{matches}` per text, in order         |
| `POST /v1/anonymize/batch` | as anonymize, with `texts` (a list) in place of `text`                          | `results`: one `{text, counts}` per text, in order    |
| `POST /v1/shield`          | `text`, `session?`, `categories?`, `preset?`                                    | `text` with `{{EMAIL_1}}` tokens, `session`, `counts` |
| `POST /v1/restore`         | `text`, `session`                                                               | `text`, `restored`, `unresolved`                      |
| `DELETE /v1/sessions/{id}` |                                                                                 | 204, or 404 if unknown                                |
| `POST /mcp`                | a JSON-RPC message or batch                                                     | the MCP tools of `anonyma/mcp`                        |

Send many short texts (log lines, rows, chat turns) to a batch endpoint: a request
costs a few hundred microseconds of HTTP whatever its size, more than detecting a
short text, and a batch pays it once. A batch answers exactly what one request per
text would, and is bounded by the same body limit.

Strategies are written as anonyma spells them:
`{"strategy": "mask", "keepTrailing": 4}`. A `hash` strategy needs a
`pepper`, and an `encrypt` strategy is not available, because the sidecar
holds no key.

### A conversation with a model

```sh
curl -s localhost:7878/v1/shield -H 'content-type: application/json' \
  -d '{"text": "Email ana@example.com the contract", "preset": "lgpd"}'
# {"text":"Email {{EMAIL_1}} the contract","session":"6f1c…","counts":{"email":1}}

# Send the text to the model, then restore its answer:
curl -s localhost:7878/v1/restore -H 'content-type: application/json' \
  -d '{"text": "Sent to {{EMAIL_1}}.", "session": "6f1c…"}'
# {"text":"Sent to ana@example.com.","restored":1,"unresolved":[]}
```

Pass the `session` back to `/v1/shield` on the next turn: a value keeps its
token across the conversation. Delete the session when the conversation ends.
Otherwise its vault, which holds the original values, is dropped after the TTL.

## gRPC

[`proto/anonyma/sidecar/v1/sidecar.proto`](proto/anonyma/sidecar/v1/sidecar.proto)
is the gRPC contract of the same endpoints. It is published so that clients
can be generated. The sidecar does not serve gRPC yet: it would be its first
runtime dependency, and HTTP/JSON covers every language today.

## Guarantees

- Nothing is logged, written to disk or sent anywhere: not the text, the
  matches, the tokens or the vaults.
- Vaults live in memory only. They are bounded in number and in lifetime, and
  emptied when the process stops.
- The image runs as a non-root user on a distroless base, with no shell and no
  package manager.
