---
title: Other languages
sidebar_position: 5
description: Use anonyma from Python, Go, Java, C# or any language, through the sidecar or the Rust core.
---

anonyma's detectors, token format, presets and receipts are available outside JavaScript in three
ways. All give the same results as the TypeScript package, because every implementation runs one
shared conformance suite.

| Way                    | Languages                     | Detectors | State                                         |
| ---------------------- | ----------------------------- | --------- | --------------------------------------------- |
| The sidecar            | any language that speaks HTTP | all 27    | available                                     |
| The Python package     | Python 3.10+                  | all 27    | alpha, on PyPI                                |
| The Go package         | Go 1.22+ with cgo             | all 27    | alpha, `github.com/izaccavalheiro/anonyma-go` |
| Node.js or WebAssembly | JavaScript                    | —         | not offered: use the `anonyma` package (\*)   |

(\*) The Rust core's Node.js addon and WebAssembly build were measured against the TypeScript
engine: the WebAssembly build is slower almost everywhere, and the addon is at most 1.8 times faster
on some operations and slower on others, which does not pay for a native binary per platform.

## The sidecar

The sidecar is a small service that runs next to your application, as a container in the same pod
or a process on the same host. Your application sends it text over `localhost`, and the data never
leaves the machine.

```sh
docker build -f packages/sidecar/Dockerfile -t anonyma-sidecar .
docker run --rm -p 127.0.0.1:7878:7878 anonyma-sidecar
```

Shield a prompt, send it to the model, and restore the answer from the same session:

```sh
curl -s localhost:7878/v1/shield -H 'content-type: application/json' \
  -d '{"text": "Mail ana@example.com", "categories": ["email"]}'
# {"text":"Mail {{EMAIL_1}}","session":"…","counts":{"email":1}}

curl -s localhost:7878/v1/restore -H 'content-type: application/json' \
  -d '{"text": "Sent to {{EMAIL_1}}.", "session": "…"}'
# {"text":"Sent to ana@example.com.","restored":1,"unresolved":[]}
```

`POST /v1/detect` and `POST /v1/anonymize` take the options of a pipeline (`preset`,
`categories`, `defaultStrategy`, `rules`), and `POST /mcp` serves the MCP tools. Set
`ANONYMA_SIDECAR_TOKEN` whenever another host can reach the port. The
[sidecar README](https://github.com/izaccavalheiro/anonyma/tree/main/packages/sidecar#readme) lists
every endpoint and setting.

## Python

The Python package runs on the Rust core: no runtime dependencies, no model to download. It is a
pre-release, so pip needs `--pre`:

```sh
pip install --pre anonyma
```

```python
from anonyma import Anonyma

engine = Anonyma(categories=["email", "credit-card"])
shielded = engine.shield_prompt("Mail ana@example.com about card 4111 1111 1111 1111.")
shielded.text                                      # 'Mail {{EMAIL_1}} about card {{CREDIT_CARD_1}}.'
engine.restore("Sent to {{EMAIL_1}}.", shielded.vault)   # 'Sent to ana@example.com.'
```

Every category and every compliance preset works as is: `Anonyma(presets=["lgpd", "hipaa"])`
detects all their categories, with the same results as the TypeScript package.

## Go

The Go package calls the Rust core through cgo. The module carries the core prebuilt for
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64, so it needs a C compiler
but no Rust toolchain:

```sh
go get github.com/izaccavalheiro/anonyma-go@latest
```

```go
import anonyma "github.com/izaccavalheiro/anonyma-go"

vault := anonyma.NewVault()
defer vault.Close()
prompt, _ := vault.Shield("Mail ana@example.com", anonyma.Options{Categories: []string{"email"}})
// prompt == "Mail {{EMAIL_1}}"
answer, _ := vault.Restore("Sent to {{EMAIL_1}}.")
// answer == "Sent to ana@example.com."
```

`Detect`, `Anonymize` and `Scan` report byte offsets into the Go string. `NewReader` anonymizes
an `io.Reader` line by line, and `Middleware` scrubs the bodies of `net/http` requests. Alpine and
other musl systems are not among the platforms yet: use the sidecar there. The
[package README](https://github.com/izaccavalheiro/anonyma/tree/main/bindings/go#readme) has the
rest.
