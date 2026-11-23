---
title: Other languages
sidebar_position: 5
description: Use anonyma from Python, Go, Java, C# or any language, through the sidecar or the Rust core.
---

anonyma's detectors, token format, presets and receipts are available outside JavaScript in two
ways. Both give the same results as the TypeScript package, because every implementation runs one
shared conformance suite.

| Way                               | Languages                     | Detectors        | State          |
| --------------------------------- | ----------------------------- | ---------------- | -------------- |
| The sidecar                       | any language that speaks HTTP | all 27           | available      |
| The Python package                | Python 3.10+                  | 13 in full, CPF  | alpha          |
| Go, Node.js, WebAssembly bindings | Go, JavaScript                | as the Rust core | in development |

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

The Python package runs on the Rust core: no runtime dependencies, no model to download.

```python
from anonyma import Anonyma

engine = Anonyma(categories=["email", "credit-card"])
shielded = engine.shield_prompt("Mail ana@example.com about card 4111 1111 1111 1111.")
shielded.text                                      # 'Mail {{EMAIL_1}} about card {{CREDIT_CARD_1}}.'
engine.restore("Sent to {{EMAIL_1}}.", shielded.vault)   # 'Sent to ana@example.com.'
```

The Rust core does not detect every category yet. A preset that needs one it lacks, such as
`Anonyma(presets=["lgpd"])`, raises `UnsupportedCategoriesError` and names the missing categories,
so data is never let through silently. Pass `allow_partial=True` to accept partial detection, or use
the sidecar from Python until the port is complete.
