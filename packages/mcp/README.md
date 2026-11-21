# @anonyma/mcp

Privacy for [Model Context Protocol](https://modelcontextprotocol.io) connections. What an MCP
server sends towards the model — tool results, resources, prompts, sampling requests, log
messages, errors — has its personal data replaced by tokens before it enters the context window.
What the model sends back — tool arguments, prompt arguments, resource URIs, sampling answers —
has the tokens replaced by the original values before it reaches the server.

The server works on real data; the model only ever sees `[EMAIL_0001]`. The mapping stays in the
proxy, and a guard belongs to one server connection, so a token can only give a server back what
that same server sent.

```
MCP host (Claude, Cursor, …) ⇄ anonyma-mcp-proxy ⇄ any stdio MCP server
                                 tokens ← │ → real values
```

Built on [`anonyma`](https://github.com/izaccavalheiro/anonyma) and tested against the official
MCP TypeScript SDK on both sides.

## Put any server behind the proxy

No change to the server or the host: configure the proxy in place of the server and put the
server's command after `--`.

```json
{
  "mcpServers": {
    "crm": {
      "command": "npx",
      "args": ["-y", "@anonyma/mcp", "--", "npx", "-y", "@example/crm-mcp-server"]
    }
  }
}
```

```
Usage: anonyma-mcp-proxy [options] -- <command> [args...]

  --categories <list>  Comma-separated categories to detect (default: all built-in)
  --preset <name>      A compliance preset, such as gdpr or hipaa
  --format <shape>     Token shape: bracket ([EMAIL_0001], default), angle or brace
  --tag <tag>          2-12 letters or digits inserted into every token
  --strict             Restore only exact tokens, not spellings a model changed
  --quiet              Do not log what was replaced (counts only, never content)
```

The proxy logs to stderr, which hosts show in their MCP logs: how many values were replaced per
method, never the values. A message it cannot process is never forwarded as it is: a request
gets a JSON-RPC error, and a line that is not JSON is dropped.

## Guard an MCP client in your own agent

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { guardMcpClient } from "@anonyma/mcp";

const client = guardMcpClient(new Client({ name: "my-agent", version: "1.0.0" }));
await client.connect(transport);

const found = await client.callTool({ name: "find_customer", arguments: { id: "42" } });
// found.content[0].text: "Customer 42: [EMAIL_0001]" — safe to put in a prompt

await client.callTool({ name: "send_mail", arguments: { to: "[EMAIL_0001]" } });
// the server received "ada@example.com"
```

`callTool`, `readResource` and `getPrompt` are guarded; every other member is the client's own.
`client.anonymaGuard.restoreText(answer)` restores the tokens in the model's final answer.

## Any transport

`createMcpGuard()` works on JSON-RPC messages, whatever carries them:

```ts
import { createMcpGuard } from "@anonyma/mcp";

const guard = createMcpGuard({ session: { format: "brace" } });
serverTransport.onmessage = (message) => hostTransport.send(guard.fromServer(message));
hostTransport.onmessage = (message) => serverTransport.send(guard.fromClient(message));
```

| Direction     | Message                                                        | What the guard does                       |
| ------------- | -------------------------------------------------------------- | ----------------------------------------- |
| server → host | `tools/call` result (`content`, `structuredContent`)           | tokenizes text; keeps types, URIs, binary |
| server → host | `resources/read`, `prompts/get` results                        | tokenizes text                            |
| server → host | error responses (`message`, `data`)                            | tokenizes                                 |
| server → host | `sampling/createMessage`, `notifications/message`/`progress`   | tokenizes                                 |
| host → server | `tools/call` and `prompts/get` arguments, `resources/read` URI | restores tokens                           |
| host → server | answer to `sampling/createMessage`                             | restores tokens                           |
| either        | everything else (`initialize`, `tools/list`, …)                | passes unchanged                          |

`onEvent` reports each changed message — direction, method, count — without content. Pass
`snapshot: guard.session.snapshot()` to a new guard to continue a mapping.

Use `createMcpServer()` from `anonyma/mcp` instead to expose anonyma's own detection and
redaction as MCP tools.

## Requirements

Node.js ≥ 18 and `anonyma` ^1.2.0 as a peer dependency.

## Versioning

This package follows [Semantic Versioning](https://semver.org) independently of `anonyma`.
While it is at 0.x, a minor version may change its API or the proxy's command line; see
[CHANGELOG.md](CHANGELOG.md).

## License

MIT
