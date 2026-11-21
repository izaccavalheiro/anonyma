---
title: Protect LLM prompts
sidebar_position: 2
description: Send prompts with tokens instead of personal data, and get the real values back in the answer.
---

A model rarely needs to know _who_; it needs to know _that_. Replace personal data with tokens before
the prompt leaves, and put the values back in the answer:

```
"Write to ana@example.com"  →  model sees "Write to {{EMAIL_1}}"  →  "Done: {{EMAIL_1}} notified"
                                                                    →  "Done: ana@example.com notified"
```

The mapping stays in your process (or in a vault you choose); the provider never sees it.

## With the Vercel AI SDK

```bash
npm install anonyma anonyma-vercel-ai ai
```

```ts
import { generateText } from "ai";
import { withAnonyma } from "anonyma-vercel-ai";

const { text } = await generateText({
  model: withAnonyma("openai/gpt-5"),
  prompt: "Draft a reply to ana@example.com about order 1182.",
});
// The model saw {{EMAIL_1}}; `text` has the address back.
```

Streaming works too: a token split across chunks is held back until it is complete. See
[Vercel AI SDK](../packages/vercel-ai.md).

## With any client

```ts
import { createLlmGuard } from "anonyma/ai";

const exchange = createLlmGuard({ session: { format: "brace" } }).begin();
const { messages } = exchange.sanitizeMessages([
  { role: "user", content: "Email ana@example.com" },
]);
const answer = await callYourModel(messages); // sees {{EMAIL_1}}
exchange.restoreText(answer).text; // the original address is back
```

## Across requests

A conversation that spans requests needs the mapping to live somewhere shared. Any store with
`store()` and `retrieve()` is an `AnonymaVault`:

```ts
import { createVaultTokenizer, restore } from "anonyma/vault";

const vault = redisVault(conversationId); // your implementation: store(key, value), retrieve(key)
const tokens = createVaultTokenizer({ vault });
```

Keep restoration scoped to the conversation that issued the tokens: a token from one conversation
must never bring back a value from another.

## For MCP tools

Put any MCP server behind [`anonyma-mcp-proxy`](../packages/mcp.md): tool results reach the model as
tokens, and tool arguments reach the server as real values.
