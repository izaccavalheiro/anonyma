---
title: LLMs and AI tools
sidebar_position: 8
description: Send prompts, chat messages, JSON and tool calls to a model with tokens instead of personal data, and restore the answers.
---

A model rarely needs to know _who_; it needs to know _that_. Replace personal data with tokens
before a prompt leaves your process, and put the values back in the answer. The mapping stays with
you; the provider never sees it.

For a ready-made integration, see the [Vercel AI SDK middleware](../packages/vercel-ai.md) or the
[MCP proxy](../packages/mcp.md). The recipe [Protect LLM prompts](../guides/protect-llm-prompts.md)
walks through the choices.

## A single prompt

```ts
import { restoreFromLLM, sanitizeForLLM } from "anonyma";

const { text: prompt, mapping } = sanitizeForLLM("Send invoice to alice@example.com");
// prompt: "Send invoice to [EMAIL_0001]"

const response = await callYourModel(prompt);
// "I have sent the invoice to [EMAIL_0001]."

const { text, unresolved } = restoreFromLLM(response, mapping);
// text: "I have sent the invoice to alice@example.com."
// unresolved: tokens in the response that the mapping does not know
```

## Chat messages and streams

`createLlmGuard()` in `anonyma/ai` sanitizes whole chat messages — text parts, tool arguments and
tool results at every depth — and leaves their structure alone: `role`, `name`, identifiers, `type`
and function names. An exchange keeps one mapping, so a value keeps its token across turns.

```ts
import { createLlmGuard } from "anonyma/ai";

const guard = createLlmGuard(); // once, at start-up
const exchange = guard.begin(); // per conversation

const { messages } = exchange.sanitizeMessages([
  { role: "user", content: "Email alice@example.com" },
]);
// messages[0].content: "Email [EMAIL_0001]"

const reply = await callYourModel(messages); // "Sent to [EMAIL_0001]."
exchange.restoreText(reply).text; // "Sent to alice@example.com."
```

Streamed output is restored as it arrives, including tokens split between chunks:

```ts
const restored = modelStream.pipeThrough(exchange.restoreStream());
// or, for an async iterable of text:
for await (const chunk of exchange.restoreIterable(textChunks)) write(chunk);
```

To continue a conversation in a later request, keep `exchange.snapshot()` on your side — it holds
the original values — and resume with `guard.begin(snapshot)`. To share tokens through a store, use
a [vault](tokenization.md#token-vaults).

`toLanguageModelMiddleware()` adapts a guard to the middleware of the Vercel AI SDK
(`wrapLanguageModel()`); [`anonyma-vercel-ai`](../packages/vercel-ai.md) packages it, with drop-in
`generateText()` and `streamText()`.

## JSON

`sanitizeJson()` keeps the shape of a value and sanitizes its strings with a
[pipeline](engine.md):

```ts
import { sanitizeJson } from "anonyma/ai";
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline({ preset: "gdpr" });

sanitizeJson({ user: { email: "alice@example.com" }, id: 7 }, { pipeline }).value;
// { user: { email: "id_…" }, id: 7 }
```

It can replace the values of named keys whole (`keyRules`), leave keys alone (`skipKeys`), sanitize
JSON held in a string (`jsonStringKeys`), and reports what it replaced where, never the values.
`sanitizeJsonText()` takes and returns JSON text, and keeps every number exact.

## MCP server

`anonyma/mcp` is a Model Context Protocol server without dependencies. Its tools are
`anonyma_detect`, `anonyma_anonymize`, `anonyma_tokenize` and `anonyma_check_policy`, plus
`anonyma_detokenize` when you enable it (`allowDetokenize`). The values behind tokens stay in server
memory, and `anonyma_detect` reports positions, not the detected text.

```js
// anonyma-mcp.mjs — register with: claude mcp add anonyma -- node anonyma-mcp.mjs
import { createMcpServer, serveStdio } from "anonyma/mcp";

await serveStdio(createMcpServer(), {
  input: process.stdin,
  write: (line) => void process.stdout.write(line),
});
```

To put _another_ MCP server behind a privacy guard, so that its tool results reach the model as
tokens, use [`anonyma-mcp`](../packages/mcp.md).

## Tool definitions

`anonyma/schemas` holds function-calling definitions of `anonymize`, `detect`, `hasPII` and
`anonymizeObject`, and a capability manifest. It needs the optional peer dependency `zod`.

```ts
import {
  ANONYMA_MANIFEST,
  ANONYMIZE_OBJECT_TOOL_DEFINITION,
  ANONYMIZE_TOOL_DEFINITION,
  HAS_PII_TOOL_DEFINITION,
} from "anonyma/schemas";

const response = await openai.chat.completions.create({
  model: "gpt-4o",
  tools: [
    { type: "function", function: ANONYMIZE_TOOL_DEFINITION },
    { type: "function", function: HAS_PII_TOOL_DEFINITION },
    { type: "function", function: ANONYMIZE_OBJECT_TOOL_DEFINITION },
  ],
  messages: [{ role: "user", content: "Anonymize: alice@example.com" }],
});
```

The definitions have the OpenAI shape, `{ name, description, parameters }`; for the Anthropic API,
pass `parameters` as `input_schema`.

## Validating options from requests

```ts
import { anonymize } from "anonyma";
import { AnonymizeOptionsSchema } from "anonyma/schemas";

const options = AnonymizeOptionsSchema.parse(req.body.options);
const result = anonymize(String(req.body.text), options);
```

The schema covers `rules`, `defaultStrategy`, `customPatterns`, `enabledCategories`,
`globalReplacement`, `consistentTokens`, `aggressive` and `includeMatches`. `parse()` removes the
other options, such as `preset`, `allowlist`, `confidenceThreshold` and `locales`. To accept a whole
pipeline from untrusted input, check a policy document with `parsePolicy()` instead — see
[Regulations and policies](compliance.md).
