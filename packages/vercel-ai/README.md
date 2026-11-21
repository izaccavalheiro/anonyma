# anonyma-vercel-ai

Personal-data redaction for the [Vercel AI SDK](https://ai-sdk.dev). Prompts are tokenized before
they leave your process — `john@example.com` becomes `[EMAIL_0001]` — and what the model returns
gets the original values back: the text, the reasoning, and the arguments of tool calls,
complete or streamed. The mapping between tokens and values never leaves your process.

Built on the LLM guard of [`anonyma`](https://github.com/izaccavalheiro/anonyma) and tested
against the real `generateText()` and `streamText()` of AI SDK 7.

```sh
npm install anonyma-vercel-ai anonyma ai
```

## Drop-in `generateText` and `streamText`

```ts
import { openai } from "@ai-sdk/openai";
import { createAnonymaAI } from "anonyma-vercel-ai";

const { generateText, streamText } = createAnonymaAI({ skipRoles: ["system"] });

const { text } = await generateText({
  model: openai("gpt-5"),
  prompt: "Write a short reply to john@example.com about invoice 42.",
});
// The model saw "[EMAIL_0001]"; `text` contains john@example.com again.

const result = streamText({ model: openai("gpt-5"), prompt: "Call 555-867-5309 back." });
for await (const delta of result.textStream) process.stdout.write(delta);
// A token split across stream parts ("[PHO" + "NE_0001]") is restored as a whole.
```

Both take the same options and return the same results as the AI SDK functions they replace.

## A wrapped model

```ts
import { generateText } from "ai";
import { withAnonyma } from "anonyma-vercel-ai";

const model = withAnonyma("openai/gpt-5"); // a model object, or a model id string
const { text } = await generateText({ model, prompt });
```

## The middleware

```ts
import { wrapLanguageModel } from "ai";
import { anonymaMiddleware } from "anonyma-vercel-ai";

const model = wrapLanguageModel({
  model: baseModel,
  middleware: [anonymaMiddleware({ session: { format: "brace" } }), otherMiddleware],
});
```

## Tools

Tool calls get the real values and the model only tokens. When the model calls
`sendMail({ to: "[EMAIL_0001]" })`, your `execute` function receives
`{ to: "john@example.com" }`. When the tool result is sent back to the model at the next step, it
is tokenized again.

## Options

Every function takes the options of `createLlmGuard()` from `anonyma/ai`, plus `onSanitized`:

| Option            | Meaning                                                                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec`            | What to detect: `categories`, `preset` (`"gdpr"`, `"hipaa"`…), `patterns`, `allow`… Defaults to every built-in category.                                 |
| `session`         | Token shape: `format` (`"bracket"` `[EMAIL_0001]`, `"angle"` `<EMAIL_1>`, `"brace"` `{{EMAIL_1}}`), `tag`, `prefixes`, `lenient` (default `true`).       |
| `skipRoles`       | Message roles sent unchanged, for example `["system"]`.                                                                                                  |
| `keyRules`        | Keys whose values are tokenized whole, such as `password`.                                                                                               |
| `passthroughKeys` | Further members that must reach the model byte for byte.                                                                                                 |
| `onSanitized`     | Called with the account of each prompt: what was replaced, and what went through unread (`unscanned`: images, files). Throw from it to stop the request. |

```ts
createAnonymaAI({
  onSanitized: (report) => {
    if (report.unscanned.length > 0) throw new Error("Attachments are not allowed here");
  },
});
```

## How tokens are scoped

Each model call gets its own token mapping. A multi-step call (`stopWhen`, tools) sends the
conversation again at each step and gets it tokenized again, so a value keeps its token as long
as it first appears at the same place in the conversation. Images, files and provider options
are passed on unread and listed in `unscanned`.

## Requirements

Node.js ≥ 22 (as AI SDK 7), and `ai` ^7 and `anonyma` ^1.2.0 as peer dependencies.

## Versioning

This package follows [Semantic Versioning](https://semver.org) independently of `anonyma`.
While it is at 0.x, a minor version may change its API; see [CHANGELOG.md](CHANGELOG.md).

## License

MIT
