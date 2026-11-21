---
title: Reversible tokenization
sidebar_position: 7
description: Replace personal data with tokens, keep the mapping on your side, and put the values back later.
---

`tokenize()` replaces personal data with placeholder tokens and returns the mapping to restore them.
Identical values share a token.

```ts
import { detokenize, tokenize } from "anonyma";

const { text, mapping } = tokenize("alice@example.com called 555-867-5309");
// text: "[EMAIL_0001] called [PHONE_0001]"

detokenize(text, mapping).text;
// "alice@example.com called 555-867-5309"
```

| `format`              | Token           |
| --------------------- | --------------- |
| `"bracket"` (default) | `[EMAIL_0001]`  |
| `"angle"`             | `<EMAIL_1>`     |
| `"brace"`             | `{{EMAIL_1}}`   |

`TokenizeOptions` also declares `format: "custom"` with `tokenTemplate`, `deterministic: false` and
`locales`, which `tokenize()` does not apply.

:::warning Keep the mapping private

The mapping holds the original values in clear. It must stay on your side: never send it to the
service that receives the tokenized text.

:::

## Token vaults

Pass a `vault` and the tokens are stored in it instead of living only in the returned mapping.
`restore(text, vault)` then puts the original values back into any text — a model's answer, a later
request, another process that reaches the same store.

```ts
import { InMemoryVault, restore, tokenize } from "anonyma";

const vault = new InMemoryVault(); // one per request or conversation

tokenize("Mail john@example.com, cc jane@example.com", { vault }).text;
// "Mail {{EMAIL_1}}, cc {{EMAIL_2}}"

// A later turn continues the numbering; a known value keeps its token.
tokenize("Reply to jane@example.com and ada@example.com", { vault }).text;
// "Reply to {{EMAIL_2}} and {{EMAIL_3}}"

restore("Sent to {{EMAIL_2}} and {{EMAIL_1}}.", vault).text;
// "Sent to jane@example.com and john@example.com."
```

`restore()` scans the text once and matches whole tokens, so `{{PERSON_1}}` is never found inside
`{{PERSON_10}}`, and a restored value is never scanned again. Unknown tokens stay in place and are
listed in `unresolved`. With a vault, `format` defaults to `"brace"`; avoid it when prompts go
through a template engine that treats `{{…}}` as a placeholder.

### Your own store

Any object with `store(key, value)` and `retrieve(key)` is a vault. Both may return promises — use
`tokenizeAsync()` and `await restore(…)`:

```ts
import { restore, tokenizeAsync, type AnonymaVault } from "anonyma";

// A Cloudflare KV namespace, with one key prefix per conversation
const kvVault = (kv: KVNamespace, conversation: string): AnonymaVault => ({
  store: (key, value) => kv.put(`${conversation}:${key}`, value, { expirationTtl: 3600 }),
  retrieve: async (key) => (await kv.get(`${conversation}:${key}`)) ?? undefined,
});

const vault = kvVault(env.TOKENS, conversationId);
const { text } = await tokenizeAsync(prompt, { vault });
const { text: answer } = await restore(await callYourModel(text), vault);
```

:::danger One vault per conversation

A vault holds original values in clear. Keep one per conversation or user: restoring a user's text
against a vault shared with other users would hand them data that is not theirs if they type
somebody else's token.

:::

## Going further

- [Keys and token vaults](vault.md): tokens that stay the same across processes, key rotation,
  erasure of one person's data, and tokens that can be opened with a key and no store.
- [LLMs and AI tools](llm.md): chat messages, streamed answers and tool calls.
- `createVaultTokenizer()` in `anonyma/vault` plugs an `AnonymaVault` into pipelines and the
  streaming restorers.
