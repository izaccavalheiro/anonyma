---
title: Keys and token vaults
sidebar_position: 11
description: Tokens that stay the same across processes, key rotation, erasure of one person's data, and tokens that open with a key alone.
---

`anonyma/vault` holds the tokenizers for data that lives longer than one request: a CRM export
that must stay joinable, a data warehouse that must honour erasure requests, a support tool that
must show the real value to the right person.

| Tokenizer                                | Reversible             | Same value, same token              | Token                     |
| ---------------------------------------- | ---------------------- | ----------------------------------- | ------------------------- |
| `createSessionTokenizer()`               | within the session     | within the session                  | `[EMAIL_0001]`            |
| `createVaultTokenizer()`                 | through your store     | within the store                    | `{{EMAIL_1}}`             |
| `createKeyedTokenizer()` with a vault    | through the vault      | across calls and processes, per key | `[EMAIL_k1_7ZK3M9QW2ABC]` |
| `createKeyedTokenizer()` without a vault | no                     | across calls and processes, per key | `[EMAIL_k1_7ZK3M9QW2ABC]` |
| `createSealedTokenizer()`                | with the key, no vault | across calls and processes, per key | `[EMAIL_k1.5wq…]`         |

Each one is a tokenization provider for the `tokenize` strategy of a [pipeline](engine.md).

## One conversation

```ts
import { compilePipeline } from "anonyma/engine";
import { createSessionTokenizer } from "anonyma/vault";

const session = createSessionTokenizer();
const pipeline = compilePipeline(
  { defaultStrategy: { strategy: "tokenize" } },
  { tokenization: session },
);

pipeline.transform("Email alice@example.com").text; // "Email [EMAIL_0001]"
session.restore("Sent to [EMAIL_0001].").text; // "Sent to alice@example.com."
```

## Stable tokens across processes

A keyed tokenizer derives the token from the value and a key, so every process with the key gives the
same value the same token, and datasets stay joinable without the values. With a vault, tokens can
also be resolved back.

```ts
import { compilePipeline } from "anonyma/engine";
import {
  createKeyedTokenizer,
  createKeyRing,
  createMemoryVault,
  generateKeyMaterial,
  restoreTokens,
} from "anonyma/vault";

const keyring = await createKeyRing({
  namespace: "crm",
  keys: [{ id: "k1", material: await generateKeyMaterial() }],
});
const keyed = createKeyedTokenizer({ keyring, vault: createMemoryVault() });
const crm = compilePipeline({ defaultStrategy: { strategy: "tokenize" } }, { tokenization: keyed });

const { text } = await crm.transformAsync("Mail alice@example.com");
// "Mail [EMAIL_k1_Y5DMH9ED2DTF]"
(await restoreTokens(text, keyed)).text; // "Mail alice@example.com"
```

`createMemoryVault()` is the reference implementation of the `TokenVault` interface; implement that
interface over your own database for production.

## Keys

Key material is either at least 32 random bytes (`{ kind: "raw", bytes }`, which
`generateKeyMaterial()` makes) or a passphrase (`{ kind: "passphrase", passphrase }`, stretched with
PBKDF2-SHA-256, 600,000 iterations by default). Each purpose gets its own key, derived with HKDF;
derived keys are non-extractable. `keyring.manifest()` describes the ring without secrets, and can
be stored next to the data.

Keep the material in your platform's secret store, never in configuration or in the repository.

## Rotation

```ts
import { rewrapVault, shredKey } from "anonyma/vault";

await keyring.rotate({ id: "k2", material: newMaterial }); // new tokens use k2
const { unrecoverable, skipped } = await rewrapVault(vault, keyring); // re-seal records under k2
if (unrecoverable === 0 && skipped === 0) await shredKey(keyring, "k1", vault);
```

`rewrapVault()` re-seals the records under the new version without changing any token.
`shredKey()` destroys a version, so that nothing sealed under it can be recovered — not even from a
backup of the vault.

## Erasure

Tokenize with a data-subject reference, and you can later erase everything of that person:

```ts
const token = await keyed.tokenize("alice@example.com", { category: "email", subject: "user-42" });
await keyed.forgetSubject("user-42"); // the token no longer resolves; returns a receipt
await keyed.forgetToken(otherToken); // one token
```

The subject reference is never stored in clear. `planErasure()` in `anonyma/compliance` tells you,
strategy by strategy, what an erasure request requires — see
[Regulations and policies](compliance.md#erasure).

## Tokens without a store

A sealed token carries the value, encrypted under the key: any machine with the key can open it,
and no vault is needed. Destroying the key version makes every token sealed under it unreadable.

```ts
import { createKeyRing, createSealedTokenizer } from "anonyma/vault";

const keyring = await createKeyRing({ namespace: "exports", keys: [{ id: "k1", material }] });
const sealed = createSealedTokenizer({ keyring });

const token = await sealed.tokenize("alice@example.com", { category: "email" });
await sealed.detokenize(token); // "alice@example.com"
```

## Your own store

`createVaultTokenizer({ vault })` turns any [`AnonymaVault`](tokenization.md#your-own-store) — an
object with `store()` and `retrieve()`, over Redis, KV or a database table — into a provider for
pipelines and the streaming restorers.
