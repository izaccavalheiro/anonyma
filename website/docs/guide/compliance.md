---
title: Regulations and policies
sidebar_position: 13
description: Regulation profiles with citations, policy documents checked against them, and erasure planning.
---

`anonyma/compliance` turns regulations into data your code can check against.

:::note

The profiles describe technical measures. They are not legal advice, and they do not make a system
compliant on their own.

:::

## Regulation profiles

`REGULATIONS` maps GDPR, LGPD, PIPEDA, CCPA/CPRA, HIPAA and PCI DSS to:

- the categories each one brings into scope, with the provision behind each one;
- the protection a replacement must give — whether it may be reversible, linkable, or reveal part of
  the value;
- the data it names that no detector covers (`gaps`), with a mitigation.

[Regulations](../reference/regulations.md) in the reference shows every profile; it is generated from
the code.

## Policies

A policy document extends one or more regulations and adds your own choices: categories to include
or exclude, strategies, patterns, allowed values. `parsePolicy()` checks it against every regulation
it extends, and rejects a choice that gives less protection than a regulation requires — citing the
provision:

```ts
import { compilePipeline } from "anonyma/engine";
import { parsePolicy, policyToSpec } from "anonyma/compliance";

const policy = parsePolicy({ version: 1, id: "clinic", extends: ["hipaa", "gdpr"] });
const clinic = compilePipeline(policyToSpec(policy));

parsePolicy({
  version: 1,
  id: "clinic",
  extends: ["hipaa"],
  rules: { email: { strategy: "mask", keepLeading: 3 } },
});
// throws PolicyError: /rules/email "mask" is not sufficient for "email" under HIPAA …
```

`checkPolicy()` returns the issues instead of throwing, and `regulationPolicy("hipaa")` gives the
policy equivalent to a profile, as a starting point. Because a policy is plain JSON, keep it in your
repository and review its changes like code; the command line takes one with `--policy`.

## Erasure

What an erasure request ("right to be forgotten") requires depends on how the data was replaced.
`planErasure()` says what, strategy by strategy:

```ts
import { planErasure } from "anonyma/compliance";

planErasure({ strategy: "redact" }).action; // "none" — nothing about the person remains
planErasure({ strategy: "hash" }).action; // "delete-outputs" — anyone can recompute a guess
planErasure({ strategy: "tokenize" }, { scheme: "keyed", reversible: true }).action;
// "delete-vault-entries" — see forgetSubject() in Keys and token vaults
planErasure({ strategy: "encrypt" }).action; // "destroy-key"
```

See [Keys and token vaults](vault.md#erasure) for the operations themselves.
