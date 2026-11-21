---
title: Several regulations at once
sidebar_position: 3
description: Combine presets, keep check digits honest, and keep signed receipts of what was done.
---

Health records of Brazilian patients fall under LGPD and HIPAA. A list of presets applies both:

```ts
import { createAnonymizer } from "anonyma";

const anonymizer = createAnonymizer({ preset: ["lgpd", "hipaa"] });
```

Every category of every preset is detected. When two presets disagree about a category, the most
protective strategy wins — one that cannot be reversed, links nothing and reveals less; between
equals, the preset listed first. [The preset table](../reference/presets.md) shows what each preset
does.

## Let the check digits decide

The validating pipelines of `anonyma/engine` replace a CPF, an IBAN or a card number only when its
check digits hold, so test data and look-alikes stay as they are:

```ts
import { compilePipeline } from "anonyma/engine";

const pipeline = compilePipeline({ preset: ["lgpd", "hipaa"] });
pipeline.transform("CPF 529.982.247-25, ref 529.982.247-26").text;
// "CPF [REDACTED], ref 529.982.247-26"
```

Your own formats can do the same, and use the words around them:

```ts
compilePipeline({
  minConfidence: 0.8,
  patterns: [
    { source: "\\b\\d{9}\\b", category: "routing", validator: "aba-routing" },
    {
      source: "\\b\\d{6}\\b",
      category: "employee-id",
      confidence: 0.5,
      context: { keywords: ["badge", "employee"], boost: 0.4 },
    },
  ],
});
```

## Keep receipts

A receipt is a signed statement of what was done: when, under which presets, how many values of
each category, and a digest of the output. It holds no value, so it can be kept, shared with an
auditor or attached to the data.

```ts
import { createReceiptIssuer } from "anonyma/audit";

const receipts = createReceiptIssuer({ key: process.env.RECEIPT_KEY!, presets: ["lgpd", "hipaa"] });
const result = pipeline.transform(record);
const receipt = await receipts.issue(result);

// Later, with the same key:
(await receipts.verify(receipt, { output: result.text })).valid; // true
```

A receipt that was edited, signed with another key, or issued for another output fails
verification. For a continuous record, the [audit chain](../guide/modules.md) links every operation
to the one before it.
