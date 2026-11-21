---
title: Compliance presets
sidebar_position: 6
description: Presets for GDPR, LGPD, PIPEDA, HIPAA, CCPA, PCI DSS, SOX and FERPA, alone or combined.
---

A preset chooses which categories are detected and how each one is replaced, for the data a
regulation names.

| Preset    | Covers                                                                     | Default strategy                                   |
| --------- | -------------------------------------------------------------------------- | -------------------------------------------------- |
| `gdpr`    | Personal, financial and health data, and online identifiers (EU GDPR)      | `pseudonymize`                                     |
| `lgpd`    | Personal data, including the CPF (Brazil, LGPD)                            | `redact`                                           |
| `pipeda`  | Personal information, including the Social Insurance Number (Canada)       | `redact`                                           |
| `hipaa`   | The HIPAA Safe Harbor identifiers that can be detected in text             | `redact`                                           |
| `ccpa`    | Consumer identifiers, financial and health data, online activity, API keys | `redact`                                           |
| `pci-dss` | Card and bank account numbers, cardholder name and contact details         | `redact`; card and account numbers keep the last 4 |
| `sox`     | Financial and corporate officer identifiers for audit trails               | `redact`                                           |
| `ferpa`   | Student data: name, contact details, date of birth, SSN, national ID       | `redact`                                           |

[Presets](../reference/presets.md) in the reference shows, category by category, what each preset
does; it is generated from the code.

```ts
import { anonymize, getPreset } from "anonyma";

anonymize(text, { preset: "hipaa" });

getPreset("hipaa").categories; // ["name", "address", "date-of-birth", "phone", ...]
```

:::note What a preset cannot do

A preset covers what the library can detect. Some data that a regulation names has no detector —
for HIPAA, ZIP codes, dates other than birth dates, device identifiers and photographs; for PCI DSS,
card verification codes. `REGULATIONS[id].gaps` in `anonyma/compliance` lists them, with the
provision that names each one, and the [regulations](../reference/regulations.md) page shows them.
A preset is a technical measure; it does not make a system compliant on its own.

:::

## Several regulations at once

Health records of Brazilian patients fall under LGPD and HIPAA. A list of presets applies all of
them: every category of every preset is detected, and each category gets the most protective of the
presets' strategies — one that cannot be reversed, links nothing and reveals less wins; between
equals, the preset listed first.

```ts
import { anonymize, combinePresets, createAnonymizer } from "anonyma";

anonymize(text, { preset: ["lgpd", "hipaa"] });
const anonymizer = createAnonymizer({ preset: ["lgpd", "hipaa"] });

// What a combination does:
combinePresets(["pci-dss", "hipaa"]).rules; // [] — HIPAA's redaction beats PCI DSS's mask
```

The recipe [Several regulations at once](../guides/several-regulations.md) goes further, with
validating detectors and signed receipts.

## Changing a preset

In `anonymize()`, `rules` replace the preset's rules and its list of categories (see
[Per-category rules](strategies.md#per-category-rules)). To add a category to a preset, or change
the strategy of one, compile a pipeline:

```ts
import { getPreset } from "anonyma";
import { compilePipeline } from "anonyma/engine";

const gdprWithKeys = compilePipeline({
  preset: "gdpr",
  categories: [...getPreset("gdpr").categories, "api-key"],
  rules: { email: { strategy: "mask", keepTrailing: 12 } },
});
```

For a policy that your organisation maintains, checked against the regulations it extends, see
[Regulations and policies](compliance.md).
