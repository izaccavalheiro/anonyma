---
title: Detecting personal data
sidebar_position: 3
description: The 27 categories anonyma detects, how to narrow or widen detection, and how to add your own formats.
---

Every category is detected without configuration. Formats with check digits — cards, IBANs, VINs,
many national and tax IDs — are confirmed by them; free-form data such as names and addresses is
found by patterns and the words around them. [Categories](../reference/categories.md) lists which
category is validated, and which presets detect it.

## Categories

### Personal information

| Category          | Examples                                                                                    | How it is recognised                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `email`           | `alice@example.com`                                                                         | RFC 5321 pattern                                                                                                              |
| `phone`           | `+1 (555) 867-5309`, `(11) 91234-5678`, `06 12 34 56 78`                                    | North American, international, and national formats of Brazil, France, the UK, Spain, Italy and the German-speaking countries |
| `ssn`             | `123-45-6789`                                                                               | Pattern and allocation rules                                                                                                  |
| `name`            | `Dear Alice Smith`, `Patient: John Doe`                                                     | Greetings, titles and labels before the name                                                                                  |
| `date-of-birth`   | `1990-04-15`, `April 15, 1990`                                                              | Several date formats                                                                                                          |
| `address`         | `123 Main St, Springfield, IL 62701`, `Musterstraße 12, 10115 Berlin`, `Av. Paulista, 1578` | Patterns and street keywords (US, UK, European and Brazilian)                                                                 |
| `passport`        | `A12345678`, `P1234567`                                                                     | Country-specific patterns                                                                                                     |
| `drivers-license` | `D123-4567-8901`, `F123-456-78-910-1`                                                       | State and country patterns                                                                                                    |
| `national-id`     | Aadhaar, NINO, CPF, RG, DNI, codice fiscale, NIR, BSN and more                              | Country-specific patterns; check digits in the span engine                                                                    |

### Financial

| Category         | Examples                                                       | How it is recognised                           |
| ---------------- | -------------------------------------------------------------- | ---------------------------------------------- |
| `credit-card`    | `4111 1111 1111 1111`                                          | Luhn check digit                               |
| `iban`           | `GB82 WEST 1234 5698 7654 32`                                  | MOD-97 (ISO 13616)                             |
| `bank-account`   | Routing and account numbers, SWIFT/BIC, PIX keys and payloads  | Keywords; ABA check digits; PIX CRC-16         |
| `cryptocurrency` | BTC, ETH and XRP wallet addresses                              | Address format of each chain                   |
| `tax-id`         | EIN `12-3456789`, VAT `GB123456789`, CNPJ `11.222.333/0001-81` | Country patterns; CNPJ check digits            |

### Healthcare

| Category           | Examples                          | How it is recognised      |
| ------------------ | --------------------------------- | ------------------------- |
| `medical-record`   | `MRN: 1234567`, `MR#00456789`     | Keywords and patterns     |
| `health-insurance` | `Subscriber ID`, `Group/Member #` | Patterns                  |
| `prescription`     | `Rx# 1234567`, DEA numbers        | Patterns; DEA check digit |

### Digital identity

| Category       | Examples                                    | How it is recognised        |
| -------------- | ------------------------------------------- | --------------------------- |
| `ipv4`         | `192.168.1.1`, `10.0.0.0/8`                 | Octet ranges                |
| `ipv6`         | `2001:0db8::8a2e:0370:7334`                 | Full and compressed forms   |
| `url`          | `https://example.com/path?q=1`              | `http` and `https` URLs     |
| `api-key`      | Bearer tokens, AWS keys, GitHub tokens, …   | Each provider's key format  |
| `social-media` | `@username`, profile URLs, handles          | Patterns                    |

### Vehicles and transport

| Category          | Examples                                 | How it is recognised      |
| ----------------- | ---------------------------------------- | ------------------------- |
| `vin`             | `1HGCM82633A004352`                      | Check digit (position 9)  |
| `license-plate`   | `ABC-1234`, `AB12CDE`                    | Country patterns          |
| `tracking-number` | FedEx, UPS, USPS and DHL tracking codes  | Each carrier's format     |

### Government and legal

| Category               | Examples                         | How it is recognised |
| ---------------------- | -------------------------------- | -------------------- |
| `case-number`          | `2023-CV-001234`, `CR-2022-5678` | Patterns             |
| `company-registration` | EIN, CRN, SIREN, ABN and more    | Country patterns     |

:::tip Names in free text

Patterns find names after a greeting, a title or a label. To find every name in prose, run a named
entity recognition model first and pass its findings in as a
[custom detector](#replace-a-built-in-detector).

:::

## Narrow detection

```ts
import { anonymize } from "anonyma";

// Only some categories
anonymize("alice@example.com — call 555-867-5309", { enabledCategories: { email: true } }).text;
// "[REDACTED] — call 555-867-5309"

// Values that are known to be safe, as strings or regular expressions
anonymize("noreply@example.org or alice@example.com", {
  allowlist: ["noreply@example.org"],
}).text;
// "noreply@example.org or [REDACTED]"

// Only matches the detectors are confident about
anonymize(text, { confidenceThreshold: 0.8 });
```

`detect(text, categories)` and `hasPII(text, categories)` take the categories as a list.

## Widen detection

Aggressive mode uses more permissive patterns, which catch obfuscated values — and more false
positives:

```ts
anonymize("user [at] example [dot] com", { aggressive: true }).text;
// "[REDACTED]"
```

## Add your own formats

A custom pattern catches a format of your own, with its own label:

```ts
anonymize("Order ACME-001234 confirmed.", {
  customPatterns: [{ pattern: /\bACME-\d{6}\b/g, label: "[ORDER_ID]" }],
}).text;
// "Order [ORDER_ID] confirmed."
```

In the span engine, a detector can have a category of its own with its own strategy, and a pattern
can require check digits or keywords nearby — see [Span engine](engine.md#your-own-formats):

```ts
import {
  constant,
  createPipeline,
  defineRegexDetector,
  emailDetector,
  redactWith,
} from "anonyma/engine";

const employeeId = defineRegexDetector({
  category: "employee-id",
  pattern: /\bEMP-\d{6}\b/g,
  confidence: 0.95,
  requires: ["EMP-"], // skip texts that cannot contain a match
});
const pipeline = createPipeline({
  detectors: [emailDetector, employeeId],
  replace: { fallback: redactWith(), byCategory: { "employee-id": constant("[EMPLOYEE]") } },
});
pipeline.transform("EMP-001234 wrote from alice@example.com").text;
// "[EMPLOYEE] wrote from [REDACTED]"
```

## Replace a built-in detector

`customDetectors` replaces the detector of a category with a function that returns matches:

```ts
anonymize("Mail ana@example.com, ops@example.com", {
  customDetectors: {
    // Only the shared mailbox counts as an email address here
    email: (text) =>
      [...text.matchAll(/\bops@example\.com\b/g)].map((m) => ({
        category: "email" as const,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence: 1,
      })),
  },
}).text;
// "Mail ana@example.com, [REDACTED]"
```

To ship detectors, strategies and validators together, write a [plugin](plugins.md).
