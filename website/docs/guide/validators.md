---
title: Checksum validators
sidebar_position: 15
description: The check-digit algorithms behind the validating detectors, available on their own.
---

The detectors use these validators to confirm what they find. `anonyma/validators` exports them,
for your own form validation or detectors:

```ts
import { cnpjChecksum, ibanMod97, luhn, nhsMod11 } from "anonyma/validators";

luhn("4111111111111111"); // true
ibanMod97("GB82WEST12345698765432"); // true
nhsMod11("943-476-5919"); // true
cnpjChecksum("12.ABC.345/01DE-35"); // true — alphanumeric CNPJ
```

| Function                        | Algorithm                  | Checks                                          |
| ------------------------------- | -------------------------- | ----------------------------------------------- |
| `luhn`                          | Luhn (ISO/IEC 7812)        | Payment cards                                   |
| `ibanMod97`                     | MOD-97 (ISO 13616)         | IBANs                                           |
| `abaRoutingChecksum`            | 3-7-1 weights              | US bank routing numbers                         |
| `npiChecksum`                   | Luhn behind prefix 80840   | US National Provider Identifiers                |
| `deaChecksum`                   | DEA check digit            | US prescriber registrations                     |
| `vinChecksum`                   | Position-9 check digit     | Vehicle identification numbers                  |
| `imeiChecksum`                  | Luhn                       | Mobile device identities                        |
| `cpfChecksum`                   | Mod-11                     | Brazilian CPF                                   |
| `cnpjChecksum`                  | Mod-11                     | Brazilian CNPJ, numeric or alphanumeric         |
| `pixPayloadChecksum`            | CRC-16                     | PIX "copia e cola" payloads                     |
| `nhsMod11`                      | Mod-11                     | UK NHS numbers                                  |
| `ninoValid`                     | Format rules               | UK National Insurance numbers                   |
| `bsnChecksum`                   | Eleven test                | Dutch BSN                                       |
| `ptNifChecksum`                 | Mod-11                     | Portuguese NIF                                  |
| `spanishIdChecksum`             | Mod-23 letter              | Spanish DNI and NIE                             |
| `italianFiscalCodeChecksum`     | Check letter               | Italian codice fiscale                          |
| `frNirChecksum`                 | 97 − n mod 97              | French NIR                                      |
| `swedishPersonnummerChecksum`   | Luhn                       | Swedish personnummer                            |
| `verhoeff`                      | Verhoeff                   | Indian Aadhaar                                  |
| `aadhaarFormat`                 | Format rules               | Indian Aadhaar                                  |
| `chineseResidentIdChecksum`     | ISO 7064 MOD 11-2          | Chinese resident identity numbers               |
| `australianTfnChecksum`         | Weighted mod-11            | Australian tax file numbers                     |

## By name

`CHECKSUMS` holds every validator by name — `"luhn"`, `"cnpj"`, `"aba-routing"`, … — and a
[pipeline pattern](engine.md#your-own-formats) names the one its matches must pass:

```ts
compilePipeline({
  patterns: [{ source: String.raw`\b\d{9}\b`, category: "routing", validator: "aba-routing" }],
});
```

[Checksums](../reference/checksums.md) lists the names; it is generated from the code. A
[plugin](plugins.md) can also attach a validator to a built-in category.
