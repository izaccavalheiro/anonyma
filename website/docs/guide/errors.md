---
title: Errors
sidebar_position: 17
description: The error classes anonyma throws, and how to tell them apart.
---

Every error the library throws is an `AnonymaError` with a machine-readable `code`. The classes are
exported from `anonyma`, including those thrown by the other entry points:

| Class                      | Thrown when                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `ValidationError`          | An argument or option is invalid                                    |
| `UnsupportedStrategyError` | A rule names a strategy that does not exist                         |
| `UnknownCategoryError`     | A rule names a category that does not exist                         |
| `PresetNotFoundError`      | A preset name is unknown                                            |
| `AsyncStrategyError`       | `transform()` meets a strategy that needs `transformAsync()`        |
| `CryptoNotAvailableError`  | The runtime has no Web Crypto                                       |
| `EncryptionError`          | Encryption or decryption fails, as with a wrong key                 |
| `AllowlistMatchError`      | An allowlist entry is invalid                                       |
| `BatchProcessingError`     | Reserved: the batch functions report each failure in its result     |
| `KeyManagementError`       | A key ring operation fails, as with a destroyed key version         |
| `TokenVaultError`          | A token vault operation fails                                       |
| `PolicyError`              | A policy document is invalid or weaker than a regulation it extends |
| `AuditIntegrityError`      | An audit chain cannot be extended or verified                       |

```ts
import { AnonymaError, PolicyError } from "anonyma";
import { parsePolicy } from "anonyma/compliance";

try {
  parsePolicy(document);
} catch (error) {
  if (error instanceof PolicyError) {
    for (const issue of error.issues) console.error(issue.path, issue.message);
  } else if (error instanceof AnonymaError) {
    console.error(error.code, error.message);
  }
}
```
