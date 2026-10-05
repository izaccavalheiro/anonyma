/**
 * @module errors
 * @description Typed error classes for the anonyma library.
 *
 * All errors extend `AnonymaError` so consumers can use a single `instanceof` check.
 *
 * @example
 * ```ts
 * import { AnonymaError, ValidationError } from "anonyma";
 *
 * try {
 *   mask(value, { keepLeading: -1 });
 * } catch (err) {
 *   if (err instanceof ValidationError) {
 *     console.error("bad input:", err.message, err.field);
 *   }
 * }
 * ```
 */

import type { PolicyIssue } from "./compliance/types.js";

/**
 * Base class for all errors thrown by the anonyma library.
 * Consumers can use `err instanceof AnonymaError` to narrowly handle library errors.
 */
export class AnonymaError extends Error {
  /** Machine-readable error code. */
  public readonly code: string;

  public constructor(message: string, code: string) {
    super(message);
    this.name = "AnonymaError";
    this.code = code;
    // Maintain proper prototype chain in transpiled ES5 environments.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a function receives an argument that fails validation.
 *
 * @example
 * ```ts
 * throw new ValidationError("keepLeading", "must be a non-negative integer");
 * ```
 */
export class ValidationError extends AnonymaError {
  /** The name of the invalid field or parameter. */
  public readonly field: string;

  public constructor(field: string, reason: string) {
    super(`Validation failed for \`${field}\`: ${reason}`, "VALIDATION_ERROR");
    this.name = "ValidationError";
    this.field = field;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an unsupported strategy name is encountered.
 *
 * @example
 * ```ts
 * throw new UnsupportedStrategyError("foobar");
 * ```
 */
export class UnsupportedStrategyError extends AnonymaError {
  /** The strategy name that was not recognised. */
  public readonly strategy: string;

  public constructor(strategy: string) {
    super(
      `Unsupported anonymization strategy: "${strategy}". ` +
        `Supported strategies are: mask, redact, pseudonymize, hash, generalize.`,
      "UNSUPPORTED_STRATEGY",
    );
    this.name = "UnsupportedStrategyError";
    this.strategy = strategy;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an unknown PII category is referenced in a rule or config.
 *
 * @example
 * ```ts
 * throw new UnknownCategoryError("passport");
 * ```
 */
export class UnknownCategoryError extends AnonymaError {
  /** The category name that was not recognised. */
  public readonly category: string;

  public constructor(category: string) {
    super(
      `Unknown PII category: "${category}". ` +
        `Supported categories are: email, phone, ssn, credit-card, ipv4, ipv6, url, iban, date-of-birth.`,
      "UNKNOWN_CATEGORY",
    );
    this.name = "UnknownCategoryError";
    this.category = category;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the runtime environment does not support a required Web Crypto API.
 * This is only relevant for the `hash` and `encrypt` strategies.
 */
export class CryptoNotAvailableError extends AnonymaError {
  public constructor() {
    super(
      "The Web Crypto API (globalThis.crypto.subtle) is not available in this environment. " +
        "Upgrade to Node.js ≥ 18 or use a polyfill.",
      "CRYPTO_NOT_AVAILABLE",
    );
    this.name = "CryptoNotAvailableError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when encryption or decryption fails.
 *
 * @example
 * ```ts
 * throw new EncryptionError("encrypt", originalError);
 * ```
 */
export class EncryptionError extends AnonymaError {
  /** The operation that failed (`"encrypt"` or `"decrypt"`). */
  public readonly operation: "encrypt" | "decrypt";

  public constructor(operation: "encrypt" | "decrypt", cause?: unknown) {
    super(
      `Encryption operation "${operation}" failed.${cause instanceof Error ? ` Cause: ${cause.message}` : ""}`,
      "ENCRYPTION_ERROR",
    );
    this.name = "EncryptionError";
    this.operation = operation;
    if (cause !== undefined) {
      (this as { cause?: unknown }).cause = cause;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an unknown compliance preset name is referenced.
 *
 * @example
 * ```ts
 * throw new PresetNotFoundError("unknown-preset");
 * ```
 */
export class PresetNotFoundError extends AnonymaError {
  /** The preset name that was not recognised. */
  public readonly preset: string;

  public constructor(preset: string) {
    super(
      `Unknown compliance preset: "${preset}". ` +
        `Available presets are: gdpr, lgpd, pipeda, hipaa, ccpa, pci-dss, sox, ferpa.`,
      "PRESET_NOT_FOUND",
    );
    this.name = "PresetNotFoundError";
    this.preset = preset;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an allowlist configuration entry is invalid.
 *
 * @example
 * ```ts
 * throw new AllowlistMatchError("allowlist[0]", "must be a non-empty string");
 * ```
 */
export class AllowlistMatchError extends AnonymaError {
  /** The allowlist entry or field that was invalid. */
  public readonly field: string;

  public constructor(field: string, reason: string) {
    super(`Invalid allowlist configuration for \`${field}\`: ${reason}`, "ALLOWLIST_MATCH_ERROR");
    this.name = "AllowlistMatchError";
    this.field = field;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a batch processing operation encounters errors.
 * Contains partial results for items that succeeded.
 *
 * @example
 * ```ts
 * try {
 *   anonymizeBatch(texts);
 * } catch (err) {
 *   if (err instanceof BatchProcessingError) {
 *     console.log(`${err.failed} items failed, ${err.succeeded} succeeded`);
 *   }
 * }
 * ```
 */
export class BatchProcessingError extends AnonymaError {
  /** Number of items that succeeded. */
  public readonly succeeded: number;
  /** Number of items that failed. */
  public readonly failed: number;
  /** Total items submitted. */
  public readonly total: number;

  public constructor(succeeded: number, failed: number, total: number) {
    super(
      `Batch processing completed with errors: ${String(succeeded)}/${String(total)} succeeded, ${String(failed)} failed.`,
      "BATCH_PROCESSING_ERROR",
    );
    this.name = "BatchProcessingError";
    this.succeeded = succeeded;
    this.failed = failed;
    this.total = total;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown by a synchronous pipeline entry point when a replacer returns a
 * promise. Use the asynchronous entry point (`transformAsync()`, an async
 * chunk transformer, or an async stream) with that replacer instead.
 *
 * @example
 * ```ts
 * throw new AsyncStrategyError("email");
 * ```
 */
export class AsyncStrategyError extends AnonymaError {
  /** The category whose replacer is asynchronous. */
  public readonly category: string;

  public constructor(category: string) {
    super(
      `The replacer for category "${category}" is asynchronous and cannot run in a synchronous ` +
        `transform. Use the asynchronous entry point instead.`,
      "ASYNC_STRATEGY",
    );
    this.name = "AsyncStrategyError";
    this.category = category;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a key version is unknown, destroyed, malformed, or cannot be
 * derived. The message never contains key material.
 *
 * @example
 * ```ts
 * throw new KeyManagementError("key version has been destroyed", "k1");
 * ```
 */
export class KeyManagementError extends AnonymaError {
  /** The key version the error refers to, when there is one. */
  public readonly keyId: string | undefined;

  public constructor(reason: string, keyId?: string) {
    super(
      keyId === undefined
        ? `Key management error: ${reason}`
        : `Key management error for key "${keyId}": ${reason}`,
      "KEY_MANAGEMENT_ERROR",
    );
    this.name = "KeyManagementError";
    this.keyId = keyId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a token vault operation fails or would corrupt the vault. The
 * message never contains an original value.
 *
 * @example
 * ```ts
 * throw new TokenVaultError("token identifier collision; increase idLength");
 * ```
 */
export class TokenVaultError extends AnonymaError {
  public constructor(reason: string) {
    super(`Token vault error: ${reason}`, "TOKEN_VAULT_ERROR");
    this.name = "TokenVaultError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a policy document is malformed or violates a requirement of a
 * regulation it extends. `issues` lists every problem that was found.
 *
 * @example
 * ```ts
 * try {
 *   parsePolicy(document);
 * } catch (err) {
 *   if (err instanceof PolicyError) {
 *     for (const issue of err.issues) console.error(issue.path, issue.message);
 *   }
 * }
 * ```
 */
export class PolicyError extends AnonymaError {
  /** Every problem found in the document, errors first. */
  public readonly issues: readonly PolicyIssue[];

  public constructor(issues: readonly PolicyIssue[]) {
    const errors = issues.filter((issue) => issue.severity === "error");
    const first = errors[0];
    super(
      `Policy rejected with ${String(errors.length)} error(s)` +
        (first === undefined ? "." : `: ${first.path === "" ? "/" : first.path} ${first.message}`),
      "POLICY_ERROR",
    );
    this.name = "PolicyError";
    this.issues = issues;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the audit chain cannot be extended or does not verify.
 *
 * @example
 * ```ts
 * throw new AuditIntegrityError("a sink rejected record 12; the logger is closed");
 * ```
 */
export class AuditIntegrityError extends AnonymaError {
  public constructor(reason: string) {
    super(`Audit integrity error: ${reason}`, "AUDIT_INTEGRITY_ERROR");
    this.name = "AuditIntegrityError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
