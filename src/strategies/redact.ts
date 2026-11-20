/**
 * @module strategies/redact
 * @description The `redact` anonymization strategy.
 */

import { ValidationError } from "../errors.js";
import type { RedactOptions } from "../types.js";

/**
 * Replace `value` entirely with a redaction label.
 *
 * @param value - The string to redact (validated but not inspected).
 * @param options - Redaction configuration.
 * @returns The redaction label.
 *
 * @throws {@link ValidationError} When `label` is an empty string.
 *
 * @example
 * ```ts
 * import { redact } from "anonyma";
 *
 * redact("john.doe@example.com");
 * // "[REDACTED]"
 *
 * redact("123-45-6789", { label: "[SSN REMOVED]" });
 * // "[SSN REMOVED]"
 * ```
 */
export function redact(value: string, options: RedactOptions = {}): string {
  const { label = "[REDACTED]" } = options;

  if (label.trim().length === 0) {
    throw new ValidationError("label", "must not be an empty string");
  }

  // The value itself is not needed: whatever it is, it becomes the label.
  return label;
}
