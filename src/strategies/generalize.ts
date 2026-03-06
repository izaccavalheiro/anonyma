/**
 * @module strategies/generalize
 * @description The `generalize` anonymization strategy.
 *
 * Replaces a precise value with a coarser, less-identifying representation.
 * Currently supports:
 * - **Numeric generalization**: bucketing a number into a range (e.g. `27` → `"20-29"`)
 * - **String passthrough**: non-numeric strings are returned unchanged.
 */

import { ValidationError } from "../errors.js";
import type { GeneralizeOptions } from "../types.js";

/**
 * Generalize `value` by replacing exact numeric values with a range bucket.
 * Non-numeric strings are returned without modification.
 *
 * @param value - The value to generalize.
 * @param options - Generalization configuration.
 * @returns A generalized string representation.
 *
 * @throws {@link ValidationError} When `bucketSize` is not a positive integer.
 *
 * @example
 * ```ts
 * import { generalize } from "anonyma";
 *
 * generalize("27");            // "20-29"
 * generalize("30");            // "30-39"
 * generalize("72");            // "70-79"
 * generalize("27", { bucketSize: 5 });  // "25-29"
 * generalize("not-a-number");  // "not-a-number" (passthrough)
 * ```
 */
export function generalize(value: string, options: GeneralizeOptions = {}): string {
  const { bucketSize = 10 } = options;

  if (!Number.isInteger(bucketSize) || bucketSize < 1) {
    throw new ValidationError("bucketSize", "must be a positive integer");
  }

  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    // Non-numeric value: return as-is (best-effort generalization).
    return value;
  }

  const n = Math.floor(parsed);
  const low = Math.floor(n / bucketSize) * bucketSize;
  const high = low + bucketSize - 1;

  return `${String(low)}-${String(high)}`;
}
