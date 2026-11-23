/**
 * @module engine/fusable
 * @description The built-in span detectors, for which batch fusion is proven
 * (see `src/internal/fusion.ts`): a pipeline made only of these scans a batch
 * as fused texts.
 *
 * @internal
 */

import * as builtin from "./builtin.js";
import * as precise from "./precise.js";
import type { SpanDetector } from "./types.js";

function isDetector(value: unknown): value is SpanDetector {
  return typeof value === "object" && value !== null && "scan" in value;
}

/**
 * Every span detector this module set defines: the precise ones and the
 * wrappers of the legacy detectors, standard and aggressive.
 *
 * @internal
 */
export const BUILTIN_SPAN_DETECTORS: ReadonlySet<SpanDetector> = new Set(
  [...Object.values(builtin), ...Object.values(precise)].filter(isDetector),
);
