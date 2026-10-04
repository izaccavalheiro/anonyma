/**
 * @module engine/detector
 * @description Factories for span detectors: a validating constructor, a
 * declarative regular-expression detector, and an adapter for the 1.x
 * `(text) => PiiMatch[]` detector functions.
 */

import { ValidationError } from "../errors.js";
import type { Detector } from "../types.js";
import type { Category, EmitSpan, SpanDetector } from "./types.js";

/**
 * Validate a detector definition and return a frozen copy of it.
 *
 * @param detector - The detector definition.
 * @returns The frozen detector.
 * @throws {@link ValidationError} When `id` or `category` is empty or `scan` is not a function.
 *
 * @example
 * ```ts
 * import { defineDetector } from "anonyma/engine";
 *
 * export const badgeDetector = defineDetector({
 *   id: "acme/badge",
 *   category: "badge",
 *   prefilter: (text) => text.includes("BDG-"),
 *   scan(text, emit) {
 *     for (let at = text.indexOf("BDG-"); at >= 0; at = text.indexOf("BDG-", at + 1)) {
 *       emit(at, at + 10, 0.9);
 *     }
 *   },
 * });
 * ```
 */
export function defineDetector(detector: SpanDetector): SpanDetector {
  if (typeof detector.id !== "string" || detector.id.length === 0) {
    throw new ValidationError("detector.id", "must be a non-empty string");
  }
  if (typeof detector.category !== "string" || detector.category.length === 0) {
    throw new ValidationError("detector.category", "must be a non-empty string");
  }
  if (typeof detector.scan !== "function") {
    throw new ValidationError("detector.scan", "must be a function");
  }
  if (
    detector.maxMatchLength !== undefined &&
    (!Number.isInteger(detector.maxMatchLength) || detector.maxMatchLength < 1)
  ) {
    throw new ValidationError("detector.maxMatchLength", "must be a positive integer");
  }
  return Object.freeze({ ...detector });
}

/**
 * Options accepted by {@link defineRegexDetector}.
 */
export interface RegexDetectorOptions {
  /** Detector identifier. Defaults to the category. */
  readonly id?: string;
  /** Category attached to every hit. */
  readonly category: Category;
  /**
   * The pattern to search for. It is compiled once; the `g` flag is added when
   * missing and the `y` flag is removed.
   */
  readonly pattern: RegExp;
  /** Confidence of a hit, fixed or computed from the match. Defaults to `0.85`. */
  readonly confidence?: number | ((match: RegExpExecArray) => number);
  /** Capture group whose text is the hit. Defaults to `0`, the whole match. */
  readonly group?: number;
  /** Extra check on a match, such as a checksum. Return `false` to discard it. */
  readonly validate?: (value: string, match: RegExpExecArray) => boolean;
  /** The detector is skipped for texts that contain none of these substrings. */
  readonly requires?: readonly string[];
  /** See {@link SpanDetector.maxMatchLength}. */
  readonly maxMatchLength?: number;
}

/**
 * Build a detector from a regular expression. The expression is compiled once
 * and reused across calls.
 *
 * @param options - The pattern and how to interpret its matches.
 * @returns A frozen {@link SpanDetector}.
 * @throws {@link ValidationError} When `pattern` is not a `RegExp`, `group` is negative or
 *   `confidence` is not a number between 0 and 1.
 *
 * @example
 * ```ts
 * import { defineRegexDetector } from "anonyma/engine";
 *
 * export const orderIdDetector = defineRegexDetector({
 *   category: "order-id",
 *   pattern: /\bACME-(\d{6})\b/,
 *   confidence: 0.9,
 *   requires: ["ACME-"],
 *   maxMatchLength: 11,
 * });
 * ```
 */
export function defineRegexDetector(options: RegexDetectorOptions): SpanDetector {
  const { category, pattern, confidence = 0.85, group = 0, validate, requires } = options;

  if (!(pattern instanceof RegExp)) {
    throw new ValidationError("pattern", "must be a RegExp instance");
  }
  if (!Number.isInteger(group) || group < 0) {
    throw new ValidationError("group", "must be a non-negative integer");
  }
  if (
    typeof confidence !== "function" &&
    !(typeof confidence === "number" && confidence >= 0 && confidence <= 1)
  ) {
    throw new ValidationError("confidence", "must be a number between 0 and 1, or a function");
  }

  let flags = pattern.flags.replace("y", "");
  if (!flags.includes("g")) flags += "g";
  if (group > 0 && !flags.includes("d")) flags += "d";
  const compiled = new RegExp(pattern.source, flags);

  const scan = (text: string, emit: EmitSpan): void => {
    compiled.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = compiled.exec(text)) !== null) {
      if (match[0].length === 0) {
        // A pattern that can match the empty string would never advance.
        compiled.lastIndex++;
        continue;
      }
      let start = match.index;
      let end = start + match[0].length;
      if (group > 0) {
        const bounds = match.indices?.[group];
        if (bounds === undefined || bounds[1] === bounds[0]) continue;
        [start, end] = bounds;
      }
      if (validate !== undefined && !validate(text.slice(start, end), match)) continue;
      emit(start, end, typeof confidence === "function" ? confidence(match) : confidence);
    }
  };

  return defineDetector({
    id: options.id ?? category,
    category,
    scan,
    ...(requires !== undefined && requires.length > 0
      ? { prefilter: (text: string): boolean => requires.some((needle) => text.includes(needle)) }
      : {}),
    ...(options.maxMatchLength !== undefined ? { maxMatchLength: options.maxMatchLength } : {}),
  });
}

/**
 * Options accepted by {@link fromLegacyDetector}.
 */
export interface LegacyDetectorOptions {
  /** Detector identifier. Defaults to the category. */
  readonly id?: string;
  /** See {@link SpanDetector.prefilter}. */
  readonly prefilter?: (text: string) => boolean;
  /** See {@link SpanDetector.maxMatchLength}. */
  readonly maxMatchLength?: number;
}

/**
 * Adapt a 1.x detector function — `(text) => PiiMatch[]` — to the span engine.
 * The adapted detector reports exactly the matches the function returns.
 *
 * @param category - Category attached to every hit.
 * @param detect - The 1.x detector function.
 * @param options - Optional identifier, prefilter and length bound.
 * @returns A frozen {@link SpanDetector}.
 *
 * @example
 * ```ts
 * import { fromLegacyDetector } from "anonyma/engine";
 * import { detectPhone } from "anonyma/detectors";
 *
 * export const phoneDetector = fromLegacyDetector("phone", detectPhone);
 * ```
 */
export function fromLegacyDetector(
  category: Category,
  detect: Detector,
  options: LegacyDetectorOptions = {},
): SpanDetector {
  if (typeof detect !== "function") {
    throw new ValidationError("detect", "must be a function");
  }
  return defineDetector({
    id: options.id ?? category,
    category,
    scan(text, emit) {
      for (const match of detect(text)) emit(match.start, match.end, match.confidence);
    },
    ...(options.prefilter !== undefined ? { prefilter: options.prefilter } : {}),
    ...(options.maxMatchLength !== undefined ? { maxMatchLength: options.maxMatchLength } : {}),
  });
}
