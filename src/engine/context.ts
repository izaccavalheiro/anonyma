/**
 * @module engine/context
 * @description Context proximity: a detector's hits gain confidence when a
 * keyword such as "CPF", "SSN" or "password" stands a few words before them,
 * and can be required to have one.
 */

import { ValidationError } from "../errors.js";
import { defineDetector } from "./detector.js";
import type { ContextOptions, EmitSpan, SpanDetector } from "./types.js";

/** Characters a word may count for when the look-back window is sized. */
const MAX_WORD = 40;

/** A letter, digit or underscore: a character inside a word. */
const WORD_CHAR = /[\p{L}\p{N}_]/u;

const DEFAULTS = { window: 3, boost: 0.15 } as const;

function escape(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");
}

/**
 * Explain what is wrong with context options, or return `undefined` when they
 * are valid. Shared by {@link withContext}, `compilePipeline()` and the policy
 * parser, so that each reports the same problems.
 *
 * @internal
 */
export function contextProblem(options: unknown): { member: string; message: string } | undefined {
  if (typeof options !== "object" || options === null) {
    return { member: "", message: "must be an object" };
  }
  const { keywords, window, boost, required } = options as Record<string, unknown>;
  if (
    !Array.isArray(keywords) ||
    keywords.length === 0 ||
    !keywords.every((keyword) => typeof keyword === "string" && keyword.trim() !== "")
  ) {
    return { member: "keywords", message: "must be a non-empty array of non-empty strings" };
  }
  if (window !== undefined && !(Number.isInteger(window) && Number(window) >= 1)) {
    return { member: "window", message: "must be a positive integer" };
  }
  if (boost !== undefined && !(typeof boost === "number" && boost >= 0 && boost <= 1)) {
    return { member: "boost", message: "must be a number between 0 and 1" };
  }
  if (required !== undefined && typeof required !== "boolean") {
    return { member: "required", message: "must be a boolean" };
  }
  return undefined;
}

/**
 * Wrap a detector so that the words before each hit count. A hit preceded,
 * within `window` words, by one of `keywords` gains `boost` confidence (up to
 * 1); with `required`, a hit without one is dropped.
 *
 * Keywords match whole words, ignoring case; a keyword may span several words
 * (`"social security"`). The window counts every word, other values
 * included: in `SSN 078-05-1120 and 219-09-9999` both numbers are within three
 * words of `SSN`. The wrapped detector keeps the `id`, category and
 * prefilter of the original, and its `maxMatchLength` grows by the look-back,
 * so a chunked stream still sees a keyword that arrived in an earlier chunk.
 *
 * Use it to raise weak detectors above a pipeline's `minConfidence` only where
 * the text says what the value is.
 *
 * @param detector - The detector to wrap.
 * @param options - Keywords, window, boost and whether a keyword is required.
 * @returns A frozen {@link SpanDetector}.
 * @throws {@link ValidationError} When the options are invalid.
 *
 * @example
 * ```ts
 * import { createPipeline, defineRegexDetector, redactWith, withContext } from "anonyma/engine";
 *
 * const employeeId = withContext(
 *   defineRegexDetector({ category: "employee-id", pattern: /\b\d{6}\b/, confidence: 0.5 }),
 *   { keywords: ["employee", "badge"], boost: 0.4 },
 * );
 * const pipeline = createPipeline({
 *   detectors: [employeeId],
 *   replace: { fallback: redactWith() },
 *   minConfidence: 0.8,
 * });
 * pipeline.transform("Badge number 123456; order 654321").text;
 * // "Badge number [REDACTED]; order 654321"
 * ```
 */
export function withContext(detector: SpanDetector, options: ContextOptions): SpanDetector {
  const problem = contextProblem(options);
  if (problem !== undefined) {
    throw new ValidationError(
      problem.member === "" ? "context" : `context.${problem.member}`,
      problem.message,
    );
  }
  const { keywords, window = DEFAULTS.window, boost = DEFAULTS.boost, required = false } = options;
  const keyword = new RegExp(
    `(?<![\\p{L}\\p{N}_])(?:${keywords
      .map((word) => escape(word.trim()).replace(/\s+/g, "\\s+"))
      .join("|")})(?![\\p{L}\\p{N}_])`,
    "iu",
  );
  const reach = window * (MAX_WORD + 1);
  const lowered = keywords.map(
    // split() always returns at least one element.
    /* v8 ignore next */
    (word) => word.trim().toLowerCase().split(/\s+/)[0] ?? "",
  );

  /** Where the look-back window before `start` begins: `window` words back, at most `reach` characters. */
  function windowStart(text: string, start: number): number {
    const limit = Math.max(0, start - reach);
    let at = start;
    for (let words = 0; words < window && at > limit; words++) {
      // Skip the separators, then the word.
      while (at > limit && !WORD_CHAR.test(text.charAt(at - 1))) at--;
      while (at > limit && WORD_CHAR.test(text.charAt(at - 1))) at--;
    }
    return at;
  }

  function scan(text: string, emit: EmitSpan): void {
    detector.scan(text, (start, end, confidence) => {
      const found = keyword.test(text.slice(windowStart(text, start), start));
      if (found) emit(start, end, Math.min(1, confidence + boost));
      else if (!required) emit(start, end, confidence);
    });
  }

  const original = detector.prefilter;
  const prefilter = required
    ? (text: string): boolean => {
        const lower = text.toLowerCase();
        return (
          lowered.some((word) => lower.includes(word)) && (original === undefined || original(text))
        );
      }
    : original;

  return defineDetector({
    id: detector.id,
    category: detector.category,
    scan,
    ...(prefilter !== undefined ? { prefilter } : {}),
    ...(detector.maxMatchLength !== undefined
      ? { maxMatchLength: detector.maxMatchLength + reach }
      : {}),
  });
}
