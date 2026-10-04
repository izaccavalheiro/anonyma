/**
 * @module engine/pipeline
 * @description The pipeline orchestrator: runs detectors, filters and
 * resolves their hits on offsets, and assembles the output in one
 * left-to-right pass.
 */

import { AsyncStrategyError, ValidationError } from "../errors.js";
import { resolveSpans } from "./resolve.js";
import type { Candidate, Resolved } from "./resolve.js";
import type {
  AllowRule,
  AppliedSpan,
  DetectedSpan,
  Pipeline,
  PipelineOptions,
  ReplaceContext,
  Replacer,
  SpanDetector,
  TransformResult,
} from "./types.js";

const NO_SPANS: readonly AppliedSpan[] = Object.freeze([]);

const OVERLAP_POLICIES: ReadonlySet<string> = new Set(["cover", "legacy"]);

/** Signals `collect()` to stop after the first qualifying hit. */
const STOP = Symbol("stop");

type AllowTest = (
  value: string,
  start: number,
  end: number,
  owner: SpanDetector,
  confidence: number,
) => boolean;

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

/**
 * Compile allow rules into a single predicate. Returns `undefined` when there
 * are no rules, so callers can skip the check entirely.
 */
function compileAllow(rules: readonly AllowRule[], caseSensitive: boolean): AllowTest | undefined {
  if (rules.length === 0) return undefined;

  const exact = new Set<string>();
  const patterns: RegExp[] = [];
  const predicates: ((value: string, span: DetectedSpan) => boolean)[] = [];

  for (const rule of rules) {
    if (typeof rule === "string") {
      exact.add(caseSensitive ? rule : rule.toLowerCase());
    } else if (rule instanceof RegExp) {
      // Drop `g` and `y`: a stateful `lastIndex` would make `test()` alternate.
      patterns.push(new RegExp(rule.source, rule.flags.replace(/[gy]/g, "")));
    } else if (typeof rule === "function") {
      predicates.push(rule);
    } else {
      throw new ValidationError("allow", "entries must be strings, RegExp instances or functions");
    }
  }

  return (value, start, end, owner, confidence) => {
    if (exact.has(caseSensitive ? value : value.toLowerCase())) return true;
    for (const pattern of patterns) if (pattern.test(value)) return true;
    if (predicates.length === 0) return false;
    const span: DetectedSpan = {
      start,
      end,
      category: owner.category,
      confidence,
      detector: owner.id,
      residual: false,
    };
    return predicates.some((predicate) => predicate(value, span));
  };
}

/**
 * Create a reusable detection-and-replacement pipeline.
 *
 * @param options - Detectors, replacement plan and filters.
 * @returns An immutable {@link Pipeline}.
 * @throws {@link ValidationError} When the configuration is invalid.
 *
 * @example
 * ```ts
 * import { createPipeline, emailDetector, creditCardDetector, redactWith, maskWith } from "anonyma/engine";
 *
 * const pipeline = createPipeline({
 *   detectors: [emailDetector, creditCardDetector],
 *   replace: {
 *     fallback: redactWith(),
 *     byCategory: { "credit-card": maskWith({ keepTrailing: 4 }) },
 *   },
 * });
 *
 * pipeline.transform("Mail alice@example.com, card 4111 1111 1111 1111").text;
 * // "Mail [REDACTED], card ***************1111"
 * ```
 */
export function createPipeline(options: PipelineOptions): Pipeline {
  const detectors = Object.freeze([...options.detectors]);
  const { minConfidence = 0, overlap = "cover", allowCaseSensitive = false } = options;

  const seen = new Set<string>();
  for (const detector of detectors) {
    if (seen.has(detector.id)) {
      throw new ValidationError("detectors", `contains the id "${detector.id}" more than once`);
    }
    seen.add(detector.id);
  }
  if (typeof minConfidence !== "number" || !(minConfidence >= 0 && minConfidence <= 1)) {
    throw new ValidationError("minConfidence", "must be a number between 0 and 1");
  }
  if (!OVERLAP_POLICIES.has(overlap)) {
    throw new ValidationError("overlap", 'must be "cover" or "legacy"');
  }
  if (typeof options.replace.fallback !== "function") {
    throw new ValidationError("replace.fallback", "must be a function");
  }

  const fallback = options.replace.fallback;
  const byCategory = new Map<string, Replacer>();
  for (const [category, replacer] of Object.entries(options.replace.byCategory ?? {})) {
    if (typeof replacer !== "function") {
      throw new ValidationError(`replace.byCategory.${category}`, "must be a function");
    }
    byCategory.set(category, replacer);
  }

  const allow = compileAllow(options.allow ?? [], allowCaseSensitive);

  function owner(index: number): SpanDetector {
    const detector = detectors[index];
    /* v8 ignore next 3 -- indices only ever come from this pipeline's own detector list */
    if (detector === undefined) {
      throw new ValidationError("detector", "index out of range");
    }
    return detector;
  }

  /**
   * Run every detector and collect the hits that pass the confidence filter.
   * With `first` set, returns `STOP` as soon as one hit that is not
   * allow-listed has been seen.
   */
  function collect(text: string, first: boolean): Candidate[] | typeof STOP {
    if (typeof text !== "string") {
      throw new ValidationError("text", "must be a string");
    }
    const candidates: Candidate[] = [];
    const state = { index: 0, found: false };

    const emit = (start: number, end: number, confidence: number): void => {
      if (
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < 0 ||
        end <= start ||
        end > text.length ||
        !(confidence >= 0 && confidence <= 1)
      ) {
        throw new ValidationError(
          "detector",
          `"${owner(state.index).id}" reported an invalid span`,
        );
      }
      if (confidence < minConfidence) return;
      const allowed =
        allow?.(text.slice(start, end), start, end, owner(state.index), confidence) === true;
      if (!allowed) state.found = true;
      candidates.push({ start, end, confidence, detector: state.index, allowed });
    };

    for (const [index, detector] of detectors.entries()) {
      if (detector.prefilter?.(text) === false) continue;
      state.index = index;
      detector.scan(text, emit);
      if (first && state.found) return STOP;
    }
    return candidates;
  }

  function describe(resolved: Resolved): DetectedSpan {
    const detector = owner(resolved.detector);
    return {
      start: resolved.start,
      end: resolved.end,
      category: detector.category,
      confidence: resolved.confidence,
      detector: detector.id,
      residual: resolved.residual,
    };
  }

  function scan(text: string): DetectedSpan[] {
    const candidates = collect(text, false);
    /* v8 ignore next -- collect() only stops early when asked to */
    if (candidates === STOP) return [];
    return resolveSpans(text, candidates, overlap).map(describe);
  }

  function test(text: string): boolean {
    // Without allow rules any hit survives resolution in some form. With allow
    // rules an allow-listed hit can shadow others, so resolve to be exact.
    if (allow === undefined) return collect(text, true) === STOP;
    return scan(text).length > 0;
  }

  function context(span: DetectedSpan, ordinal: number): ReplaceContext {
    return {
      category: span.category,
      detector: span.detector,
      confidence: span.confidence,
      start: span.start,
      end: span.end,
      ordinal,
      residual: span.residual,
    };
  }

  function replace(value: string, replaceContext: ReplaceContext): string | Promise<string> {
    return (byCategory.get(replaceContext.category) ?? fallback)(value, replaceContext);
  }

  function checked(replacement: unknown, category: string): string {
    if (typeof replacement !== "string") {
      throw new ValidationError(
        "replace",
        `the replacer for category "${category}" must return a string`,
      );
    }
    return replacement;
  }

  function transform(text: string): TransformResult {
    const spans = scan(text);
    if (spans.length === 0) return { text, spans: NO_SPANS };

    const parts: string[] = [];
    const applied: AppliedSpan[] = [];
    let cursor = 0;
    let outLength = 0;

    for (const [i, span] of spans.entries()) {
      const replacement = replace(text.slice(span.start, span.end), context(span, i));
      if (isThenable(replacement)) {
        // Do not leave a rejection unhandled when the caller picked the wrong entry point.
        void Promise.resolve(replacement).catch(() => undefined);
        throw new AsyncStrategyError(span.category);
      }
      const value = checked(replacement, span.category);
      parts.push(text.slice(cursor, span.start), value);
      outLength += span.start - cursor;
      applied.push({ ...span, outStart: outLength, outEnd: outLength + value.length });
      outLength += value.length;
      cursor = span.end;
    }
    parts.push(text.slice(cursor));
    return { text: parts.join(""), spans: applied };
  }

  async function transformAsync(text: string): Promise<TransformResult> {
    const spans = scan(text);
    if (spans.length === 0) return { text, spans: NO_SPANS };

    const parts: string[] = [];
    const applied: AppliedSpan[] = [];
    let cursor = 0;
    let outLength = 0;

    for (const [i, span] of spans.entries()) {
      const value = checked(
        await replace(text.slice(span.start, span.end), context(span, i)),
        span.category,
      );
      parts.push(text.slice(cursor, span.start), value);
      outLength += span.start - cursor;
      applied.push({ ...span, outStart: outLength, outEnd: outLength + value.length });
      outLength += value.length;
      cursor = span.end;
    }
    parts.push(text.slice(cursor));
    return { text: parts.join(""), spans: applied };
  }

  return Object.freeze({ detectors, scan, test, replace, transform, transformAsync });
}

/**
 * Return the text a span refers to.
 *
 * @param text - The text the span was detected in.
 * @param span - The span.
 * @returns The matched text.
 *
 * @example
 * ```ts
 * const [span] = pipeline.scan("Mail alice@example.com");
 * spanText("Mail alice@example.com", span); // "alice@example.com"
 * ```
 */
export function spanText(text: string, span: Pick<DetectedSpan, "start" | "end">): string {
  return text.slice(span.start, span.end);
}
