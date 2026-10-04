/**
 * @module engine/types
 * @description Contracts of the span-based anonymization engine exposed as
 * `"anonyma/engine"`. This module contains types only — it has no runtime code.
 *
 * The engine works on **spans** (offsets into the scanned text) rather than on
 * copied substrings: detectors report hits through a callback, overlap
 * resolution runs on offsets, and the output is assembled in a single
 * left-to-right pass.
 */

import type { CompliancePreset, EncryptOptions, PiiCategory, StrategyOptions } from "../types.js";
import type { TokenizationProvider } from "../vault/types.js";

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * A PII category label. Built-in categories autocomplete; any other string is
 * accepted so that custom detectors can introduce their own categories.
 */
export type Category = PiiCategory | (string & {});

/**
 * Callback through which a detector reports one hit.
 *
 * @param start - Zero-based UTF-16 offset of the first character of the hit.
 * @param end - Exclusive end offset. Must be greater than `start`.
 * @param confidence - Score in the range [0, 1].
 */
export type EmitSpan = (start: number, end: number, confidence: number) => void;

/**
 * A detector for the span engine.
 *
 * Detectors are plain objects so that each one can be imported on its own and
 * unused ones are dropped by bundlers. A detector must be pure: the same text
 * always produces the same hits, and it must not keep a reference to the text.
 *
 * @example
 * ```ts
 * import { defineRegexDetector } from "anonyma/engine";
 *
 * export const orderIdDetector = defineRegexDetector({
 *   category: "order-id",
 *   pattern: /\bACME-\d{6}\b/g,
 *   confidence: 0.9,
 *   requires: ["ACME-"],
 * });
 * ```
 */
export interface SpanDetector {
  /** Stable identifier, unique within a pipeline (e.g. `"email"`, `"acme/order-id"`). */
  readonly id: string;
  /** Category attached to every span this detector reports. */
  readonly category: Category;
  /**
   * Scan `text` and report every hit through `emit`. Hits may be reported in
   * any order and may overlap; the pipeline resolves overlaps.
   */
  readonly scan: (text: string, emit: EmitSpan) => void;
  /**
   * Optional cheap gate. When present and it returns `false`, `scan` is not
   * called for that text. It must never return `false` for a text in which
   * `scan` would report a hit.
   */
  readonly prefilter?: (text: string) => boolean;
  /**
   * Upper bound, in UTF-16 units, on the length of a hit including any
   * look-around the detector needs. The chunked scanner uses it to size its
   * hold-back window. Detectors without a bound fall back to the window
   * configured on the stream.
   */
  readonly maxMatchLength?: number;
}

/**
 * A resolved detection. It carries offsets only — never the matched text — so
 * a list of spans is safe to log.
 */
export interface DetectedSpan {
  /** Zero-based UTF-16 start offset in the scanned text. */
  readonly start: number;
  /** Exclusive end offset in the scanned text. */
  readonly end: number;
  /** Category of the detector that produced the span. */
  readonly category: Category;
  /** Confidence score in [0, 1]. */
  readonly confidence: number;
  /** `id` of the detector that produced the span. */
  readonly detector: string;
  /**
   * `true` when this span is the part of a lower-priority detection that was
   * left uncovered after a higher-priority overlapping detection was accepted.
   */
  readonly residual: boolean;
}

/**
 * How overlapping detections are resolved.
 *
 * - `"cover"` (default): detections are accepted by priority (higher
 *   confidence, then longer, then earlier, then detector order). The parts of
 *   a losing detection that no accepted detection covers are kept as
 *   `residual` spans, so no detected character is ever left in the output.
 * - `"legacy"`: the 1.x rule — earliest start wins, ties go to the higher
 *   confidence, and losing detections are dropped entirely.
 */
export type OverlapPolicy = "cover" | "legacy";

/**
 * A rule that exempts a detected value from replacement.
 *
 * - `string`: the whole value must equal the string (case-insensitive unless
 *   `allowCaseSensitive` is set).
 * - `RegExp`: tested against the value. The `g` and `y` flags are ignored.
 * - function: called with the value and its span.
 */
export type AllowRule = string | RegExp | ((value: string, span: DetectedSpan) => boolean);

// ---------------------------------------------------------------------------
// Replacement
// ---------------------------------------------------------------------------

/**
 * Information passed to a {@link Replacer} about the span being replaced.
 */
export interface ReplaceContext {
  /** Category of the span. */
  readonly category: Category;
  /** `id` of the detector that produced the span. */
  readonly detector: string;
  /** Confidence score in [0, 1]. */
  readonly confidence: number;
  /** Start offset of the span in the input text. */
  readonly start: number;
  /** Exclusive end offset of the span in the input text. */
  readonly end: number;
  /** Zero-based position of the span among the replaced spans, in document order. */
  readonly ordinal: number;
  /** See {@link DetectedSpan.residual}. */
  readonly residual: boolean;
}

/**
 * Produces the replacement for one detected value. Replacers are always
 * invoked in document order. A replacer that returns a promise can only be
 * used with the asynchronous entry points.
 */
export type Replacer = (value: string, context: ReplaceContext) => string | Promise<string>;

/**
 * Which replacer handles which category.
 */
export interface ReplacementPlan {
  /** Replacer for every category that has no entry in `byCategory`. */
  readonly fallback: Replacer;
  /** Per-category replacers, keyed by category label. */
  readonly byCategory?: Readonly<Record<string, Replacer>>;
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/**
 * Configuration accepted by `createPipeline()`.
 */
export interface PipelineOptions {
  /** Detectors to run, in priority order for otherwise equal detections. */
  readonly detectors: readonly SpanDetector[];
  /** Replacement plan. */
  readonly replace: ReplacementPlan;
  /** Detections below this confidence are discarded before overlap resolution. Defaults to `0`. */
  readonly minConfidence?: number;
  /** Values that must be left untouched. */
  readonly allow?: readonly AllowRule[];
  /** When `true`, string allow rules are compared case-sensitively. Defaults to `false`. */
  readonly allowCaseSensitive?: boolean;
  /** Overlap resolution policy. Defaults to `"cover"`. */
  readonly overlap?: OverlapPolicy;
}

/**
 * A span that was replaced, with its position in the output.
 */
export interface AppliedSpan extends DetectedSpan {
  /** Start offset of the replacement in the output text. */
  readonly outStart: number;
  /** Exclusive end offset of the replacement in the output text. */
  readonly outEnd: number;
}

/**
 * Result of a pipeline transform.
 */
export interface TransformResult {
  /** The transformed text. */
  readonly text: string;
  /** Every replaced span in document order. Contains no matched text. */
  readonly spans: readonly AppliedSpan[];
}

/**
 * A compiled, reusable detection-and-replacement pipeline. Instances are
 * immutable and safe to share between calls.
 */
export interface Pipeline {
  /** The detectors this pipeline runs. */
  readonly detectors: readonly SpanDetector[];
  /**
   * Detect, filter and resolve. Returns the spans that a transform would
   * replace, in document order.
   */
  readonly scan: (text: string) => DetectedSpan[];
  /** `true` when at least one span would be replaced. */
  readonly test: (text: string) => boolean;
  /**
   * Run the replacer configured for `context.category` on one value. This is
   * the building block for callers that assemble output themselves, such as
   * the chunked transformer and the JSON sanitizers.
   */
  readonly replace: (value: string, context: ReplaceContext) => string | Promise<string>;
  /**
   * Transform synchronously.
   *
   * @throws AsyncStrategyError When a replacer returns a promise.
   */
  readonly transform: (text: string) => TransformResult;
  /** Transform, awaiting replacers one at a time in document order. */
  readonly transformAsync: (text: string) => Promise<TransformResult>;
}

// ---------------------------------------------------------------------------
// Chunked (streaming) transformation
// ---------------------------------------------------------------------------

/**
 * Options for the chunk-boundary-safe transformer and stream.
 */
export interface ChunkOptions {
  /**
   * Hold-back window in UTF-16 units: the amount of trailing text kept
   * unemitted until more input arrives, so that PII split across chunk
   * boundaries is still detected. Defaults to the largest `maxMatchLength`
   * among the pipeline's detectors, and to `256` for detectors without one.
   */
  readonly window?: number;
  /**
   * How many characters of new input to accumulate before scanning again.
   * Larger values raise throughput when input arrives in small chunks; smaller
   * values shorten the delay before output appears. Defaults to `4096`. Use
   * `0` to scan on every push, as an interactive stream needs.
   */
  readonly batch?: number;
  /**
   * Longest unbroken run of printable ASCII characters that is held back
   * whole. A key or a token that arrives in pieces cannot be recognised from
   * its beginning, so no part of such a run is emitted before it ends.
   * Defaults to `8192`; `0` turns the rule off.
   */
  readonly tokenLimit?: number;
}

/**
 * Push-style transformer that accepts text in arbitrary chunks and returns
 * transformed text as soon as it is settled.
 */
export interface ChunkTransformer {
  /** Feed the next chunk; returns the output that is now final (possibly empty). */
  readonly push: (chunk: string) => string;
  /** Signal end of input; returns the remaining output. */
  readonly flush: () => string;
}

/**
 * Asynchronous counterpart of {@link ChunkTransformer} for pipelines with
 * asynchronous replacers.
 */
export interface AsyncChunkTransformer {
  /** Feed the next chunk; resolves to the output that is now final (possibly empty). */
  readonly push: (chunk: string) => Promise<string>;
  /** Signal end of input; resolves to the remaining output. */
  readonly flush: () => Promise<string>;
}

// ---------------------------------------------------------------------------
// Declarative pipeline specification
// ---------------------------------------------------------------------------

/**
 * A strategy in JSON-serialisable form. Secrets are never part of a spec: the
 * `tokenize` and `encrypt` strategies take their provider or key from
 * {@link CompileDependencies}.
 */
export type StrategySpec =
  | Exclude<StrategyOptions, { strategy: "tokenize" } | { strategy: "encrypt" }>
  | { readonly strategy: "tokenize" }
  | { readonly strategy: "encrypt" };

/**
 * A custom regular-expression pattern in JSON-serialisable form.
 */
export interface PatternSpec {
  /** Regular-expression source. */
  readonly source: string;
  /** Regular-expression flags. The `g` flag is implied. */
  readonly flags?: string;
  /** Category label for matches. */
  readonly category: string;
  /** Confidence score in [0, 1]. Defaults to `0.85`. */
  readonly confidence?: number;
}

/**
 * A complete pipeline described as plain data. Because it contains no
 * functions it can be stored in a configuration file, sent to a worker thread
 * or passed as a tool argument, and compiled with `compilePipeline()`.
 */
export interface PipelineSpec {
  /**
   * A built-in compliance preset to start from. Its categories and strategies
   * apply unless `categories`, `defaultStrategy` or `rules` override them.
   */
  readonly preset?: CompliancePreset;
  /**
   * Built-in categories to detect. Defaults to the categories of `preset`, or
   * to all built-in categories when no preset is given.
   */
  readonly categories?: readonly PiiCategory[];
  /** Use the aggressive variant of the built-in detectors. Defaults to `false`. */
  readonly aggressive?: boolean;
  /**
   * Which built-in detectors to use.
   *
   * - `"precise"` (default): the validating detectors for email, SSN, IBAN,
   *   IPv4, IPv6 and payment cards, and the 1.x detectors for the other
   *   categories.
   * - `"legacy"`: the 1.x detectors for every category.
   */
  readonly detection?: "precise" | "legacy";
  /** Additional regular-expression detectors. */
  readonly patterns?: readonly PatternSpec[];
  /**
   * Strategy for categories without a rule. Defaults to the default strategy
   * of `preset`, or to `{ strategy: "redact" }` when no preset is given.
   */
  readonly defaultStrategy?: StrategySpec;
  /** Per-category strategies, keyed by category label. They take precedence over those of `preset`. */
  readonly rules?: Readonly<Record<string, StrategySpec>>;
  /** See {@link PipelineOptions.minConfidence}. */
  readonly minConfidence?: number;
  /** Exact values to leave untouched. */
  readonly allow?: readonly string[];
  /** See {@link PipelineOptions.allowCaseSensitive}. */
  readonly allowCaseSensitive?: boolean;
  /** See {@link PipelineOptions.overlap}. */
  readonly overlap?: OverlapPolicy;
}

/**
 * Runtime collaborators a {@link PipelineSpec} may need but cannot carry.
 */
export interface CompileDependencies {
  /** Provider backing the `tokenize` strategy. */
  readonly tokenization?: TokenizationProvider;
  /** Key material backing the `encrypt` strategy. */
  readonly encryption?: EncryptOptions;
  /**
   * Secrets for strategies whose spec leaves them out, so that they never
   * have to be written into a configuration file.
   */
  readonly secrets?: {
    /** Pepper for `hash` strategies without one. */
    readonly hashPepper?: string;
    /** Seed for `pseudonymize` strategies without one. */
    readonly pseudonymizeSeed?: string;
    /** Seed for `synthesize` strategies without one. */
    readonly synthesizeSeed?: string;
  };
}
