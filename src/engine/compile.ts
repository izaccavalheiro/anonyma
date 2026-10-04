/**
 * @module engine/compile
 * @description Compiles a declarative {@link PipelineSpec} into a pipeline.
 */

import { UnknownCategoryError, ValidationError } from "../errors.js";
import { getPreset } from "../presets.js";
import type { PiiCategory } from "../types.js";
import { BUILTIN_CATEGORIES, LEGACY_AGGRESSIVE_DETECTORS, LEGACY_DETECTORS } from "./builtin.js";
import { defineRegexDetector } from "./detector.js";
import { createPipeline } from "./pipeline.js";
import {
  bareSsnDetector,
  creditCardDetector,
  emailDetector,
  ibanDetector,
  ipv4Detector,
  ipv6Detector,
  maskedCardDetector,
  obfuscatedEmailDetector,
  ssnDetector,
} from "./precise.js";
import { FAIL_CLOSED_LABEL, strategyReplacer } from "./replacers.js";
import type {
  CompileDependencies,
  Pipeline,
  PipelineSpec,
  Replacer,
  SpanDetector,
  StrategySpec,
} from "./types.js";

/** The validating detectors, and the extra detectors each gains in aggressive mode. */
const PRECISE: Readonly<Partial<Record<PiiCategory, readonly [SpanDetector, ...SpanDetector[]]>>> =
  {
    email: [emailDetector, obfuscatedEmailDetector],
    ssn: [ssnDetector, bareSsnDetector],
    iban: [ibanDetector],
    ipv4: [ipv4Detector],
    ipv6: [ipv6Detector],
    "credit-card": [creditCardDetector, maskedCardDetector],
  };

const DEFAULT_STRATEGY: StrategySpec = { strategy: "redact" };

function isBuiltinCategory(category: string): category is PiiCategory {
  return (BUILTIN_CATEGORIES as readonly string[]).includes(category);
}

/**
 * Return the built-in span detectors for a set of categories.
 *
 * @param categories - The categories to detect. Defaults to every built-in category.
 * @param options - `detection` selects the validating or the 1.x detectors,
 *   `aggressive` adds the permissive variants.
 * @returns The detectors, in scan order.
 * @throws {@link UnknownCategoryError} When a category is not built in.
 *
 * @example
 * ```ts
 * import { builtinDetectors, createPipeline, redactWith } from "anonyma/engine";
 *
 * const pipeline = createPipeline({
 *   detectors: builtinDetectors(["email", "phone"]),
 *   replace: { fallback: redactWith() },
 * });
 * ```
 */
export function builtinDetectors(
  categories: readonly PiiCategory[] = BUILTIN_CATEGORIES,
  options: { readonly detection?: "precise" | "legacy"; readonly aggressive?: boolean } = {},
): SpanDetector[] {
  const { detection = "precise", aggressive = false } = options;
  const out: SpanDetector[] = [];
  const seen = new Set<string>();

  for (const category of categories) {
    if (!isBuiltinCategory(category)) throw new UnknownCategoryError(category);
    if (seen.has(category)) continue;
    seen.add(category);

    const precise = detection === "precise" ? PRECISE[category] : undefined;
    if (precise !== undefined) {
      out.push(...(aggressive ? precise : [precise[0]]));
    } else {
      out.push((aggressive ? LEGACY_AGGRESSIVE_DETECTORS : LEGACY_DETECTORS)[category]);
    }
  }
  return out;
}

/**
 * Compile a declarative pipeline specification.
 *
 * Every strategy is instantiated while compiling, so an invalid option or a
 * missing dependency is reported here rather than on the first match.
 *
 * @param spec - The specification. An empty object detects every built-in
 *   category and redacts it.
 * @param dependencies - Tokenization provider, encryption key and secrets for
 *   the strategies that need them.
 * @returns The compiled {@link Pipeline}.
 * @throws {@link UnknownCategoryError} When a listed category is not built in.
 * @throws {@link ValidationError} When a strategy, pattern or option is invalid.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 *
 * const pipeline = compilePipeline({
 *   preset: "pci-dss",
 *   rules: { email: { strategy: "mask", keepLeading: 1 } },
 *   minConfidence: 0.8,
 * });
 * pipeline.transform("Card 4111 1111 1111 1111").text; // "Card ***************1111"
 * ```
 */
export function compilePipeline(
  spec: PipelineSpec = {},
  dependencies: CompileDependencies = {},
): Pipeline {
  const input: unknown = spec;
  if (typeof input !== "object" || input === null) {
    throw new ValidationError("spec", "must be an object");
  }
  const preset = spec.preset === undefined ? undefined : getPreset(spec.preset);
  const detection: unknown = spec.detection;
  if (detection !== undefined && detection !== "precise" && detection !== "legacy") {
    throw new ValidationError("detection", 'must be "precise" or "legacy"');
  }

  const detectors = builtinDetectors(spec.categories ?? preset?.categories ?? BUILTIN_CATEGORIES, {
    ...(spec.detection !== undefined ? { detection: spec.detection } : {}),
    ...(spec.aggressive !== undefined ? { aggressive: spec.aggressive } : {}),
  });

  for (const [index, pattern] of (spec.patterns ?? []).entries()) {
    if (typeof pattern.category !== "string" || pattern.category.length === 0) {
      throw new ValidationError(
        `patterns[${String(index)}].category`,
        "must be a non-empty string",
      );
    }
    const { confidence } = pattern;
    if (
      confidence !== undefined &&
      !(typeof confidence === "number" && confidence >= 0 && confidence <= 1)
    ) {
      throw new ValidationError(
        `patterns[${String(index)}].confidence`,
        "must be a number between 0 and 1",
      );
    }
    let compiled: RegExp;
    try {
      compiled = new RegExp(pattern.source, pattern.flags ?? "");
    } catch {
      throw new ValidationError(`patterns[${String(index)}]`, "is not a valid regular expression");
    }
    detectors.push(
      defineRegexDetector({
        id: `pattern/${String(index)}`,
        category: pattern.category,
        pattern: compiled,
        ...(pattern.confidence !== undefined ? { confidence: pattern.confidence } : {}),
      }),
    );
  }

  const strategies = new Map<string, StrategySpec>();
  for (const rule of preset?.rules ?? []) {
    // Preset rules never use the strategies that need a dependency.
    strategies.set(rule.category, rule.strategy as StrategySpec);
  }
  for (const [category, strategy] of Object.entries(spec.rules ?? {})) {
    const rule: unknown = strategy;
    if (typeof rule !== "object" || rule === null) {
      throw new ValidationError(`rules.${category}`, "must be a strategy object");
    }
    strategies.set(category, strategy);
  }

  const byCategory: Record<string, Replacer> = {};
  for (const [category, strategy] of strategies) {
    Object.defineProperty(byCategory, category, {
      value: strategyReplacer(strategy, dependencies),
      enumerable: true,
    });
  }

  const defaultStrategy =
    spec.defaultStrategy ??
    (preset?.defaultStrategy as StrategySpec | undefined) ??
    DEFAULT_STRATEGY;

  // A redaction label must survive a second pass unchanged. The 1.x bank-account
  // detector reads any eight-letter upper-case word, "REDACTED" included, as a
  // BIC, so the labels in use are exempt from detection. That includes the label
  // the other strategies fall back to when they cannot change a value.
  const labels = new Set<string>();
  for (const strategy of [defaultStrategy, ...strategies.values()]) {
    if (strategy.strategy === "tokenize" || strategy.strategy === "hash") continue;
    if (strategy.strategy === "encrypt") continue;
    const label =
      strategy.strategy === "redact" ? (strategy.label ?? "[REDACTED]") : FAIL_CLOSED_LABEL;
    labels.add(label);
    labels.add(label.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, ""));
  }
  labels.delete("");

  return createPipeline({
    detectors,
    replace: { fallback: strategyReplacer(defaultStrategy, dependencies), byCategory },
    ...(spec.minConfidence !== undefined ? { minConfidence: spec.minConfidence } : {}),
    allow: [...(spec.allow ?? []), ...labels],
    ...(spec.allowCaseSensitive !== undefined
      ? { allowCaseSensitive: spec.allowCaseSensitive }
      : {}),
    ...(spec.overlap !== undefined ? { overlap: spec.overlap } : {}),
  });
}
