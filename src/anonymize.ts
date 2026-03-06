/**
 * @module anonymize
 * @description Core anonymization engine — detects PII and applies strategies.
 */

import { DETECTOR_REGISTRY, AGGRESSIVE_DETECTOR_REGISTRY } from "./detectors/index.js";
import {
  createTokenStore,
  assignToken as assignTokenFn,
} from "./strategies/tokenize.js";
import { mask } from "./strategies/mask.js";
import { redact } from "./strategies/redact.js";
import { pseudonymize } from "./strategies/pseudonymize.js";
import { generalize } from "./strategies/generalize.js";
import {
  UnsupportedStrategyError,
  UnknownCategoryError,
  ValidationError,
  PresetNotFoundError,
} from "./errors.js";
import { getPreset } from "./presets.js";
import type {
  AnonymizeOptions,
  AnonymizeResult,
  AnonymizerConfig,
  Anonymizer,
  FieldRuleMap,
  PiiCategory,
  PiiMatch,
  StrategyOptions,
  Detector,
  CustomPattern,
  TokenizeOptions,
  TokenMatch,
} from "./types.js";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** All recognised PII category names. */
const ALL_CATEGORIES: readonly PiiCategory[] = [
  "email",
  "phone",
  "ssn",
  "credit-card",
  "ipv4",
  "ipv6",
  "url",
  "iban",
  "date-of-birth",
  "name",
  "address",
  "passport",
  "drivers-license",
  "national-id",
  "bank-account",
  "cryptocurrency",
  "tax-id",
  "medical-record",
  "health-insurance",
  "prescription",
  "api-key",
  "social-media",
  "vin",
  "license-plate",
  "tracking-number",
  "case-number",
  "company-registration",
] as const;

/**
 * Category → token prefix mapping for `consistentTokens` mode.
 * @internal
 */
const TOKEN_PREFIX_MAP: Readonly<Record<PiiCategory, string>> = {
  email: "EMAIL",
  phone: "PHONE",
  ssn: "SSN",
  "credit-card": "CREDIT_CARD",
  ipv4: "IPV4",
  ipv6: "IPV6",
  url: "URL",
  iban: "IBAN",
  "date-of-birth": "DATE",
  name: "PERSON",
  address: "ADDRESS",
  passport: "PASSPORT",
  "drivers-license": "DRIVERS_LICENSE",
  "national-id": "NATIONAL_ID",
  "bank-account": "BANK_ACCOUNT",
  cryptocurrency: "CRYPTO",
  "tax-id": "TAX_ID",
  "medical-record": "MEDICAL_RECORD",
  "health-insurance": "HEALTH_INSURANCE",
  prescription: "PRESCRIPTION",
  "api-key": "API_KEY",
  "social-media": "SOCIAL_MEDIA",
  vin: "VIN",
  "license-plate": "LICENSE_PLATE",
  "tracking-number": "TRACKING_NUMBER",
  "case-number": "CASE_NUMBER",
  "company-registration": "COMPANY_REG",
} as const;

/**
 * Apply a single strategy synchronously. The `hash` strategy is async but
 * for text-level anonymization we need synchronous replacement. We use
 * pseudonymize as a deterministic fallback for hash in sync contexts.
 *
 * @remarks
 * ⚠️ **`hash` fallback**: When `hash` is used in a synchronous `anonymize()`
 * call, it falls back to a deterministic pseudonym. If true SHA-256 hashing is
 * required, call `hash()` directly (it returns a `Promise<string>`).
 *
 * @internal
 */
function applyStrategySync(value: string, opts: StrategyOptions): string {
  switch (opts.strategy) {
    case "mask":
      return mask(value, opts);
    case "redact":
      return redact(value, opts);
    case "pseudonymize":
      return pseudonymize(value, opts);
    case "hash":
      // Hash is async; callers that need true hashing should use hashValue() directly.
      // For the synchronous pipeline we fall back to a deterministic pseudonym.
      // eslint-disable-next-line no-console
      console.warn(
        "[anonyma] The `hash` strategy is async and cannot be used in the synchronous " +
          "`anonymize()` pipeline. Falling back to a deterministic pseudonym. " +
          "Use `hash()` directly if you need true SHA-256 output.",
      );
      return pseudonymize(value, { seed: opts.pepper ?? "__hash_fallback__", prefix: "hsh_" });
    case "generalize":
      return generalize(value, opts);
    case "tokenize":
    case "encrypt":
    case "synthesize":
      // These strategies are async-only. In sync contexts we fall back to redact.
      // eslint-disable-next-line no-console
      console.warn(
        `[anonyma] The \`${opts.strategy}\` strategy requires async execution. ` +
          `Falling back to redact in the synchronous pipeline. Use anonymizeAsync() instead.`,
      );
      return redact(value);
    default: {
      // Exhaustiveness check — TypeScript should never reach here.
      const _exhaustive: never = opts;
      throw new UnsupportedStrategyError((_exhaustive as StrategyOptions).strategy);
    }
  }
}

/**
 * Sort and de-duplicate an array of PII matches by position.
 * When matches overlap, the one with the higher confidence wins.
 *
 * Works on any match-like object that has `start`, `end`, and `confidence`.
 *
 * @internal
 */
function deduplicateMatches<T extends { start: number; end: number; confidence: number }>(
  matches: T[],
): T[] {
  // Sort by start position; on ties prefer higher confidence.
  const sorted = [...matches].sort(
    (a, b) => a.start - b.start || b.confidence - a.confidence,
  );

  const result: T[] = [];
  let cursor = 0;

  for (const m of sorted) {
    if (m.start >= cursor) {
      result.push(m);
      cursor = m.end;
    }
  }

  return result;
}

/**
 * Get the active detector for a category, merging custom overrides.
 *
 * @internal
 */
function resolveDetector(
  category: PiiCategory,
  customDetectors?: Partial<Record<PiiCategory, Detector>>,
  aggressive?: boolean,
): Detector {
  if (customDetectors?.[category]) return customDetectors[category];
  return aggressive ? AGGRESSIVE_DETECTOR_REGISTRY[category] : DETECTOR_REGISTRY[category];
}

/**
 * Internal representation of a custom pattern match used within the
 * anonymization pipeline. Not exposed publicly.
 *
 * @internal
 */
interface CustomMatch {
  readonly category: string;
  readonly value: string;
  readonly start: number;
  readonly end: number;
  readonly confidence: number;
  readonly replacement: string;
}

/**
 * Run custom patterns against `text` and produce CustomMatch objects.
 *
 * @internal
 */
function detectCustomPatterns(
  text: string,
  customPatterns: readonly CustomPattern[],
): CustomMatch[] {
  const results: CustomMatch[] = [];

  for (const cp of customPatterns) {
    if (!(cp.pattern instanceof RegExp)) {
      throw new ValidationError("customPatterns[].pattern", "must be a RegExp instance");
    }

    // Ensure global flag is set; create a fresh copy to avoid lastIndex mutation.
    const flags = cp.pattern.flags.includes("g") ? cp.pattern.flags : cp.pattern.flags + "g";
    const re = new RegExp(cp.pattern.source, flags);
    const category = cp.category ?? "custom";
    const confidence = cp.confidence ?? 0.85;
    const label = cp.label ?? "[REDACTED]";

    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      results.push({
        category,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence,
        replacement: label,
      });
    }
  }

  return results;
}

/**
 * Resolve the list of categories to detect from `AnonymizeOptions`.
 * Handles `rules`, `enabledCategories`, and defaults.
 *
 * @internal
 */
function resolveCategories(options: AnonymizeOptions): PiiCategory[] {
  const { rules = [], enabledCategories } = options;

  if (rules.length > 0) {
    // rules takes priority — only scan the explicitly listed categories.
    return rules.map((r) => r.category);
  }

  if (enabledCategories) {
    return ALL_CATEGORIES.filter((cat) => enabledCategories[cat] === true);
  }

  return [...ALL_CATEGORIES];
}

// ---------------------------------------------------------------------------
// Public: detect()
// ---------------------------------------------------------------------------

/**
 * Detect all PII in `text` using the built-in detectors.
 *
 * @param text - The input string to scan.
 * @param categories - Optional subset of categories to check. Defaults to all.
 * @param customDetectors - Optional overrides for built-in detectors.
 * @param aggressive - When `true`, use expanded pattern sets for each detector.
 * @returns A sorted array of non-overlapping {@link PiiMatch} objects.
 *
 * @example
 * ```ts
 * import { detect } from "anonyma";
 *
 * detect("Email: alice@example.com, IP: 192.168.1.1");
 * // [
 * //   { category: "email",  value: "alice@example.com", start: 7,  end: 24, confidence: 0.99 },
 * //   { category: "ipv4",   value: "192.168.1.1",       start: 30, end: 41, confidence: 0.98 },
 * // ]
 * ```
 */
export function detect(
  text: string,
  categories: readonly PiiCategory[] = ALL_CATEGORIES,
  customDetectors?: Partial<Record<PiiCategory, Detector>>,
  aggressive?: boolean,
): PiiMatch[] {
  if (typeof text !== "string") {
    throw new ValidationError("text", "must be a string");
  }

  const raw: PiiMatch[] = [];

  for (const category of categories) {
    if (!ALL_CATEGORIES.includes(category)) {
      throw new UnknownCategoryError(category);
    }
    const detector = resolveDetector(category, customDetectors, aggressive);
    raw.push(...detector(text));
  }

  return deduplicateMatches(raw);
}

// ---------------------------------------------------------------------------
// Public: hasPII()
// ---------------------------------------------------------------------------

/**
 * Return `true` if `text` contains any detectable PII, `false` otherwise.
 *
 * Uses an early-exit optimisation — scanning stops after the first match is
 * found. Useful for validation gates and conditional processing pipelines.
 *
 * @param text - The input string to scan.
 * @param categories - Optional subset of categories to check. Defaults to all.
 * @param customDetectors - Optional overrides for built-in detectors.
 * @returns `true` if any PII is detected; `false` otherwise.
 *
 * @example
 * ```ts
 * import { hasPII } from "anonyma";
 *
 * if (hasPII(commentText)) {
 *   return { error: "Comment contains personal information." };
 * }
 * ```
 */
export function hasPII(
  text: string,
  categories: readonly PiiCategory[] = ALL_CATEGORIES,
  customDetectors?: Partial<Record<PiiCategory, Detector>>,
): boolean {
  if (typeof text !== "string") {
    throw new ValidationError("text", "must be a string");
  }

  for (const category of categories) {
    if (!ALL_CATEGORIES.includes(category)) {
      throw new UnknownCategoryError(category);
    }
    const detector = resolveDetector(category, customDetectors);
    if (detector(text).length > 0) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Public: anonymize()
// ---------------------------------------------------------------------------

/**
 * Detect and anonymize all PII in `text`.
 *
 * Operates in a single left-to-right pass: detected matches are replaced in
 * reverse order (right-to-left) to preserve correct string offsets.
 *
 * @param text - The input string to anonymize.
 * @param options - Anonymization configuration.
 * @returns An {@link AnonymizeResult} containing the anonymized text and
 *          optionally the detected matches.
 *
 * @example
 * ```ts
 * import { anonymize } from "anonyma";
 *
 * anonymize("Contact alice@example.com or call 555-867-5309.");
 * // { text: "Contact [REDACTED] or call [REDACTED].", matches: [] }
 *
 * // Consistent tokens — same value gets same label
 * anonymize("alice@example.com and alice@example.com again", { consistentTokens: true });
 * // { text: "EMAIL_1 and EMAIL_1 again", matches: [] }
 *
 * // Aggressive mode — catches obfuscated PII
 * anonymize("Email user [at] example [dot] com", { aggressive: true });
 * // { text: "Email [REDACTED]", matches: [] }
 * ```
 */
export function anonymize(text: string, options: AnonymizeOptions = {}): AnonymizeResult {
  if (typeof text !== "string") {
    throw new ValidationError("text", "must be a string");
  }

  if (options.globalReplacement?.trim().length === 0) {
    throw new ValidationError("globalReplacement", "must not be an empty string");
  }

  // Resolve preset if provided.
  let resolvedPreset: ReturnType<typeof getPreset> | undefined;
  if (options.preset) {
    try {
      resolvedPreset = getPreset(options.preset);
    } catch {
      throw new PresetNotFoundError(options.preset);
    }
  }

  const {
    rules = resolvedPreset
      ? resolvedPreset.categories.map((category) => ({
          category,
          strategy:
            resolvedPreset.rules?.find((r) => r.category === category)?.strategy ??
            resolvedPreset.defaultStrategy,
        }))
      : [],
    defaultStrategy = resolvedPreset?.defaultStrategy ?? { strategy: "redact" as const },
    includeMatches = false,
    customDetectors,
    customPatterns = [],
    globalReplacement,
    consistentTokens = false,
    aggressive = false,
    enabledCategories,
    allowlist = [],
    allowlistPatterns = [],
    allowlistCaseSensitive = false,
    confidenceThreshold = 0,
  } = options;

  // Build a category → strategy map from the rules array.
  const ruleMap = new Map<PiiCategory, StrategyOptions>();
  for (const rule of rules) {
    if (!ALL_CATEGORIES.includes(rule.category)) {
      throw new UnknownCategoryError(rule.category);
    }
    ruleMap.set(rule.category, rule.strategy);
  }

  // Resolve which categories to scan.
  const categories = resolveCategories({
    rules,
    ...(enabledCategories !== undefined ? { enabledCategories } : {}),
  });

  // Pre-compile allowlist patterns for performance.
  const compiledAllowlistPatterns: RegExp[] = [
    ...allowlistPatterns,
    ...allowlist.map(
      (entry) =>
        new RegExp(
          entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
          allowlistCaseSensitive ? "" : "i",
        ),
    ),
  ];

  /**
   * Returns true if `value` matches any allowlist entry — i.e. it should
   * NOT be anonymized even if detected as PII.
   */
  function isAllowlisted(value: string): boolean {
    if (compiledAllowlistPatterns.length === 0) return false;
    return compiledAllowlistPatterns.some((re) => re.test(value));
  }

  // Run built-in detectors.
  const builtInMatches = detect(text, categories, customDetectors, aggressive);

  // Run custom patterns.
  const customMatches = customPatterns.length > 0 ? detectCustomPatterns(text, customPatterns) : [];

  // Apply allowlist + confidenceThreshold filtering to built-in matches.
  const filteredBuiltInMatches = builtInMatches.filter(
    (m) => m.confidence >= confidenceThreshold && !isAllowlisted(m.value),
  );

  // Combine and deduplicate all matches by position.
  type UnifiedMatch = (PiiMatch & { replacement?: string }) | CustomMatch;
  const allRaw: UnifiedMatch[] = [...filteredBuiltInMatches, ...customMatches];
  const allDeduped = deduplicateMatches(allRaw);

  // --- Consistent token state (scoped to this call only) ---
  const tokenMap = new Map<string, string>(); // key: "category:normalizedValue" → token
  const tokenCounters = new Map<string, number>(); // key: prefix → counter

  function assignToken(category: string, value: string): string {
    const prefix = (TOKEN_PREFIX_MAP as Readonly<Record<string, string | undefined>>)[category] ?? category.toUpperCase();
    const key = `${prefix}:${value.toLowerCase()}`;
    const existing = tokenMap.get(key);
    if (existing) return existing;
    const count = (tokenCounters.get(prefix) ?? 0) + 1;
    tokenCounters.set(prefix, count);
    const token = `${prefix}_${String(count)}`;
    tokenMap.set(key, token);
    return token;
  }

  // Apply strategies in reverse order to preserve indices.
  let result = text;
  const reversed = [...allDeduped].reverse();

  for (const match of reversed) {
    let replacement: string;

    if (globalReplacement !== undefined) {
      replacement = globalReplacement;
    } else if (consistentTokens) {
      replacement = assignToken(match.category, match.value);
    } else if ("replacement" in match) {
      // Pre-computed replacement from custom pattern.
      replacement = match.replacement;
    } else {
      // Built-in PII match: look up per-category rule or fall back to default.
      const strategy = ruleMap.get(match.category) ?? defaultStrategy;
      replacement = applyStrategySync(match.value, strategy);
    }

    result = result.slice(0, match.start) + replacement + result.slice(match.end);
  }

  // Only include built-in PiiMatch objects in the public result (custom matches
  // have a non-PiiCategory category and are not part of the public API surface).
  const reportedMatches = includeMatches ? filteredBuiltInMatches : [];

  return {
    text: result,
    matches: reportedMatches,
  };
}

// ---------------------------------------------------------------------------
// Public: anonymizeAsync()
// ---------------------------------------------------------------------------

/**
 * Asynchronous version of {@link anonymize}. Supports the `hash` strategy
 * (uses true SHA-256 via the Web Crypto API) and future async strategies
 * (`tokenize`, `encrypt`, `synthesize`).
 *
 * Falls back to the synchronous implementation for all other strategies.
 *
 * @param text - The input string to anonymize.
 * @param options - Anonymization configuration. Supports the same options as
 *   {@link anonymize} plus `hash` strategy with actual SHA-256 output.
 * @returns A promise that resolves to an {@link AnonymizeResult}.
 *
 * @example
 * ```ts
 * import { anonymizeAsync } from "anonyma";
 *
 * const result = await anonymizeAsync("Contact alice@example.com", {
 *   defaultStrategy: { strategy: "hash" },
 * });
 * // { text: "Contact <sha256-hex>", matches: [] }
 * ```
 */
export async function anonymizeAsync(
  text: string,
  options: AnonymizeOptions = {},
): Promise<AnonymizeResult> {
  if (typeof text !== "string") {
    throw new ValidationError("text", "must be a string");
  }

  // For strategies that don't involve async primitives, delegate to sync.
  const hasAsyncStrategy = (opts: StrategyOptions): boolean =>
    opts.strategy === "hash" || opts.strategy === "encrypt" ||
    opts.strategy === "tokenize" || opts.strategy === "synthesize";

  const needsAsync =
    (options.defaultStrategy != null && hasAsyncStrategy(options.defaultStrategy)) ||
    (options.rules ?? []).some((r) => hasAsyncStrategy(r.strategy));

  if (!needsAsync) {
    return anonymize(text, options);
  }

  // Lazy-import to avoid circular dependency on strategies not yet in the
  // synchronous bundle (hash is async-native, others upcoming).
  const { hash: hashFn } = await import("./strategies/hash.js");

  // Resolve identical logic as sync path.
  let resolvedPreset: ReturnType<typeof getPreset> | undefined;
  if (options.preset) {
    try {
      resolvedPreset = getPreset(options.preset);
    } catch {
      throw new PresetNotFoundError(options.preset);
    }
  }

  const {
    rules = resolvedPreset
      ? resolvedPreset.categories.map((category) => ({
          category,
          strategy:
            resolvedPreset.rules?.find((r) => r.category === category)?.strategy ??
            resolvedPreset.defaultStrategy,
        }))
      : [],
    defaultStrategy = resolvedPreset?.defaultStrategy ?? { strategy: "redact" as const },
    includeMatches = false,
    customDetectors,
    customPatterns = [],
    globalReplacement,
    consistentTokens = false,
    aggressive = false,
    enabledCategories,
    allowlist = [],
    allowlistPatterns = [],
    allowlistCaseSensitive = false,
    confidenceThreshold = 0,
  } = options;

  const ruleMap = new Map<PiiCategory, StrategyOptions>();
  for (const rule of rules) {
    if (!ALL_CATEGORIES.includes(rule.category)) throw new UnknownCategoryError(rule.category);
    ruleMap.set(rule.category, rule.strategy);
  }

  const categories = resolveCategories({
    rules,
    ...(enabledCategories !== undefined ? { enabledCategories } : {}),
  });

  const builtInMatches = detect(text, categories, customDetectors, aggressive);
  const customMatches = customPatterns.length > 0 ? detectCustomPatterns(text, customPatterns) : [];

  const compiledAllowlistPatterns: RegExp[] = [
    ...allowlistPatterns,
    ...allowlist.map(
      (entry) =>
        new RegExp(
          entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
          allowlistCaseSensitive ? "" : "i",
        ),
    ),
  ];
  const isAllowlisted = (value: string): boolean =>
    compiledAllowlistPatterns.some((re) => re.test(value));

  const filteredBuiltInMatches = builtInMatches.filter(
    (m) => m.confidence >= confidenceThreshold && !isAllowlisted(m.value),
  );

  type UnifiedMatch = (PiiMatch & { replacement?: string }) | CustomMatch;
  const allRaw: UnifiedMatch[] = [...filteredBuiltInMatches, ...customMatches];
  const allDeduped = deduplicateMatches(allRaw);

  const tokenMap = new Map<string, string>();
  const tokenCounters = new Map<string, number>();
  function assignToken(category: string, value: string): string {
    const prefix = (TOKEN_PREFIX_MAP as Readonly<Record<string, string | undefined>>)[category] ?? category.toUpperCase();
    const key = `${prefix}:${value.toLowerCase()}`;
    const existing = tokenMap.get(key);
    if (existing) return existing;
    const count = (tokenCounters.get(prefix) ?? 0) + 1;
    tokenCounters.set(prefix, count);
    const token = `${prefix}_${String(count)}`;
    tokenMap.set(key, token);
    return token;
  }

  let result = text;
  const reversed = [...allDeduped].reverse();

  for (const match of reversed) {
    let replacement: string;

    if (globalReplacement !== undefined) {
      replacement = globalReplacement;
    } else if (consistentTokens) {
      replacement = assignToken(match.category, match.value);
    } else if ("replacement" in match) {
      replacement = match.replacement;
    } else {
      const strategy = ruleMap.get(match.category) ?? defaultStrategy;
      if (strategy.strategy === "hash") {
        replacement = await hashFn(match.value, strategy);
      } else {
        replacement = applyStrategySync(match.value, strategy);
      }
    }

    result = result.slice(0, match.start) + replacement + result.slice(match.end);
  }

  return {
    text: result,
    matches: includeMatches ? filteredBuiltInMatches : [],
  };
}

// ---------------------------------------------------------------------------
// Public: anonymizeObject()
// ---------------------------------------------------------------------------

/**
 * Recursively anonymize every string value found in a JSON-serializable object
 * tree. Returns a deep clone — the input is never mutated.
 *
 * Handles:
 * - Plain objects (nested to any depth)
 * - Arrays (including mixed-type arrays)
 * - Primitive values (`null`, `undefined`, numbers, booleans) — passed through unchanged
 * - Circular references — throws {@link ValidationError}
 *
 * @param obj - The root object to anonymize. Must be free of circular references.
 * @param options - Optional anonymization configuration forwarded to `anonymize()`.
 * @returns A new object of the same shape with all string values anonymized.
 *
 * @throws {@link ValidationError} When `obj` contains a circular reference or is not an object.
 *
 * @example
 * ```ts
 * import { anonymizeObject } from "anonyma";
 *
 * const result = anonymizeObject({
 *   user: { name: "Alice", email: "alice@example.com" },
 *   notes: ["Call 555-867-5309", "No PII here"],
 * });
 * // {
 * //   user: { name: "Alice", email: "[REDACTED]" },
 * //   notes: ["[REDACTED]", "No PII here"],
 * // }
 * ```
 */
export function anonymizeObject<T extends object>(obj: T, options?: AnonymizeOptions): T {
  if (typeof obj !== "object") {
    throw new ValidationError("obj", "must be an object");
  }
  return deepAnonymizeValue(obj, options, new WeakSet()) as T;
}

/**
 * Recursive implementation for `anonymizeObject`.
 * `seen` tracks visited objects to detect circular references.
 *
 * @internal
 */
function deepAnonymizeValue(
  value: unknown,
  options: AnonymizeOptions | undefined,
  seen: WeakSet<object>,
): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    return anonymize(value, options).text;
  }

  if (typeof value !== "object") {
    // numbers, booleans, Symbols, BigInts — pass through unchanged.
    return value;
  }

  if (seen.has(value)) {
    throw new ValidationError("obj", "contains a circular reference");
  }
  seen.add(value);

  if (Array.isArray(value)) {
    const result = value.map((item) => deepAnonymizeValue(item, options, seen));
    seen.delete(value as object);
    return result;
  }

  // Plain object.
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>)) {
    result[key] = deepAnonymizeValue(
      (value as Record<string, unknown>)[key],
      options,
      seen,
    );
  }
  seen.delete(value);
  return result;
}

// ---------------------------------------------------------------------------
// Public: anonymizeRecord()
// ---------------------------------------------------------------------------

/**
 * Safely get a nested value from a plain record using dot-notation path.
 *
 * @internal
 */
function getByPath(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    // Safe: we check isObject above.
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Safely set a nested value on a plain record using dot-notation path.
 * Returns a new object (shallow clone at each level touched).
 *
 * @internal
 */
function setByPath(
  obj: Record<string, unknown>,
  path: string,
  value: unknown,
): Record<string, unknown> {
  const parts = path.split(".");

  if (parts.length === 1) {
    return { ...obj, [path]: value };
  }

  const [head, ...tail] = parts as [string, ...string[]];
  // setByPath is only called after getByPath confirmed the path exists, so obj[head] is
  // always defined in practice. The `?? {}` fallback is a defensive guard.
  /* v8 ignore next */
  const nested = (obj[head] ?? {}) as Record<string, unknown>;
  return {
    ...obj,
    [head]: setByPath(nested, tail.join("."), value),
  };
}

/**
 * Anonymize specific fields in a plain record using field-level rules.
 * Supports dot-notation paths for nested fields.
 *
 * This function returns a new record — it never mutates the input.
 *
 * @param record - The input record.
 * @param rules - A map of field path → {@link FieldRule}.
 * @returns A new record with the specified fields anonymized.
 *
 * @example
 * ```ts
 * import { anonymizeRecord } from "anonyma";
 *
 * anonymizeRecord(
 *   { name: "Alice", email: "alice@example.com", age: "27" },
 *   {
 *     email: { strategy: { strategy: "mask", keepLeading: 1, keepTrailing: 3 } },
 *     age:   { strategy: { strategy: "generalize" } },
 *   }
 * );
 * // { name: "Alice", email: "a***************com", age: "20-29" }
 * ```
 */
export function anonymizeRecord<T extends Record<string, unknown>>(
  record: T,
  rules: FieldRuleMap,
): T {
  if (typeof record !== "object" || Array.isArray(record)) {
    throw new ValidationError("record", "must be a plain object");
  }

  let result: Record<string, unknown> = { ...record };

  for (const [path, rule] of Object.entries(rules)) {
    if (Object.prototype.hasOwnProperty.call(rules, path)) {
      const raw = getByPath(result, path);
      if (raw === undefined || raw === null) continue;
      if (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "boolean") continue;

      const strValue = String(raw);
      const anonymized = applyStrategySync(strValue, rule.strategy);
      result = setByPath(result, path, anonymized);
    }
  }

  return result as T;
}

// ---------------------------------------------------------------------------
// Public: createAnonymizer()
// ---------------------------------------------------------------------------

/**
 * Create a reusable, pre-configured {@link Anonymizer} instance.
 *
 * @param config - Anonymizer configuration.
 * @returns A configured {@link Anonymizer}.
 *
 * @example
 * ```ts
 * import { createAnonymizer } from "anonyma";
 *
 * const anonymizer = createAnonymizer({
 *   categories: ["email", "phone"],
 *   defaultStrategy: { strategy: "mask", keepLeading: 0, keepTrailing: 4 },
 * });
 *
 * anonymizer.anonymize("Call 555-867-5309 or email alice@example.com");
 * // { text: "Call ****5309 or email **.com", matches: [] }
 *
 * anonymizer.hasPII("No PII here");
 * // false
 *
 * anonymizer.anonymizeObject({ email: "alice@example.com", score: 42 });
 * // { email: "[REDACTED]", score: 42 }
 * ```
 */
export function createAnonymizer(config: AnonymizerConfig = {}): Anonymizer {
  // Resolve preset first so its defaults can be overridden by explicit config.
  let presetConfig: ReturnType<typeof getPreset> | undefined;
  if (config.preset) {
    try {
      presetConfig = getPreset(config.preset);
    } catch {
      throw new PresetNotFoundError(config.preset);
    }
  }

  const {
    categories = presetConfig ? presetConfig.categories : [...ALL_CATEGORIES],
    defaultStrategy = presetConfig?.defaultStrategy ?? { strategy: "redact" as const },
    customDetectors,
    customPatterns,
    globalReplacement,
    consistentTokens,
    aggressive,
  } = config;

  // Validate categories up-front.
  for (const cat of categories) {
    if (!ALL_CATEGORIES.includes(cat)) {
      throw new UnknownCategoryError(cat);
    }
  }

  /** Shared base options derived from config. */
  function baseOptions(overrides?: Partial<AnonymizeOptions>): AnonymizeOptions {
    const base: AnonymizeOptions = {
      defaultStrategy,
      ...(customDetectors !== undefined ? { customDetectors } : {}),
      ...(customPatterns !== undefined ? { customPatterns } : {}),
      ...(globalReplacement !== undefined ? { globalReplacement } : {}),
      ...(consistentTokens !== undefined ? { consistentTokens } : {}),
      ...(aggressive !== undefined ? { aggressive } : {}),
      ...overrides,
      rules:
        overrides?.rules ??
        (presetConfig
          ? presetConfig.categories.map((category) => ({
              category,
              strategy:
                presetConfig.rules?.find((r) => r.category === category)?.strategy ??
                defaultStrategy,
            }))
          : categories.map((category) => ({
              category,
              strategy: defaultStrategy,
            }))),
    };
    return base;
  }

  return {
    anonymize(text: string, options?: Partial<AnonymizeOptions>): AnonymizeResult {
      return anonymize(text, baseOptions(options));
    },

    detect(text: string): PiiMatch[] {
      return detect(text, categories, customDetectors, aggressive);
    },

    anonymizeRecord<T extends Record<string, unknown>>(record: T, rules: FieldRuleMap): T {
      return anonymizeRecord(record, rules);
    },

    anonymizeObject<T extends object>(obj: T, options?: AnonymizeOptions): T {
      return anonymizeObject(obj, baseOptions(options));
    },

    async anonymizeAsync(text: string, options?: Partial<AnonymizeOptions>): Promise<AnonymizeResult> {
      return anonymizeAsync(text, baseOptions(options));
    },

    tokenize(text: string, options?: TokenizeOptions): ReturnType<Anonymizer["tokenize"]> {
      // Inline implementation to avoid circular dependency (tokenize.ts imports detectFn)
      const {
        categories: tCats,
        format = "bracket",
        customDetectors: tCustDet,
        aggressive: tAgg = aggressive,
        confidenceThreshold: tConfidence = 0,
        allowlist: tAllowlist = [],
        allowlistCaseSensitive: tCaseSensitive = false,
      } = options ?? {};

      const tCompiledAllowlist = tAllowlist.map(
        (entry: string) =>
          new RegExp(entry.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&"), tCaseSensitive ? "" : "i"),
      );
      const isAllowlisted = (v: string): boolean => tCompiledAllowlist.some((re: RegExp) => re.test(v));

      const tMatches = detect(text, tCats ?? categories, tCustDet ?? customDetectors, tAgg).filter(
        (m) => m.confidence >= tConfidence && !isAllowlisted(m.value),
      );

      const store = createTokenStore();
      let tResult = text;
      const tTokens: TokenMatch[] = [];
      for (const match of [...tMatches].reverse()) {
        // detect() exclusively returns PiiCategory matches, so the toUpperCase() fallback
        // is unreachable through the public API.
        /* v8 ignore next */
        const prefix = TOKEN_PREFIX_MAP[match.category];
        const token = assignTokenFn(store, match.category, match.value, prefix, format);
        tTokens.push({
          token,
          original: match.value,
          category: match.category,
          start: match.start,
          end: match.end,
        });
        tResult = tResult.slice(0, match.start) + token + tResult.slice(match.end);
      }
      return { text: tResult, mapping: store.tokens, tokens: tTokens };
    },

    hasPII(text: string): boolean {
      return hasPII(text, categories, customDetectors);
    },
  };
}
