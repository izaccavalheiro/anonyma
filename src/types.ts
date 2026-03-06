/**
 * @module types
 * @description Core TypeScript types and interfaces for the anonyma library.
 */

// ---------------------------------------------------------------------------
// PII entity types
// ---------------------------------------------------------------------------

/**
 * All PII (Personally Identifiable Information) categories that anonyma can detect.
 *
 * @remarks
 * `"name"` detection is heuristic — it catches names that follow greeting keywords,
 * title prefixes (Mr./Dr./etc.), and context clues (patient, client, defendant, etc.).
 * It is not an NLP-based name recogniser and may miss names that appear without
 * any of these context signals.
 */
export type PiiCategory =
  // --- Original categories ---
  | "email"
  | "phone"
  | "ssn"
  | "credit-card"
  | "ipv4"
  | "ipv6"
  | "url"
  | "iban"
  | "date-of-birth"
  | "name"
  // --- Personal Information ---
  | "address"
  | "passport"
  | "drivers-license"
  | "national-id"
  // --- Financial ---
  | "bank-account"
  | "cryptocurrency"
  | "tax-id"
  // --- Healthcare ---
  | "medical-record"
  | "health-insurance"
  | "prescription"
  // --- Digital Identity ---
  | "api-key"
  | "social-media"
  // --- Vehicles & Transportation ---
  | "vin"
  | "license-plate"
  | "tracking-number"
  // --- Government & Legal ---
  | "case-number"
  | "company-registration";

/**
 * A detected PII entity within a text string.
 */
export interface PiiMatch {
  /** The category of PII detected. */
  readonly category: PiiCategory;
  /** The verbatim matched value. */
  readonly value: string;
  /** Zero-based start index within the source string. */
  readonly start: number;
  /** Zero-based exclusive end index within the source string. */
  readonly end: number;
  /** Confidence score in the range [0, 1]. */
  readonly confidence: number;
}

// ---------------------------------------------------------------------------
// Custom patterns
// ---------------------------------------------------------------------------

/**
 * An ad-hoc regex pattern that participates in PII detection and anonymization
 * alongside the built-in detectors.
 *
 * @example
 * ```ts
 * const pattern: CustomPattern = {
 *   pattern: /\bACME-\d{6}\b/g,
 *   category: "order-id",
 *   confidence: 0.9,
 *   label: "[ORDER_ID]",
 * };
 * ```
 */
export interface CustomPattern {
  /**
   * The regular expression to match. If the global flag is absent it will be
   * added automatically before execution.
   */
  readonly pattern: RegExp;
  /**
   * Category label attached to matches. Defaults to `"custom"`.
   * Does not need to be a built-in {@link PiiCategory}.
   */
  readonly category?: string;
  /**
   * Confidence score in [0, 1]. Defaults to `0.85`.
   */
  readonly confidence?: number;
  /**
   * Replacement label used when a match is replaced.
   * Defaults to `"[REDACTED]"`.
   */
  readonly label?: string;
}



// ---------------------------------------------------------------------------
// Locale type
// ---------------------------------------------------------------------------

/**
 * Locale codes for locale-aware PII detection. `"global"` covers universally-
 * formatted PII (e.g. email, IPv4, credit card).
 */
export type Locale =
  | "global"
  | "us"
  | "uk"
  | "eu"
  | "ca"
  | "au"
  | "br"
  | "in"
  | "cn"
  | "jp"
  | "kr"
  | "za";

// ---------------------------------------------------------------------------
// Compliance presets
// ---------------------------------------------------------------------------

/**
 * Built-in compliance preset identifiers.
 */
export type CompliancePreset = "gdpr" | "hipaa" | "ccpa" | "pci-dss" | "sox" | "ferpa";

// ---------------------------------------------------------------------------
// Tokenization types
// ---------------------------------------------------------------------------

/**
 * A single tokenized PII match.
 */
export interface TokenMatch {
  /** The placeholder token, e.g. `<Email_1>` or `[EMAIL_a3f9]`. */
  readonly token: string;
  /** The original PII value. */
  readonly original: string;
  /** The PII category. */
  readonly category: PiiCategory;
  /** Zero-based start index within the source string. */
  readonly start: number;
  /** Zero-based exclusive end index within the source string. */
  readonly end: number;
}

/**
 * Result returned by `tokenize()`.
 */
export interface TokenizeResult {
  /** The tokenized text with PII replaced by placeholder tokens. */
  readonly text: string;
  /** A map from token → original value for reversibility. */
  readonly mapping: ReadonlyMap<string, string>;
  /** All token match details. */
  readonly tokens: readonly TokenMatch[];
}

/**
 * Result returned by `detokenize()`.
 */
export interface DetokenizeResult {
  /** The restored text with tokens replaced by original values. */
  readonly text: string;
  /** Number of tokens successfully replaced. */
  readonly replacedCount: number;
  /** Any tokens not found in the mapping (left unchanged in output). */
  readonly unresolved: readonly string[];
}

/**
 * Token format style.
 * - `"angle"`: `<Category_N>` (default, LLM-friendly)
 * - `"bracket"`: `[CATEGORY_xxxx]`
 * - `"custom"`: Use `tokenTemplate` function
 */
export type TokenFormat = "angle" | "bracket" | "custom";

/**
 * Options accepted by `tokenize()`.
 */
export interface TokenizeOptions {
  /**
   * Categories to detect and tokenize. Defaults to all.
   */
  readonly categories?: readonly PiiCategory[];
  /**
   * Token format style. Defaults to `"bracket"`.
   */
  readonly format?: TokenFormat;
  /**
   * Custom token template function. Only used when `format: "custom"`.
   * @param category - The PII category.
   * @param counter - The incrementing counter for this category.
   * @param value - The original matched value.
   */
  readonly tokenTemplate?: (category: string, counter: number, value: string) => string;
  /**
   * When `true`, identical PII values receive the same token. Defaults to `true`.
   */
  readonly deterministic?: boolean;
  /**
   * When `true`, use aggressive detector patterns. Defaults to `false`.
   */
  readonly aggressive?: boolean;
  /**
   * Locales to enable for detection. Defaults to `["global"]`.
   */
  readonly locales?: readonly Locale[];
  /**
   * Confidence threshold - only tokenize matches at or above this score. Defaults to `0`.
   */
  readonly confidenceThreshold?: number;
  /**
   * Custom detector overrides (same as `AnonymizeOptions.customDetectors`).
   */
  readonly customDetectors?: Partial<Record<PiiCategory, Detector>>;
  /**
   * Values that should never be tokenized even when detected as PII.
   */
  readonly allowlist?: readonly string[];
  /**
   * When `true`, allowlist string matches are case-sensitive. Defaults to `false`.
   */
  readonly allowlistCaseSensitive?: boolean;
}

// ---------------------------------------------------------------------------
// Encryption types
// ---------------------------------------------------------------------------

/**
 * Options for the `encrypt` strategy.
 */
export interface EncryptOptions {
  /**
   * Passphrase used to derive an AES-256-GCM key via PBKDF2.
   * Provide either `passphrase` or `keyBytes`, not both.
   */
  readonly passphrase?: string;
  /**
   * Raw key bytes (16 or 32 bytes) for AES-128 or AES-256 GCM.
   * Provide either `keyBytes` or `passphrase`, not both.
   */
  readonly keyBytes?: Uint8Array;
  /** Output encoding for the ciphertext. Defaults to `"base64"`. */
  readonly encoding?: "base64" | "hex";
}

// ---------------------------------------------------------------------------
// Synthesis types
// ---------------------------------------------------------------------------

/**
 * Options for the `synthesize` strategy.
 */
export interface SynthesizeOptions {
  /**
   * Optional seed string for deterministic output.
   * Same seed + same value + same category always produces the same synthetic replacement.
   */
  readonly seed?: string;
  /** Locale hint for locale-specific synthesis (e.g. phone-number format). */
  readonly locale?: Locale;
}

// ---------------------------------------------------------------------------
// Batch processing types
// ---------------------------------------------------------------------------

/**
 * An individual error entry within a batch result.
 */
export interface BatchError {
  /** Zero-based index of the failed item. */
  readonly index: number;
  /** The error that occurred. */
  readonly error: Error;
}

/**
 * Result of a batch processing operation.
 */
/**
 * A single item result from a batch processing operation.
 *
 * @example
 * ```ts
 * const results = anonymizeBatch(["alice@example.com", "bad input"]);
 * for (const r of results) {
 *   if (r.ok) console.log(r.value.text);
 *   else console.error(`Item ${r.index} failed:`, r.error.message);
 * }
 * ```
 */
export type BatchResult<T> =
  | { readonly index: number; readonly ok: true; readonly value: T }
  | { readonly index: number; readonly ok: false; readonly error: Error };

// ---------------------------------------------------------------------------
// Plugin architecture
// ---------------------------------------------------------------------------

/**
 * A validator function that performs checksum/format validation.
 * Returns `true` if the value is valid.
 */
export type ValidatorFunction = (value: string) => boolean;

/**
 * A strategy function that transforms a PII value to its anonymized form.
 */
export type StrategyFunction = (value: string, options?: Record<string, unknown>) => string;

/**
 * An anonyma plugin that extends detection, anonymization strategy, or validation.
 */
export interface AnonymaPlugin {
  /** Unique plugin name. */
  readonly name: string;
  /** Additional or replacement detectors (keyed by category name). */
  readonly detectors?: Record<string, Detector>;
  /** Additional anonymization strategy implementations. */
  readonly strategies?: Record<string, StrategyFunction>;
  /** Additional checksum/format validators. */
  readonly validators?: Record<string, ValidatorFunction>;
}

// ---------------------------------------------------------------------------
// Built-in anonymization strategy identifiers
// ---------------------------------------------------------------------------

/**
 * Built-in anonymization strategy identifiers.
 */
export type StrategyName =
  | "mask"
  | "redact"
  | "pseudonymize"
  | "hash"
  | "generalize"
  | "tokenize"
  | "encrypt"
  | "synthesize";

/**
 * Options for the `mask` strategy.
 */
export interface MaskOptions {
  /** Character used as the mask. Defaults to `"*"`. */
  readonly maskChar?: string;
  /** Number of leading characters to keep visible. Defaults to `0`. */
  readonly keepLeading?: number;
  /** Number of trailing characters to keep visible. Defaults to `0`. */
  readonly keepTrailing?: number;
  /**
   * When `true`, apply format-preserving masking: alphabetic chars → `X`,
   * digits → `0`, separators and punctuation preserved.
   *
   * @example `123-45-6789` → `000-00-0000`, `john@example.com` → `XXXX@XXXXXXX.XXX`
   */
  readonly preserveFormat?: boolean;
}

/**
 * Options for the `redact` strategy.
 */
export interface RedactOptions {
  /** Replacement label. Defaults to `"[REDACTED]"`. */
  readonly label?: string;
}

/**
 * Options for the `pseudonymize` strategy.
 */
export interface PseudonymizeOptions {
  /**
   * Secret seed used for deterministic output. When provided the same input + seed
   * always produces the same pseudonym, enabling consistent replacement across a dataset.
   * When omitted, a random pseudonym is generated.
   */
  readonly seed?: string;
  /** Namespace prefix appended to the pseudonym. Defaults to `"id_"`. */
  readonly prefix?: string;
}

/**
 * Options for the `hash` strategy.
 */
export interface HashOptions {
  /** Number of hex characters to keep from the digest. Defaults to `16`. */
  readonly truncate?: number;
  /**
   * Optional pepper (a per-deployment secret) mixed into the hash. Using a pepper
   * ensures hashes cannot be reversed via rainbow tables.
   */
  readonly pepper?: string;
}

/**
 * Options for the `generalize` strategy.
 */
export interface GeneralizeOptions {
  /**
   * For numeric fields: the bucket/range width. For example `10` turns `27` into `"20-29"`.
   * Defaults to `10`.
   */
  readonly bucketSize?: number;
}

/**
 * Union of all strategy option shapes.
 */
export type StrategyOptions =
  | ({ strategy: "mask" } & MaskOptions)
  | ({ strategy: "redact" } & RedactOptions)
  | ({ strategy: "pseudonymize" } & PseudonymizeOptions)
  | ({ strategy: "hash" } & HashOptions)
  | ({ strategy: "generalize" } & GeneralizeOptions)
  | ({ strategy: "tokenize" } & Omit<TokenizeOptions, "categories" | "aggressive" | "locales" | "confidenceThreshold">)
  | ({ strategy: "encrypt" } & EncryptOptions)
  | ({ strategy: "synthesize" } & SynthesizeOptions & { category?: PiiCategory });

// ---------------------------------------------------------------------------
// Anonymize function types
// ---------------------------------------------------------------------------

/**
 * A rule that maps a PII category to an anonymization strategy.
 */
export interface AnonymizationRule {
  /** The PII category this rule applies to. */
  readonly category: PiiCategory;
  /** The strategy to apply. */
  readonly strategy: StrategyOptions;
}

/**
 * Options accepted by the top-level `anonymize()` function.
 */
export interface AnonymizeOptions {
  /**
   * Per-category overrides. When specified, only the listed categories are processed;
   * all others are left untouched.
   */
  readonly rules?: readonly AnonymizationRule[];
  /**
   * Default strategy applied to any category not covered by `rules`.
   * Defaults to `{ strategy: "redact" }`.
   */
  readonly defaultStrategy?: StrategyOptions;
  /**
   * When `true`, detected matches are included in the result object.
   * Defaults to `false` for performance.
   */
  readonly includeMatches?: boolean;
  /**
   * Additional or overriding custom detectors per built-in category.
   * Custom detectors are called instead of (not in addition to) the built-in detector
   * for the specified category.
   */
  readonly customDetectors?: Partial<Record<PiiCategory, Detector>>;
  /**
   * Additional ad-hoc regex patterns to match and replace alongside built-in detectors.
   * Custom pattern matches participate in the standard overlap deduplication.
   */
  readonly customPatterns?: readonly CustomPattern[];
  /**
   * When set, every detected PII entity (from all strategies) is replaced with
   * this exact string, overriding per-category rules and `defaultStrategy`.
   * Must be a non-empty string.
   */
  readonly globalReplacement?: string;
  /**
   * When `true`, identical PII values receive the same token across the entire
   * `anonymize()` call (e.g. `EMAIL_1`), and different values get different tokens.
   * Tokens are category-prefixed with incrementing counters.
   * State is scoped to a single call — no cross-call leakage.
   *
   * @example `alice@example.com` → `EMAIL_1`, `bob@example.com` → `EMAIL_2`
   */
  readonly consistentTokens?: boolean;
  /**
   * When `true`, each detector uses its expanded, more permissive pattern set.
   * This catches obfuscated or partial PII (e.g. `user [at] domain [dot] com`)
   * at the cost of more false positives. Confidence scores are reduced accordingly.
   */
  readonly aggressive?: boolean;
  /**
   * Convenience enable/disable map for PII categories.
   * Categories set to `true` are active; `false` or missing entries are excluded.
   * When both `enabledCategories` and `rules` are provided, `rules` takes
   * precedence for the categories it covers.
   *
   * @example
   * ```ts
   * anonymize(text, { enabledCategories: { email: true, phone: true, ssn: false } });
   * ```
   */
  readonly enabledCategories?: Partial<Record<PiiCategory, boolean>>;
  /**
   * Exact values to exclude from detection (case-insensitive by default).
   * Matches in the allowlist are skipped before strategy application.
   *
   * @example `allowlist: ["noreply@company.com"]`
   */
  readonly allowlist?: readonly string[];
  /**
   * RegExp patterns for values to skip. Matches against the full PII value.
   *
   * @example `allowlistPatterns: [/^192\.168\./]`
   */
  readonly allowlistPatterns?: readonly RegExp[];
  /**
   * When `allowlist` matching is case-sensitive. Defaults to `false` (case-insensitive).
   */
  readonly allowlistCaseSensitive?: boolean;
  /**
   * Minimum confidence score [0, 1] for a match to be anonymized.
   * Matches below this threshold are left untouched. Defaults to `0` (process all).
   */
  readonly confidenceThreshold?: number;
  /**
   * Apply a built-in compliance preset, which pre-configures `enabledCategories`
   * and `defaultStrategy`. Explicit `rules` and `defaultStrategy` options take
   * precedence over preset values.
   */
  readonly preset?: CompliancePreset;
  /**
   * Locales to activate for locale-specific detectors.
   * Defaults to `["global"]` which includes universally-formatted PII.
   * Add specific locales to include region-specific patterns (e.g. `["us", "uk"]`).
   */
  readonly locales?: readonly Locale[];
}

/**
 * Result returned by `anonymize()`.
 */
export interface AnonymizeResult {
  /** The anonymized text. */
  readonly text: string;
  /** Detected PII matches (only populated when `includeMatches: true`). */
  readonly matches: readonly PiiMatch[];
}

// ---------------------------------------------------------------------------
// Object anonymization types
// ---------------------------------------------------------------------------

/**
 * A field-level rule for `anonymizeObject()` / `anonymizeRecord()`.
 */
export interface FieldRule {
  /** The strategy to apply to this field's value. */
  readonly strategy: StrategyOptions;
}

/**
 * A mapping of object field paths → `FieldRule`.
 * Dot-notation is supported for nested paths (e.g. `"user.email"`).
 */
export type FieldRuleMap = Readonly<Record<string, FieldRule>>;

// ---------------------------------------------------------------------------
// Detector types
// ---------------------------------------------------------------------------

/**
 * A function that finds PII matches of a specific category in a string.
 *
 * @param text - The input string to scan.
 * @returns An array of matches (may be empty).
 */
export type Detector = (text: string) => PiiMatch[];

/**
 * Registry of all available detectors keyed by PII category.
 */
export type DetectorRegistry = Readonly<Record<PiiCategory, Detector>>;

// ---------------------------------------------------------------------------
// Anonymizer factory types
// ---------------------------------------------------------------------------

/**
 * A configured, reusable anonymizer instance produced by `createAnonymizer()`.
 */
export interface Anonymizer {
  /**
   * Anonymize a text string.
   * @param text - The input text.
   * @param options - Optional per-call overrides.
   */
  readonly anonymize: (text: string, options?: Partial<AnonymizeOptions>) => AnonymizeResult;

  /**
   * Anonymize a text string asynchronously (supports `hash` and `encrypt` strategies natively).
   * @param text - The input text.
   * @param options - Optional per-call overrides.
   */
  readonly anonymizeAsync: (text: string, options?: Partial<AnonymizeOptions>) => Promise<AnonymizeResult>;

  /**
   * Detect all PII in a text string without anonymizing.
   * @param text - The input text.
   */
  readonly detect: (text: string) => PiiMatch[];

  /**
   * Anonymize specific fields in a plain record/object.
   * @param record - The input record.
   * @param rules - Field-level rules.
   */
  readonly anonymizeRecord: <T extends Record<string, unknown>>(
    record: T,
    rules: FieldRuleMap,
  ) => T;

  /**
   * Recursively anonymize all string values in a JSON-serializable object tree.
   * @param obj - The input object. Must be free of circular references.
   * @param options - Optional per-call anonymization overrides.
   */
  readonly anonymizeObject: <T extends object>(obj: T, options?: AnonymizeOptions) => T;

  /**
   * Tokenize PII in text for LLM-safe transmission.
   * @param text - The input text.
   * @param options - Tokenization options.
   */
  readonly tokenize: (text: string, options?: TokenizeOptions) => TokenizeResult;

  /**
   * Return `true` if `text` contains any detectable PII.
   * Stops scanning after the first match for performance.
   * @param text - The input text.
   */
  readonly hasPII: (text: string) => boolean;
}

/**
 * Configuration for `createAnonymizer()`.
 */
export interface AnonymizerConfig {
  /** Ordered list of categories to detect. Defaults to all built-in categories. */
  readonly categories?: readonly PiiCategory[];
  /** Default strategy applied when no per-category rule is provided. */
  readonly defaultStrategy?: StrategyOptions;
  /** Additional or overriding custom detectors. */
  readonly customDetectors?: Partial<Record<PiiCategory, Detector>>;
  /** Ad-hoc regex patterns applied alongside built-in detectors. */
  readonly customPatterns?: readonly CustomPattern[];
  /**
   * When set, every detected PII entity is replaced with this exact string.
   * Overrides `defaultStrategy` and per-category rules.
   */
  readonly globalReplacement?: string;
  /**
   * When `true`, identical PII values receive consistent tokens within a call.
   * @see {@link AnonymizeOptions.consistentTokens}
   */
  readonly consistentTokens?: boolean;
  /**
   * When `true`, detectors use expanded, more permissive patterns.
   * @see {@link AnonymizeOptions.aggressive}
   */
  readonly aggressive?: boolean;
  /**
   * Plugins to extend detector, strategy, or validator capabilities.
   */
  readonly plugins?: readonly AnonymaPlugin[];
  /**
   * Apply a built-in compliance preset as the base for this anonymizer.
   */
  readonly preset?: CompliancePreset;
  /**
   * Locales to activate for locale-specific detectors.
   */
  readonly locales?: readonly Locale[];
}
