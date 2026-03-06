/**
 * @module schemas
 * @description Optional Zod schemas and JSON Schema definitions for anonyma's
 * public API surface. Import from `"anonyma/schemas"`.
 *
 * These schemas enable:
 * - Runtime input validation
 * - OpenAI / Anthropic function-calling definitions
 * - MCP (Model Context Protocol) tool definitions
 * - Automatic form generation
 *
 * @example
 * ```ts
 * import { AnonymizeOptionsSchema, toJsonSchema } from "anonyma/schemas";
 *
 * // Validate at runtime:
 * const opts = AnonymizeOptionsSchema.parse(unknownInput);
 *
 * // Obtain JSON Schema for an AI tool definition:
 * const jsonSchema = toJsonSchema(AnonymizeOptionsSchema);
 * ```
 *
 * @remarks
 * This module requires `zod` to be installed (`peerDependency`).
 * Import it only when you need runtime validation or AI schema generation.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Category & strategy schemas
// ---------------------------------------------------------------------------

/**
 * Zod schema for the {@link PiiCategory} union.
 */
export const PiiCategorySchema = z.enum([
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
]);

/**
 * Zod schema for {@link MaskOptions}.
 */
export const MaskOptionsSchema = z.object({
  strategy: z.literal("mask"),
  maskChar: z
    .string()
    .length(1, "maskChar must be exactly one character")
    .default("*")
    .optional(),
  keepLeading: z.number().int().nonnegative().default(0).optional(),
  keepTrailing: z.number().int().nonnegative().default(0).optional(),
});

/**
 * Zod schema for {@link RedactOptions}.
 */
export const RedactOptionsSchema = z.object({
  strategy: z.literal("redact"),
  label: z.string().min(1, "label must not be empty").default("[REDACTED]").optional(),
});

/**
 * Zod schema for {@link PseudonymizeOptions}.
 */
export const PseudonymizeOptionsSchema = z.object({
  strategy: z.literal("pseudonymize"),
  seed: z.string().optional(),
  prefix: z.string().regex(/^\S+$/, "prefix must not contain whitespace").default("id_").optional(),
});

/**
 * Zod schema for {@link HashOptions}.
 */
export const HashOptionsSchema = z.object({
  strategy: z.literal("hash"),
  truncate: z.number().int().min(1).max(64).default(16).optional(),
  pepper: z.string().optional(),
});

/**
 * Zod schema for {@link GeneralizeOptions}.
 */
export const GeneralizeOptionsSchema = z.object({
  strategy: z.literal("generalize"),
  bucketSize: z.number().int().positive().default(10).optional(),
});

/**
 * Discriminated union schema for {@link StrategyOptions}.
 */
export const StrategyOptionsSchema = z.discriminatedUnion("strategy", [
  MaskOptionsSchema,
  RedactOptionsSchema,
  PseudonymizeOptionsSchema,
  HashOptionsSchema,
  GeneralizeOptionsSchema,
]);

// ---------------------------------------------------------------------------
// Match & result schemas
// ---------------------------------------------------------------------------

/**
 * Zod schema for {@link PiiMatch}.
 */
export const PiiMatchSchema = z.object({
  category: PiiCategorySchema,
  value: z.string(),
  start: z.number().int().nonnegative(),
  end: z.number().int().positive(),
  confidence: z.number().min(0).max(1),
});

/**
 * Zod schema for {@link AnonymizeResult}.
 */
export const AnonymizeResultSchema = z.object({
  text: z.string(),
  matches: z.array(PiiMatchSchema),
});

// ---------------------------------------------------------------------------
// Anonymize options schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for a single {@link AnonymizationRule}.
 */
export const AnonymizationRuleSchema = z.object({
  category: PiiCategorySchema,
  strategy: StrategyOptionsSchema,
});

/**
 * Zod schema for a {@link CustomPattern}.
 */
export const CustomPatternSchema = z.object({
  pattern: z.instanceof(RegExp, { message: "pattern must be a RegExp instance" }),
  category: z.string().min(1).optional(),
  confidence: z.number().min(0).max(1).optional(),
  label: z.string().min(1, "label must not be empty").optional(),
});

/**
 * Zod schema for {@link AnonymizeOptions}.
 */
export const AnonymizeOptionsSchema = z.object({
  rules: z.array(AnonymizationRuleSchema).optional(),
  defaultStrategy: StrategyOptionsSchema.optional(),
  includeMatches: z.boolean().default(false).optional(),
  customPatterns: z.array(CustomPatternSchema).optional(),
  globalReplacement: z.string().min(1, "globalReplacement must not be empty").optional(),
  consistentTokens: z.boolean().default(false).optional(),
  aggressive: z.boolean().default(false).optional(),
  enabledCategories: z.record(PiiCategorySchema, z.boolean()).optional(),
});

// ---------------------------------------------------------------------------
// Field-level anonymization schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for a single field rule.
 */
export const FieldRuleSchema = z.object({
  strategy: StrategyOptionsSchema,
});

/**
 * Zod schema for a {@link FieldRuleMap}.
 */
export const FieldRuleMapSchema = z.record(z.string(), FieldRuleSchema);

// ---------------------------------------------------------------------------
// JSON Schema / OpenAI function-calling definitions
// ---------------------------------------------------------------------------

/**
 * A minimal JSON Schema representation extracted from a Zod schema.
 * Suitable for use in OpenAI function definitions, MCP tool definitions, etc.
 */
export interface JsonSchemaDefinition {
  readonly type: string;
  readonly description?: string;
  readonly properties?: Record<string, JsonSchemaDefinition>;
  readonly items?: JsonSchemaDefinition;
  readonly enum?: readonly string[];
  readonly required?: readonly string[];
  readonly anyOf?: readonly JsonSchemaDefinition[];
  readonly default?: unknown;
}

/**
 * OpenAI-compatible function definition shape.
 */
export interface OpenAiFunctionDefinition {
  readonly name: string;
  readonly description: string;
  readonly parameters: {
    readonly type: "object";
    readonly properties: Record<string, JsonSchemaDefinition>;
    readonly required?: readonly string[];
  };
}

/**
 * Pre-built OpenAI / MCP tool definition for the `anonymize` function.
 *
 * @example
 * ```ts
 * import { ANONYMIZE_TOOL_DEFINITION } from "anonyma/schemas";
 *
 * // Pass directly to OpenAI client tools array:
 * const response = await openai.chat.completions.create({
 *   model: "gpt-4o",
 *   tools: [{ type: "function", function: ANONYMIZE_TOOL_DEFINITION }],
 *   messages: [...],
 * });
 * ```
 */
export const ANONYMIZE_TOOL_DEFINITION: OpenAiFunctionDefinition = {
  name: "anonymize",
  description:
    "Detect and anonymize PII (personally identifiable information) in a text string. " +
    "Returns the anonymized text and, optionally, a list of detected PII matches.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The input text to anonymize.",
      },
      defaultStrategy: {
        type: "object",
        description:
          "The anonymization strategy to apply to all detected PII. " +
          "Defaults to `{ strategy: 'redact' }`.",
        properties: {
          strategy: {
            type: "string",
            enum: ["mask", "redact", "pseudonymize", "hash", "generalize"] as const,
          },
        },
        required: ["strategy"],
      },
      includeMatches: {
        type: "boolean",
        description: "When true, include detected PII matches in the response.",
      },
      globalReplacement: {
        type: "string",
        description:
          "When set, every detected PII entity is replaced with this exact string, " +
          "overriding per-category rules and defaultStrategy.",
      },
      consistentTokens: {
        type: "boolean",
        description:
          "When true, identical PII values receive the same token (e.g. EMAIL_1) " +
          "across the entire call. Different values get different tokens.",
      },
      aggressive: {
        type: "boolean",
        description:
          "When true, detectors use expanded, more permissive patterns to catch " +
          "obfuscated PII at the cost of higher false-positive rates.",
      },
    },
    required: ["text"],
  },
};

/**
 * Pre-built OpenAI / MCP tool definition for the `detect` function.
 */
export const DETECT_TOOL_DEFINITION: OpenAiFunctionDefinition = {
  name: "detect",
  description:
    "Detect all PII (email, phone, SSN, credit card, IP, URL, IBAN, date-of-birth, name) " +
    "in a text string without modifying it. Returns a list of matches.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The input text to scan for PII.",
      },
      categories: {
        type: "array",
        description:
          "Optional subset of PII categories to detect. " +
          "Defaults to all supported categories.",
        items: {
          type: "string",
          enum: [
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
          ] as const,
        },
      },
    },
    required: ["text"],
  },
};

/**
 * Pre-built OpenAI / MCP tool definition for the `hasPII` function.
 *
 * @example
 * ```ts
 * import { HAS_PII_TOOL_DEFINITION } from "anonyma/schemas";
 *
 * const response = await openai.chat.completions.create({
 *   tools: [{ type: "function", function: HAS_PII_TOOL_DEFINITION }],
 *   messages: [...],
 * });
 * ```
 */
export const HAS_PII_TOOL_DEFINITION: OpenAiFunctionDefinition = {
  name: "hasPII",
  description:
    "Check whether a text string contains any detectable PII without redacting it. " +
    "Returns true/false. Uses early-exit optimisation — stops scanning after the first match.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The input text to check for PII.",
      },
      categories: {
        type: "array",
        description: "Optional subset of PII categories to check. Defaults to all.",
        items: {
          type: "string",
          enum: [
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
          ] as const,
        },
      },
    },
    required: ["text"],
  },
};

/**
 * Pre-built OpenAI / MCP tool definition for the `anonymizeObject` function.
 *
 * @example
 * ```ts
 * import { ANONYMIZE_OBJECT_TOOL_DEFINITION } from "anonyma/schemas";
 * ```
 */
export const ANONYMIZE_OBJECT_TOOL_DEFINITION: OpenAiFunctionDefinition = {
  name: "anonymizeObject",
  description:
    "Recursively anonymize all string values found in a JSON-serializable object tree. " +
    "Returns a deep clone with PII replaced. Arrays, nested objects, and mixed structures " +
    "are all handled. Non-string primitives pass through unchanged.",
  parameters: {
    type: "object",
    properties: {
      obj: {
        type: "object",
        description: "The JSON-serializable object to anonymize.",
      },
      options: {
        type: "object",
        description: "Optional anonymization configuration (same as anonymize() options).",
        properties: {
          globalReplacement: {
            type: "string",
            description: "Replace all PII with this exact string.",
          },
          consistentTokens: {
            type: "boolean",
            description: "Same PII value → same token across the entire object.",
          },
          aggressive: {
            type: "boolean",
            description: "Enable more permissive detection patterns.",
          },
        },
      },
    },
    required: ["obj"],
  },
};

// ---------------------------------------------------------------------------
// AI-readable capability manifest
// ---------------------------------------------------------------------------

/**
 * Machine-readable manifest describing anonyma's capabilities.
 * Useful for AI agents that need to discover and reason about available tools.
 *
 * @example
 * ```ts
 * import { ANONYMA_MANIFEST } from "anonyma/schemas";
 *
 * // Provide to an AI agent as system context:
 * const systemPrompt = `You have access to the following data privacy tool:\n\n${JSON.stringify(ANONYMA_MANIFEST, null, 2)}`;
 * ```
 */
export const ANONYMA_MANIFEST = {
  name: "anonyma",
  version: "1.0.0",
  description:
    "TypeScript-first PII detection & anonymization — 26 built-in detectors (email, SSN, IBAN, passport, credit card, and more), 8 strategies (mask, redact, hash, AES-256 encrypt, tokenize, pseudonymize, generalize, synthesize), 6 compliance presets (GDPR, HIPAA, CCPA, PCI-DSS, SOX, FERPA), reversible tokenization, LLM/AI pipeline helpers, WHATWG streaming, batch processing, checksum validators, and optional Zod/MCP schemas. Zero runtime dependencies.",
  capabilities: {
    detect: {
      description: "Detect PII in free text without modifying it.",
      supportedCategories: [
        "email", "phone", "ssn", "credit-card", "ipv4", "ipv6", "url",
        "iban", "date-of-birth", "name", "address", "passport", "drivers-license",
        "national-id", "bank-account", "cryptocurrency", "tax-id", "medical-record",
        "health-insurance", "prescription", "api-key", "social-media", "vin",
        "license-plate", "tracking-number", "case-number", "company-registration",
      ],
      notes: {
        name:
          "Name detection is heuristic — only catches names preceded by greeting keywords " +
          "(e.g. 'Dear Alice'). Not an NLP-based named-entity recogniser.",
      },
      returns: "Array of PiiMatch objects with category, value, position, and confidence.",
    },
    hasPII: {
      description:
        "Return true/false indicating whether a string contains detectable PII. " +
        "Uses early-exit optimisation for performance.",
      returns: "boolean",
    },
    anonymize: {
      description: "Detect and replace PII in free text using a configurable strategy.",
      strategies: {
        mask: "Replace characters with a mask char, keeping optional leading/trailing chars.",
        redact: "Replace the entire value with a label such as [REDACTED].",
        pseudonymize:
          "Replace with a deterministic pseudonym (requires seed for reproducibility).",
        hash: "Replace with a one-way SHA-256 hash (requires Node.js ≥ 18).",
        generalize: "Replace a numeric value with a bucket range (e.g. 27 → 20-29).",
        tokenize: "Replace with a reversible opaque token ([CATEGORY_NNNN]) for LLM pipelines.",
        encrypt: "Replace with AES-GCM ciphertext (requires Node.js ≥ 18 + passphrase/key).",
        synthesize: "Replace with structurally-valid synthetic data (format-preserving).",
      },
      options: {
        globalReplacement: "Override ALL strategy outputs with a single replacement string.",
        consistentTokens:
          "Same PII value → same token (EMAIL_1, PHONE_2, etc.) within a call.",
        aggressive:
          "Use expanded, more permissive regex patterns to catch obfuscated PII.",
        enabledCategories: "Convenience boolean map for enabling/disabling categories.",
        customPatterns: "Ad-hoc regex patterns merged into the detection pipeline.",
        customDetectors: "Override built-in detectors on a per-category basis.",
        preset: "Apply a compliance preset (gdpr | hipaa | ccpa | pci-dss | sox | ferpa).",
        allowlist: "String values that should never be anonymized even when detected as PII.",
        confidenceThreshold: "Minimum confidence score (0-1) for a match to be anonymized.",
      },
      returns: "AnonymizeResult { text: string; matches: PiiMatch[] }",
    },
    tokenize: {
      description:
        "Replace PII with reversible opaque tokens. Use detokenize() to restore.",
      returns: "TokenizeResult { text: string; mapping: Map<string, string> }",
    },
    anonymizeObject: {
      description:
        "Recursively anonymize all string values in a JSON-serializable object tree. " +
        "Deep-clones the input — no mutation. Detects circular references.",
      returns: "A new object of the same shape with all string PII anonymized.",
    },
    anonymizeRecord: {
      description: "Anonymize specific fields in a JSON object using dot-notation paths.",
      returns: "A new object with the specified fields anonymized.",
    },
    batch: {
      description:
        "anonymizeBatch / tokenizeBatch / detectBatch — process arrays of text. " +
        "Per-item errors are collected without aborting the rest of the batch.",
      returns: "BatchResult<T>[] where ok/error per item is available.",
    },
    presets: {
      description: "GDPR, HIPAA, CCPA, PCI-DSS, SOX, FERPA compliance presets.",
      available: ["gdpr", "hipaa", "ccpa", "pci-dss", "sox", "ferpa"],
    },
  },
  toolDefinitions: {
    openai: [
      ANONYMIZE_TOOL_DEFINITION,
      DETECT_TOOL_DEFINITION,
      HAS_PII_TOOL_DEFINITION,
      ANONYMIZE_OBJECT_TOOL_DEFINITION,
    ],
  },
} as const;

// ---------------------------------------------------------------------------
// Inferred TypeScript types from Zod schemas
// ---------------------------------------------------------------------------

export type PiiCategoryInput = z.infer<typeof PiiCategorySchema>;
export type StrategyOptionsInput = z.infer<typeof StrategyOptionsSchema>;
export type AnonymizeOptionsInput = z.infer<typeof AnonymizeOptionsSchema>;
export type AnonymizationRuleInput = z.infer<typeof AnonymizationRuleSchema>;
export type CustomPatternInput = z.infer<typeof CustomPatternSchema>;
export type PiiMatchOutput = z.infer<typeof PiiMatchSchema>;
export type AnonymizeResultOutput = z.infer<typeof AnonymizeResultSchema>;
export type FieldRuleInput = z.infer<typeof FieldRuleSchema>;
export type FieldRuleMapInput = z.infer<typeof FieldRuleMapSchema>;
