/**
 * @module anonyma
 * @description
 * **anonyma** — A modern, zero-dependency data anonymization and PII detection
 * library for the AI era.
 *
 * ## Quick Start
 *
 * ```ts
 * import { anonymize, detect, hasPII, anonymizeObject, mask, redact } from "anonyma";
 *
 * // Detect all PII in a string
 * const matches = detect("Contact alice@example.com or 555-867-5309.");
 *
 * // Quick boolean check
 * hasPII("alice@example.com"); // true
 * hasPII("no pii here");       // false
 *
 * // Anonymize all PII with the default redact strategy
 * const { text } = anonymize("Contact alice@example.com or 555-867-5309.");
 * // "Contact [REDACTED] or [REDACTED]."
 *
 * // Consistent token mapping — same value → same label
 * anonymize("alice@example.com and alice@example.com", { consistentTokens: true });
 * // "EMAIL_1 and EMAIL_1"
 *
 * // Reversible tokenization for LLM pipelines
 * import { tokenize, detokenize, sanitizeForLLM, restoreFromLLM } from "anonyma";
 * const { text: sanitized, mapping } = sanitizeForLLM("Email alice@example.com");
 * const restored = restoreFromLLM(llmResponse, mapping);
 *
 * // Compliance presets
 * const { text } = anonymize("...", { preset: "hipaa" });
 *
 * // Batch processing
 * import { anonymizeBatch } from "anonyma";
 * const results = anonymizeBatch(["alice@example.com", "192.0.2.1"]);
 * ```
 *
 * ## Subpath Imports
 *
 * - `"anonyma"` — Core API (no Zod dependency)
 * - `"anonyma/detectors"` — Individual PII detectors + registry
 * - `"anonyma/schemas"` — Zod schemas + AI/MCP tool definitions (requires `zod`)
 * - `"anonyma/validators"` — Checksum validators (Luhn, IBAN mod-97, NHS, etc.)
 * - `"anonyma/stream"` — WHATWG TransformStream wrappers (Node ≥ 18)
 */

// Core functions
export {
  anonymize,
  anonymizeAsync,
  detect,
  anonymizeRecord,
  anonymizeObject,
  hasPII,
  createAnonymizer,
} from "./anonymize.js";

// Reversible tokenization
export { tokenize, tokenizeAsync, detokenize } from "./tokenize.js";

// LLM helpers
export { sanitizeForLLM, restoreFromLLM } from "./llm.js";

// Batch processing
export { anonymizeBatch, anonymizeBatchAsync, tokenizeBatch, detectBatch } from "./batch.js";

// Compliance presets
export { getPreset, PRESET_REGISTRY } from "./presets.js";

// Individual strategies (tree-shakeable)
export { mask } from "./strategies/mask.js";
export { redact } from "./strategies/redact.js";
export { pseudonymize } from "./strategies/pseudonymize.js";
export { hash } from "./strategies/hash.js";
export { generalize } from "./strategies/generalize.js";
export { encrypt, decrypt } from "./strategies/encrypt.js";
export { synthesize } from "./strategies/synthesize.js";

// Error classes
export {
  AnonymaError,
  ValidationError,
  UnsupportedStrategyError,
  UnknownCategoryError,
  CryptoNotAvailableError,
  EncryptionError,
  PresetNotFoundError,
  AllowlistMatchError,
  BatchProcessingError,
} from "./errors.js";

// TypeScript types (type-only exports — zero runtime cost)
export type {
  PiiCategory,
  PiiMatch,
  StrategyName,
  MaskOptions,
  RedactOptions,
  PseudonymizeOptions,
  HashOptions,
  GeneralizeOptions,
  TokenizeOptions,
  TokenizeResult,
  DetokenizeResult,
  TokenFormat,
  EncryptOptions,
  SynthesizeOptions,
  BatchResult,
  CompliancePreset,
  Locale,
  StrategyOptions,
  AnonymizationRule,
  AnonymizeOptions,
  AnonymizeResult,
  CustomPattern,
  FieldRule,
  FieldRuleMap,
  Detector,
  DetectorRegistry,
  Anonymizer,
  AnonymizerConfig,
  ValidatorFunction,
  AnonymaPlugin,
} from "./types.js";

export type { PresetConfig } from "./presets.js";
