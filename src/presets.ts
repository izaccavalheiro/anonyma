/**
 * @module presets
 * @description Built-in compliance preset configurations for GDPR, HIPAA, CCPA,
 * PCI-DSS, SOX, and FERPA. Import from `"anonyma"` or extend using the
 * `preset` option in {@link AnonymizeOptions}.
 *
 * @example
 * ```ts
 * import { anonymize } from "anonyma";
 *
 * // Apply HIPAA preset — redacts all 18 HIPAA Safe Harbor identifiers
 * anonymize(text, { preset: "hipaa" });
 *
 * // Extend GDPR preset with API key detection
 * anonymize(text, { preset: "gdpr", enabledCategories: { "api-key": true } });
 * ```
 */

import { PresetNotFoundError } from "./errors.js";
import type { CompliancePreset, PiiCategory, StrategyOptions, AnonymizationRule } from "./types.js";

// ---------------------------------------------------------------------------
// Preset definition type
// ---------------------------------------------------------------------------

/**
 * A compliance preset configuration.
 */
export interface PresetConfig {
  /** Display name of the preset. */
  readonly name: CompliancePreset;
  /** Description of what the preset covers. */
  readonly description: string;
  /**
   * PII categories this preset activates.
   * The anonymizer will detect and redact these categories.
   */
  readonly categories: readonly PiiCategory[];
  /**
   * Default strategy applied to all categories in this preset.
   */
  readonly defaultStrategy: StrategyOptions;
  /**
   * Per-category strategy overrides (optional).
   */
  readonly rules?: readonly AnonymizationRule[];
}

// ---------------------------------------------------------------------------
// Individual preset definitions
// ---------------------------------------------------------------------------

/**
 * GDPR — EU General Data Protection Regulation.
 * Covers all personal data that can identify an EU natural person.
 * Default strategy: pseudonymize (allows data utility while protecting identity).
 */
const GDPR_PRESET: PresetConfig = {
  name: "gdpr",
  description:
    "EU General Data Protection Regulation — Covers all categories of personal data " +
    "that can identify a natural person.",
  categories: [
    "name",
    "email",
    "phone",
    "address",
    "date-of-birth",
    "ssn",
    "national-id",
    "passport",
    "drivers-license",
    "iban",
    "bank-account",
    "credit-card",
    "ipv4",
    "ipv6",
    "url",
    "medical-record",
    "health-insurance",
    "prescription",
    "social-media",
    "cryptocurrency",
    "tax-id",
  ],
  defaultStrategy: { strategy: "pseudonymize" },
};

/**
 * HIPAA — US Health Insurance Portability and Accountability Act.
 * Covers the 18 HIPAA Safe Harbor identifiers.
 * Default strategy: redact (no reconstructability).
 *
 * The 18 Safe Harbor identifiers are:
 * 1. Names, 2. Geographic data, 3. Dates (except year), 4. Phone numbers,
 * 5. Fax numbers, 6. Email addresses, 7. SSNs, 8. MRN, 9. Health plan beneficiary numbers,
 * 10. Account numbers, 11. Certificate/license numbers, 12. VINs, 13. Device identifiers,
 * 14. URLs, 15. IP addresses, 16. Biometric identifiers, 17. Full-face photos,
 * 18. Unique identifying numbers/codes (NPI, DEA, etc.)
 */
const HIPAA_PRESET: PresetConfig = {
  name: "hipaa",
  description:
    "US HIPAA Safe Harbor — Covers all 18 protected health information (PHI) identifiers " +
    "to de-identify medical records.",
  categories: [
    "name",
    "address",
    "date-of-birth",
    "phone",
    "email",
    "ssn",
    "medical-record",
    "health-insurance",
    "prescription",
    "bank-account",
    "drivers-license",
    "vin",
    "url",
    "ipv4",
    "ipv6",
    "national-id",
    "tax-id",
    "company-registration",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * CCPA — California Consumer Privacy Act.
 * Covers consumer data categories defined by CCPA.
 * Default strategy: redact.
 */
const CCPA_PRESET: PresetConfig = {
  name: "ccpa",
  description:
    "California Consumer Privacy Act — Covers personal information categories defined " +
    "by CCPA, including identifiers, financial data, and online activity.",
  categories: [
    "name",
    "email",
    "phone",
    "address",
    "ssn",
    "national-id",
    "passport",
    "drivers-license",
    "bank-account",
    "credit-card",
    "tax-id",
    "ipv4",
    "ipv6",
    "url",
    "social-media",
    "date-of-birth",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * PCI-DSS — Payment Card Industry Data Security Standard.
 * Covers cardholder data (CHD) and sensitive authentication data (SAD).
 * Default strategy: mask with last 4 visible (industry standard).
 */
const PCI_DSS_PRESET: PresetConfig = {
  name: "pci-dss",
  description:
    "PCI-DSS Cardholder Data — Covers credit/debit card numbers, bank accounts, " +
    "and associated cardholder identifiers.",
  categories: [
    "credit-card",
    "bank-account",
    "name",
    "address",
    "email",
    "phone",
  ],
  defaultStrategy: { strategy: "redact" },
  rules: [
    {
      category: "credit-card",
      strategy: { strategy: "mask", keepTrailing: 4 },
    },
    {
      category: "bank-account",
      strategy: { strategy: "mask", keepTrailing: 4 },
    },
  ],
};

/**
 * SOX — Sarbanes-Oxley Act.
 * Covers financial audit trail and corporate officer identifiers.
 * Default strategy: redact.
 */
const SOX_PRESET: PresetConfig = {
  name: "sox",
  description:
    "Sarbanes-Oxley Act — Covers financial records, corporate officer identifiers, " +
    "and audit trail data.",
  categories: [
    "name",
    "email",
    "tax-id",
    "bank-account",
    "company-registration",
    "ssn",
    "address",
    "phone",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * FERPA — Family Educational Rights and Privacy Act.
 * Covers student education records.
 * Default strategy: redact.
 */
const FERPA_PRESET: PresetConfig = {
  name: "ferpa",
  description:
    "FERPA — Covers education records and student personally identifiable information (PII).",
  categories: [
    "name",
    "email",
    "phone",
    "address",
    "date-of-birth",
    "ssn",
    "national-id",
  ],
  defaultStrategy: { strategy: "redact" },
};

// ---------------------------------------------------------------------------
// Registry & lookup
// ---------------------------------------------------------------------------

/** All built-in presets keyed by name. */
export const PRESET_REGISTRY: Readonly<Record<CompliancePreset, PresetConfig>> = {
  gdpr: GDPR_PRESET,
  hipaa: HIPAA_PRESET,
  ccpa: CCPA_PRESET,
  "pci-dss": PCI_DSS_PRESET,
  sox: SOX_PRESET,
  ferpa: FERPA_PRESET,
} as const;

/**
 * Get a compliance preset configuration by name.
 *
 * @param name - The preset name.
 * @returns The {@link PresetConfig} for the named preset.
 * @throws {@link PresetNotFoundError} if the preset name is not recognised.
 *
 * @example
 * ```ts
 * import { getPreset } from "anonyma";
 *
 * const preset = getPreset("hipaa");
 * console.log(preset.categories); // ["name", "address", ...]
 * ```
 */
export function getPreset(name: CompliancePreset): PresetConfig {
  const preset = (PRESET_REGISTRY as Partial<Record<CompliancePreset, PresetConfig>>)[name];
  if (preset === undefined) {
    throw new PresetNotFoundError(name);
  }
  return preset;
}
