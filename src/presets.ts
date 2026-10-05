/**
 * @module presets
 * @description Built-in compliance preset configurations for GDPR, LGPD,
 * PIPEDA, CCPA/CPRA, HIPAA, PCI-DSS, SOX, and FERPA. Import from `"anonyma"`
 * or extend using the `preset` option in {@link AnonymizeOptions}.
 *
 * A preset selects the categories that the library can detect for an
 * instrument and the strategy applied to them. The legal provisions behind
 * each category, and the data elements each instrument names that no detector
 * covers, are documented in `"anonyma/compliance"`.
 *
 * @example
 * ```ts
 * import { anonymize } from "anonyma";
 *
 * // Apply HIPAA preset — redacts the Safe Harbor identifiers that have a detector
 * anonymize(text, { preset: "hipaa" });
 *
 * // Extend GDPR preset with API key detection (anonymize() uses the preset's categories)
 * import { compilePipeline } from "anonyma/engine";
 * compilePipeline({ preset: "gdpr", categories: [...getPreset("gdpr").categories, "api-key"] });
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
 * Covers the HIPAA Safe Harbor identifiers that can be detected in text.
 * Default strategy: redact (no reconstructability).
 *
 * The 18 Safe Harbor identifiers are listed below. City, county, ZIP code,
 * dates other than birth dates, ages over 89, device identifiers, biometrics
 * and photographs have no detector and need field-level rules:
 * 1. Names, 2. Geographic data, 3. Dates (except year), 4. Phone numbers,
 * 5. Fax numbers, 6. Email addresses, 7. SSNs, 8. MRN, 9. Health plan beneficiary numbers,
 * 10. Account numbers, 11. Certificate/license numbers, 12. VINs, 13. Device identifiers,
 * 14. URLs, 15. IP addresses, 16. Biometric identifiers, 17. Full-face photos,
 * 18. Unique identifying numbers/codes (NPI, DEA, etc.)
 */
const HIPAA_PRESET: PresetConfig = {
  name: "hipaa",
  description:
    "US HIPAA Safe Harbor — Redacts the identifiers of 45 CFR 164.514(b)(2)(i) that can be " +
    "detected in text. City, county, ZIP code, dates other than birth dates, ages over 89, " +
    "device identifiers, biometrics and photographs need field-level rules.",
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
    "credit-card",
    "iban",
    "drivers-license",
    "passport",
    "vin",
    "license-plate",
    "url",
    "ipv4",
    "ipv6",
    "national-id",
    "tax-id",
    "social-media",
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
    "medical-record",
    "health-insurance",
    "api-key",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * LGPD — Lei Geral de Proteção de Dados Pessoais (Brazil, Lei nº 13.709/2018).
 * Covers dados pessoais and the identifiers that lead to dados pessoais sensíveis.
 * Default strategy: redact (anonymisation in the sense of Art. 5, XI).
 */
const LGPD_PRESET: PresetConfig = {
  name: "lgpd",
  description:
    "Brazilian Lei Geral de Proteção de Dados — Covers personal data that identifies a " +
    "natural person. CPF is detected in its punctuated form; CNPJ, RG, CNH and CEP need " +
    "custom patterns.",
  categories: [
    "name",
    "email",
    "phone",
    "address",
    "date-of-birth",
    "national-id",
    "tax-id",
    "passport",
    "drivers-license",
    "bank-account",
    "iban",
    "credit-card",
    "cryptocurrency",
    "ipv4",
    "ipv6",
    "url",
    "social-media",
    "license-plate",
    "medical-record",
    "health-insurance",
    "prescription",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * PIPEDA — Personal Information Protection and Electronic Documents Act (Canada).
 * Covers information about an identifiable individual.
 * Default strategy: redact.
 */
const PIPEDA_PRESET: PresetConfig = {
  name: "pipeda",
  description:
    "Canadian PIPEDA — Covers information about an identifiable individual, including the " +
    "Social Insurance Number. Provincial health card numbers and postal codes need custom " +
    "patterns.",
  categories: [
    "name",
    "email",
    "phone",
    "address",
    "date-of-birth",
    "national-id",
    "ssn",
    "passport",
    "drivers-license",
    "tax-id",
    "bank-account",
    "iban",
    "credit-card",
    "ipv4",
    "ipv6",
    "social-media",
    "medical-record",
    "health-insurance",
    "prescription",
  ],
  defaultStrategy: { strategy: "redact" },
};

/**
 * PCI-DSS — Payment Card Industry Data Security Standard.
 * Covers the card number and the cardholder data around it. Sensitive
 * authentication data (card verification codes, track data, PINs) has no
 * detector.
 * Default strategy: redact. Card and bank account numbers are masked with
 * the last 4 digits visible (industry standard).
 */
const PCI_DSS_PRESET: PresetConfig = {
  name: "pci-dss",
  description:
    "PCI-DSS Cardholder Data — Covers credit/debit card numbers, bank accounts, " +
    "and associated cardholder identifiers.",
  categories: ["credit-card", "bank-account", "name", "address", "email", "phone"],
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
  categories: ["name", "email", "phone", "address", "date-of-birth", "ssn", "national-id"],
  defaultStrategy: { strategy: "redact" },
};

// ---------------------------------------------------------------------------
// Registry & lookup
// ---------------------------------------------------------------------------

/** All built-in presets keyed by name. */
export const PRESET_REGISTRY: Readonly<Record<CompliancePreset, PresetConfig>> = {
  gdpr: GDPR_PRESET,
  lgpd: LGPD_PRESET,
  pipeda: PIPEDA_PRESET,
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
