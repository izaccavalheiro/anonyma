/**
 * @module vault/tokens
 * @description Token grammar shared by the tokenization providers.
 * @internal
 */

import { ValidationError } from "../errors.js";

/** Token prefixes of the built-in categories (the same labels the 1.x tokenizer uses). */
const BUILTIN_PREFIXES: Readonly<Record<string, string>> = {
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
};

/** Source of the pattern every token prefix satisfies. */
export const PREFIX_SOURCE = "[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*";

/** Source of the pattern every key version identifier satisfies. */
export const KEY_ID_SOURCE = "[A-Za-z0-9]{1,16}";

const KEY_ID_PATTERN = new RegExp(`^${KEY_ID_SOURCE}$`);

/**
 * Whether `id` is a valid key version identifier.
 * @internal
 */
export function isKeyId(id: unknown): id is string {
  return typeof id === "string" && KEY_ID_PATTERN.test(id);
}

/** FNV-1a hash of a string, as upper-case base 36. Not cryptographic: it only keeps labels apart. */
function fnv1a(text: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36).toUpperCase();
}

/**
 * Build the function that maps a category to its token prefix.
 *
 * Built-in categories use fixed labels. Any other category is upper-cased and
 * every run of characters outside `[A-Z0-9]` becomes one underscore, so the
 * result always satisfies {@link PREFIX_SOURCE}. A category with no such
 * character at all (a label in another script) gets a prefix derived from a
 * hash of its name, so two such categories never share one.
 *
 * @param overrides - Caller-supplied prefixes, keyed by category.
 * @throws {@link ValidationError} When an override does not satisfy the prefix grammar.
 * @internal
 */
export function prefixResolver(
  overrides: Readonly<Record<string, string>> = {},
): (category: string) => string {
  const custom = new Map<string, string>();
  const valid = new RegExp(`^${PREFIX_SOURCE}$`);
  for (const [category, prefix] of Object.entries(overrides)) {
    if (typeof prefix !== "string" || !valid.test(prefix) || prefix.length > 40) {
      throw new ValidationError(
        `prefixes.${category}`,
        "must be 1-40 characters of A-Z, 0-9 and single underscores, starting with a letter",
      );
    }
    custom.set(category, prefix);
  }

  const derived = new Map<string, string>();
  return (category) => {
    const known = custom.get(category) ?? derived.get(category);
    if (known !== undefined) return known;

    let prefix = Object.hasOwn(BUILTIN_PREFIXES, category) ? BUILTIN_PREFIXES[category] : undefined;
    if (prefix === undefined) {
      // Cut first, then trim: the cut may land right after a separator.
      const cleaned = category
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, "_")
        .replace(/^_+/, "")
        .slice(0, 38)
        .replace(/_+$/, "");
      if (cleaned === "") prefix = `X${fnv1a(category)}`;
      else prefix = /^[A-Z]/.test(cleaned) ? cleaned : `X_${cleaned}`;
    }
    derived.set(category, prefix);
    return prefix;
  };
}
