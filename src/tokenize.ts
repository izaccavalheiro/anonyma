/**
 * @module tokenize
 * @description High-level reversible tokenization API for anonyma.
 *
 * Unlike `anonymize()` — which is one-way — `tokenize()` replaces PII with
 * opaque tokens that can be restored later via `detokenize()`. This is
 * particularly useful for LLM pipelines where the model receives sanitized
 * text and the output must be un-redacted before delivery.
 *
 * @example
 * ```ts
 * import { tokenize, detokenize } from "anonyma";
 *
 * const { text, mapping } = tokenize("Contact alice@example.com");
 * // text:    "Contact [EMAIL_0001]"
 * // mapping: Map { "[EMAIL_0001]" => "alice@example.com" }
 *
 * const original = detokenize(text, mapping);
 * // "Contact alice@example.com"
 * ```
 */

import { detect } from "./anonymize.js";
import { createTokenStore, assignToken, detokenizeText } from "./strategies/tokenize.js";
import { ValidationError } from "./errors.js";
import type {
  TokenizeResult,
  DetokenizeResult,
  TokenizeOptions,
  TokenMatch,
} from "./types.js";

// Category → token prefix mapping (mirrors TOKEN_PREFIX_MAP in anonymize.ts).
const TOKEN_PREFIX_MAP: Record<string, string> = {
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

// ---------------------------------------------------------------------------
// Public: tokenize()
// ---------------------------------------------------------------------------

/**
 * Replace all detected PII in `text` with reversible opaque tokens.
 *
 * The returned `mapping` maps each token back to its original value. Pass it
 * to {@link detokenize} to restore the original text.
 *
 * @param text    - The input string.
 * @param options - Tokenization options (categories, format, custom detectors…).
 * @returns A {@link TokenizeResult} containing `text` and `mapping`.
 *
 * @example
 * ```ts
 * const { text, mapping } = tokenize(
 *   "Email alice@example.com, phone 555-867-5309",
 *   { categories: ["email", "phone"], format: "bracket" }
 * );
 * // text:    "Email [EMAIL_0001], phone [PHONE_0001]"
 * // mapping: Map { "[EMAIL_0001]" => "alice@example.com", "[PHONE_0001]" => "555-867-5309" }
 * ```
 */
export function tokenize(text: string, options: TokenizeOptions = {}): TokenizeResult {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");

  const {
    categories,
    format = "bracket",
    customDetectors,
    aggressive = false,
    confidenceThreshold = 0,
    allowlist = [],
    allowlistCaseSensitive = false,
  } = options;

  const compiledAllowlist = allowlist.map(
    (entry) =>
      new RegExp(entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), allowlistCaseSensitive ? "" : "i"),
  );
  const isAllowlisted = (v: string): boolean => compiledAllowlist.some((re) => re.test(v));

  // Detect PII.
  const allMatches = detect(text, categories, customDetectors, aggressive).filter(
    (m) => m.confidence >= confidenceThreshold && !isAllowlisted(m.value),
  );

  const store = createTokenStore();
  let result = text;
  const reversed = [...allMatches].reverse();
  const tokenMatches: TokenMatch[] = [];

  for (const match of reversed) {
    const prefix = TOKEN_PREFIX_MAP[match.category] ?? match.category.toUpperCase();
    const token = assignToken(store, match.category, match.value, prefix, format);
    tokenMatches.push({
      token,
      original: match.value,
      category: match.category,
      start: match.start,
      end: match.end,
    });
    result = result.slice(0, match.start) + token + result.slice(match.end);
  }

  return { text: result, mapping: store.tokens, tokens: tokenMatches };
}

// ---------------------------------------------------------------------------
// Public: tokenizeAsync()
// ---------------------------------------------------------------------------

/**
 * Async variant of {@link tokenize} — identical behaviour but returns a Promise.
 * Useful for consistency in async pipelines.
 */
export function tokenizeAsync(
  text: string,
  options: TokenizeOptions = {},
): Promise<TokenizeResult> {
  return Promise.resolve(tokenize(text, options));
}

// ---------------------------------------------------------------------------
// Public: detokenize()
// ---------------------------------------------------------------------------

/**
 * Restore all tokens in `text` using the `mapping` returned by {@link tokenize}.
 *
 * Tokens not present in `mapping` are left unchanged and reported in
 * `unresolved`.
 *
 * @param text    - A tokenized string produced by {@link tokenize}.
 * @param mapping - The `mapping` from the matching {@link TokenizeResult}.
 * @returns A {@link DetokenizeResult} with the restored `text` and
 *   any `unresolved` tokens.
 *
 * @example
 * ```ts
 * const original = detokenize("[EMAIL_0001]", new Map([["[EMAIL_0001]", "alice@example.com"]]));
 * // { text: "alice@example.com", unresolved: [] }
 * ```
 */
export function detokenize(
  text: string,
  mapping: ReadonlyMap<string, string>,
): DetokenizeResult {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");

  // Build a temporary store from the mapping.
  const store = createTokenStore();
  for (const [token, value] of mapping) {
    store.tokens.set(token, value);
  }

  const result = detokenizeText(text, store);
  // Count how many token occurrences appeared in the text and were resolved.
  // We scan the text for all token-like patterns and subtract the unresolved ones.
  const TOKEN_RE = /(\[[A-Z_]+_\d+\]|<[A-Z_]+_\d+>)/g;
  const totalInText = (text.match(TOKEN_RE) ?? []).length;
  const replacedCount = totalInText - result.unresolved.length;
  return {
    text: result.text,
    replacedCount,
    unresolved: result.unresolved,
  };
}
