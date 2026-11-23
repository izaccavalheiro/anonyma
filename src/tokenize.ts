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
import {
  createTokenStore,
  assignToken,
  detokenizeText,
  LEGACY_TOKEN_PATTERN,
} from "./strategies/tokenize.js";
import { ValidationError } from "./errors.js";
import { compileAllowlist } from "./internal/allowlist.js";
import { replaceSpans, type Replacement } from "./internal/replace.js";
import { isThenable } from "./vault/anonyma-vault.js";
import type { AnonymaVault } from "./vault/anonyma-vault.js";
import { createVaultTokenizer } from "./vault/vault-tokenizer.js";
import type { VaultTokenizer } from "./vault/vault-tokenizer.js";
import type {
  TokenizeResult,
  DetokenizeResult,
  TokenizeOptions,
  TokenMatch,
  TokenFormat,
  PiiMatch,
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
 *
 * // Keep the tokens in a vault, and restore them later from any text:
 * const vault = new InMemoryVault();
 * tokenize("Mail john@example.com", { vault }).text; // "Mail {{EMAIL_1}}"
 * restore("Sent to {{EMAIL_1}}.", vault).text;       // "Sent to john@example.com."
 * ```
 *
 * @throws {@link ValidationError} When `vault` answers asynchronously; use {@link tokenizeAsync}.
 */
export function tokenize(text: string, options: TokenizeOptions = {}): TokenizeResult {
  const matches = detectForTokenize(text, options);
  if (options.vault !== undefined) {
    const tokenizer = vaultTokenizerFor(options.vault, options.format);
    const placed = matches.map((match) => {
      const token = tokenizer.tokenize(match.value, { category: match.category });
      if (isThenable(token)) {
        // The vault is asynchronous; tokenizeAsync() is the entry point for it.
        void token.catch(() => undefined);
        throw new ValidationError("vault", "answers asynchronously: use tokenizeAsync()");
      }
      return { match, token };
    });
    return replaceInOrder(text, placed);
  }

  const store = createTokenStore();
  const replacements: Replacement[] = [];
  const reversed = [...matches].reverse();
  const tokenMatches: TokenMatch[] = [];
  const format = options.format ?? "bracket";

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
    replacements.push({ start: match.start, end: match.end, replacement: token });
  }

  return {
    text: replaceSpans(text, replacements.reverse()),
    mapping: store.tokens,
    tokens: tokenMatches,
  };
}

// ---------------------------------------------------------------------------
// Public: tokenizeAsync()
// ---------------------------------------------------------------------------

/**
 * Async variant of {@link tokenize} — identical behaviour but returns a Promise.
 * It is the entry point for an asynchronous `vault` (Redis, a KV store, …).
 *
 * @example
 * ```ts
 * const { text } = await tokenizeAsync("Mail john@example.com", { vault: redisVault });
 * // "Mail {{EMAIL_1}}"
 * ```
 */
export async function tokenizeAsync(
  text: string,
  options: TokenizeOptions = {},
): Promise<TokenizeResult> {
  if (options.vault === undefined) return tokenize(text, options);
  const matches = detectForTokenize(text, options);
  const tokenizer = vaultTokenizerFor(options.vault, options.format);
  const placed: Placed[] = [];
  for (const match of matches) {
    placed.push({
      match,
      token: await tokenizer.tokenize(match.value, { category: match.category }),
    });
  }
  return replaceInOrder(text, placed);
}

/** The detections `tokenize()` replaces, in document order. */
function detectForTokenize(text: string, options: TokenizeOptions): PiiMatch[] {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");
  const {
    categories,
    customDetectors,
    aggressive = false,
    confidenceThreshold = 0,
    allowlist = [],
    allowlistCaseSensitive = false,
  } = options;
  const isAllowlisted = compileAllowlist(allowlist, [], allowlistCaseSensitive);
  return detect(text, categories, customDetectors, aggressive).filter(
    (m) => m.confidence >= confidenceThreshold && !isAllowlisted(m.value),
  );
}

/** The vault tokenizer for one `tokenize()` call. */
function vaultTokenizerFor(vault: AnonymaVault, format: TokenFormat = "brace"): VaultTokenizer {
  return createVaultTokenizer({ vault, format: format === "custom" ? "angle" : format });
}

/** A detection and the token that replaces it. */
interface Placed {
  readonly match: PiiMatch;
  readonly token: string;
}

/** Replace each match with its token, in document order. */
function replaceInOrder(text: string, placed: readonly Placed[]): TokenizeResult {
  const parts: string[] = [];
  const mapping = new Map<string, string>();
  const tokenMatches: TokenMatch[] = [];
  let cursor = 0;
  for (const { match, token } of placed) {
    parts.push(text.slice(cursor, match.start), token);
    cursor = match.end;
    if (!mapping.has(token)) mapping.set(token, match.value);
    tokenMatches.push({
      token,
      original: match.value,
      category: match.category,
      start: match.start,
      end: match.end,
    });
  }
  parts.push(text.slice(cursor));
  return { text: parts.join(""), mapping, tokens: tokenMatches };
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
export function detokenize(text: string, mapping: ReadonlyMap<string, string>): DetokenizeResult {
  if (typeof text !== "string") throw new ValidationError("text", "must be a string");

  // Build a temporary store from the mapping.
  const store = createTokenStore();
  for (const [token, value] of mapping) {
    store.tokens.set(token, value);
  }

  const result = detokenizeText(text, store);
  // Count how many token occurrences appeared in the text and were resolved.
  // We scan the text for all token-like patterns and subtract the unresolved ones.
  const totalInText = (text.match(LEGACY_TOKEN_PATTERN) ?? []).length;
  const replacedCount = totalInText - result.unresolved.length;
  return {
    text: result.text,
    replacedCount,
    unresolved: result.unresolved,
  };
}
