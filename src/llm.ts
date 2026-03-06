/**
 * @module llm
 * @description Helpers designed for LLM (Large Language Model) pipelines.
 *
 * The pattern is:
 * 1. **Sanitize** user text before sending it to the LLM → all PII replaced with tokens.
 * 2. Send the sanitized text to the LLM.
 * 3. **Restore** the LLM's response by swapping tokens back to original values.
 *
 * Tokens survive typical LLM round-trips because they use a safe character set
 * (`[CATEGORY_NNNN]`) that models rarely re-format.
 *
 * @example
 * ```ts
 * import { sanitizeForLLM, restoreFromLLM } from "anonyma";
 *
 * const { text, mapping } = sanitizeForLLM("Send invoice to alice@example.com");
 * // text: "Send invoice to [EMAIL_0001]"
 *
 * const llmResponse = await callLLM(text);
 * // "I have sent the invoice to [EMAIL_0001]."
 *
 * const final = restoreFromLLM(llmResponse, mapping);
 * // "I have sent the invoice to alice@example.com."
 * ```
 */

import { tokenize, detokenize } from "./tokenize.js";
import type { TokenizeOptions, TokenizeResult, DetokenizeResult } from "./types.js";

// ---------------------------------------------------------------------------
// Public: sanitizeForLLM()
// ---------------------------------------------------------------------------

/**
 * Replace all PII in `text` with reversible opaque tokens before passing the
 * text to a language model.
 *
 * This is a thin convenience wrapper around {@link tokenize} with sensible
 * defaults for LLM use-cases:
 * - `format`: `"bracket"` (tokens are `[CATEGORY_NNNN]`)
 * - Aggressive mode off by default (reduces false-positive noise in prompts)
 *
 * @param text    - The user-supplied text to sanitize.
 * @param options - Optional overrides for tokenization settings.
 * @returns A {@link TokenizeResult}. Pass `mapping` to {@link restoreFromLLM}.
 */
export function sanitizeForLLM(text: string, options: TokenizeOptions = {}): TokenizeResult {
  return tokenize(text, { format: "bracket", aggressive: false, ...options });
}

// ---------------------------------------------------------------------------
// Public: restoreFromLLM()
// ---------------------------------------------------------------------------

/**
 * Replace all tokens in the LLM `response` with their original PII values.
 *
 * Tokens that aren't found in `mapping` are left unchanged (the LLM may have
 * dropped or altered them). Unresolved tokens are reported in the returned
 * `unresolved` array so callers can detect data loss.
 *
 * @param response - The raw response string from the language model.
 * @param mapping  - The `mapping` from the corresponding {@link sanitizeForLLM} call.
 * @returns A {@link DetokenizeResult} with the restored text.
 */
export function restoreFromLLM(
  response: string,
  mapping: ReadonlyMap<string, string>,
): DetokenizeResult {
  return detokenize(response, mapping);
}
