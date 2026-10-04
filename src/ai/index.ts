/**
 * @module ai
 * @description AI-native redaction, exposed as `"anonyma/ai"`:
 * structure-preserving JSON sanitization, prompt and chat-message
 * sanitization with reversible tokens, and restoration of tokens in complete
 * and streamed model output.
 *
 * @example
 * ```ts
 * import { createLlmGuard } from "anonyma/ai";
 *
 * const exchange = createLlmGuard().begin();
 * const { messages } = exchange.sanitizeMessages(chatMessages);
 * const answer = exchange.restoreText(await llm.complete(messages)).text;
 * ```
 */

export { sanitizeJson, sanitizeJsonAsync } from "./json.js";
export type { JsonSanitizeOptions, JsonSanitizeResult, KeyRule } from "./json.js";
export {
  contentLens,
  createRestoreStream,
  createRestoreTransformer,
  deltaLens,
  restoreChunks,
  restoreJsonText,
  textDeltaLens,
} from "./restore.js";
export type { ChunkLens } from "./restore.js";
export { createLlmGuard, toLanguageModelMiddleware } from "./guard.js";
export type {
  LanguageModelMiddlewareLike,
  LanguageModelMiddlewareOptions,
  LlmExchange,
  LlmGuard,
  LlmGuardOptions,
  SanitizedMessages,
} from "./guard.js";
