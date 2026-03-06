/**
 * @module strategies
 * @description Barrel export for all built-in anonymization strategies.
 *
 * @example
 * ```ts
 * import { mask, redact, pseudonymize, hash, generalize } from "anonyma";
 *
 * mask("alice@example.com", { keepLeading: 1, keepTrailing: 3 });
 * // "a**************com"
 *
 * redact("123-45-6789");
 * // "[REDACTED]"
 *
 * pseudonymize("alice@example.com", { seed: "secret" });
 * // "id_3a7f1c2b9e4d0f1a"
 *
 * await hash("alice@example.com", { pepper: "my-pepper" });
 * // "5f3e4b3a9c1d8f2a"
 *
 * generalize("27");
 * // "20-29"
 * ```
 */

export { mask } from "./mask.js";
export { redact } from "./redact.js";
export { pseudonymize } from "./pseudonymize.js";
export { hash } from "./hash.js";
export { generalize } from "./generalize.js";
export { encrypt, decrypt } from "./encrypt.js";
export { synthesize } from "./synthesize.js";
export { assignToken, resolveToken, detokenizeText, createTokenStore } from "./tokenize.js";

