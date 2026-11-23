/*
 * anonyma: the C ABI of anonyma-core (crates/anonyma-ffi).
 *
 * Every function that returns a string returns JSON text owned by the
 * caller: {"ok": <result>} or {"error": "<message>"}. Free it with
 * anonyma_string_free. Strings passed in are NUL-terminated UTF-8.
 * The operations and their inputs are those of the conformance suite
 * (packages/conformance/README.md), plus "capabilities" and "validators".
 */
#ifndef ANONYMA_H
#define ANONYMA_H

#ifdef __cplusplus
extern "C" {
#endif

/* A token vault owned by the caller. It holds original values in clear. */
typedef struct AnonymaVault AnonymaVault;

/* Perform an operation ("detect", "anonymize", "validate", ...). */
char *anonyma_call(const char *op, const char *input_json);

/* A new, empty token vault; free it with anonyma_vault_free. */
AnonymaVault *anonyma_vault_new(void);

/* anonyma_call with a vault: "shield" stores tokens in it, "restore" reads them.
 * A vault must not be used by two threads at once. */
char *anonyma_vault_call(AnonymaVault *vault, const char *op, const char *input_json);

/* Free a vault and every value it holds. */
void anonyma_vault_free(AnonymaVault *vault);

/* An engine built once from options and reused: each call skips parsing the
 * options and building the detectors. It may be shared by threads. */
typedef struct AnonymaEngine AnonymaEngine;

/* Build an engine from JSON options (categories, preset, rules,
 * defaultStrategy, aggressive, strict, allowPartial). Returns NULL on failure,
 * and then, when error is not NULL, stores an error JSON string in it to free
 * with anonyma_string_free. */
AnonymaEngine *anonyma_engine_new(const char *options_json, char **error);

/* "detect" and "anonymize" on input.text; "detect_batch" and "anonymize_batch"
 * on input.texts, answering {"results": [...]} in order (short texts are
 * scanned together). "offsets" as for anonyma_call. */
char *anonyma_engine_call(const AnonymaEngine *engine, const char *op, const char *input_json);

/* Free an engine. */
void anonyma_engine_free(AnonymaEngine *engine);

/* Free a string returned by this library. */
void anonyma_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif /* ANONYMA_H */
