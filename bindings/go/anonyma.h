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

/* Free a string returned by this library. */
void anonyma_string_free(char *text);

#ifdef __cplusplus
}
#endif

#endif /* ANONYMA_H */
