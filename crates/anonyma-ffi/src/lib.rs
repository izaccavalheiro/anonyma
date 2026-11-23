//! # anonyma-ffi
//!
//! [`api`]: the JSON API of `anonyma-core`, shared by the bindings that cannot
//! pass Rust types (Node.js, WebAssembly, Go). With the `c-abi` feature
//! (default), the C functions declared in `include/anonyma.h`:
//!
//! ```c
//! char *anonyma_call(const char *op, const char *input_json);
//! AnonymaVault *anonyma_vault_new(void);
//! char *anonyma_vault_call(AnonymaVault *vault, const char *op, const char *input_json);
//! void anonyma_vault_free(AnonymaVault *vault);
//! void anonyma_string_free(char *text);
//! ```
//!
//! Every call returns `{"ok": result}` or `{"error": message}` as JSON text,
//! never null for valid arguments, and never unwinds a panic across the
//! boundary.

pub mod api;

#[cfg(feature = "c-abi")]
mod c_abi;

#[cfg(feature = "c-abi")]
pub use c_abi::*;
