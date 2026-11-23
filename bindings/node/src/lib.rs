//! Node.js and Bun bindings of `anonyma-core` (napi-rs): the JSON API and a
//! vault handle. Offsets: pass `"offsets": "utf-16"` to index JavaScript
//! strings.
//!
//! The TypeScript package `anonyma` does not use it: the core benchmark
//! (`bench/core.mjs`) found no case for a native engine in the npm package
//! (docs/rfcs/0001-polyglot-core.md). The benchmark loads this addon.

use anonyma_core::InMemoryVault;
use anonyma_ffi::api::{call_json, call_json_with_vault};
use napi_derive::napi;

/// Perform an operation of the JSON API: returns `{"ok": ...}` or `{"error": ...}`.
#[napi]
pub fn call(op: String, input_json: String) -> String {
    call_json(&op, &input_json)
}

/// The version of the Rust core.
#[napi]
pub fn core_version() -> String {
    anonyma_core::VERSION.to_string()
}

/// A token vault: `shield` stores tokens in it, `restore` reads them.
#[napi]
pub struct Vault {
    inner: InMemoryVault,
}

#[napi]
impl Vault {
    /// An empty vault.
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Vault {
            inner: InMemoryVault::new(),
        }
    }

    /// [`call`] with this vault.
    #[napi]
    pub fn call(&mut self, op: String, input_json: String) -> String {
        call_json_with_vault(&op, &input_json, Some(&mut self.inner))
    }

    /// Number of tokens held.
    #[napi(getter)]
    pub fn size(&self) -> u32 {
        u32::try_from(self.inner.len()).unwrap_or(u32::MAX)
    }
}
