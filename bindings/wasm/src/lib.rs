//! WebAssembly bindings of `anonyma-core` (wasm-bindgen), for browsers,
//! Cloudflare Workers, Deno and Bun: the JSON API and a vault handle. Pass
//! `"offsets": "utf-16"` to index JavaScript strings.

use anonyma_core::InMemoryVault;
use anonyma_ffi::api::{call_json, call_json_with_vault};
use wasm_bindgen::prelude::*;

/// Perform an operation of the JSON API: returns `{"ok": ...}` or `{"error": ...}`.
#[wasm_bindgen]
pub fn call(op: &str, input_json: &str) -> String {
    call_json(op, input_json)
}

/// The version of the Rust core.
#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    anonyma_core::VERSION.to_string()
}

/// A token vault: `shield` stores tokens in it, `restore` reads them.
#[wasm_bindgen]
pub struct Vault {
    inner: InMemoryVault,
}

#[wasm_bindgen]
impl Vault {
    /// An empty vault.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Vault {
        Vault {
            inner: InMemoryVault::new(),
        }
    }

    /// [`call`] with this vault.
    pub fn call(&mut self, op: &str, input_json: &str) -> String {
        call_json_with_vault(op, input_json, Some(&mut self.inner))
    }

    /// Number of tokens held.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.inner.len()
    }
}
