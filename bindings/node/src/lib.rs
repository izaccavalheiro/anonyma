//! Node.js and Bun bindings of `anonyma-core` (napi-rs), published as
//! `anonyma-native`: an [`Engine`] built once from anonyma's options, the JSON
//! API and a vault handle. Offsets of the engine are UTF-16 code units, as
//! JavaScript strings index them; the JSON API takes `"offsets": "utf-16"`.
//!
//! The TypeScript package `anonyma` never loads it: applications opt in
//! (docs/rfcs/0001-polyglot-core.md, step 4).

use anonyma_core::offsets::OffsetMap;
use anonyma_core::{AnonymaEngine, InMemoryVault, Match};
use anonyma_ffi::api::{call_json, call_json_with_vault, engine_json};
use napi::bindgen_prelude::{Error, Result};
use napi_derive::napi;

/// A value found, as `PiiMatch` of anonyma: offsets in UTF-16 code units.
#[napi(object)]
pub struct NativeMatch {
    pub category: String,
    pub value: String,
    pub start: u32,
    pub end: u32,
    pub confidence: f64,
}

/// An anonymized text and, when asked for, the values replaced.
#[napi(object)]
pub struct NativeAnonymized {
    pub text: String,
    pub matches: Vec<NativeMatch>,
}

/// One entry of an anonymized batch: the result, or the error of that text.
#[napi(object)]
pub struct NativeAnonymizedEntry {
    pub value: Option<NativeAnonymized>,
    pub error: Option<String>,
}

fn offset(map: &OffsetMap<'_>, byte: usize) -> u32 {
    u32::try_from(map.utf16(byte)).unwrap_or(u32::MAX)
}

fn matches_of(text: &str, matches: Vec<Match>) -> Vec<NativeMatch> {
    if matches.is_empty() {
        return Vec::new();
    }
    let map = OffsetMap::new(text);
    matches
        .into_iter()
        .map(|m| NativeMatch {
            category: m.category.as_str().to_string(),
            start: offset(&map, m.start),
            end: offset(&map, m.end),
            value: m.value,
            confidence: m.confidence,
        })
        .collect()
}

/// An engine built once from options (`categories`, `preset`, `rules`,
/// `defaultStrategy`, `aggressive`, `strict`, as JSON) and safe to reuse.
#[napi]
pub struct Engine {
    inner: AnonymaEngine,
}

#[napi]
impl Engine {
    /// Build the engine; throws on options the core refuses.
    #[napi(constructor)]
    pub fn new(options_json: String) -> Result<Self> {
        engine_json(&options_json)
            .map(|inner| Engine { inner })
            .map_err(Error::from_reason)
    }

    /// The values found in `text`, in document order.
    #[napi]
    pub fn detect(&self, text: String) -> Vec<NativeMatch> {
        let found = self.inner.detect(&text);
        matches_of(&text, found)
    }

    /// `text` with each value replaced by its category's strategy.
    #[napi]
    pub fn anonymize(&self, text: String, include_matches: bool) -> Result<NativeAnonymized> {
        let out = self
            .inner
            .anonymize(&text)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(NativeAnonymized {
            matches: if include_matches {
                matches_of(&text, out.matches)
            } else {
                Vec::new()
            },
            text: out.text,
        })
    }

    /// [`detect`](Self::detect) on each text, scanning short texts together,
    /// on every core.
    #[napi]
    pub fn detect_batch(&self, texts: Vec<String>) -> Vec<Vec<NativeMatch>> {
        self.inner
            .detect_batch(&texts)
            .into_iter()
            .zip(&texts)
            .map(|(found, text)| matches_of(text, found))
            .collect()
    }

    /// [`anonymize`](Self::anonymize) on each text; a text that fails gives
    /// an entry with its error.
    #[napi]
    pub fn anonymize_batch(
        &self,
        texts: Vec<String>,
        include_matches: bool,
    ) -> Vec<NativeAnonymizedEntry> {
        self.inner
            .anonymize_batch(&texts)
            .into_iter()
            .zip(&texts)
            .map(|(out, text)| match out {
                Ok(out) => NativeAnonymizedEntry {
                    value: Some(NativeAnonymized {
                        matches: if include_matches {
                            matches_of(text, out.matches)
                        } else {
                            Vec::new()
                        },
                        text: out.text,
                    }),
                    error: None,
                },
                Err(e) => NativeAnonymizedEntry {
                    value: None,
                    error: Some(e.to_string()),
                },
            })
            .collect()
    }
}

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
