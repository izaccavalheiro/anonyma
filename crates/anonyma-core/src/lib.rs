//! # anonyma-core
//!
//! The engine of [anonyma](https://github.com/izaccavalheiro/anonyma) for
//! every language: PII detection, checksum validation, anonymization
//! strategies, reversible tokens with a vault, compliance presets and signed
//! anonymization receipts. The Python, Node.js, WebAssembly and Go bindings
//! call it; none re-implements a detection rule.
//!
//! The TypeScript package `anonyma` is the reference. This crate ports it
//! function by function and passes the shared conformance suite
//! (`packages/conformance`) for every capability it declares in
//! [`capabilities`]. Detectors it has not ported yet are refused rather than
//! silently skipped: see [`EngineBuilder::allow_partial`].
//!
//! ```
//! use anonyma_core::{AnonymaEngine, Category, StrategySpec};
//!
//! let engine = AnonymaEngine::builder()
//!     .rule(Category::CreditCard, StrategySpec::mask_trailing(4))
//!     .rule(Category::Email, StrategySpec::redact())
//!     .build()?;
//! let out = engine.anonymize("Card 4111111111111111, mail ana@example.com")?;
//! assert_eq!(out.text, "Card ************1111, mail [REDACTED]");
//! # Ok::<(), anonyma_core::Error>(())
//! ```
//!
//! Offsets are UTF-8 byte offsets; [`offsets`] converts them.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod category;
pub mod detectors;
mod engine;
mod error;
mod jsregex;
pub mod offsets;
pub mod presets;
pub mod receipt;
pub mod strategy;
pub mod validators;
pub mod vault;

pub use category::{Category, Support};
pub use detectors::{BuiltinDetector, Detector, Match};
pub use engine::{AnonymaEngine, Anonymized, EngineBuilder};
pub use error::{Error, Result};
pub use presets::{combine as combine_presets, CombinedPreset, Preset};
pub use receipt::{
    canonicalize, sha256_hex, AuditReceipt, Invalid, IssueOptions, Json, ReceiptIssuer,
};
pub use strategy::{AnonymizerStrategy, StrategySpec};
pub use validators::Validator;
pub use vault::{detokenize, restore, InMemoryVault, Restored, Shielded, Tokenized, Vault};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the conformance suite this crate passes.
pub const CONFORMANCE_SUITE: &str = "1.0.0";

/// The conformance capabilities this crate provides (see
/// `packages/conformance/README.md`). A case that requires anything else is
/// skipped by the conformance runners; every case it does not skip passes.
pub fn capabilities() -> Vec<String> {
    let mut out: Vec<String> = validators::CHECKSUMS
        .iter()
        .map(|v| format!("validate:{}", v.name()))
        .collect();
    for category in Category::ALL {
        match category.support() {
            Support::Full => out.push(format!("detect:{category}")),
            Support::Partial | Support::None => {}
        }
    }
    out.extend(
        [
            "detect:email+aggressive",
            "detect:credit-card+aggressive",
            "detect:ssn+aggressive",
            "detect:phone+aggressive",
            "detect:name+aggressive",
            "detect:national-id/br-cpf",
            "detect:national-id+strict",
            "tokenize",
            "detokenize",
            "shield",
            "restore",
            "anonymize",
            "strategy:redact",
            "strategy:mask",
            "strategy:pseudonymize",
            "preset",
            "receipt",
        ]
        .map(String::from),
    );
    // A preset is available for anonymization when every category it covers is detected in full.
    for preset in Preset::ALL {
        if preset
            .categories()
            .iter()
            .all(|c| c.support() == Support::Full)
        {
            out.push(format!("preset:{preset}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn capabilities_name_what_is_ported() {
        let caps = super::capabilities();
        assert!(caps.contains(&"validate:cpf".to_string()));
        assert!(caps.contains(&"detect:email".to_string()));
        assert!(!caps.contains(&"detect:national-id".to_string()));
        // PCI-DSS covers ported categories only; LGPD needs passports, among others.
        assert!(caps.contains(&"preset:pci-dss".to_string()));
        assert!(!caps.contains(&"preset:lgpd".to_string()));
    }
}
