//! Anonymization strategies (`src/strategies/`): redact, mask and
//! pseudonymize. The others of the reference (`hash`, `encrypt`, `tokenize`,
//! `generalize`, `synthesize`) are not ported yet; see [`crate::shield`] for
//! reversible tokens.

use std::sync::OnceLock;

use regex::Regex;

use crate::{Category, Error, Result};

/// Replaces one detected value.
pub trait AnonymizerStrategy: Send + Sync {
    /// The replacement of `value`, a value of `category`.
    fn apply(&self, value: &str, category: Category) -> Result<String>;
}

/// A built-in strategy and its options, as the reference spells them
/// (`{ strategy: "mask", keepTrailing: 4 }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategySpec {
    /// Replace the value by a label.
    Redact {
        /// The label; `[REDACTED]` when `None`.
        label: Option<String>,
    },
    /// Replace characters by a mask character.
    Mask {
        /// One character; `*` when `None`.
        mask_char: Option<String>,
        /// Characters left visible at the start.
        keep_leading: Option<usize>,
        /// Characters left visible at the end.
        keep_trailing: Option<usize>,
        /// Letters become `X`/`x`, digits `0`, punctuation stays.
        preserve_format: Option<bool>,
    },
    /// Replace the value by an identifier: deterministic with a seed, random
    /// without one.
    Pseudonymize {
        /// Seed of the deterministic identifier.
        seed: Option<String>,
        /// Prefix of the identifier; `id_` when `None`.
        prefix: Option<String>,
    },
}

impl StrategySpec {
    /// `{ strategy: "redact" }`.
    pub const fn redact() -> Self {
        StrategySpec::Redact { label: None }
    }

    /// `{ strategy: "mask", keepTrailing }`.
    pub const fn mask_trailing(keep: usize) -> Self {
        StrategySpec::Mask {
            mask_char: None,
            keep_leading: None,
            keep_trailing: Some(keep),
            preserve_format: None,
        }
    }

    /// `{ strategy: "pseudonymize" }`.
    pub const fn pseudonymize() -> Self {
        StrategySpec::Pseudonymize {
            seed: None,
            prefix: None,
        }
    }

    /// The name of the strategy (`redact`, `mask`, `pseudonymize`).
    pub const fn name(&self) -> &'static str {
        match self {
            StrategySpec::Redact { .. } => "redact",
            StrategySpec::Mask { .. } => "mask",
            StrategySpec::Pseudonymize { .. } => "pseudonymize",
        }
    }

    /// How much of the value or of its links the strategy exposes, as the
    /// reference ranks strategies when it combines presets: lower is more
    /// protective.
    pub(crate) fn exposure(&self) -> u32 {
        match self {
            StrategySpec::Redact { .. } => 0,
            StrategySpec::Mask {
                keep_leading,
                keep_trailing,
                ..
            } => u32::from(keep_leading.unwrap_or(0) + keep_trailing.unwrap_or(0) > 0),
            // A seeded pseudonym is linkable: the same value gets the same identifier.
            StrategySpec::Pseudonymize { seed, .. } => {
                if seed.is_some() {
                    4
                } else {
                    0
                }
            }
        }
    }
}

impl AnonymizerStrategy for StrategySpec {
    fn apply(&self, value: &str, _category: Category) -> Result<String> {
        match self {
            StrategySpec::Redact { label } => redact(label.as_deref()),
            StrategySpec::Mask {
                mask_char,
                keep_leading,
                keep_trailing,
                preserve_format,
            } => mask(
                value,
                mask_char.as_deref().unwrap_or("*"),
                keep_leading.unwrap_or(0),
                keep_trailing.unwrap_or(0),
                preserve_format.unwrap_or(false),
            ),
            StrategySpec::Pseudonymize { seed, prefix } => {
                pseudonymize(value, seed.as_deref(), prefix.as_deref().unwrap_or("id_"))
            }
        }
    }
}

/// The label that replaces a value.
pub fn redact(label: Option<&str>) -> Result<String> {
    let label = label.unwrap_or("[REDACTED]");
    if label.trim().is_empty() {
        return Err(Error::validation("label", "must not be an empty string"));
    }
    Ok(label.to_string())
}

fn letter() -> &'static Regex {
    static LETTER: OnceLock<Regex> = OnceLock::new();
    LETTER.get_or_init(|| Regex::new(r"^\p{L}$").expect("valid pattern"))
}

/// Mask `value`. Lengths are counted in UTF-16 code units in standard mode and
/// in code points in format-preserving mode, as the reference counts them.
pub fn mask(
    value: &str,
    mask_char: &str,
    keep_leading: usize,
    keep_trailing: usize,
    preserve_format: bool,
) -> Result<String> {
    if mask_char.encode_utf16().count() != 1 {
        return Err(Error::validation(
            "maskChar",
            "must be exactly one character",
        ));
    }
    if value.is_empty() {
        return Ok(String::new());
    }
    let visible = keep_leading + keep_trailing;

    if preserve_format {
        let chars: Vec<char> = value.chars().collect();
        if visible >= chars.len() {
            return Ok(value.to_string());
        }
        let interior_end = chars.len() - keep_trailing;
        let mut out = String::with_capacity(value.len());
        for (index, &c) in chars.iter().enumerate() {
            if index < keep_leading || index >= interior_end {
                out.push(c);
            } else if letter().is_match(c.encode_utf8(&mut [0; 4])) {
                let lower: String = c.to_lowercase().collect();
                out.push(if lower == c.to_string() { 'x' } else { 'X' });
            } else if c.is_numeric() {
                out.push('0');
            } else {
                out.push(c);
            }
        }
        return Ok(out);
    }

    let units: Vec<u16> = value.encode_utf16().collect();
    if visible >= units.len() {
        return Ok(mask_char.repeat(units.len()));
    }
    let leading = String::from_utf16_lossy(&units[..keep_leading]);
    let trailing = String::from_utf16_lossy(&units[units.len() - keep_trailing..]);
    Ok(format!(
        "{leading}{}{trailing}",
        mask_char.repeat(units.len() - visible)
    ))
}

/// djb2 (xor variant) over UTF-16 code units, as the reference hashes strings.
fn djb2(text: &str) -> u32 {
    text.encode_utf16().fold(5381u32, |hash, unit| {
        (hash << 5).wrapping_add(hash) ^ u32::from(unit)
    })
}

/// A pseudonym: `<prefix>` and 16 hexadecimal digits, derived from the seed and
/// the value, or random without a seed.
pub fn pseudonymize(value: &str, seed: Option<&str>, prefix: &str) -> Result<String> {
    if prefix.chars().any(crate::validators::is_js_space) {
        return Err(Error::validation(
            "prefix",
            "must not contain whitespace characters",
        ));
    }
    match seed {
        Some(seed) => {
            let combined = format!("{seed}:{value}");
            let first = djb2(&combined);
            let second = djb2(&format!("{combined}:v2"));
            Ok(format!("{prefix}{first:08x}{second:08x}"))
        }
        None => {
            let mut bytes = [0u8; 8];
            getrandom::getrandom(&mut bytes)
                .map_err(|error| Error::Unsupported(format!("no random source: {error}")))?;
            Ok(format!("{prefix}{}", crate::receipt::hex(&bytes)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_labels() {
        assert_eq!(redact(None).unwrap(), "[REDACTED]");
        assert_eq!(redact(Some("<EMAIL>")).unwrap(), "<EMAIL>");
        assert!(redact(Some("  ")).is_err());
    }

    #[test]
    fn mask_modes() {
        assert_eq!(
            mask("4111111111111111", "*", 0, 4, false).unwrap(),
            "************1111"
        );
        assert_eq!(
            mask("ann@example.com", "#", 2, 0, false).unwrap(),
            "an#############"
        );
        assert_eq!(mask("123-45-6789", "*", 0, 4, true).unwrap(), "000-00-6789");
        assert_eq!(mask("Ab-9", "*", 0, 0, true).unwrap(), "Xx-0");
        assert_eq!(mask("abc", "*", 2, 2, false).unwrap(), "***");
        assert!(mask("abc", "**", 0, 0, false).is_err());
    }

    #[test]
    fn seeded_pseudonyms_are_deterministic() {
        assert_eq!(
            pseudonymize("alice@example.com", Some("s3cr3t"), "id_").unwrap(),
            "id_dce0436c55d847d2"
        );
        let random = pseudonymize("alice@example.com", None, "id_").unwrap();
        assert_eq!(random.len(), 19);
        assert!(pseudonymize("x", None, "a b").is_err());
    }

    #[test]
    fn exposure_ranks_like_the_reference() {
        assert_eq!(StrategySpec::redact().exposure(), 0);
        assert_eq!(StrategySpec::mask_trailing(4).exposure(), 1);
        assert_eq!(StrategySpec::pseudonymize().exposure(), 0);
    }
}
