//! Reversible tokens: classic bracket tokens (`[EMAIL_0001]`) with a mapping,
//! and vault tokens (`{{EMAIL_1}}`) kept in a [`Vault`] and restored from any
//! text (`src/tokenize.ts`, `src/vault/`).

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::jsregex::JsRegex;
use crate::{Category, Error, Match, Result};

/// Where vault tokens and their original values are kept.
///
/// Implement it over Redis, a KV store or a database to share tokens between
/// processes. A vault holds original values in clear: keep it scoped to one
/// conversation.
pub trait Vault {
    /// Keep `value` under `token`, replacing what the token held.
    fn store(&mut self, token: &str, value: &str) -> Result<()>;
    /// The value kept under `token`.
    fn retrieve(&self, token: &str) -> Option<String>;
}

/// A [`Vault`] in memory, in insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryVault {
    entries: Vec<(String, String)>,
    index: HashMap<String, usize>,
}

impl InMemoryVault {
    /// An empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// A vault holding `entries`, for example from an earlier export.
    pub fn from_entries<I, K, V>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut vault = Self::new();
        for (token, value) in entries {
            vault.store(token.as_ref(), value.as_ref())?;
        }
        Ok(vault)
    }

    /// Every token and its value, in the order the tokens were first stored.
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    /// Number of tokens held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the vault holds no token.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forget a token. Returns whether the vault held it.
    pub fn delete(&mut self, token: &str) -> bool {
        let Some(position) = self.index.remove(token) else {
            return false;
        };
        self.entries.remove(position);
        for slot in self.index.values_mut() {
            if *slot > position {
                *slot -= 1;
            }
        }
        true
    }

    /// Forget every token.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
    }
}

impl Vault for InMemoryVault {
    fn store(&mut self, token: &str, value: &str) -> Result<()> {
        if token.is_empty() {
            return Err(Error::validation("key", "must be a non-empty string"));
        }
        match self.index.get(token) {
            Some(&position) => self.entries[position].1 = value.to_string(),
            None => {
                self.index.insert(token.to_string(), self.entries.len());
                self.entries.push((token.to_string(), value.to_string()));
            }
        }
        Ok(())
    }

    fn retrieve(&self, token: &str) -> Option<String> {
        self.index
            .get(token)
            .map(|&position| self.entries[position].1.clone())
    }
}

/// The result of [`restore`] and [`detokenize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The text with every known token replaced by its value.
    pub text: String,
    /// How many token occurrences were replaced.
    pub restored: usize,
    /// Every occurrence of a token the vault or mapping does not hold, in order.
    pub unresolved: Vec<String>,
}

/// Classic tokens and the mapping back to their values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokenized {
    /// The text with every detected value replaced by its token.
    pub text: String,
    /// Each token and the value it stands for.
    pub mapping: Vec<(String, String)>,
}

/// The result of [`shield`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shielded {
    /// The text with every detected value replaced by its vault token.
    pub text: String,
    /// The token of each replaced value, in document order, with its category.
    pub tokens: Vec<(String, Category)>,
}

/// The body of any token: a prefix, optional segments (a tag), a number.
const ANY_TOKEN_BODY: &str = r"[A-Z][A-Za-z0-9]{0,39}(?:_[A-Za-z0-9]{1,40}){0,13}?_\d{1,12}";

fn any_token() -> &'static JsRegex {
    static CELL: OnceLock<JsRegex> = OnceLock::new();
    CELL.get_or_init(|| {
        JsRegex::new(&format!(
            r"\{{\{{{ANY_TOKEN_BODY}\}}\}}|\[{ANY_TOKEN_BODY}\]|<{ANY_TOKEN_BODY}>"
        ))
    })
}

fn legacy_token() -> &'static JsRegex {
    static CELL: OnceLock<JsRegex> = OnceLock::new();
    CELL.get_or_init(|| {
        JsRegex::new(
            r"\[[A-Z][A-Z0-9_]{0,60}_\d{1,12}\]|<[A-Z][A-Z0-9_]{0,60}_\d{1,12}>|\{\{[A-Z][A-Z0-9_]{0,60}_\d{1,12}\}\}",
        )
    })
}

/// Replace every brace, bracket or angle token of `text` that `vault` holds by
/// its value, in one left-to-right pass: each token is matched whole, so
/// `{{PERSON_1}}` never matches inside `{{PERSON_10}}`, and a restored value
/// is never restored again.
pub fn restore(text: &str, vault: &dyn Vault) -> Restored {
    let mut values: HashMap<&str, Option<String>> = HashMap::new();
    let mut out = String::with_capacity(text.len());
    let mut unresolved = Vec::new();
    let mut restored = 0;
    let mut cursor = 0;
    for (start, end) in any_token().ranges(text) {
        let token = &text[start..end];
        let value = values.entry(token).or_insert_with(|| vault.retrieve(token));
        match value {
            Some(value) => {
                out.push_str(&text[cursor..start]);
                out.push_str(value);
                cursor = end;
                restored += 1;
            }
            None => unresolved.push(token.to_string()),
        }
    }
    if restored == 0 {
        return Restored {
            text: text.to_string(),
            restored,
            unresolved,
        };
    }
    out.push_str(&text[cursor..]);
    Restored {
        text: out,
        restored,
        unresolved,
    }
}

/// Restore classic tokens with the `mapping` of [`tokenize`]. Unknown tokens
/// stay and are reported.
pub fn detokenize(text: &str, mapping: &[(String, String)]) -> Restored {
    let lookup: HashMap<&str, &str> = mapping
        .iter()
        .map(|(token, value)| (token.as_str(), value.as_str()))
        .collect();
    let mut out = String::with_capacity(text.len());
    let mut unresolved = Vec::new();
    let mut total = 0;
    let mut cursor = 0;
    for (start, end) in legacy_token().ranges(text) {
        total += 1;
        let token = &text[start..end];
        out.push_str(&text[cursor..start]);
        match lookup.get(token) {
            Some(value) => out.push_str(value),
            None => {
                out.push_str(token);
                unresolved.push(token.to_string());
            }
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Restored {
        text: out,
        restored: total - unresolved.len(),
        unresolved,
    }
}

/// Classic tokens for `matches` (resolved, in document order): numbered from
/// the end of the text backwards, one counter per prefix, values equal
/// ignoring case sharing a token, as the reference's `tokenize()` does.
pub(crate) fn tokenize_matches(text: &str, matches: &[Match]) -> Tokenized {
    let mut index: HashMap<String, String> = HashMap::new();
    let mut counters: HashMap<&'static str, usize> = HashMap::new();
    let mut mapping: Vec<(String, String)> = Vec::new();
    let mut spans = Vec::with_capacity(matches.len());
    for m in matches.iter().rev() {
        let prefix = m.category.token_prefix();
        let key = format!("{prefix}:{}", m.value.to_lowercase());
        let token = match index.get(&key) {
            Some(token) => token.clone(),
            None => {
                let counter = counters.entry(prefix).or_insert(0);
                *counter += 1;
                let token = format!("[{prefix}_{:04}]", *counter);
                index.insert(key, token.clone());
                mapping.push((token.clone(), m.value.clone()));
                token
            }
        };
        spans.push((m.start, m.end, token));
    }
    Tokenized {
        text: crate::splice::replace_spans(text, &spans),
        mapping,
    }
}

/// Most numbers probed for one value before the vault is considered broken.
const MAX_PROBES: usize = 1_000_000;

/// Allocates vault tokens for one call, as the reference's vault tokenizer.
struct VaultTokenizer<'v> {
    vault: &'v mut dyn Vault,
    /// `prefix NUL value` -> token
    index: HashMap<String, String>,
    /// prefix -> highest number seen taken
    counters: HashMap<&'static str, usize>,
}

impl VaultTokenizer<'_> {
    fn tokenize(&mut self, value: &str, category: Category) -> Result<String> {
        let prefix = category.token_prefix();
        let key = format!("{prefix}\0{value}");
        if let Some(token) = self.index.get(&key) {
            return Ok(token.clone());
        }
        let first = self.counters.get(prefix).copied().unwrap_or(0) + 1;
        for number in first..first + MAX_PROBES {
            let token = format!("{{{{{prefix}_{number}}}}}");
            match self.vault.retrieve(&token) {
                None => {
                    self.vault.store(&token, value)?;
                    return Ok(self.commit(key, prefix, token, number));
                }
                Some(existing) if existing == value => {
                    return Ok(self.commit(key, prefix, token, number));
                }
                // A token held for another value: remember it, and try the next number.
                Some(existing) => {
                    self.index
                        .entry(format!("{prefix}\0{existing}"))
                        .or_insert_with(|| token.clone());
                }
            }
        }
        Err(Error::Vault(format!(
            "no free token number after {MAX_PROBES} attempts"
        )))
    }

    fn commit(
        &mut self,
        key: String,
        prefix: &'static str,
        token: String,
        number: usize,
    ) -> String {
        self.index.insert(key, token.clone());
        let counter = self.counters.entry(prefix).or_insert(0);
        *counter = (*counter).max(number);
        token
    }
}

/// Replace `matches` (resolved, in document order) by vault tokens
/// (`{{EMAIL_1}}`), numbered per category in document order. Values are
/// compared exactly. A token the vault already holds for the same value is
/// reused, one it holds for another value is skipped, so a second request of
/// a conversation never overwrites the first one's tokens.
pub(crate) fn shield_matches(
    text: &str,
    matches: &[Match],
    vault: &mut dyn Vault,
) -> Result<Shielded> {
    let mut tokenizer = VaultTokenizer {
        vault,
        index: HashMap::new(),
        counters: HashMap::new(),
    };
    let mut out = String::with_capacity(text.len());
    let mut tokens = Vec::with_capacity(matches.len());
    let mut cursor = 0;
    for m in matches {
        let token = tokenizer.tokenize(&m.value, m.category)?;
        out.push_str(&text[cursor..m.start]);
        out.push_str(&token);
        cursor = m.end;
        tokens.push((token, m.category));
    }
    out.push_str(&text[cursor..]);
    Ok(Shielded { text: out, tokens })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(entries: &[(&str, &str)]) -> InMemoryVault {
        InMemoryVault::from_entries(entries.iter().copied()).unwrap()
    }

    #[test]
    fn restore_matches_tokens_whole() {
        let v = vault(&[("{{PERSON_1}}", "Ana"), ("{{PERSON_10}}", "Bruno")]);
        let out = restore("{{PERSON_10}} met {{PERSON_1}}.", &v);
        assert_eq!(out.text, "Bruno met Ana.");
        assert_eq!(out.restored, 2);
    }

    #[test]
    fn restore_reports_unknown_tokens_and_ignores_look_alikes() {
        let v = vault(&[("{{EMAIL_1}}", "ann@example.com")]);
        let out = restore("{{EMAIL_1}} and {{EMAIL_9}}", &v);
        assert_eq!(out.text, "ann@example.com and {{EMAIL_9}}");
        assert_eq!(out.unresolved, vec!["{{EMAIL_9}}".to_string()]);
        let same = "{{ EMAIL_1 }} and {{email_1}} and {EMAIL_1}";
        assert_eq!(restore(same, &v).text, same);
    }

    #[test]
    fn restore_handles_tags_and_does_not_recurse() {
        let v = vault(&[("{{EMAIL_k3Xf_1}}", "ann@example.com")]);
        assert_eq!(
            restore("Reply to {{EMAIL_k3Xf_1}}", &v).text,
            "Reply to ann@example.com"
        );
        let v = vault(&[("{{PERSON_1}}", "{{PERSON_2}}"), ("{{PERSON_2}}", "Ana")]);
        assert_eq!(restore("{{PERSON_1}}", &v).text, "{{PERSON_2}}");
    }

    #[test]
    fn detokenize_counts_and_reports() {
        let mapping = vec![("[EMAIL_0001]".to_string(), "a@example.com".to_string())];
        let out = detokenize("[EMAIL_0001] and [PHONE_0001]", &mapping);
        assert_eq!(out.text, "a@example.com and [PHONE_0001]");
        assert_eq!(out.restored, 1);
        assert_eq!(out.unresolved, vec!["[PHONE_0001]".to_string()]);
    }

    #[test]
    fn vault_keeps_insertion_order_and_deletes() {
        let mut v = vault(&[("a", "1"), ("b", "2"), ("c", "3")]);
        v.store("a", "9").unwrap();
        assert!(v.delete("b"));
        assert!(!v.delete("b"));
        assert_eq!(v.retrieve("c").as_deref(), Some("3"));
        assert_eq!(
            v.entries(),
            &[
                ("a".to_string(), "9".to_string()),
                ("c".to_string(), "3".to_string())
            ]
        );
        assert!(v.store("", "x").is_err());
    }
}
