//! [`AnonymaEngine`]: detectors, a strategy per category, and the operations
//! of the reference's classic API (`detect`, `anonymize`, `tokenize`) plus
//! vault tokens (`shield`).

use std::collections::HashMap;
use std::sync::Arc;

use crate::detectors::{resolve, BuiltinDetector, Detector, Match};
use crate::presets::{combine, Preset};
use crate::strategy::{AnonymizerStrategy, StrategySpec};
use crate::vault::{shield_matches, tokenize_matches, Shielded, Tokenized, Vault};
use crate::{Category, Error, Result, Support};

/// The result of [`AnonymaEngine::anonymize`].
#[derive(Debug, Clone, PartialEq)]
pub struct Anonymized {
    /// The anonymized text.
    pub text: String,
    /// What was replaced, in document order.
    pub matches: Vec<Match>,
}

impl Anonymized {
    /// How many values of each category were replaced, for a receipt.
    pub fn counts(&self) -> Vec<(String, u64)> {
        let mut counts: Vec<(String, u64)> = Vec::new();
        for m in &self.matches {
            let name = m.category.as_str();
            match counts.iter_mut().find(|(c, _)| c == name) {
                Some((_, n)) => *n += 1,
                None => counts.push((name.to_string(), 1)),
            }
        }
        counts
    }
}

/// Builds an [`AnonymaEngine`].
#[derive(Clone, Default)]
pub struct EngineBuilder {
    presets: Vec<Preset>,
    categories: Option<Vec<Category>>,
    rules: Vec<(Category, Arc<dyn AnonymizerStrategy>)>,
    default_strategy: Option<Arc<dyn AnonymizerStrategy>>,
    detectors: Vec<Arc<dyn Detector>>,
    aggressive: bool,
    strict: bool,
    allow_partial: bool,
}

impl std::fmt::Debug for EngineBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("presets", &self.presets)
            .field("categories", &self.categories)
            .field("aggressive", &self.aggressive)
            .field("strict", &self.strict)
            .field("allow_partial", &self.allow_partial)
            .finish_non_exhaustive()
    }
}

impl EngineBuilder {
    /// Apply a compliance preset; several combine as `combinePresets()` does.
    pub fn preset(mut self, preset: Preset) -> Self {
        self.presets.push(preset);
        self
    }

    /// Detect these categories only, in this order. Without it, an engine
    /// detects the categories of its presets and of its rules: with a preset,
    /// a rule overrides the strategy of its category or adds the category, as
    /// in `anonymize()`. Without presets or rules, it detects every category.
    pub fn categories(mut self, categories: impl IntoIterator<Item = Category>) -> Self {
        self.categories = Some(categories.into_iter().collect());
        self
    }

    /// Anonymize `category` with `strategy`.
    pub fn rule(self, category: Category, strategy: StrategySpec) -> Self {
        self.rule_with(category, Arc::new(strategy))
    }

    /// Anonymize `category` with a strategy of your own.
    pub fn rule_with(mut self, category: Category, strategy: Arc<dyn AnonymizerStrategy>) -> Self {
        self.rules.retain(|(c, _)| *c != category);
        self.rules.push((category, strategy));
        self
    }

    /// The strategy of categories without a rule (`redact` by default).
    pub fn default_strategy(mut self, strategy: StrategySpec) -> Self {
        self.default_strategy = Some(Arc::new(strategy));
        self
    }

    /// Use a detector of your own for its category, instead of the built-in one.
    pub fn detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.detectors
            .retain(|d| d.category() != detector.category());
        self.detectors.push(detector);
        self
    }

    /// Use the aggressive variants of the detectors.
    pub fn aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        self
    }

    /// Use the strict variants, which verify check digits (`national-id`).
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Accept categories this crate does not detect in full: they are detected
    /// as far as it can ([`Support::Partial`]) or not at all ([`Support::None`]),
    /// and [`AnonymaEngine::undetected`] lists them. Without it, building an
    /// engine that would miss data fails.
    pub fn allow_partial(mut self, allow: bool) -> Self {
        self.allow_partial = allow;
        self
    }

    /// Build the engine.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCategories`] when a category is not detected in full
    /// and partial detection was not allowed.
    pub fn build(self) -> Result<AnonymaEngine> {
        let combined = if self.presets.is_empty() {
            None
        } else {
            Some(combine(&self.presets)?)
        };

        // Categories: explicit, else the presets' and the rules', else all.
        // Duplicates are skipped below.
        let categories: Vec<Category> = match (&self.categories, &combined) {
            (Some(categories), _) => categories.clone(),
            (None, None) if self.rules.is_empty() => Category::ALL.to_vec(),
            (None, preset) => preset
                .iter()
                .flat_map(|preset| preset.categories.iter().copied())
                .chain(self.rules.iter().map(|(c, _)| *c))
                .collect(),
        };

        let mut rules: HashMap<Category, Arc<dyn AnonymizerStrategy>> = HashMap::new();
        if let Some(preset) = &combined {
            for (category, strategy) in &preset.rules {
                rules.insert(*category, Arc::new(strategy.clone()));
            }
        }
        for (category, strategy) in &self.rules {
            rules.insert(*category, Arc::clone(strategy));
        }
        let default_strategy: Arc<dyn AnonymizerStrategy> =
            match (&self.default_strategy, &combined) {
                (Some(strategy), _) => Arc::clone(strategy),
                (None, Some(preset)) => Arc::new(preset.default_strategy.clone()),
                (None, None) => Arc::new(StrategySpec::redact()),
            };

        let mut detectors: Vec<Arc<dyn Detector>> = Vec::new();
        let mut fusable = true;
        let mut undetected = Vec::new();
        let mut seen = Vec::new();
        for category in categories {
            if seen.contains(&category) {
                continue;
            }
            seen.push(category);
            if let Some(custom) = self.detectors.iter().find(|d| d.category() == category) {
                detectors.push(Arc::clone(custom));
                // Fusion is proven for the built-in detectors only.
                fusable = false;
                continue;
            }
            if category.support() != Support::Full {
                undetected.push(category);
            }
            if let Some(builtin) = BuiltinDetector::new(category, self.aggressive, self.strict) {
                detectors.push(Arc::new(builtin));
            }
        }
        if !undetected.is_empty() && !self.allow_partial {
            return Err(Error::UnsupportedCategories(undetected));
        }

        let names = seen.contains(&Category::Name);
        // The index of candidate starts pays for itself with national-id's
        // twenty formats, or once three detectors share it.
        let indexed: Vec<Category> = detectors
            .iter()
            .filter_map(|d| d.as_builtin())
            .filter(|b| b.uses_index())
            .map(|b| b.category())
            .collect();
        let index = indexed.contains(&Category::NationalId) || indexed.len() >= 3;
        Ok(AnonymaEngine {
            detectors,
            rules,
            default_strategy,
            undetected,
            fusable,
            names,
            index,
        })
    }
}

/// Detects and anonymizes personal data.
///
/// ```
/// use anonyma_core::{AnonymaEngine, Category, InMemoryVault, restore};
///
/// let engine = AnonymaEngine::builder()
///     .categories([Category::Email, Category::Iban])
///     .build()?;
/// let mut vault = InMemoryVault::new();
/// let shielded = engine.shield("Mail ana@example.com", &mut vault)?;
/// assert_eq!(shielded.text, "Mail {{EMAIL_1}}");
/// assert_eq!(restore("Sent to {{EMAIL_1}}", &vault).text, "Sent to ana@example.com");
/// # Ok::<(), anonyma_core::Error>(())
/// ```
#[derive(Clone)]
pub struct AnonymaEngine {
    detectors: Vec<Arc<dyn Detector>>,
    rules: HashMap<Category, Arc<dyn AnonymizerStrategy>>,
    default_strategy: Arc<dyn AnonymizerStrategy>,
    undetected: Vec<Category>,
    /// Every detector is built in, so a batch may be scanned as fused texts.
    fusable: bool,
    /// The name detector runs (greetings anchor at the start of a text).
    names: bool,
    /// Enough detectors share an index of candidate starts for it to pay off.
    index: bool,
}

impl std::fmt::Debug for AnonymaEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let categories: Vec<Category> = self.detectors.iter().map(|d| d.category()).collect();
        f.debug_struct("AnonymaEngine")
            .field("categories", &categories)
            .field("undetected", &self.undetected)
            .finish_non_exhaustive()
    }
}

impl AnonymaEngine {
    /// Start building an engine.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// The categories this engine was asked for but does not detect in full.
    pub fn undetected(&self) -> &[Category] {
        &self.undetected
    }

    /// Every value found, without overlaps, in document order.
    pub fn detect(&self, text: &str) -> Vec<Match> {
        // One index of the text, built on first use, for every built-in detector.
        let index = crate::anchored::TextIndex::new(text, self.index);
        let mut raw = Vec::new();
        for detector in &self.detectors {
            match detector.as_builtin() {
                Some(builtin) => raw.extend(builtin.detect_in(&index)),
                None => raw.extend(detector.detect(text)),
            }
        }
        resolve(raw)
    }

    /// [`detect`](Self::detect) on each text of a batch, in order. With the
    /// built-in detectors, texts under 8 KB are joined, scanned once and split
    /// back: the same matches, at a fraction of the cost for short texts.
    pub fn detect_batch<S: AsRef<str>>(&self, texts: &[S]) -> Vec<Vec<Match>> {
        let texts: Vec<&str> = texts.iter().map(AsRef::as_ref).collect();
        let fused = if self.fusable {
            crate::fusion::fuse_each(
                &texts,
                self.names,
                |text| self.detect(text),
                |m| m.start,
                |mut m, offset| {
                    m.start -= offset;
                    m.end -= offset;
                    m
                },
            )
        } else {
            texts.iter().map(|_| None).collect()
        };
        // Texts scanned alone run on the pool too, with the `parallel` feature;
        // only they go to it, not the entries whose matches are already split back.
        let alone: Vec<usize> = (0..texts.len()).filter(|&i| fused[i].is_none()).collect();
        let mut scanned = crate::fusion::map_all(alone, |i| self.detect(texts[i])).into_iter();
        fused
            .into_iter()
            .map(|found| found.unwrap_or_else(|| scanned.next().unwrap_or_default()))
            .collect()
    }

    /// [`anonymize`](Self::anonymize) on each text of a batch, in order, with
    /// the matches of [`detect_batch`](Self::detect_batch).
    pub fn anonymize_batch<S: AsRef<str>>(&self, texts: &[S]) -> Vec<Result<Anonymized>> {
        let pending: Vec<(&str, Vec<Match>)> = texts
            .iter()
            .map(AsRef::as_ref)
            .zip(self.detect_batch(texts))
            .collect();
        crate::fusion::map_all(pending, |(text, matches)| {
            self.anonymize_matches(text, matches)
        })
    }

    /// Replace every value found with its category's strategy.
    pub fn anonymize(&self, text: &str) -> Result<Anonymized> {
        self.anonymize_matches(text, self.detect(text))
    }

    fn anonymize_matches(&self, text: &str, matches: Vec<Match>) -> Result<Anonymized> {
        let mut spans = Vec::with_capacity(matches.len());
        for m in matches.iter().rev() {
            let strategy = self
                .rules
                .get(&m.category)
                .unwrap_or(&self.default_strategy);
            spans.push((m.start, m.end, strategy.apply(&m.value, m.category)?));
        }
        Ok(Anonymized {
            text: crate::splice::replace_spans(text, &spans),
            matches,
        })
    }

    /// Replace every value found with a classic token (`[EMAIL_0001]`) and
    /// return the mapping back; [`crate::detokenize`] restores them.
    pub fn tokenize(&self, text: &str) -> Tokenized {
        tokenize_matches(text, &self.detect(text))
    }

    /// Replace every value found with a vault token (`{{EMAIL_1}}`) kept in
    /// `vault`; [`crate::restore`] restores them, in this text or in a model's
    /// answer to it.
    pub fn shield(&self, text: &str, vault: &mut dyn Vault) -> Result<Shielded> {
        shield_matches(text, &self.detect(text), vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryVault;

    #[test]
    fn indexes_the_text_when_enough_detectors_share_the_index() {
        let build = |categories: &[Category]| {
            AnonymaEngine::builder()
                .categories(categories.iter().copied())
                .build()
                .unwrap()
                .index
        };
        assert!(AnonymaEngine::builder().build().unwrap().index);
        assert!(build(&[Category::NationalId]));
        assert!(build(&[
            Category::Passport,
            Category::TaxId,
            Category::BankAccount
        ]));
        assert!(!build(&[Category::Passport, Category::Prescription]));
        assert!(!build(&[Category::Email]));
    }

    #[test]
    fn serves_every_preset_in_full() {
        for &preset in Preset::ALL {
            let engine = AnonymaEngine::builder().preset(preset).build().unwrap();
            assert!(engine.undetected().is_empty(), "{preset}");
        }
    }

    #[test]
    fn a_custom_detector_replaces_the_built_in_one() {
        struct Nothing;
        impl Detector for Nothing {
            fn category(&self) -> Category {
                Category::Email
            }
            fn detect(&self, _text: &str) -> Vec<crate::Match> {
                Vec::new()
            }
        }
        let engine = AnonymaEngine::builder()
            .categories([Category::Email])
            .detector(Arc::new(Nothing))
            .build()
            .unwrap();
        assert!(engine.detect("ana@example.com").is_empty());
    }

    #[test]
    fn rules_choose_the_categories() {
        let engine = AnonymaEngine::builder()
            .rule(Category::Email, StrategySpec::redact())
            .rule(
                Category::Ipv4,
                StrategySpec::Redact {
                    label: Some("[IP]".into()),
                },
            )
            .build()
            .unwrap();
        let out = engine
            .anonymize("From ann@example.com at 192.0.2.10")
            .unwrap();
        assert_eq!(out.text, "From [REDACTED] at [IP]");
        assert_eq!(
            out.counts(),
            vec![("email".to_string(), 1u64), ("ipv4".to_string(), 1u64)]
        );
    }

    #[test]
    fn preset_rules_apply() {
        let engine = AnonymaEngine::builder()
            .preset(Preset::PciDss)
            .categories([Category::CreditCard, Category::Email])
            .build()
            .unwrap();
        let out = engine
            .anonymize("Card 4111111111111111, mail ana@example.com")
            .unwrap();
        assert_eq!(out.text, "Card ************1111, mail [REDACTED]");
    }

    #[test]
    fn rules_override_and_extend_a_preset() {
        let engine = AnonymaEngine::builder()
            .preset(Preset::PciDss)
            .rule(
                Category::Email,
                StrategySpec::Mask {
                    mask_char: None,
                    keep_leading: None,
                    keep_trailing: None,
                    preserve_format: None,
                },
            )
            .rule(
                Category::Ipv4,
                StrategySpec::Redact {
                    label: Some("[IP]".into()),
                },
            )
            .build()
            .unwrap();
        let out = engine
            .anonymize("Card 4111111111111111, mail ana@example.com from 192.0.2.10")
            .unwrap();
        assert_eq!(
            out.text,
            "Card ************1111, mail *************** from [IP]"
        );
    }

    #[test]
    fn classic_and_vault_tokens() {
        let engine = AnonymaEngine::builder()
            .categories([Category::Email])
            .build()
            .unwrap();
        let tokenized = engine.tokenize("alice@example.com, bob@example.com, ALICE@example.com");
        assert_eq!(tokenized.text, "[EMAIL_0001], [EMAIL_0002], [EMAIL_0001]");

        let mut vault = InMemoryVault::from_entries([("{{EMAIL_1}}", "old@example.com")]).unwrap();
        let shielded = engine
            .shield("Mail new@example.com and old@example.com", &mut vault)
            .unwrap();
        assert_eq!(shielded.text, "Mail {{EMAIL_2}} and {{EMAIL_1}}");
    }

    struct Upper;
    impl AnonymizerStrategy for Upper {
        fn apply(&self, value: &str, _category: Category) -> Result<String> {
            Ok(value.to_uppercase())
        }
    }

    #[test]
    fn custom_strategies() {
        let engine = AnonymaEngine::builder()
            .rule_with(Category::Email, Arc::new(Upper))
            .build()
            .unwrap();
        assert_eq!(
            engine.anonymize("x ann@example.com").unwrap().text,
            "x ANN@EXAMPLE.COM"
        );
    }
}
