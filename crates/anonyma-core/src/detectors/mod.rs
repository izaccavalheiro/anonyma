//! Built-in detectors: ports of the reference's detectors (`src/detectors/`),
//! pattern for pattern, conformance-tested against them.
//!
//! Offsets are UTF-8 byte offsets into the text. Bindings convert them to
//! their language's unit (code points for Python, UTF-16 units for
//! JavaScript); [`crate::offsets`] has the conversions.

use std::cmp::Ordering;

use crate::anchored::TextIndex;
use crate::{Category, Support};

mod address;
mod api_key;
mod bank_account;
mod case_number;
mod company_registration;
mod credit_card;
mod cryptocurrency;
mod date_of_birth;
mod drivers_license;
mod email;
mod health_insurance;
mod iban;
mod ip;
mod license_plate;
mod medical_record;
mod name;
mod national_id;
mod passport;
mod phone;
pub(crate) mod precise;
mod prescription;
mod social_media;
mod ssn;
mod tax_id;
mod tracking_number;
mod url;
mod vin;

/// A detection of personal data in a text.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    /// The category of the value.
    pub category: Category,
    /// The matched text.
    pub value: String,
    /// Byte offset of the first byte of the value.
    pub start: usize,
    /// Byte offset just past the value.
    pub end: usize,
    /// How likely the value is personal data, from 0 to 1.
    pub confidence: f64,
}

impl Match {
    pub(crate) fn new(
        category: Category,
        text: &str,
        start: usize,
        end: usize,
        confidence: f64,
    ) -> Self {
        Match {
            category,
            value: text[start..end].to_string(),
            start,
            end,
            confidence,
        }
    }
}

/// Finds the values of one category in a text.
pub trait Detector: Send + Sync {
    /// The category this detector reports.
    fn category(&self) -> Category;
    /// Every value found, in the order the detector finds them.
    fn detect(&self, text: &str) -> Vec<Match>;

    /// This detector as a built-in one, so that an engine can share work
    /// between built-in detectors on one text. Custom detectors keep the default.
    fn as_builtin(&self) -> Option<&BuiltinDetector> {
        None
    }
}

/// The built-in detector of a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinDetector {
    category: Category,
    aggressive: bool,
    strict: bool,
}

impl BuiltinDetector {
    /// The built-in detector of `category`, or `None` when this crate does not
    /// detect the category ([`Support::None`]).
    ///
    /// `aggressive` selects the aggressive variant where there is one (`email`,
    /// `credit-card`, `ssn`, `phone`, `name`, `vin`); `strict` the strict one (`national-id`, which then
    /// verifies check digits).
    pub fn new(category: Category, aggressive: bool, strict: bool) -> Option<Self> {
        (category.support() != Support::None).then_some(BuiltinDetector {
            category,
            aggressive,
            strict,
        })
    }
}

impl Detector for BuiltinDetector {
    fn category(&self) -> Category {
        self.category
    }

    fn detect(&self, text: &str) -> Vec<Match> {
        // Alone, only national-id's twenty formats pay for an index of the text.
        self.detect_in(&TextIndex::new(text, self.category == Category::NationalId))
    }

    fn as_builtin(&self) -> Option<&BuiltinDetector> {
        Some(self)
    }
}

impl BuiltinDetector {
    /// Whether this detector searches some patterns at the candidate starts of
    /// a [`TextIndex`] (src/anchored.rs).
    pub(crate) fn uses_index(&self) -> bool {
        matches!(
            self.category,
            Category::NationalId
                | Category::Passport
                | Category::BankAccount
                | Category::TaxId
                | Category::TrackingNumber
                | Category::HealthInsurance
                | Category::MedicalRecord
                | Category::CompanyRegistration
                | Category::DriversLicense
                | Category::LicensePlate
                | Category::Prescription
        )
    }

    /// [`Detector::detect`] with an index of the text that every built-in
    /// detector of one call shares.
    pub(crate) fn detect_in(&self, index: &TextIndex<'_>) -> Vec<Match> {
        let text = index.text();
        match self.category {
            Category::Email => email::detect(text, self.aggressive),
            Category::Ipv4 => ip::detect_ipv4(text),
            Category::Ipv6 => ip::detect_ipv6(text),
            Category::CreditCard => credit_card::detect(text, self.aggressive),
            // The aggressive SSN pattern only finds what the standard one does.
            Category::Ssn => ssn::detect(text),
            Category::Iban => iban::detect(text),
            Category::NationalId => national_id::detect_in(text, index, self.strict),
            Category::TaxId => tax_id::detect_in(text, index),
            Category::BankAccount => bank_account::detect_in(text, index),
            Category::Phone => phone::detect(text, self.aggressive),
            Category::Name => name::detect(text, self.aggressive),
            Category::Address => address::detect(text),
            Category::Passport => passport::detect_in(text, index),
            Category::DriversLicense => drivers_license::detect_in(text, index),
            Category::Cryptocurrency => cryptocurrency::detect(text),
            Category::SocialMedia => social_media::detect(text),
            Category::MedicalRecord => medical_record::detect_in(text, index),
            Category::HealthInsurance => health_insurance::detect_in(text, index),
            Category::Prescription => prescription::detect_in(text, index),
            Category::Vin => vin::detect(text, self.aggressive),
            Category::LicensePlate => license_plate::detect_in(text, index),
            Category::CompanyRegistration => company_registration::detect_in(text, index),
            Category::ApiKey => api_key::detect(text),
            Category::TrackingNumber => tracking_number::detect_in(text, index),
            Category::CaseNumber => case_number::detect(text),
            Category::Url => url::detect(text),
            Category::DateOfBirth => date_of_birth::detect(text),
        }
    }
}

/// Whether `start..end` overlaps one of `ranges`.
pub(crate) fn overlaps(start: usize, end: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|&(s, e)| start < e && end > s)
}

/// Collects matches, dropping a second one with the same range (the `seen`
/// set of the reference's composite detectors).
pub(crate) struct Collector<'t> {
    text: &'t str,
    category: Category,
    seen: std::collections::HashSet<(usize, usize)>,
    matches: Vec<Match>,
}

impl<'t> Collector<'t> {
    pub(crate) fn new(text: &'t str, category: Category) -> Self {
        Collector {
            text,
            category,
            seen: std::collections::HashSet::new(),
            matches: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, start: usize, end: usize, confidence: f64) {
        if self.seen.insert((start, end)) {
            self.matches
                .push(Match::new(self.category, self.text, start, end, confidence));
        }
    }

    pub(crate) fn finish(self) -> Vec<Match> {
        self.matches
    }
}

/// End offsets of every match of a label pattern: a value "has context" when
/// it starts shortly after one.
pub(crate) fn label_ends(ranges: Vec<(usize, usize)>) -> Vec<usize> {
    ranges.into_iter().map(|(_, end)| end).collect()
}

/// The ranges `scan` finds, for a pattern whose matches are reported only
/// after a label: none, without scanning, when the text has no label. Skipping
/// the scan changes no result, since every candidate would be rejected and a
/// rejected candidate leaves no trace.
pub(crate) fn after_labels(
    labels: &[usize],
    scan: impl FnOnce() -> Vec<(usize, usize)>,
) -> Vec<(usize, usize)> {
    if labels.is_empty() {
        Vec::new()
    } else {
        scan()
    }
}

/// Whether a value at `index` starts at most `limit` UTF-16 units after the
/// end of a label.
///
/// `labels` are in ascending order, as [`label_ends`] returns them. Only the
/// labels at most `3 × limit` bytes before `index` can be within `limit` UTF-16
/// units (a unit takes at most three bytes), so a binary search finds them:
/// the cost no longer grows with the number of labels times the number of
/// candidate values.
pub(crate) fn has_context(text: &str, labels: &[usize], index: usize, limit: usize) -> bool {
    debug_assert!(labels.windows(2).all(|pair| pair[0] <= pair[1]));
    let up_to = labels.partition_point(|&position| position <= index);
    labels[..up_to]
        .iter()
        .rev()
        .take_while(|&&position| index - position <= limit * 3)
        .any(|&position| crate::jsregex::within(text, position, index, limit))
}

/// Resolve overlapping detections as the reference's `detect()` does: sort by
/// start, then by confidence, highest first (a stable sort, so ties keep the
/// order of detection), and drop every match that starts before the end of
/// the previous kept one.
pub fn resolve(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by(|a, b| {
        a.start.cmp(&b.start).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
        })
    });
    let mut kept = Vec::with_capacity(matches.len());
    let mut cursor = 0;
    for m in matches {
        if m.start >= cursor {
            cursor = m.end;
            kept.push(m);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(category: Category, start: usize, end: usize, confidence: f64) -> Match {
        Match {
            category,
            value: String::new(),
            start,
            end,
            confidence,
        }
    }

    #[test]
    fn has_context_finds_what_a_linear_search_finds() {
        let text = "id: 12 \u{1F600}\u{1F600} id:\u{00E9}\u{00E9}\u{00E9} 345 id: id: 6789 end";
        let labels: Vec<usize> = text.match_indices("id:").map(|(i, _)| i + 3).collect();
        for index in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
            for limit in [0, 1, 2, 3, 5, 8, 40] {
                let linear = labels
                    .iter()
                    .any(|&position| crate::jsregex::within(text, position, index, limit));
                assert_eq!(
                    has_context(text, &labels, index, limit),
                    linear,
                    "index {index}, limit {limit}"
                );
            }
        }
        assert!(!has_context(text, &[], 5, 40));
    }

    #[test]
    fn resolve_prefers_earlier_then_more_confident() {
        let kept = resolve(vec![
            at(Category::BankAccount, 15, 31, 0.8),
            at(Category::CreditCard, 15, 31, 0.97),
            at(Category::Email, 0, 5, 0.99),
            at(Category::Ipv4, 3, 9, 0.98),
        ]);
        let order: Vec<Category> = kept.iter().map(|m| m.category).collect();
        assert_eq!(order, vec![Category::Email, Category::CreditCard]);
    }

    #[test]
    fn every_category_has_a_detector() {
        for &category in Category::ALL {
            assert!(
                BuiltinDetector::new(category, false, false).is_some(),
                "{category}"
            );
        }
    }
}
