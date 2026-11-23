//! Prescription identifiers (`src/detectors/prescription.ts`): DEA numbers
//! verified by their check digit, NDC drug codes, and prescription numbers
//! within 30 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::anchored::TextIndex;
use crate::jsregex::js_regex;
use crate::validators::dea;
use crate::Category;

js_regex!(label = insensitive r"\b(?:rx\s*(?:number|no\.?|#)?|prescription\s*(?:number|no\.?|#)?|prescription\s+id|ndc|drug\s+code|dea\s*(?:number|no\.?|#)?)\s*:?\s*");
js_regex!(dea_number = insensitive r"\b[abcdefghjklmnprstux][a-z9]\d{7}\b");
js_regex!(
    ndc =
        r"\b\d{4}-\d{4}-\d{2}\b|\b\d{5}-\d{3}-\d{2}\b|\b\d{5}-\d{4}-\d{1}\b|\b\d{5}-\d{4}-\d{2}\b"
);
js_regex!(rx_number = r"\b\d{4,12}\b");

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true))
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::Prescription);
    for (start, end) in dea_number().ranges_with(text, index) {
        if dea(&text[start..end]) {
            found.push(start, end, 0.9);
        }
    }
    for (start, end) in ndc().ranges_with(text, index) {
        found.push(start, end, if labelled(start) { 0.9 } else { 0.78 });
    }
    for (start, end) in after_labels(&labels, || rx_number().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.82);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_case_sensitive_patterns_are_searched_at_candidate_starts() {
        assert!(rx_number().is_anchored());
        crate::anchored::parity::check(rx_number());
    }

    #[test]
    fn identifiers() {
        let values: Vec<String> = detect("Rx #: 1234567 and NDC 0777-3105-02")
            .into_iter()
            .map(|m| m.value)
            .collect();
        // The digit runs inside the labelled NDC code are reported too;
        // overlap resolution keeps the code.
        assert_eq!(values[..2], ["0777-3105-02", "1234567"]);
    }
}
