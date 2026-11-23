//! Health insurance numbers (`src/detectors/health-insurance.ts`): US
//! Medicare beneficiary identifiers, UK NHS numbers verified by mod 11, and
//! EHIC or member numbers within 40 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::anchored::TextIndex;
use crate::jsregex::js_regex;
use crate::validators::nhs;
use crate::Category;

js_regex!(label = insensitive r"\b(?:health\s+insurance(?:\s+(?:number|id|no\.?|#|card))?|insurance\s+(?:number|id|no\.?|#|member\s+id)|member\s+(?:id|number|no\.?)|policy\s+(?:number|no\.?|#)|medicare|medicaid|nhs(?:\s+(?:number|no\.?|#))?|ehic|beneficiary\s+(?:id|number))\s*:?\s*");
js_regex!(mbi = insensitive r"\b[1-9][ac-hj-np-rt-y][0-9][ac-hj-np-rt-y][ac-hj-np-rt-y0-9]\d[ac-hj-np-rt-y][ac-hj-np-rt-y0-9]{2}\d{2}\b");
js_regex!(nhs_number = r"\b\d{3}[\s-]\d{3}[\s-]\d{4}\b|\b\d{10}\b");
js_regex!(ehic = r"\b[A-Z]{2}\d{6,10}\b");
js_regex!(member = r"\b[A-Z0-9]{8,14}\b");

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true))
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 40);
    let mut found = Collector::new(text, Category::HealthInsurance);
    for (start, end) in mbi().ranges_with(text, index) {
        found.push(start, end, if labelled(start) { 0.9 } else { 0.8 });
    }
    for (start, end) in nhs_number().ranges_with(text, index) {
        if nhs(&text[start..end]) {
            found.push(start, end, if labelled(start) { 0.92 } else { 0.82 });
        }
    }
    for (start, end) in after_labels(&labels, || ehic().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.78);
        }
    }
    for (start, end) in after_labels(&labels, || member().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.75);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_case_sensitive_patterns_are_searched_at_candidate_starts() {
        for pattern in [nhs_number(), ehic(), member()] {
            assert!(pattern.is_anchored());
            crate::anchored::parity::check(pattern);
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(detect("Medicare 1A0C01DCD23")[0].confidence, 0.9);
        assert_eq!(detect("Medicare 1EG4TE5MK73")[0].confidence, 0.75);
        assert_eq!(detect("NHS number: 943 476 5919")[0].confidence, 0.92);
    }
}
