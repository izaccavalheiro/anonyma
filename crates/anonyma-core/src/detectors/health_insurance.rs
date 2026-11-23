//! Health insurance numbers (`src/detectors/health-insurance.ts`): US
//! Medicare beneficiary identifiers, UK NHS numbers verified by mod 11, and
//! EHIC or member numbers within 40 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::validators::nhs;
use crate::Category;

js_regex!(label = insensitive r"\b(?:health\s+insurance(?:\s+(?:number|id|no\.?|#|card))?|insurance\s+(?:number|id|no\.?|#|member\s+id)|member\s+(?:id|number|no\.?)|policy\s+(?:number|no\.?|#)|medicare|medicaid|nhs(?:\s+(?:number|no\.?|#))?|ehic|beneficiary\s+(?:id|number))\s*:?\s*");
js_regex!(mbi = insensitive r"\b[1-9][ac-hj-np-rt-y][0-9][ac-hj-np-rt-y][ac-hj-np-rt-y0-9]\d[ac-hj-np-rt-y][ac-hj-np-rt-y0-9]{2}\d{2}\b");
js_regex!(nhs_number = r"\b\d{3}[\s-]\d{3}[\s-]\d{4}\b|\b\d{10}\b");
js_regex!(ehic = r"\b[A-Z]{2}\d{6,10}\b");
js_regex!(member = r"\b[A-Z0-9]{8,14}\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 40);
    let mut found = Collector::new(text, Category::HealthInsurance);
    for (start, end) in mbi().ranges(text) {
        found.push(start, end, if labelled(start) { 0.9 } else { 0.8 });
    }
    for (start, end) in nhs_number().ranges(text) {
        if nhs(&text[start..end]) {
            found.push(start, end, if labelled(start) { 0.92 } else { 0.82 });
        }
    }
    for (start, end) in after_labels(&labels, || ehic().ranges(text)) {
        if labelled(start) {
            found.push(start, end, 0.78);
        }
    }
    for (start, end) in after_labels(&labels, || member().ranges(text)) {
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
    fn numbers() {
        assert_eq!(detect("Medicare 1A0C01DCD23")[0].confidence, 0.9);
        assert_eq!(detect("Medicare 1EG4TE5MK73")[0].confidence, 0.75);
        assert_eq!(detect("NHS number: 943 476 5919")[0].confidence, 0.92);
    }
}
