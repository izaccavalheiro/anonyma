//! Medical record numbers (`src/detectors/medical-record.ts`): DEA numbers
//! and NPIs verified by their check digits, and any record number within 30
//! characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::validators::{dea, luhn};
use crate::Category;

js_regex!(label = insensitive r"\b(?:mrn|medical\s+record\s+(?:number|no\.?|#)|patient\s+(?:id|number|no\.?|#)|chart\s+(?:number|no\.?|#))\s*:?\s*");
js_regex!(dea_number = insensitive r"\b[abcdefghjklmnprstux][a-z9]\d{7}\b");
js_regex!(npi = r"\b[12]\d{9}\b");
js_regex!(record = r"\b[A-Z0-9]{6,12}\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::MedicalRecord);
    for (start, end) in dea_number().ranges(text) {
        if dea(&text[start..end]) {
            found.push(start, end, 0.9);
        }
    }
    for (start, end) in npi().ranges(text) {
        if luhn(&format!("80840{}", &text[start..end])) {
            found.push(start, end, if labelled(start) { 0.88 } else { 0.75 });
        }
    }
    for (start, end) in after_labels(&labels, || record().ranges(text)) {
        if labelled(start) {
            found.push(start, end, 0.85);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(detect("MRN: A1234567 for the patient")[0].value, "A1234567");
        let found = detect("Prescriber NPI 1234567893, DEA AB1234563");
        assert_eq!(found.len(), 2);
    }
}
