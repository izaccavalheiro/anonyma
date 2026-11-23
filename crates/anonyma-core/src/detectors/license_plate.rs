//! Licence plates (`src/detectors/license-plate.ts`): UK formats on their
//! own, European formats and any other plate within 20 characters after a label.

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(label = insensitive r"\b(?:licen[sc]e\s+plate|number\s+plate|registration\s+(?:plate|number)|reg(?:istration)?\s*(?:no\.?|#|:)|plate(?:\s+(?:number|no\.?))?)\s*:?\s*");
js_regex!(uk_current = insensitive r"\b[a-z]{2}\d{2}[\s]?[a-z]{3}\b");
js_regex!(uk_old = insensitive r"\b[a-z]\d{1,4}[\s]?[a-z]{3}\b");
js_regex!(european = insensitive r"\b[a-z]{1,2}[\s-]?\d{1,4}[\s-]?[a-z]{1,3}\b");
js_regex!(any_plate = r"\b[A-Z0-9]{2,8}\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 20);
    let mut found = Collector::new(text, Category::LicensePlate);
    for (start, end) in uk_current().ranges(text) {
        found.push(start, end, if labelled(start) { 0.9 } else { 0.78 });
    }
    for (start, end) in uk_old().ranges(text) {
        found.push(start, end, if labelled(start) { 0.85 } else { 0.7 });
    }
    for (start, end) in european().ranges(text) {
        // Reported only after a label: 0.65 without one is below the threshold of 0.7.
        if labelled(start) {
            found.push(start, end, 0.82);
        }
    }
    for (start, end) in any_plate().ranges(text) {
        if labelled(start) {
            found.push(start, end, 0.8);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plates() {
        assert_eq!(detect("Car AB12 CDE parked")[0].value, "AB12 CDE");
        assert_eq!(detect("Plate number: 7ABC123")[0].value, "7ABC123");
    }
}
