//! Driving licence numbers (`src/detectors/drivers-license.ts`): the UK DVLA
//! format on its own, any other number only within 20 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::anchored::TextIndex;
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(label = insensitive r"\b(?:driver(?:'?s)?\s+licen[cs]e|driving\s+licen[cs]e|dl\s*#?|d\.?l\.?(?:\s*#)?|licen[cs]e\s+(?:no|number|#))\s*:?\s*");
js_regex!(uk_dvla = r"\b[A-Z9]{5}\d{6}[02-9]\d[A-Z]{2}\w{2}\b");
js_regex!(generic = r"\b[A-Z0-9]{5,15}\b");

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true))
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let mut found = Collector::new(text, Category::DriversLicense);
    for (start, end) in uk_dvla().ranges_with(text, index) {
        found.push(start, end, 0.78);
    }
    for (start, end) in after_labels(&labels, || generic().ranges_with(text, index)) {
        if has_context(text, &labels, start, 20) {
            found.push(start, end, 0.85);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_case_sensitive_patterns_are_searched_at_candidate_starts() {
        for pattern in [uk_dvla(), generic()] {
            assert!(pattern.is_anchored());
            crate::anchored::parity::check(pattern);
        }
    }

    #[test]
    fn uk_format_and_labelled_numbers() {
        assert_eq!(detect("Licence MORGA75311629SMIJ held")[0].confidence, 0.78);
        assert_eq!(
            detect("Driver's license: D1234567 issued")[0].value,
            "D1234567"
        );
        assert_eq!(detect("DL# A1B2C3D4E5")[0].value, "A1B2C3D4E5");
        assert!(detect("Reference D1234567").is_empty());
    }
}
