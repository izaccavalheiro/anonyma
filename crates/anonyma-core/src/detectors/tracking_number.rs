//! Parcel tracking numbers (`src/detectors/tracking-number.ts`): UPS, Amazon,
//! USPS and DHL formats on their own, digit runs within 30 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::anchored::TextIndex;
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(label = insensitive r"\b(?:tracking(?:\s+(?:number|no\.?|#|id))?|shipment(?:\s+(?:number|id|tracking))?|parcel(?:\s+(?:number|id))?|package(?:\s+(?:number|id|tracking))?|(?:fedex|ups|usps|dhl|amazon)\s+(?:tracking|shipment)?)\s*:?\s*");
js_regex!(ups = insensitive r"\b1z[a-z0-9]{16}\b");
js_regex!(amazon = insensitive r"\btba\d{12}\b");
js_regex!(usps_format = insensitive r"\b(?:9[2-5]\d{18,20}|[a-z]{2}\d{9}us)\b");
js_regex!(dhl = insensitive r"\bjd\d{9}\b|\b\d{10,11}\b");
js_regex!(usps_long = r"\b\d{20,22}\b");
js_regex!(fedex = r"\b(?:\d{12}|\d{15}|\d{20,22})\b");

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true))
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::TrackingNumber);
    for (start, end) in ups().ranges_with(text, index) {
        found.push(start, end, 0.96);
    }
    for (start, end) in amazon().ranges_with(text, index) {
        found.push(start, end, 0.97);
    }
    for (start, end) in usps_format().ranges_with(text, index) {
        found.push(start, end, 0.9);
    }
    for (start, end) in dhl().ranges_with(text, index) {
        // The reference tests the prefix in upper or lower case, not mixed.
        let value = &text[start..end];
        if value.starts_with("JD") || value.starts_with("jd") {
            found.push(start, end, 0.88);
        } else if labelled(start) {
            found.push(start, end, 0.78);
        }
    }
    for (start, end) in after_labels(&labels, || usps_long().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.8);
        }
    }
    for (start, end) in after_labels(&labels, || fedex().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.78);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_case_sensitive_patterns_are_searched_at_candidate_starts() {
        for pattern in [usps_long(), fedex()] {
            assert!(pattern.is_anchored());
            crate::anchored::parity::check(pattern);
        }
    }

    #[test]
    fn carriers_and_labels() {
        assert_eq!(detect("UPS 1Z999AA10123456784 shipped")[0].confidence, 0.96);
        assert_eq!(detect("DHL JD123456789")[0].confidence, 0.88);
        assert_eq!(
            detect("Tracking number: 123456789012")[0].value,
            "123456789012"
        );
        assert!(detect("Order 123456789012").is_empty());
    }
}
