//! Passport numbers (`src/detectors/passport.ts`): letter-and-digit formats,
//! and nine digits after a label. A label within 30 characters raises the
//! confidence by 0.15.

use std::sync::OnceLock;

use super::{has_context, label_ends, Match};
use crate::jsregex::{js_regex, JsRegex};
use crate::Category;

js_regex!(label = insensitive r"\b(?:passport(?:\s+(?:number|no\.?|#))?)\s*:?\s*");

fn formats() -> &'static [(JsRegex, f64)] {
    static CELL: OnceLock<Vec<(JsRegex, f64)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            // US: one letter and eight digits.
            (JsRegex::new(r"\b[A-Z]\d{8}\b"), 0.75),
            // Canada: two letters and six digits.
            (JsRegex::new(r"\b[A-Z]{2}\d{6}\b"), 0.75),
            // Australia: one letter and seven digits.
            (JsRegex::new(r"\b[A-Z]\d{7}\b"), 0.73),
            // UK: nine digits, too common without a label.
            (JsRegex::new(r"\b\d{9}\b"), 0.6),
            // EU: one or two letters and five to eight digits.
            (JsRegex::new(r"\b[A-Z]{1,2}\d{5,8}\b"), 0.7),
        ]
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for (pattern, base) in formats() {
        for (start, end) in pattern.ranges(text) {
            if seen.contains(&(start, end)) {
                continue;
            }
            let labelled = has_context(text, &labels, start, 30);
            let confidence = if labelled {
                (base + 0.15).min(0.95)
            } else {
                *base
            };
            if confidence < 0.7 && !labelled {
                continue;
            }
            seen.insert((start, end));
            found.push(Match::new(Category::Passport, text, start, end, confidence));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_formats() {
        assert!((detect("Passport number: X1234567")[0].confidence - 0.88).abs() < 1e-9);
        assert_eq!(detect("Passport: 123456789")[0].value, "123456789");
        let unlabelled: Vec<String> = detect("Ref A12345678 and 123456789")
            .into_iter()
            .map(|m| m.value)
            .collect();
        assert_eq!(unlabelled, ["A12345678"]);
    }
}
