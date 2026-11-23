//! Dates that may be dates of birth (`src/detectors/date-of-birth.ts`): ISO,
//! US and European numeric dates, and dates with a month name.

use super::Match;
use crate::jsregex::JsRegex;
use crate::Category;
use std::sync::OnceLock;

const MONTHS: &str = "(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)";

/// The patterns and their confidence, in the reference's order.
fn patterns() -> &'static [(JsRegex, f64)] {
    static CELL: OnceLock<Vec<(JsRegex, f64)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                JsRegex::new(r"\b(19|20)\d{2}[- /](0[1-9]|1[0-2])[- /](0[1-9]|[12]\d|3[01])\b"),
                0.85,
            ),
            (
                JsRegex::new(r"\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b"),
                0.8,
            ),
            (
                JsRegex::new(r"\b(0[1-9]|[12]\d|3[01])[/.](0[1-9]|1[0-2])[/.](19|20)\d{2}\b"),
                0.78,
            ),
            (
                JsRegex::new(&format!(
                    r"\b{MONTHS}\s+(0?[1-9]|[12]\d|3[01]),?\s+(19|20)\d{{2}}\b"
                )),
                0.88,
            ),
            (
                JsRegex::new(&format!(
                    r"\b(0?[1-9]|[12]\d|3[01])\s+{MONTHS}\s+(19|20)\d{{2}}\b"
                )),
                0.88,
            ),
        ]
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let mut candidates: Vec<Match> = Vec::new();
    for (pattern, confidence) in patterns() {
        for (start, end) in pattern.ranges(text) {
            candidates.push(Match::new(
                Category::DateOfBirth,
                text,
                start,
                end,
                *confidence,
            ));
        }
    }
    // The most confident candidate claims its characters first; ties keep their order.
    candidates.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut kept: Vec<Match> = Vec::new();
    for candidate in candidates {
        if !kept
            .iter()
            .any(|m| candidate.start < m.end && candidate.end > m.start)
        {
            kept.push(candidate);
        }
    }
    kept.sort_by_key(|m| m.start);
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_and_long_dates() {
        let values: Vec<String> = detect("Born 1990-05-17, 05/17/1990, 17.05.1990, May 17, 1990")
            .into_iter()
            .map(|m| m.value)
            .collect();
        assert_eq!(
            values,
            ["1990-05-17", "05/17/1990", "17.05.1990", "May 17, 1990"]
        );
        assert!(detect("Not 1990-13-01").is_empty());
    }

    #[test]
    fn overlapping_candidates_keep_the_most_confident() {
        let found = detect("Seen 2021-01-02/2021-03-04 on file");
        let values: Vec<&str> = found.iter().map(|m| m.value.as_str()).collect();
        assert_eq!(values, ["2021-01-02", "2021-03-04"]);
    }
}
