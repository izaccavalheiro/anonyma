//! US Social Security numbers (`src/detectors/ssn.ts`).
//!
//! The reference rejects never-issued numbers with lookaheads:
//! `\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0{4})\d{4}\b`. Here the
//! three groups are captured and checked afterwards; a rejected candidate
//! resumes the search one character later, where the reference's next attempt
//! starts. No other path through the pattern can succeed at a rejected start:
//! skipping a separator to dodge `(?!00)` leaves the separator where a digit
//! is required.

use super::Match;
use crate::jsregex::{js_regex, next_char, Haystack};
use crate::Category;

js_regex!(candidate = r"\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b");

fn slice(text: &str, (start, end): (usize, usize)) -> &str {
    &text[start..end]
}

fn assignable(area: &str, group: &str, serial: &str) -> bool {
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let haystack = Haystack::new(text);
    let mut matches = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = candidate().captures_at(&haystack, at) else {
            break;
        };
        let (Some((start, end)), Some(area), Some(group), Some(serial)) =
            (groups[0], groups[1], groups[2], groups[3])
        else {
            break;
        };
        if assignable(slice(text, area), slice(text, group), slice(text, serial)) {
            matches.push(Match::new(Category::Ssn, text, start, end, 0.95));
            at = end;
        } else {
            at = next_char(text, start);
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_are_optional() {
        for text in ["SSN: 123-45-6789", "SSN 123 45 6789", "SSN 123456789"] {
            assert_eq!(detect(text).len(), 1, "{text}");
        }
    }

    #[test]
    fn never_issued_numbers_are_ignored() {
        assert!(detect("000-12-3456 666-12-3456 900-12-3456 123-00-4567 123-45-0000").is_empty());
    }

    #[test]
    fn a_rejected_candidate_does_not_hide_the_next_one() {
        let found = detect("900-12-3456 123-45-6789");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "123-45-6789");
    }
}
