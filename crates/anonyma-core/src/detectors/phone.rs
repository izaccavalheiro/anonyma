//! Telephone numbers (`src/detectors/phone.ts`): North American and
//! international numbers, then national formats of Brazil, France, the United
//! Kingdom, Spain, Italy and German-speaking countries.
//!
//! The reference's patterns use lookbehind, lookahead and, for France, a
//! backreference; [`Guarded`] emulates the first two exactly, and the
//! backreference becomes a check that the separators are equal.

use std::sync::OnceLock;

use super::{overlaps, Match};
use crate::jsregex::{js_regex, Guarded, JsRegex, NOT_BEFORE_DIGIT, NOT_BEFORE_SEPARATED_DIGIT};
use crate::Category;

/// North American numbers: `(?<!\d)` before them.
const NANP: &str = r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}";
/// International numbers: a `+` and 7 to 15 digits, with separators.
const INTERNATIONAL: &str = r"\+(?:\d[ .\-()]{0,2}){6,14}\d";

fn digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn digit_or_plus(c: char) -> bool {
    c.is_ascii_digit() || c == '+'
}

/// `(?<!\d)NANP(?!\d)|INTERNATIONAL(?!\d)`, both alternatives in one search.
fn standard() -> &'static JsRegex {
    static CELL: OnceLock<JsRegex> = OnceLock::new();
    CELL.get_or_init(|| {
        JsRegex::new(&format!(
            "({NANP})(?:{NOT_BEFORE_DIGIT})|({INTERNATIONAL})(?:{NOT_BEFORE_DIGIT})"
        ))
    })
}

/// The second alternative alone, tried where the first fails its lookbehind.
fn international() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| Guarded::new(INTERNATIONAL, NOT_BEFORE_DIGIT, |_| false))
}

/// Matches of the standard pattern, as the reference's `exec` loop finds them.
fn standard_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = standard().captures_at(text, at) else {
            break;
        };
        let (first, second) = (groups[1], groups[2]);
        let Some((start, end)) = first.or(second) else {
            break;
        };
        let preceded_by_digit = text[..start].chars().next_back().is_some_and(digit);
        let found = if first.is_some() && preceded_by_digit {
            // The first alternative fails its lookbehind: the second one is tried at the same start.
            international()
                .candidate(text, start)
                .and_then(|g| g[1])
                .filter(|&(s, _)| s == start)
        } else {
            Some((start, end))
        };
        match found {
            Some((s, e)) => {
                out.push((s, e));
                at = e;
            }
            None => at = crate::jsregex::next_char(text, start),
        }
    }
    out
}

/// The national patterns and their confidence, in the reference's order.
fn national() -> &'static [(Guarded, f64)] {
    static CELL: OnceLock<Vec<(Guarded, f64)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let tail = NOT_BEFORE_SEPARATED_DIGIT;
        vec![
            // Brazil: (11) 91234-5678, (21) 3456-7890.
            (
                Guarded::new(
                    r"\(0?[1-9]{2}\)\s?(?:9\s?\d{4}|[2-5]\d{3})[\s.-]?\d{4}",
                    tail,
                    digit_or_plus,
                ),
                0.88,
            ),
            // Brazil: 11 91234-5678, 021 3456 7890.
            (
                Guarded::new(
                    r"0?[1-9]{2}[\s.]?(?:9\s?\d{4}|[2-5]\d{3})[-\s]\d{4}",
                    tail,
                    digit_or_plus,
                ),
                0.82,
            ),
            // France: 06 12 34 56 78, the same separator throughout (checked below).
            (
                Guarded::new(
                    r"0[1-9]([\s.-])\d{2}(?:[\s.-]\d{2}){3}",
                    tail,
                    digit_or_plus,
                ),
                0.85,
            ),
            // United Kingdom: 020 7946 0958, 0161 496 0000, 07700 900123.
            (
                Guarded::new(
                    r"0(?:\d{2} \d{4} \d{4}|\d{3} \d{3} \d{4}|\d{4} \d{5,6})",
                    tail,
                    digit_or_plus,
                ),
                0.82,
            ),
            // Spain: 612 34 56 78, 91 123 45 67.
            (
                Guarded::new(
                    r"(?:[6-9]\d{2}(?: \d{2}){3}|9[1-8] \d{3}(?: \d{2}){2})",
                    tail,
                    digit_or_plus,
                ),
                0.8,
            ),
            // Italy: 06 1234 5678, 02 1234 567.
            (
                Guarded::new(r"0\d{1,3} \d{3,4} \d{3,4}", tail, digit_or_plus),
                0.78,
            ),
            // Germany, Austria, Switzerland: 030 12345678, 089/1234567, 0151-23456789.
            (
                Guarded::new(r"0[1-9]\d{1,4}[ /-]\d{5,8}", tail, digit_or_plus),
                0.76,
            ),
        ]
    })
}

/// The French pattern's backreference: the four separators are the same character.
fn same_separators(text: &str, groups: &[Option<(usize, usize)>]) -> bool {
    let Some((start, end)) = groups[1] else {
        return false;
    };
    // 0, digit, then four times: separator, two digits.
    let chars: Vec<char> = text[start..end].chars().collect();
    chars.len() == 14 && [5, 8, 11].iter().all(|&i| chars[i] == chars[2])
}

js_regex!(seven_digits = r"\b\d{3}[-.\s]\d{4}\b");

pub(super) fn detect(text: &str, aggressive: bool) -> Vec<Match> {
    let mut matches: Vec<Match> = Vec::new();
    for (start, end) in standard_ranges(text) {
        // The reference trims the value but keeps the offsets of the match.
        let value = text[start..end].trim();
        if value.bytes().filter(u8::is_ascii_digit).count() < 7 {
            continue;
        }
        matches.push(Match {
            category: Category::Phone,
            value: value.to_string(),
            start,
            end,
            confidence: 0.9,
        });
    }

    // A national number is reported unless a match found so far covers it.
    for (index, (pattern, confidence)) in national().iter().enumerate() {
        let ranges = if index == 2 {
            pattern.ranges_where(text, |groups| same_separators(text, groups))
        } else {
            pattern.ranges(text)
        };
        for (start, end) in ranges {
            if matches.iter().any(|m| m.start <= start && end <= m.end) {
                continue;
            }
            matches.push(Match::new(Category::Phone, text, start, end, *confidence));
        }
    }

    if aggressive {
        let ranges: Vec<(usize, usize)> = matches.iter().map(|m| (m.start, m.end)).collect();
        for (start, end) in seven_digits().ranges(text) {
            if !overlaps(start, end, &ranges) {
                matches.push(Match::new(Category::Phone, text, start, end, 0.7));
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str, aggressive: bool) -> Vec<String> {
        detect(text, aggressive)
            .into_iter()
            .map(|m| m.value)
            .collect()
    }

    #[test]
    fn north_american_and_international() {
        assert_eq!(values("Call (555) 123-4567 now", false), ["(555) 123-4567"]);
        assert_eq!(
            values("Call +1 555 123 4567 or 1-555-765-4321", false),
            ["+1 555 123 4567", "1-555-765-4321"]
        );
        assert_eq!(
            values("Ring +44 20 7946 0958 today", false),
            ["+44 20 7946 0958"]
        );
        assert!(values("Order 12345678901234567890", false).is_empty());
    }

    #[test]
    fn the_second_alternative_where_the_first_fails_its_lookbehind() {
        assert_eq!(values("5+1 555 123 4567", false), ["+1 555 123 4567"]);
    }

    #[test]
    fn national_formats() {
        assert_eq!(
            values("Ligue (11) 91234-5678 ou 21 3456 7890", false),
            ["(11) 91234-5678", "21 3456 7890"]
        );
        assert_eq!(
            values("Appelez 06 12 34 56 78 ou 06 12.34 56 78", false),
            ["06 12 34 56 78"]
        );
        assert_eq!(
            values("Office 020 7946 0958, mobile 07700 900123", false),
            ["020 7946 0958", "07700 900123"]
        );
        assert_eq!(
            values("Büro 030 12345678, Handy 0151-23456789", false),
            ["030 12345678", "0151-23456789"]
        );
    }

    #[test]
    fn seven_digits_in_aggressive_mode_only() {
        assert!(values("Ext 555-0199 inside", false).is_empty());
        assert_eq!(values("Ext 555-0199 inside", true), ["555-0199"]);
    }
}
