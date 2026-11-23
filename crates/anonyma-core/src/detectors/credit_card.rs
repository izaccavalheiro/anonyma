//! Card numbers, verified by the Luhn check (`src/detectors/credit-card.ts`).

use super::{overlaps, Match};
use crate::jsregex::js_regex;
use crate::validators::luhn_digits;
use crate::Category;

// 13 to 19 digits, optionally separated by a space or a hyphen. The match
// starts and ends with a digit: the separator after the last group is not part
// of it (`4111 1111 1111 1111 exp`).
js_regex!(card = r"\b\d(?:[ -]?\d){12,18}\b");

js_regex!(masked = r"\*{4}[ -]?\*{4}[ -]?\*{4}[ -]?\d{4}\b");

pub(super) fn detect(text: &str, aggressive: bool) -> Vec<Match> {
    let mut matches = Vec::new();
    for (start, end) in card().ranges(text) {
        let digits: String = text[start..end]
            .chars()
            .filter(|c| *c != ' ' && *c != '-')
            .collect();
        if (13..=19).contains(&digits.len()) && luhn_digits(&digits) {
            matches.push(Match::new(Category::CreditCard, text, start, end, 0.97));
        }
    }
    if aggressive {
        let ranges: Vec<(usize, usize)> = matches.iter().map(|m| (m.start, m.end)).collect();
        for (start, end) in masked().ranges(text) {
            if !overlaps(start, end, &ranges) {
                matches.push(Match::new(Category::CreditCard, text, start, end, 0.8));
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_valid_numbers_only() {
        assert_eq!(
            detect("Card 4111 1111 1111 1111.", false)[0].value,
            "4111 1111 1111 1111"
        );
        assert!(detect("Card 4111 1111 1111 1112.", false).is_empty());
    }

    #[test]
    fn the_separator_after_the_last_group_is_left_out() {
        let found = detect("Card 4111 1111 1111 1111 exp 12/30", false);
        assert_eq!(found[0].value, "4111 1111 1111 1111");
        let found = detect("Card 4111-1111-1111-1111-x", false);
        assert_eq!(found[0].value, "4111-1111-1111-1111");
    }

    #[test]
    fn masked_cards_in_aggressive_mode() {
        let text = "Card ending ****-****-****-1234 on file";
        assert!(detect(text, false).is_empty());
        assert_eq!(detect(text, true)[0].confidence, 0.8);
    }
}
