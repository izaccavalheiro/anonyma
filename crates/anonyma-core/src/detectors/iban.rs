//! IBANs, verified by MOD-97 (`src/detectors/iban.ts`).

use super::Match;
use crate::jsregex::js_regex;
use crate::validators::mod97;
use crate::Category;

js_regex!(candidate = r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){1,7}[A-Z0-9]{1,4}\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    candidate()
        .ranges(text)
        .into_iter()
        // The detector's own check accepts 5 to 34 characters, unlike `iban` (15).
        .filter(|&(start, end)| mod97(&text[start..end], 5))
        .map(|(start, end)| Match::new(Category::Iban, text, start, end, 0.99))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_and_compact() {
        assert_eq!(
            detect("IBAN: GB82 WEST 1234 5698 7654 32")[0].value,
            "GB82 WEST 1234 5698 7654 32"
        );
        assert_eq!(
            detect("to DE89370400440532013000 today")[0].value,
            "DE89370400440532013000"
        );
        assert!(detect("IBAN: GB82 WEST 1234 5698 7654 33").is_empty());
    }
}
