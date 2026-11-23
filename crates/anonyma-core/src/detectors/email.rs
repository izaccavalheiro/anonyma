//! E-mail addresses (`src/detectors/email.ts`).

use super::{overlaps, Match};
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(
    standard = r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b"
);

// Obfuscated forms: `user [at] example [dot] com`. Case-insensitive.
js_regex!(obfuscated = insensitive r"\b[a-z0-9][a-z0-9._-]*\s*(?:@|\[at\]|\(at\))\s*[a-z0-9][\w.-]*\s*(?:\.|\[dot\]|\(dot\))\s*[a-z]{2,}\b");

pub(super) fn detect(text: &str, aggressive: bool) -> Vec<Match> {
    let mut matches: Vec<Match> = standard()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| Match::new(Category::Email, text, start, end, 0.99))
        .collect();
    if aggressive {
        let ranges: Vec<(usize, usize)> = matches.iter().map(|m| (m.start, m.end)).collect();
        for (start, end) in obfuscated().ranges(text) {
            if !overlaps(start, end, &ranges) {
                matches.push(Match::new(Category::Email, text, start, end, 0.75));
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_addresses() {
        let found = detect("Contact us at support@example.com.", false);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].start, found[0].end), (14, 33));
        assert!(detect("user@localhost", false).is_empty());
    }

    #[test]
    fn aggressive_finds_obfuscated_addresses() {
        let text = "Write to user [at] example [dot] com today";
        assert!(detect(text, false).is_empty());
        let found = detect(text, true);
        assert_eq!(found[0].value, "user [at] example [dot] com");
        assert_eq!(found[0].confidence, 0.75);
    }
}
