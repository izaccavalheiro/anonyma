//! Web addresses (`src/detectors/url.ts`): `http` and `https` URLs with a
//! domain, `localhost` or an IPv4 host.

use super::Match;
use crate::jsregex::js_regex;
use crate::Category;

// The final \b drops trailing punctuation such as a full stop or a slash.
js_regex!(
    pattern = r#"\bhttps?:\/\/(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|localhost|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:\/[^\s,;'"<>()[\]{}]*)?(?:\?[^\s,;'"<>()[\]{}]*)?(?:#[^\s,;'"<>()[\]{}]*)?\b"#
);

pub(super) fn detect(text: &str) -> Vec<Match> {
    pattern()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| Match::new(Category::Url, text, start, end, 0.95))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_without_trailing_punctuation() {
        let found = detect("See https://example.com/a/b?q=1#top.");
        assert_eq!(found[0].value, "https://example.com/a/b?q=1#top");
        assert_eq!(
            detect("Local http://localhost:8080/api)")[0].value,
            "http://localhost:8080/api"
        );
        assert_eq!(detect("ftp://example.com").len(), 0);
    }
}
