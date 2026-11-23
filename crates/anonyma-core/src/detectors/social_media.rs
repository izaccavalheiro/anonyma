//! Social media identifiers (`src/detectors/social-media.ts`): handles,
//! YouTube channels, Reddit users, LinkedIn profiles, and Discord IDs after a
//! label.

use std::sync::OnceLock;

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::jsregex::{js_regex, Guarded};
use crate::Category;

js_regex!(discord_label = insensitive r"\b(?:discord(?:\s+(?:id|user|server|guild))?|user\s+id|uid)\s*:?\s*");
js_regex!(youtube = r"\bUC[a-zA-Z0-9_-]{22}\b");
js_regex!(reddit = r"\b(?:u|\/u)\/[a-zA-Z0-9_-]{3,20}\b");
js_regex!(linkedin = insensitive r"\blinkedin\.com\/in\/[a-z0-9-]{3,100}\b");
js_regex!(discord_id = r"\b\d{17,19}\b");

/// `(?<![a-zA-Z0-9])@[a-zA-Z0-9_]{1,15}(?![a-zA-Z0-9_@])`
fn handle() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        Guarded::new(r"@[a-zA-Z0-9_]{1,15}", r"$|[^a-zA-Z0-9_@]", |c| {
            c.is_ascii_alphanumeric()
        })
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(discord_label().ranges(text));
    let mut found = Collector::new(text, Category::SocialMedia);
    for (start, end) in handle().ranges(text) {
        found.push(start, end, 0.78);
    }
    for (start, end) in youtube().ranges(text) {
        found.push(start, end, 0.9);
    }
    for (start, end) in reddit().ranges(text) {
        found.push(start, end, 0.85);
    }
    for (start, end) in linkedin().ranges(text) {
        found.push(start, end, 0.92);
    }
    for (start, end) in after_labels(&labels, || discord_id().ranges(text)) {
        if has_context(text, &labels, start, 30) {
            found.push(start, end, 0.85);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> Vec<String> {
        detect(text).into_iter().map(|m| m.value).collect()
    }

    #[test]
    fn identifiers() {
        assert_eq!(
            values("Follow @ana_dev, mail ana@example.com"),
            ["@ana_dev"]
        );
        assert_eq!(
            values("See u/ana_dev and linkedin.com/in/ana-example"),
            ["u/ana_dev", "linkedin.com/in/ana-example"]
        );
        assert_eq!(
            values("Discord ID: 123456789012345678"),
            ["123456789012345678"]
        );
        assert!(values("Order 123456789012345678").is_empty());
    }
}
