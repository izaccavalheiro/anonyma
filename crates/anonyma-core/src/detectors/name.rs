//! Personal names (`src/detectors/name.ts`): capitalised words after a
//! greeting, a title or a context keyword.
//!
//! The reference's greeting and aggressive patterns are case-insensitive, so
//! their captures may start with a lower-case word; such a capture is dropped,
//! and a capture keeps only its leading capitalised words. Both behaviours are
//! reproduced, quirks included (conformance cases `detect.name.*`).

use std::sync::OnceLock;

use super::Match;
use crate::jsregex::{next_char, JsRegex};
use crate::Category;

const TITLES: &str = "(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof(?:essor)?|Rev(?:erend)?|Hon(?:orable)?|Capt(?:ain)?|Cmdr|Commander|Lt|Lieu?t(?:enant)?|Sgt|Sergeant|Fr|Father|Sr|Sister|Br|Brother|Esq|Esquire)";

const KEYWORDS: &str = "patient|client|defendant|plaintiff|applicant|appellant|respondent|petitioner|claimant|employee|employer|teacher|student|author|by|from|to|signed by|authored by|submitted by|prepared by|filed by|reviewed by|approved by|written by|sent by|received by|referring to|regarding|re:|concerning|subject:|for|name:|full name:|contact:";

/// A pattern, written in the reference's case, and whether it is
/// case-insensitive (then it is lower-cased: `[A-Z]` becomes `[a-z]`, which
/// on the ASCII-lower-cased haystack matches any ASCII letter, as `/i` does).
fn compile(source: &str, insensitive: bool) -> JsRegex {
    if insensitive {
        JsRegex::insensitive(&source.to_lowercase())
    } else {
        JsRegex::new(source)
    }
}

struct Patterns {
    greeting: JsRegex,
    title: JsRegex,
    context: JsRegex,
    aggressive: JsRegex,
    leading_capitalised: JsRegex,
}

fn patterns() -> &'static Patterns {
    static CELL: OnceLock<Patterns> = OnceLock::new();
    CELL.get_or_init(|| {
        // The reference escapes the keywords for its aggressive pattern, `|` included,
        // so that alternative only matches the whole keyword list written out.
        let escaped = regex::escape(KEYWORDS);
        Patterns {
            greeting: compile(
                r"(?:^|\.\s+)(?:dear|hi|hello|greetings|hey there|hey)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
                true,
            ),
            title: compile(
                &format!(r"\b{TITLES}\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)"),
                false,
            ),
            context: compile(
                &format!(r"\b(?:{KEYWORDS})\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)"),
                false,
            ),
            aggressive: compile(
                &format!(
                    r"(?:(?:^|\.[\s]+)(?:dear|hi|hello|greetings|hey there|hey)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*))|(?:\b{TITLES}\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*))|(?:\b(?:{escaped})\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+))"
                ),
                true,
            ),
            leading_capitalised: JsRegex::new(r"^(?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+)*"),
        }
    })
}

fn extract(text: &str, pattern: &JsRegex, confidence: f64, out: &mut Vec<Match>) {
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = pattern.captures_at(text, at) else {
            break;
        };
        let Some((start, end)) = groups[0] else {
            break;
        };
        at = if end > start {
            end
        } else {
            next_char(text, end)
        };

        let Some((cs, ce)) = groups.iter().skip(1).flatten().next().copied() else {
            continue;
        };
        let raw = text[cs..ce].trim();
        if raw.is_empty() {
            continue;
        }
        // The reference looks the capture up again from the start of the match.
        let Some(capture) = text[start..].find(raw).map(|offset| start + offset) else {
            continue;
        };
        if !text[capture..].starts_with(|c: char| c.is_ascii_uppercase()) {
            continue;
        }
        let Some(&(_, length)) = patterns()
            .leading_capitalised
            .ranges(&text[capture..])
            .first()
        else {
            continue;
        };
        out.push(Match::new(
            Category::Name,
            text,
            capture,
            capture + length,
            confidence,
        ));
    }
}

/// Sort by start, then by confidence, highest first, and keep the matches that
/// do not start inside the previous one.
fn deduplicate(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by(|a, b| {
        a.start.cmp(&b.start).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    let mut kept = Vec::with_capacity(matches.len());
    let mut cursor = 0;
    for m in matches {
        if m.start >= cursor {
            cursor = m.end;
            kept.push(m);
        }
    }
    kept
}

pub(super) fn detect(text: &str, aggressive: bool) -> Vec<Match> {
    let p = patterns();
    let mut found = Vec::new();
    if aggressive {
        extract(text, &p.aggressive, 0.65, &mut found);
    } else {
        extract(text, &p.greeting, 0.75, &mut found);
        extract(text, &p.title, 0.78, &mut found);
        extract(text, &p.context, 0.7, &mut found);
    }
    deduplicate(found)
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
    fn greetings_titles_and_keywords() {
        assert_eq!(values("Dear John Smith, thank you.", false), ["John Smith"]);
        assert_eq!(
            values("Appointment with Dr. Maria Silva today", false),
            ["Maria Silva"]
        );
        assert_eq!(
            values("Signed by Ana Costa Lima on Monday", false),
            ["Ana Costa Lima"]
        );
    }

    #[test]
    fn reference_quirks() {
        assert!(values("Report. Hi alice Brown", false).is_empty());
        assert!(values("hello there, hi john doe and HELLO Ana Lima", false).is_empty());
        assert_eq!(values("Mr Smith and Mrs. Jane Doe", true), ["Smith"]);
    }
}
