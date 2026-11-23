//! Postal addresses (`src/detectors/address.ts`): US streets, European and
//! Brazilian streets with their postal code and town, UK postcodes, post
//! office boxes, and the text after an address label.
//!
//! The European patterns are Unicode-aware (`\p{Lu}`, `\p{L}`) and guarded by
//! `(?<![\p{L}\d])` before and, for two of them, `(?![\p{L}\d])` after the
//! house number, followed by an optional town. The lookbehind is checked on
//! the candidate; the lookahead becomes an alternative of the town: the town
//! itself (which starts with a comma or a space, so the lookahead holds), the
//! end of the text, or one character that is neither a letter nor a digit.

use std::collections::HashSet;
use std::sync::OnceLock;

use super::Match;
use crate::jsregex::{is_letter_or_digit, js_regex, next_char, Haystack, JsRegex};
use crate::Category;

js_regex!(us_street = insensitive r"\b\d{1,5}\s+(?:(?:n|s|e|w|ne|nw|se|sw|north|south|east|west|northeast|northwest|southeast|southwest)\.?\s+)?(?:[a-z][a-z]+\s+){1,4}(?:st(?:reet)?|ave(?:nue)?|blvd|boulevard|dr(?:ive)?|rd|road|ln|lane|ct|court|pl|place|cir|circle|way|pkwy|parkway|hwy|highway|trl|trail|terr(?:ace)?|terr)\.?(?:\s+(?:apt|apartment|suite|ste|unit|#)\s*\w+)?\b");
js_regex!(uk_postcode = insensitive r"\b[a-z]{1,2}\d[a-z\d]?\s*\d[a-z]{2}\b");
js_regex!(po_box = insensitive r"\bp\.?o\.?\s+box\s+\d+\b");
// `[^\n,]{10,80}` counts characters here and UTF-16 units in the reference:
// they differ only for characters outside the Basic Multilingual Plane.
js_regex!(labelled = insensitive r"(?:address(?:ed to)?|lives at|located at|shipped? to|mailing address|billing address|residence|resides at|home address|headquartered at|office address)\s*:?\s*([^\n,]{10,80})");

/// Postal code and town after a European street (without the reference's final `?`).
const TOWN: &str = r"(?:,?\s+(?:[A-Z]{1,2}-)?\d{4,5}(?:-\d{3}|\s[A-Z]{2})?\s+\p{Lu}[\p{L}'-]+(?:\s\p{Lu}[\p{L}'-]+)?)";

const SUFFIX: &str = r"(?:stra(?:ß|ss)e|str\.|weg|gasse|platz|allee|damm|ufer|straat|laan|gracht|plein|kade|singel|gatan|vägen|veien|gade)";
const WORD: &str = r"(?:Stra(?:ß|ss)e|Str\.|Weg|Gasse|Platz|Allee|Damm|Ufer|Straat|Laan)";
const TYPE: &str = r"(?:[Rr]ue|[Aa]venue|[Bb]oulevard|[Bb]d|[Cc]hemin|[Ii]mpasse|[Aa]llée|[Qq]uai|Calle|C\/|Avenida|Avda\.|Av\.|Paseo|Plaza|Carrer|Via|Viale|Piazza|Corso|Largo|Rua|Travessa|Praça|Alameda|Estrada|Rodovia)";
const LINK: &str =
    r"(?:(?:de|del|de la|des|du|d'|la|le|l'|las|los|el|da|das|do|dos|di|della|delle|dei)\s?)";

/// A European street pattern: `(core)` then the town, and whether the
/// reference puts `(?![\p{L}\d])` between them.
struct Street {
    regex: JsRegex,
}

impl Street {
    fn new(core: &str, lookahead: bool) -> Self {
        let source = if lookahead {
            format!(r"({core})(?:({TOWN})|$|[^\p{{L}}\d])")
        } else {
            format!(r"({core})({TOWN})?")
        };
        Street {
            regex: JsRegex::new(&source),
        }
    }

    /// The matches, as a global `exec` loop finds them: the street, with its
    /// town when there is one.
    fn ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let haystack = Haystack::new(text);
        let mut out = Vec::new();
        let mut at = 0;
        while at <= text.len() {
            let Some(groups) = self.regex.captures_at(&haystack, at) else {
                break;
            };
            let Some((start, core_end)) = groups[1] else {
                break;
            };
            if text[..start]
                .chars()
                .next_back()
                .is_some_and(is_letter_or_digit)
            {
                at = next_char(text, start);
                continue;
            }
            let end = groups[2].map_or(core_end, |(_, town_end)| town_end);
            out.push((start, end));
            at = if end > start {
                end
            } else {
                next_char(text, end)
            };
        }
        out
    }
}

fn streets() -> &'static [Street] {
    static CELL: OnceLock<Vec<Street>> = OnceLock::new();
    CELL.get_or_init(|| {
        let name = format!(r"{LINK}{{0,3}}\p{{Lu}}[\p{{L}}'-]*(?:\s{LINK}{{0,3}}\p{{Lu}}[\p{{L}}'-]*){{0,3}}");
        vec![
            // Hauptstraße 12, Ein Weg 12a.
            Street::new(
                &format!(r"(?:\p{{Lu}}\p{{Ll}}*{SUFFIX}|\p{{Lu}}\p{{Ll}}+[\s-]{WORD})\s+\d{{1,4}}\s?[a-z]?"),
                true,
            ),
            // 12 rue de la Paix.
            Street::new(
                &format!(r"\d{{1,4}}(?:\s?(?:bis|ter))?,?\s+{TYPE}\s+{name}"),
                false,
            ),
            // Rua das Flores, 123.
            Street::new(
                &format!(r"{TYPE}\s+{name},?\s+(?:n[º°o.]\s?)?\d{{1,5}}[A-Za-z]?"),
                true,
            ),
        ]
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let mut matches: Vec<Match> = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut push = |matches: &mut Vec<Match>, start: usize, end: usize, confidence: f64| {
        if seen.insert((start, end)) {
            matches.push(Match::new(Category::Address, text, start, end, confidence));
        }
    };

    for (start, end) in us_street().ranges(text) {
        push(&mut matches, start, end, 0.8);
    }

    // A European street inside one found before it is not reported; it
    // replaces the shorter matches it contains.
    let mut found_streets: Vec<(usize, usize)> = Vec::new();
    for street in streets() {
        for (start, end) in street.ranges(text) {
            if matches.iter().any(|m| m.start <= start && end <= m.end) {
                continue;
            }
            matches.retain(|m| !(start <= m.start && m.end <= end));
            push(&mut matches, start, end, 0.8);
            found_streets.push((start, end));
        }
    }

    for (start, end) in uk_postcode().ranges(text) {
        push(&mut matches, start, end, 0.78);
    }
    for (start, end) in po_box().ranges(text) {
        push(&mut matches, start, end, 0.85);
    }

    // Text after an address label, unless it lies inside a street found whole.
    let haystack = Haystack::new(text);
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = labelled().captures_at(&haystack, at) else {
            break;
        };
        let (Some((match_start, match_end)), Some((cs, ce))) = (groups[0], groups[1]) else {
            break;
        };
        at = if match_end > match_start {
            match_end
        } else {
            next_char(text, match_end)
        };
        let captured = text[cs..ce].trim();
        let Some(start) = text[match_start..].find(captured).map(|i| match_start + i) else {
            continue;
        };
        let end = start + captured.len();
        if found_streets.iter().any(|&(s, e)| s <= start && end <= e) {
            continue;
        }
        push(&mut matches, start, end, 0.82);
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str) -> Vec<String> {
        detect(text).into_iter().map(|m| m.value).collect()
    }

    #[test]
    fn us_and_uk() {
        assert_eq!(
            values("Send it to 742 Evergreen Terrace please"),
            ["742 Evergreen Terrace"]
        );
        assert_eq!(
            values("Postcode SW1A 1AA and P.O. Box 1234"),
            ["SW1A 1AA", "P.O. Box 1234"]
        );
    }

    #[test]
    fn european_and_brazilian_streets() {
        assert_eq!(
            values("Wohnt in der Hauptstraße 12, 10115 Berlin."),
            ["Hauptstraße 12, 10115 Berlin"]
        );
        assert_eq!(values("Ein Weg 12a ist kurz"), ["Ein Weg 12a"]);
        assert_eq!(
            values("Adresse: 12 rue de la Paix, 75002 Paris"),
            ["12 rue de la Paix, 75002 Paris"]
        );
        assert_eq!(
            values("Mora na Rua das Flores, 123, São Paulo"),
            ["Rua das Flores, 123"]
        );
    }

    #[test]
    fn labelled_text() {
        assert_eq!(
            values("Billing address: 221B Baker Street London"),
            ["221B Baker Street London"]
        );
        assert_eq!(
            values("Shipped to: 10 Downing Street, London"),
            ["10 Downing Street"]
        );
    }
}
