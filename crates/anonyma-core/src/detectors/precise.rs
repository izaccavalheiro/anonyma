//! The precise detectors of the engine (`src/engine/precise.ts`): fewer false
//! positives than the classic ones, for e-mail addresses, SSNs and IBANs.
//! Each returns `(start, end, confidence)` in byte offsets.

use std::sync::OnceLock;

use crate::jsregex::{is_letter, js_regex, Guarded, Lookbehind};
use crate::validators::iban_mod97;

/// A detection: byte range and confidence.
pub(crate) type Hit = (usize, usize, f64);

fn group(groups: &[Option<(usize, usize)>], index: usize) -> Option<(usize, usize)> {
    groups.get(index).copied().flatten()
}

/// `text[..start]`, limited to its last `units` UTF-16 code units, as
/// `text.slice(Math.max(0, start - units), start)` (a character that would be
/// cut in half is left out).
fn before(text: &str, start: usize, units: usize) -> &str {
    let mut taken = 0;
    let mut from = start;
    for c in text[..start].chars().rev() {
        let width = c.len_utf16();
        if taken + width > units {
            break;
        }
        taken += width;
        from -= c.len_utf8();
    }
    &text[from..start]
}

fn letter_or_number(c: char) -> bool {
    is_letter(c) || c.is_numeric()
}

// ---------------------------------------------------------------------------
// E-mail
// ---------------------------------------------------------------------------

const NOT_A_TLD: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "css", "js", "json", "map",
    "service", "socket", "timer", "mount", "target", "slice", "scope",
];

const COMMON_TLD: &[&str] = &[
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "io", "co",
    "me", "dev", "app", "ai",
];

fn email_pattern() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        // `giu` in the reference: Unicode case folding, as `(?i)` does here.
        Guarded::with(
            r"(?i:[\p{L}\p{N}_%+-](?:[\p{L}\p{N}._%+'-]{0,62}[\p{L}\p{N}_%+-])?@((?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+)(xn--[a-z0-9-]{1,59}|\p{L}{2,24}))",
            r"$|\P{L}",
            Lookbehind::Char(|c| letter_or_number(c) || matches!(c, '_' | '%' | '+' | '-')),
            false,
        )
    })
}

js_regex!(url_userinfo_before = insensitive r"[a-z][a-z0-9+.-]*:\/\/[a-z0-9._~%!$*+:-]*$");
js_regex!(message_id_before = insensitive r"\b(?:message-id|in-reply-to|references)\s*:\s*(?:<[^\s<>]*>\s*)*<[^\s<>@]*$");

pub(crate) fn email(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for groups in email_pattern().matches(text) {
        let (Some((start, end)), Some((ds, de)), Some((ts, te))) =
            (group(&groups, 1), group(&groups, 2), group(&groups, 3))
        else {
            continue;
        };
        let value = &text[start..end];
        let domain = &text[ds..de];
        let tld = text[ts..te].to_lowercase();
        if NOT_A_TLD.contains(&tld.as_str()) {
            continue;
        }
        // "name@1.0.0-beta": a package version, not a domain.
        let leading_digits = domain.bytes().take_while(u8::is_ascii_digit).count();
        if leading_digits > 0 {
            let rest = &domain[leading_digits..];
            if let Some(rest) = rest.strip_prefix('.') {
                let more = rest.bytes().take_while(u8::is_ascii_digit).count();
                if more > 0 && rest[more..].starts_with('.') {
                    continue;
                }
            }
        }
        // "W@x.flatten()": a call on a short identifier, not an address.
        let at = value[..value.find('@').unwrap_or(0)].encode_utf16().count();
        if text[end..].starts_with('(')
            && at <= 2
            && tld.encode_utf16().count() > 2
            && !COMMON_TLD.contains(&tld.as_str())
        {
            continue;
        }
        // The account every Git remote uses is nobody's address.
        if value.starts_with("git@") {
            continue;
        }
        let context = before(text, start, 96);
        if url_userinfo_before().is_match(context) || message_id_before().is_match(context) {
            continue;
        }
        out.push((start, end, 0.99));
    }
    out
}

fn obfuscated_pattern() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        Guarded::with(
            r"(?i:[\p{L}\p{N}_%+-][\p{L}\p{N}._%+-]{0,63}(?:\s*(?:\[at\]|\(at\)|\{at\}|\[@\])\s*|[ \t]+@[ \t]*|@[ \t]+)[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\s*(?:\[dot\]|\(dot\)|\{dot\}|\[\.\]|\.)\s*[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\s*(?:\[dot\]|\(dot\)|\{dot\}|\[\.\]|\.)\s*\p{L}{2,24})",
            r"$|[^\p{L}\p{N}]",
            Lookbehind::Char(|c| letter_or_number(c) || matches!(c, '.' | '_' | '%' | '+' | '-')),
            false,
        )
    })
}

pub(crate) fn obfuscated_email(text: &str) -> Vec<Hit> {
    obfuscated_pattern()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| (start, end, 0.75))
        .collect()
}

// ---------------------------------------------------------------------------
// SSN
// ---------------------------------------------------------------------------

fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2010}'..='\u{2015}' | '\u{2212}' | '.')
}

fn assignable(
    text: &str,
    area: (usize, usize),
    group: (usize, usize),
    serial: (usize, usize),
) -> bool {
    let area = &text[area.0..area.1];
    area != "000"
        && area != "666"
        && !area.starts_with('9')
        && &text[group.0..group.1] != "00"
        && &text[serial.0..serial.1] != "0000"
}

fn separated_ssn() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        const SEPARATOR: &str = r"(?:\s?[-‐-―−.]\s?|\s{1,2})";
        // (?<!\d)(?<!\d[-‐-―−./])
        fn rejects(before: &str) -> bool {
            let mut chars = before.chars().rev();
            match (chars.next(), chars.next()) {
                (Some(last), _) if last.is_ascii_digit() => true,
                (Some(last), Some(previous)) => {
                    (is_dash(last) || last == '/') && previous.is_ascii_digit()
                }
                _ => false,
            }
        }
        Guarded::with(
            &format!(r"(\d{{3}}){SEPARATOR}(\d{{2}}){SEPARATOR}(\d{{4}})"),
            r"$|[^\d\-‐-―−.]|[\-‐-―−.](?:$|[^\d])",
            Lookbehind::Text(rejects),
            false,
        )
    })
}

fn labelled_ssn() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        Guarded::with(
            r"(?:\bssn|\bss#|\bsocial\s+security)(?:\s*(?:number|num\.?|no\.?|#))?[^\d\n.;!?]{0,24}(\d{9})",
            r"$|[^\d]",
            Lookbehind::None,
            true,
        )
    })
}

pub(crate) fn ssn(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for groups in separated_ssn().matches(text) {
        if let (Some((start, end)), Some(a), Some(g), Some(s)) = (
            group(&groups, 1),
            group(&groups, 2),
            group(&groups, 3),
            group(&groups, 4),
        ) {
            if assignable(text, a, g, s) {
                out.push((start, end, 0.95));
            }
        }
    }
    for groups in labelled_ssn().matches(text) {
        if let Some((start, end)) = group(&groups, 2) {
            if assignable(
                text,
                (start, start + 3),
                (start + 3, start + 5),
                (start + 5, end),
            ) {
                out.push((start, end, 0.9));
            }
        }
    }
    out
}

fn bare_ssn_pattern() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        Guarded::new(
            r"(\d{3})(\d{2})(\d{4})",
            r"$|[^\d.,]|[.,](?:$|[^\d])",
            |c| c.is_ascii_digit() || c == '.' || c == ',',
        )
    })
}

pub(crate) fn bare_ssn(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for groups in bare_ssn_pattern().matches(text) {
        if let (Some((start, _)), Some(a), Some(g), Some(s)) = (
            group(&groups, 1),
            group(&groups, 2),
            group(&groups, 3),
            group(&groups, 4),
        ) {
            if assignable(text, a, g, s) {
                out.push((start, start + 9, 0.5));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

/// The length of an IBAN by country: the registry, and the countries outside it
/// that use the format.
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BI", 27),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DJ", 27),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HN", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("LY", 25),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MN", 20),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NI", 28),
    ("NL", 18),
    ("NO", 15),
    ("OM", 23),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("RU", 33),
    ("SA", 24),
    ("SC", 31),
    ("SD", 18),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("SO", 23),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
    ("YE", 30),
    ("AO", 25),
    ("BF", 28),
    ("BJ", 28),
    ("CF", 27),
    ("CG", 27),
    ("CI", 28),
    ("CM", 27),
    ("CV", 25),
    ("DZ", 26),
    ("GA", 27),
    ("GQ", 27),
    ("GW", 25),
    ("IR", 26),
    ("KM", 27),
    ("MA", 28),
    ("MG", 27),
    ("ML", 28),
    ("MZ", 25),
    ("NE", 28),
    ("SN", 28),
    ("TD", 27),
    ("TG", 28),
];

fn iban_start() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| Guarded::new(r"[A-Za-z]{2}\d{2}", "", |c| c.is_ascii_alphanumeric()))
}

fn is_iban_separator(c: char) -> bool {
    matches!(c, ' ' | '\u{A0}' | '-' | '\t' | '\n' | '\r')
}

/// The end of the IBAN of `length` characters that starts at `start`.
fn end_of_iban(text: &str, start: usize, length: usize) -> Option<usize> {
    let mut collected = String::with_capacity(length);
    let mut end = start;
    let mut separators = 2;
    for (offset, c) in text[start..].char_indices() {
        if collected.len() >= length {
            break;
        }
        if c.is_ascii_alphanumeric() {
            collected.push(c);
            separators = 0;
            end = start + offset + 1;
        } else if separators < 2 && is_iban_separator(c) {
            separators += 1;
        } else {
            break;
        }
    }
    if collected.len() != length || text[end..].starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    let normalised = collected.to_ascii_uppercase();
    let check: u32 = normalised[2..4].parse().ok()?;
    ((2..=98).contains(&check) && iban_mod97(&normalised)).then_some(end)
}

pub(crate) fn iban(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = iban_start().candidate(text, at) else {
            break;
        };
        let Some((start, match_end)) = group(&groups, 1) else {
            break;
        };
        if !iban_start().may_start(text, start) {
            at = crate::jsregex::next_char(text, start);
            continue;
        }
        at = match_end;
        let country = text[start..start + 2].to_ascii_uppercase();
        let Some(&(_, length)) = IBAN_LENGTHS.iter().find(|(code, _)| *code == country) else {
            continue;
        };
        if let Some(end) = end_of_iban(text, start, length) {
            out.push((start, end, 0.99));
            at = end;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(text: &str, hits: Vec<Hit>) -> Vec<String> {
        hits.into_iter()
            .map(|(s, e, _)| text[s..e].to_string())
            .collect()
    }

    #[test]
    fn precise_email() {
        let text = "Mail ana@example.com, see logo@2x.png and git@github.com:org/repo.git";
        assert_eq!(values(text, email(text)), ["ana@example.com"]);
        let text = "Open https://ana@example.com/x or ftp://bob@example.org";
        assert!(email(text).is_empty());
        assert!(email("Message-ID: <abc123@mail.example.com>").is_empty());
        let text = "Write to ana [at] example [dot] com";
        assert_eq!(
            values(text, obfuscated_email(text)),
            ["ana [at] example [dot] com"]
        );
    }

    #[test]
    fn precise_ssn() {
        let text = "SSN 123\u{2013}45\u{2013}6789 and 123 45 6789";
        assert_eq!(
            values(text, ssn(text)),
            ["123\u{2013}45\u{2013}6789", "123 45 6789"]
        );
        let text = "SSN of the applicant: 123456789.";
        assert_eq!(values(text, ssn(text)), ["123456789"]);
        assert_eq!(bare_ssn("Ref 123456789 here").len(), 1);
    }

    #[test]
    fn precise_iban() {
        let text = "IBAN gb82 west 1234 5698 7654 32 ok";
        assert_eq!(values(text, iban(text)), ["gb82 west 1234 5698 7654 32"]);
        let text = "Account GB82-WEST-1234-5698-7654-32.";
        assert_eq!(values(text, iban(text)), ["GB82-WEST-1234-5698-7654-32"]);
    }

    #[test]
    fn context_before_counts_utf16_units() {
        // "ab😀cd": the three units before "d" are the surrogate pair and "c".
        assert_eq!(before("ab\u{1F600}cd", 7, 3), "\u{1F600}c");
        assert_eq!(before("ab\u{1F600}cd", 7, 2), "c");
        assert_eq!(before("abc", 3, 96), "abc");
    }
}
