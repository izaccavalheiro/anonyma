//! The precise detectors of the engine (`src/engine/precise.ts`): fewer false
//! positives than the classic ones, for e-mail addresses, SSNs and IBANs.
//! Each returns `(start, end, confidence)` in byte offsets.

use std::sync::OnceLock;

use crate::jsregex::{is_letter, js_regex, Guarded, Haystack, Lookbehind};
use crate::validators::{iban_mod97, is_js_space};

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
    let haystack = Haystack::new(text);
    let mut out = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = iban_start().candidate(&haystack, at) else {
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

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// The text after `end`, limited to `units` UTF-16 code units.
fn after(text: &str, end: usize, units: usize) -> &str {
    let mut taken = 0;
    let mut to = end;
    for c in text[end..].chars() {
        let width = c.len_utf16();
        if taken + width > units {
            break;
        }
        taken += width;
        to += c.len_utf8();
    }
    &text[end..to]
}

fn ipv4_pattern() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        const OCTET: &str = r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)";
        // The reference's `(\/prefix(?![\w/.]))?(?!\.?\d)`: a prefix length when
        // nothing word-like follows it, else the address alone when no digit follows.
        Guarded::with(
            &format!(r"({OCTET}\.)({OCTET}\.{OCTET}\.{OCTET})"),
            r"(\/(?:3[0-2]|[12]?\d))(?:$|[^\w/.])|$|[^\d.]|\.(?:$|[^\d])",
            Lookbehind::Char(|c| c.is_ascii_digit() || c == '.'),
            false,
        )
    })
}

js_regex!(version_before = insensitive r#"(?:\bv|version|\bver\.?|\bfirmware|\brev\.?)\s*[:=#("']{0,3}\s*$"#);
js_regex!(numbering_before = insensitive r#"(?:\bsection|\bsec\.|\bchapter|\bclause|\bappendix|\bannex|\boid|§)\s*[:=#("']{0,3}\s*$"#);
js_regex!(weak_version_before = insensitive r#"(?:\brelease|\bbuild)\s*[:=#("']{0,3}\s*$"#);
js_regex!(
    reference_before = r#"(?:\bTable|\bFigure|\bFig\.|\b[A-Z]{2,6}-\d+)\s*[:=#("']{0,3}\s*$"#
);
js_regex!(version_suffix_after = r"^(?:[-.][A-Za-z]|-\d+[A-Za-z])");

/// `(?<![/\w.+-])(?!(?:tcp|udp|...)\/)[a-z][\w.+-]*\/\s*$` (case-insensitive):
/// a product name and a slash end the text, as in "nginx/".
fn product_before(before: &str) -> bool {
    const PROTOCOLS: &[&str] = &[
        "tcp", "udp", "sctp", "icmp", "ip", "ipv4", "inet", "ssh", "dns", "peer", "host", "addr",
        "src", "dst",
    ];
    let trimmed = before.trim_end_matches(is_js_space);
    let Some(body) = trimmed.strip_suffix('/') else {
        return false;
    };
    let token_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-');
    let start = body
        .char_indices()
        .rev()
        .take_while(|&(_, c)| token_char(c))
        .last()
        .map(|(index, _)| index);
    let Some(start) = start else {
        return false;
    };
    let token = &body[start..];
    token.starts_with(|c: char| c.is_ascii_alphabetic())
        && !body[..start].ends_with('/')
        && !PROTOCOLS.contains(&token.to_ascii_lowercase().as_str())
}

fn is_reserved_ipv4(octets: &[u32]) -> bool {
    let (a, b, c) = (octets[0], octets[1], octets[2]);
    a == 10
        || a == 127
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

pub(crate) fn ipv4(text: &str) -> Vec<Hit> {
    let pattern = ipv4_pattern();
    let haystack = Haystack::new(text);
    let mut out = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(groups) = pattern.candidate(&haystack, at) else {
            break;
        };
        let Some((start, core_end)) = group(&groups, 1) else {
            break;
        };
        if !pattern.may_start(text, start) {
            at = crate::jsregex::next_char(text, start);
            continue;
        }
        let prefix = group(&groups, 4);
        let mut end = prefix.map_or(core_end, |(_, e)| e);
        at = end;
        let value = &text[start..end];
        let first = group(&groups, 2).map(|(s, e)| &text[s..e]);
        // Netmasks, broadcast and the unspecified address identify nobody.
        if first == Some("255.") || value.starts_with("0.0.0.0") {
            continue;
        }
        let address = &text[start..core_end];
        let octets: Vec<&str> = address.split('.').collect();
        // Zero padding is only credible when every octet has three digits.
        if octets.iter().any(|o| o.len() == 2 && o.starts_with('0')) {
            continue;
        }
        if octets.contains(&"000") && octets.iter().any(|o| o.len() != 3) {
            continue;
        }
        let context = before(text, start, 48);
        if version_before().is_match(context) || product_before(context) {
            continue;
        }
        let small = octets.iter().all(|o| o.len() <= 2);
        if small && numbering_before().is_match(context) {
            continue;
        }
        let numbers: Vec<u32> = octets.iter().map(|o| o.parse().unwrap_or(0)).collect();
        if !is_reserved_ipv4(&numbers) {
            if weak_version_before().is_match(context)
                || (small && reference_before().is_match(context))
            {
                continue;
            }
            if version_suffix_after().is_match(after(text, end, 8)) {
                continue;
            }
        }
        // After "//" a slash starts a URL path, not a prefix length.
        if prefix.is_some() && context.ends_with("//") {
            end = core_end;
        }
        out.push((start, end, 0.95));
    }
    out
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

js_regex!(ipv6_run = r"[0-9A-Fa-f:.]{2,}");

fn is_word_character(c: char) -> bool {
    c == '_' || is_letter(c) || c.is_numeric()
}

fn is_hex_group(group: &str) -> bool {
    (1..=4).contains(&group.len()) && group.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_dotted_quad(group: &str) -> bool {
    let parts: Vec<&str> = group.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u32>().is_ok_and(|n| n <= 255)
        })
}

/// Number of 16-bit groups of one side of an address, `None` if malformed.
fn count_groups(side: &str, ipv4_tail: bool) -> Option<usize> {
    if side.is_empty() {
        return Some(0);
    }
    let groups: Vec<&str> = side.split(':').collect();
    let mut count = 0;
    for (index, group) in groups.iter().enumerate() {
        if is_hex_group(group) {
            count += 1;
        } else if ipv4_tail && index == groups.len() - 1 && is_dotted_quad(group) {
            count += 2;
        } else {
            return None;
        }
    }
    Some(count)
}

fn is_ipv6(candidate: &str) -> bool {
    let Some(compression) = candidate.find("::") else {
        let groups: Vec<&str> = candidate.split(':').collect();
        // Eight groups of two hex digits is an EUI-64 / MAC-style identifier.
        if groups.len() == 8 && groups.iter().all(|g| g.len() == 2) {
            return false;
        }
        return count_groups(candidate, true) == Some(8);
    };
    if candidate[compression + 1..].contains("::") {
        return false;
    }
    match (
        count_groups(&candidate[..compression], false),
        count_groups(&candidate[compression + 2..], true),
    ) {
        (Some(head), Some(tail)) => head + tail <= 7 && head + tail > 0,
        _ => false,
    }
}

pub(crate) fn ipv6(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for (run_start, run_end) in ipv6_run().ranges(text) {
        let mut start = run_start;
        let mut value = &text[run_start..run_end];
        // A run inside or right after a label ("IPv6:2001:db8::1", "eth0:fe80::1"):
        // the address begins after the first colon.
        let glued = text[..start]
            .chars()
            .next_back()
            .is_some_and(is_word_character);
        let colon = value.find(':');
        if !value.starts_with("::") && (colon == Some(0) || (glued && matches!(colon, Some(1 | 2))))
        {
            let skip = colon.unwrap_or(0) + 1;
            start += skip;
            value = &value[skip..];
        } else if glued {
            continue;
        }
        // Trailing full stops and a single trailing colon are not part of an address.
        value = value.trim_end_matches('.');
        if value.ends_with(':') && !value.ends_with("::") {
            value = &value[..value.len() - 1];
        }
        if value.len() < 3 || value.len() > 45 {
            continue;
        }
        if value.find(':') == value.rfind(':') {
            continue;
        }
        let end = start + value.len();
        if text[end..].chars().next().is_some_and(is_word_character) {
            continue;
        }
        // "Add::add" and "dead::beef" are identifiers and words, not addresses.
        if !value.bytes().any(|b| b.is_ascii_digit())
            && value.split(':').filter(|g| !g.is_empty()).count() < 3
        {
            continue;
        }
        if is_ipv6(value) {
            out.push((start, end, 0.95));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Payment cards
// ---------------------------------------------------------------------------

const CARD_GROUPINGS: &[&[usize]] = &[
    &[4, 4, 4, 4, 3],
    &[4, 4, 4, 4],
    &[4, 4, 4, 3],
    &[4, 4, 4, 2],
    &[4, 4, 4, 1],
    &[4, 6, 5],
    &[4, 6, 4],
    &[8, 8],
    &[6, 13],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Separator {
    None,
    Space,
    Hyphen,
    Dot,
    Newline,
}

fn separator_kind(between: &str) -> Separator {
    let mut chars = between.chars();
    let space = |c: char| c == ' ' || c == '\u{A0}';
    match (chars.next(), chars.next(), chars.next()) {
        (Some(c), None, None) if space(c) => Separator::Space,
        (Some('-'), None, None) => Separator::Hyphen,
        (Some('.'), None, None) => Separator::Dot,
        (Some('\n'), None, None) => Separator::Newline,
        (Some(a), Some(b), None) if space(a) && space(b) => Separator::Space,
        (Some('\r'), Some('\n'), None) => Separator::Newline,
        _ => Separator::None,
    }
}

fn in_range(digits: &str, length: usize, low: u32, high: u32) -> bool {
    digits
        .get(..length.min(digits.len()))
        .and_then(|prefix| prefix.parse::<u32>().ok())
        .is_some_and(|n| (low..=high).contains(&n))
}

fn starts_3_diners(digits: &str) -> bool {
    ["3095", "36", "38", "39"]
        .iter()
        .any(|p| digits.starts_with(p))
}

fn is_issued_range(digits: &str, grouped: bool) -> bool {
    let length = digits.len();
    if digits.starts_with('4') {
        return matches!(length, 13 | 16 | 19);
    }
    if in_range(digits, 2, 51, 55) || in_range(digits, 4, 2221, 2720) {
        return length == 16;
    }
    if digits.starts_with("34") || digits.starts_with("37") {
        return length == 15;
    }
    // UATP; an unseparated 15-digit number that starts with 1 is too often something else.
    if digits.starts_with('1') {
        return grouped && length == 15;
    }
    if length == 14 {
        return in_range(digits, 3, 300, 305) || starts_3_diners(digits);
    }
    if length < 16 {
        return false;
    }
    digits.starts_with("6011")
        || in_range(digits, 3, 644, 649)
        || digits.starts_with("65")
        || digits.starts_with("62")
        || in_range(digits, 4, 3528, 3589)
        || in_range(digits, 3, 300, 305)
        || starts_3_diners(digits)
        || in_range(digits, 4, 2200, 2205)
        || digits.starts_with("50")
        || in_range(digits, 2, 56, 69)
        // RuPay, UzCard, Humo, Troy, NAPAS, T-Union.
        || in_range(digits, 2, 81, 82)
        || ["8600", "9860", "9792", "9704", "31"]
            .iter()
            .any(|p| digits.starts_with(p))
}

pub(crate) fn card(text: &str) -> Vec<Hit> {
    use crate::validators::luhn_digits;
    // The digit runs of the text.
    let bytes = text.as_bytes();
    let mut starts = Vec::new();
    let mut ends = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at].is_ascii_digit() {
            starts.push(at);
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
            }
            ends.push(at);
        } else {
            at += 1;
        }
    }
    // (run, start, end, confidence)
    let mut candidates: Vec<(usize, usize, usize, f64)> = Vec::new();
    let mut reach: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut add = |run: usize, end: usize, confidence: f64| {
        candidates.push((run, starts[run], end, confidence));
        let r = reach.entry(run).or_insert(0);
        *r = (*r).max(end);
    };
    for run in 0..starts.len() {
        let start = starts[run];
        let length = ends[run] - start;
        if (13..=19).contains(&length) {
            let digits = &text[start..start + length];
            if is_issued_range(digits, false) && luhn_digits(digits) {
                add(run, start + length, 0.92);
            }
            continue;
        }
        for grouping in CARD_GROUPINGS {
            if grouping[0] != length {
                continue;
            }
            let mut digits = String::new();
            let mut uniform = true;
            let mut kind = Separator::None;
            let mut fits = true;
            for (offset, &size) in grouping.iter().enumerate() {
                let index = run + offset;
                if index >= starts.len() || ends[index] - starts[index] != size {
                    fits = false;
                    break;
                }
                if offset > 0 {
                    let between = separator_kind(&text[ends[index - 1]..starts[index]]);
                    if between == Separator::None {
                        fits = false;
                        break;
                    }
                    if kind != Separator::None && between != kind {
                        uniform = false;
                    }
                    kind = between;
                }
                digits.push_str(&text[starts[index]..ends[index]]);
            }
            if !fits || !luhn_digits(&digits) {
                continue;
            }
            let end = ends[run + grouping.len() - 1];
            if is_issued_range(&digits, true) {
                add(run, end, if uniform { 0.97 } else { 0.85 });
            } else if uniform
                && digits.len() == 16
                && grouping.len() == 4
                && !digits.bytes().all(|b| b == digits.as_bytes()[0])
            {
                // Four groups of four with a valid check digit: a card of a network outside the table.
                add(run, end, 0.6);
            }
        }
    }
    // Report the candidates that add something: one that only covers the end of an
    // accepted number and the beginning of the next candidate is the same digits read
    // out of phase.
    let mut out = Vec::new();
    let mut covered: Option<usize> = None;
    for (run, start, end, confidence) in candidates {
        if covered.is_some_and(|c| end <= c) {
            continue;
        }
        if let Some(c) = covered {
            if start < c {
                let mut next = run;
                while next < starts.len() && starts[next] < c {
                    next += 1;
                }
                if reach.get(&next).copied().unwrap_or(0) >= end {
                    continue;
                }
            }
        }
        out.push((start, end, confidence));
        covered = Some(covered.map_or(end, |c| c.max(end)));
    }
    out
}

fn masked_card_pattern() -> &'static Guarded {
    static CELL: OnceLock<Guarded> = OnceLock::new();
    CELL.get_or_init(|| {
        Guarded::new(
            r"(?:[*Xx•]{4}[ -]?){2,3}(?:[*Xx•]{2}\d{2}|\d{4})",
            r"$|[^\d]",
            |c| c.is_ascii_alphanumeric() || c == '_' || c == '*',
        )
    })
}

pub(crate) fn masked_card(text: &str) -> Vec<Hit> {
    masked_card_pattern()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| (start, end, 0.8))
        .collect()
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
    fn precise_ipv4() {
        let text = "Client 203.0.113.7 and 198.51.100.24/24 connected";
        assert_eq!(
            values(text, ipv4(text)),
            ["203.0.113.7", "198.51.100.24/24"]
        );
        assert!(ipv4("Mask 255.255.255.0, any 0.0.0.0, version 1.2.3.4").is_empty());
        assert!(ipv4("See section 4.2.1.3 and nginx/1.25.3.1 build").is_empty());
        let text = "URL http://192.0.2.10/24/index";
        assert_eq!(values(text, ipv4(text)), ["192.0.2.10"]);
        assert!(product_before("nginx/ "));
        assert!(!product_before("tcp/"));
    }

    #[test]
    fn precise_ipv6() {
        let text = "Address IPv6:2001:db8:0:0:1:0:0:1 and eth0:fe80::1";
        assert_eq!(
            values(text, ipv6(text)),
            ["2001:db8:0:0:1:0:0:1", "fe80::1"]
        );
        assert!(ipv6("MAC 00:1a:2b:3c:4d:5e:6f:70 and Add::add").is_empty());
    }

    #[test]
    fn precise_cards() {
        let text = "Card 4111-1111 1111.1111 and 5555555555554444";
        let found = card(text);
        assert_eq!(
            values(text, found.clone()),
            ["4111-1111 1111.1111", "5555555555554444"]
        );
        assert_eq!(found[0].2, 0.85);
        let text = "Card ending ****-****-****-1234 or XXXX XXXX XXXX 5678";
        assert_eq!(masked_card(text).len(), 2);
        assert_eq!(separator_kind("\r\n"), Separator::Newline);
    }

    #[test]
    fn context_before_counts_utf16_units() {
        // "ab😀cd": the three units before "d" are the surrogate pair and "c".
        assert_eq!(before("ab\u{1F600}cd", 7, 3), "\u{1F600}c");
        assert_eq!(before("ab\u{1F600}cd", 7, 2), "c");
        assert_eq!(before("abc", 3, 96), "abc");
    }
}
