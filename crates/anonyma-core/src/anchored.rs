//! Searching many patterns over one text without a full scan per pattern.
//!
//! A global search loop finds a pattern's leftmost match at or after a cursor.
//! That match starts at the first position `s >= cursor` where an *anchored*
//! leftmost-first search of the pattern succeeds, and it is that anchored match.
//! So the loop can try a pattern only at the positions where it could start,
//! in order, and get exactly the matches of `find_iter`, provided those
//! positions include every real start.
//!
//! [`Candidates`] indexes, in one pass over a text, the ASCII word starts with
//! the length of their leading run of digits or capitals, and the `&`/`Ñ` that
//! follow a word character. A pattern that begins with an ASCII `\b` and a class
//! of digits, capitals, `&` or `Ñ` gets a [`StartFilter`], derived from its
//! syntax tree: the shortest leading run a match can begin with, a lower bound,
//! so the filter never rejects a real start. Every other pattern keeps the full
//! scan. The anchored searches run on a lazy DFA; when it gives up (its cache
//! thrashes on adversarial input), the pattern falls back to the full scan.

use std::sync::Mutex;

use regex_automata::hybrid::dfa::{Cache, DFA};
use regex_automata::{Anchored, Input};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

/// The kind of a candidate start: what its first character is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An ASCII digit after a non-word character (or the start of the text).
    Digit,
    /// An ASCII capital after a non-word character.
    Upper,
    /// `&` or `Ñ` after an ASCII word character.
    Special,
}

/// The positions of a text where a filtered pattern can start, in order.
pub(crate) struct Candidates {
    /// (byte offset, kind, length of the leading run of digits or capitals).
    starts: Vec<(usize, Kind, usize)>,
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl Candidates {
    /// Index `text` in one pass.
    pub(crate) fn new(text: &str) -> Self {
        let bytes = text.as_bytes();
        let run = |from: usize, class: fn(&u8) -> bool| {
            bytes[from..].iter().take_while(|b| class(b)).count()
        };
        let mut starts = Vec::new();
        let mut previous_word = false;
        for (i, &b) in bytes.iter().enumerate() {
            let word = is_word(b);
            if word && !previous_word {
                if b.is_ascii_digit() {
                    starts.push((i, Kind::Digit, run(i, u8::is_ascii_digit)));
                } else if b.is_ascii_uppercase() {
                    starts.push((i, Kind::Upper, run(i, u8::is_ascii_uppercase)));
                }
            } else if previous_word && (b == b'&' || (b == 0xC3 && bytes.get(i + 1) == Some(&0x91)))
            {
                starts.push((i, Kind::Special, 0));
            }
            previous_word = word;
        }
        Candidates { starts }
    }
}

/// Where a pattern can start: the shortest leading run of digits and of
/// capitals a match can begin with (`None` when it cannot begin with one), and
/// whether it can begin with `&` or `Ñ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct StartFilter {
    digit: Option<usize>,
    upper: Option<usize>,
    special: bool,
}

impl StartFilter {
    fn admits(&self, kind: Kind, run: usize) -> bool {
        match kind {
            Kind::Digit => self.digit.is_some_and(|min| run >= min),
            Kind::Upper => self.upper.is_some_and(|min| run >= min),
            Kind::Special => self.special,
        }
    }

    /// The filter of a pattern (translated syntax), or `None` when the pattern
    /// does not begin with an ASCII `\b` and a class this module indexes.
    pub(crate) fn of(pattern: &str) -> Option<Self> {
        let hir = regex_syntax::parse(pattern).ok()?;
        let items = concat_items(&hir);
        match items.first()?.kind() {
            HirKind::Look(Look::WordAscii) => lead(&items[1..]),
            _ => None,
        }
    }
}

/// The items of a concatenation, through capture groups; a single item otherwise.
fn concat_items(hir: &Hir) -> Vec<&Hir> {
    match hir.kind() {
        HirKind::Concat(items) => items.iter().flat_map(concat_items).collect(),
        HirKind::Capture(capture) => concat_items(&capture.sub),
        _ => vec![hir],
    }
}

/// What the characters of a class are, among those this module indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Set {
    Digits,
    Uppers,
    /// Digits and capitals.
    Word,
    /// Capitals with `&` and `Ñ`.
    UppersAndSpecial,
}

fn set_of(ranges: impl Iterator<Item = (u32, u32)>) -> Option<Set> {
    let (mut digit, mut upper, mut special) = (false, false, false);
    for (start, end) in ranges {
        for c in start..=end {
            match c {
                0x30..=0x39 => digit = true,
                0x41..=0x5A => upper = true,
                0x26 | 0xD1 => special = true,
                _ => return None,
            }
        }
    }
    match (digit, upper, special) {
        (true, false, false) => Some(Set::Digits),
        (false, true, false) => Some(Set::Uppers),
        (true, true, false) => Some(Set::Word),
        (false, _, true) => Some(Set::UppersAndSpecial),
        _ => None,
    }
}

/// The characters one atom matches, when it is a class or a one-character literal.
fn atom_set(hir: &Hir) -> Option<Set> {
    match hir.kind() {
        HirKind::Class(Class::Unicode(class)) => set_of(
            class
                .ranges()
                .iter()
                .map(|r| (r.start() as u32, r.end() as u32)),
        ),
        HirKind::Class(Class::Bytes(class)) => set_of(
            class
                .ranges()
                .iter()
                .map(|r| (r.start() as u32, r.end() as u32)),
        ),
        HirKind::Literal(literal) => {
            let text = std::str::from_utf8(&literal.0).ok()?;
            let mut chars = text.chars();
            let c = chars.next()?;
            set_of(std::iter::once((c as u32, c as u32)))
        }
        _ => None,
    }
}

/// The filter of the items that follow the leading `\b`.
fn lead(items: &[&Hir]) -> Option<StartFilter> {
    let first = items.first()?;
    if let HirKind::Alternation(branches) = first.kind() {
        // Each branch alone: what follows the alternation can only lengthen a run.
        let mut filter = StartFilter::default();
        for branch in branches {
            let own = lead(&concat_items(branch))?;
            filter.digit = min_of(filter.digit, own.digit);
            filter.upper = min_of(filter.upper, own.upper);
            filter.special |= own.special;
        }
        return Some(filter);
    }
    // The first atom: a class, a literal, or one repeated at least once.
    let (atom, _) = repeated(first)?;
    match atom_set(atom)? {
        Set::Digits => Some(StartFilter {
            digit: Some(run(items, Set::Digits)),
            ..StartFilter::default()
        }),
        Set::Uppers => Some(StartFilter {
            upper: Some(run(items, Set::Uppers)),
            ..StartFilter::default()
        }),
        // Mixed classes: a match may begin with a run of one character.
        Set::Word => Some(StartFilter {
            digit: Some(1),
            upper: Some(1),
            special: false,
        }),
        Set::UppersAndSpecial => Some(StartFilter {
            digit: None,
            upper: Some(1),
            special: true,
        }),
    }
}

fn min_of(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// The atom of an item and how many times it repeats at least, or `None` for
/// an item that may match nothing or is not an atom.
fn repeated(item: &Hir) -> Option<(&Hir, usize)> {
    match item.kind() {
        HirKind::Repetition(repetition) if repetition.min >= 1 => {
            let min = usize::try_from(repetition.min).ok()?;
            let (atom, inner) = repeated(&repetition.sub)?;
            Some((atom, min * inner))
        }
        HirKind::Capture(capture) => repeated(&capture.sub),
        HirKind::Class(_) => Some((item, 1)),
        HirKind::Literal(literal) => {
            // Each character of a literal counts once.
            let text = std::str::from_utf8(&literal.0).ok()?;
            (text.chars().count() == 1).then_some((item, 1))
        }
        _ => None,
    }
}

/// The shortest run of `set` the leading items must match: the minimum counts
/// of the consecutive items whose characters all belong to `set`.
fn run(items: &[&Hir], set: Set) -> usize {
    let mut total = 0;
    for item in items {
        match repeated(item) {
            Some((atom, min)) if atom_set(atom) == Some(set) => total += min,
            _ => break,
        }
    }
    total
}

/// A pattern searched at candidate starts with a lazy DFA.
pub(crate) struct AnchoredSearch {
    dfa: DFA,
    filter: StartFilter,
    /// Caches of the lazy DFA, one per concurrent search.
    caches: Mutex<Vec<Cache>>,
}

impl AnchoredSearch {
    /// The anchored search of `pattern` (translated syntax), or `None` when it
    /// has no [`StartFilter`] or no lazy DFA.
    pub(crate) fn new(pattern: &str) -> Option<Self> {
        let filter = StartFilter::of(pattern)?;
        let dfa = DFA::new(pattern).ok()?;
        Some(AnchoredSearch {
            dfa,
            filter,
            caches: Mutex::new(Vec::new()),
        })
    }

    /// The successive non-overlapping matches, as `find_iter` finds them, or
    /// `None` when the lazy DFA gave up and the caller must scan.
    pub(crate) fn ranges(
        &self,
        text: &str,
        candidates: &Candidates,
    ) -> Option<Vec<(usize, usize)>> {
        let mut cache = self
            .caches
            .lock()
            .ok()
            .and_then(|mut caches| caches.pop())
            .unwrap_or_else(|| self.dfa.create_cache());
        let mut out = Vec::new();
        let mut cursor = 0;
        let mut complete = true;
        for &(at, kind, run) in &candidates.starts {
            if at < cursor || !self.filter.admits(kind, run) {
                continue;
            }
            let input = Input::new(text).range(at..).anchored(Anchored::Yes);
            match self.dfa.try_search_fwd(&mut cache, &input) {
                Ok(Some(end)) if end.offset() > at => {
                    out.push((at, end.offset()));
                    cursor = end.offset();
                }
                Ok(_) => {}
                Err(_) => {
                    complete = false;
                    break;
                }
            }
        }
        if let Ok(mut caches) = self.caches.lock() {
            caches.push(cache);
        }
        complete.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsregex::translate;

    fn filter(source: &str) -> Option<StartFilter> {
        StartFilter::of(&translate(source))
    }

    fn digits(min: usize) -> Option<StartFilter> {
        Some(StartFilter {
            digit: Some(min),
            ..StartFilter::default()
        })
    }

    #[test]
    fn filters_are_the_shortest_leading_runs() {
        assert_eq!(filter(r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b"), digits(3));
        assert_eq!(filter(r"\b[2-9]\d{3}[\s-]?\d{4}\b"), digits(4));
        assert_eq!(filter(r"\b\d{17}[\dX]\b"), digits(17));
        assert_eq!(filter(r"\b\d{2,3}[.\s]?\d{3}\b"), digits(2));
        assert_eq!(filter(r"\b[12]\s?\d{2}\b"), digits(1));
        assert_eq!(
            filter(r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b"),
            Some(StartFilter {
                digit: Some(8),
                upper: Some(1),
                special: false
            })
        );
        assert_eq!(
            filter(r"\b[A-Z]{6}\d{2}\b"),
            Some(StartFilter {
                upper: Some(6),
                ..StartFilter::default()
            })
        );
        assert_eq!(
            filter(r"\b[A-ZÑ&]{3,4}\d{6}\b"),
            Some(StartFilter {
                digit: None,
                upper: Some(1),
                special: true
            })
        );
        assert_eq!(
            filter(r"\b[A-Z0-9]{9}\b"),
            Some(StartFilter {
                digit: Some(1),
                upper: Some(1),
                special: false
            })
        );
    }

    #[test]
    fn patterns_without_a_leading_boundary_and_class_have_no_filter() {
        assert_eq!(filter(r"\d{3}"), None);
        assert_eq!(filter(r"\b[a-z]+"), None);
        assert_eq!(filter(r"\b\d?x"), None);
        assert_eq!(filter(r"\b.x"), None);
        assert_eq!(filter(r"\b(?:\d{3}|x)"), None);
    }

    #[test]
    fn candidates_index_word_starts_and_specials() {
        let index = Candidates::new("ab 123 XY,4 a&b Ñx 9");
        let starts: Vec<(usize, Kind, usize)> = index.starts;
        assert_eq!(
            starts,
            vec![
                (3, Kind::Digit, 3),
                (7, Kind::Upper, 2),
                (10, Kind::Digit, 1),
                (13, Kind::Special, 0),
                (20, Kind::Digit, 1),
            ]
        );
    }
}
