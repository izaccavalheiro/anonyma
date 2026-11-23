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
    /// (byte offset, kind, length of the leading run of its kind (digits or
    /// capitals), length of the leading run of digits and capitals together).
    starts: Vec<(usize, Kind, usize, usize)>,
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
                let both = |b: &u8| b.is_ascii_digit() || b.is_ascii_uppercase();
                if b.is_ascii_digit() {
                    starts.push((i, Kind::Digit, run(i, u8::is_ascii_digit), run(i, both)));
                } else if b.is_ascii_uppercase() {
                    starts.push((i, Kind::Upper, run(i, u8::is_ascii_uppercase), run(i, both)));
                }
            } else if previous_word && (b == b'&' || (b == 0xC3 && bytes.get(i + 1) == Some(&0x91)))
            {
                starts.push((i, Kind::Special, 0, 0));
            }
            previous_word = word;
        }
        Candidates { starts }
    }
}

/// A text and its [`Candidates`], built on first use and shared by every
/// detector of one call.
pub(crate) struct TextIndex<'t> {
    text: &'t str,
    /// Whether enough detectors share the index for it to pay for itself;
    /// without it, every pattern keeps its full scan.
    enabled: bool,
    candidates: std::cell::OnceCell<Candidates>,
}

impl<'t> TextIndex<'t> {
    pub(crate) fn new(text: &'t str, enabled: bool) -> Self {
        TextIndex {
            text,
            enabled,
            candidates: std::cell::OnceCell::new(),
        }
    }

    /// The text.
    pub(crate) fn text(&self) -> &'t str {
        self.text
    }

    /// The candidate starts of the text.
    /// The candidate starts of the text, when the index is enabled.
    pub(crate) fn candidates(&self) -> Option<&Candidates> {
        self.enabled
            .then(|| self.candidates.get_or_init(|| Candidates::new(self.text)))
    }
}

/// Where a pattern can start: the shortest leading run of digits and of
/// capitals a match can begin with (`None` when it cannot begin with one), and
/// whether it can begin with `&` or `Ñ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct StartFilter {
    digit: Option<usize>,
    upper: Option<usize>,
    /// The shortest leading run of digits and capitals together, for a match
    /// that begins with either (0 when there is no such bound).
    word: usize,
    special: bool,
}

impl StartFilter {
    fn admits(&self, kind: Kind, run: usize, word: usize) -> bool {
        match kind {
            Kind::Digit => self.digit.is_some_and(|min| run >= min) && word >= self.word,
            Kind::Upper => self.upper.is_some_and(|min| run >= min) && word >= self.word,
            Kind::Special => self.special,
        }
    }

    /// The filter of a pattern (translated syntax), or `None` when the pattern
    /// does not begin with an ASCII `\b` and a class this module indexes.
    pub(crate) fn of(pattern: &str) -> Option<Self> {
        let hir = regex_syntax::parse(pattern).ok()?;
        match hir.kind() {
            // `\b...|\b...`: every alternative must begin with a boundary.
            HirKind::Alternation(branches) => {
                let mut filter = StartFilter::default();
                let mut first = true;
                for branch in branches {
                    let own = Self::of_branch(branch)?;
                    filter = combine(filter, own, first);
                    first = false;
                }
                Some(filter)
            }
            _ => Self::of_branch(&hir),
        }
    }

    fn of_branch(hir: &Hir) -> Option<Self> {
        let items = concat_items(hir);
        match items.first()?.kind() {
            HirKind::Look(Look::WordAscii) => lead(&items.iter().skip(1).collect::<Vec<_>>()),
            _ => None,
        }
    }
}

/// The items of a concatenation, through capture groups, with a literal of
/// several characters split into one item per character; a single item otherwise.
fn concat_items(hir: &Hir) -> Vec<Hir> {
    match hir.kind() {
        HirKind::Concat(items) => items.iter().flat_map(concat_items).collect(),
        HirKind::Capture(capture) => concat_items(&capture.sub),
        HirKind::Literal(literal) => match std::str::from_utf8(&literal.0) {
            Ok(text) => text
                .chars()
                .map(|c| Hir::literal(c.to_string().into_bytes()))
                .collect(),
            Err(_) => vec![hir.clone()],
        },
        _ => vec![hir.clone()],
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
        let mut first = true;
        for branch in branches {
            let own = lead(&concat_items(branch).iter().collect::<Vec<_>>())?;
            filter = combine(filter, own, first);
            first = false;
        }
        return Some(filter);
    }
    // The first atom: a class, a literal, or one repeated at least once.
    let (atom, _) = repeated(first)?;
    let word = run(items, Set::Word);
    match atom_set(atom)? {
        Set::Digits => Some(StartFilter {
            digit: Some(run(items, Set::Digits)),
            word,
            ..StartFilter::default()
        }),
        Set::Uppers => Some(StartFilter {
            upper: Some(run(items, Set::Uppers)),
            word,
            ..StartFilter::default()
        }),
        // Digits and capitals: the run of either kind may be one character.
        Set::Word => Some(StartFilter {
            digit: Some(1),
            upper: Some(1),
            word,
            special: false,
        }),
        // `&` and `Ñ` end a run of digits and capitals: no bound on it.
        Set::UppersAndSpecial => Some(StartFilter {
            digit: None,
            upper: Some(1),
            word: 0,
            special: true,
        }),
    }
}

/// The filter that admits what either filter admits.
fn combine(filter: StartFilter, other: StartFilter, first: bool) -> StartFilter {
    if first {
        return other;
    }
    StartFilter {
        digit: min_of(filter.digit, other.digit),
        upper: min_of(filter.upper, other.upper),
        word: filter.word.min(other.word),
        special: filter.special || other.special,
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
/// of the consecutive items whose characters all belong to `set` (digits and
/// capitals both belong to [`Set::Word`]).
fn run(items: &[&Hir], set: Set) -> usize {
    let within =
        |own: Set| own == set || (set == Set::Word && matches!(own, Set::Digits | Set::Uppers));
    let mut total = 0;
    for item in items {
        match repeated(item) {
            Some((atom, min)) if atom_set(atom).is_some_and(within) => total += min,
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
        for &(at, kind, run, word) in &candidates.starts {
            if at < cursor || !self.filter.admits(kind, run, word) {
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

/// Checks, for tests, that the anchored search finds what a full scan finds.
#[cfg(test)]
pub(crate) mod parity {
    use super::Candidates;
    use crate::jsregex::JsRegex;

    /// Texts where the anchored search could differ from a full scan: values at
    /// the edges, glued to letters and digits, separators, `&`, `Ñ` and other
    /// multi-byte characters, and random strings over the characters the
    /// patterns read.
    pub(crate) fn texts() -> Vec<String> {
        let values = [
            "123.456.789-09",
            "123 456 782",
            "AB 12 34 56 C",
            "AB123456C",
            "2345 6789 0124",
            "850101-1234567",
            "850101+1234",
            "12345678Z",
            "X1234567L",
            "RSSMRA85T10A562S",
            "GODE561231GR8",
            "ÑAPE561231GR8",
            "&ABC561231GR8",
            "1 85 05 78 006 084 36",
            "12.345.678",
            "1234567890123",
            "12345678901",
            "123456789",
            "11010519491231002X",
            "12.345.678-9",
            "A1234567",
            "4111 1111 1111 1111",
        ];
        let edges = [
            "", " ", "x", "9", "A", "-", ".", "&", "Ñ", "é", "\n", "_", "Z1",
        ];
        let mut texts = Vec::new();
        for value in values {
            for before in edges {
                for after in edges {
                    texts.push(format!("{before}{value}{after}"));
                    texts.push(format!("id {before}{value}{after}, national id {value}"));
                }
            }
        }
        texts.push(values.join(" "));
        texts.push(values.join(""));
        texts.push(values.join("\n").repeat(50));
        // Random strings over the characters the patterns read, xorshift-seeded.
        let alphabet: Vec<char> = "0123456789 -.+/XABCDEFHMZÑ&xé\n\t,".chars().collect();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..5000 {
            let mut text = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = 1 + (state % 40) as usize;
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                text.push(alphabet[(state % alphabet.len() as u64) as usize]);
            }
            texts.push(text);
        }
        texts
    }

    /// The ranges of `pattern` both ways on every text of [`texts`].
    pub(crate) fn check(pattern: &JsRegex) {
        for text in texts() {
            let candidates = Candidates::new(&text);
            assert_eq!(
                pattern.ranges_in(&text, &candidates),
                pattern.ranges(&text),
                "{text:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsregex::translate;

    fn filter(source: &str) -> Option<StartFilter> {
        StartFilter::of(&translate(source))
    }

    /// A filter: minimum digit run, capital run, run of both, and `&`/`Ñ`.
    fn f(
        digit: Option<usize>,
        upper: Option<usize>,
        word: usize,
        special: bool,
    ) -> Option<StartFilter> {
        Some(StartFilter {
            digit,
            upper,
            word,
            special,
        })
    }

    #[test]
    fn filters_are_the_shortest_leading_runs() {
        assert_eq!(
            filter(r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b"),
            f(Some(3), None, 3, false)
        );
        assert_eq!(
            filter(r"\b[2-9]\d{3}[\s-]?\d{4}\b"),
            f(Some(4), None, 4, false)
        );
        assert_eq!(filter(r"\b\d{17}[\dX]\b"), f(Some(17), None, 18, false));
        assert_eq!(
            filter(r"\b\d{2,3}[.\s]?\d{3}\b"),
            f(Some(2), None, 2, false)
        );
        assert_eq!(filter(r"\b[12]\s?\d{2}\b"), f(Some(1), None, 1, false));
        assert_eq!(
            filter(r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b"),
            f(Some(8), Some(1), 9, false)
        );
        assert_eq!(filter(r"\b[A-Z]{6}\d{2}\b"), f(None, Some(6), 8, false));
        assert_eq!(filter(r"\b[A-ZÑ&]{3,4}\d{6}\b"), f(None, Some(1), 0, true));
        assert_eq!(filter(r"\b[A-Z0-9]{9}\b"), f(Some(1), Some(1), 9, false));
        assert_eq!(
            filter(r"\b[A-Z9]{5}\d{6}[02-9]\b"),
            f(Some(1), Some(1), 12, false)
        );
    }

    #[test]
    fn literals_count_one_character_each() {
        // Branches are measured alone: what follows them is not counted.
        assert_eq!(
            filter(r"\b(?:0[1-9]|80)\d{7}\b"),
            f(Some(2), None, 2, false)
        );
        assert_eq!(filter(r"\b9\d{2}[\s-]"), f(Some(3), None, 3, false));
    }

    #[test]
    fn alternatives_that_all_begin_with_a_boundary_combine() {
        assert_eq!(
            filter(r"\b\d{3}[\s-]\d{3}[\s-]\d{4}\b|\b\d{10}\b"),
            f(Some(3), None, 3, false)
        );
        assert_eq!(filter(r"\b\d{3}|\d{10}"), None);
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
        assert_eq!(
            index.starts,
            vec![
                (3, Kind::Digit, 3, 3),
                (7, Kind::Upper, 2, 2),
                (10, Kind::Digit, 1, 1),
                (13, Kind::Special, 0, 0),
                (20, Kind::Digit, 1, 1),
            ]
        );
    }
}
