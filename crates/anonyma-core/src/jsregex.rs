//! ECMAScript regular expressions on the Rust `regex` crate.
//!
//! The reference implementation's patterns are ECMAScript regular expressions
//! without the `u` flag. The `regex` crate differs from them in ways that
//! change what matches:
//!
//! | ECMAScript (no `u`)                  | `regex` crate default                   | Here                              |
//! | ------------------------------------ | --------------------------------------- | --------------------------------- |
//! | `\b`, `\w` are ASCII                 | Unicode-aware                           | `(?-u:\b)`, `[A-Za-z0-9_]`        |
//! | `\d` is `[0-9]`                      | any Unicode digit (`٣`)                 | `[0-9]`                           |
//! | `\s` is a fixed list of 25 code points | Unicode `White_Space` (no U+FEFF)     | that list, spelled out            |
//! | `i` folds ASCII letters only         | `(?i)` folds `ſ` to `s`, `K` to `k`     | ASCII-lower-cased haystack        |
//! | lookahead, lookbehind, `\B`          | not supported (linear time)             | rejected; detectors post-filter   |
//!
//! Matching semantics are otherwise the same: both report the leftmost match,
//! and among matches at one position the one a backtracking engine finds first
//! (alternation order, greedy and lazy quantifiers). The `regex` crate does it
//! in linear time, so no input can make a detector take exponential time.

use regex::{Captures, Regex};

/// The code points of ECMAScript's `\s`, as the contents of a character class.
pub(crate) const JS_SPACE: &str = r"\t\n\x0B\x0C\r\x20\u{A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}";

/// Translate the source of an ECMAScript regular expression (no `u` flag) to
/// the syntax of the `regex` crate with ECMAScript's meaning.
///
/// # Panics
///
/// On lookaround assertions, which the `regex` crate cannot express, and on
/// `\D`, `\S`, `\W` inside a character class.
pub(crate) fn translate(source: &str) -> String {
    let mut out = String::with_capacity(source.len() * 2);
    let mut chars = source.chars().peekable();
    let mut in_class = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(next) = chars.next() else {
                    panic!("pattern ends with a backslash: {source}");
                };
                match (next, in_class) {
                    ('b', false) => out.push_str(r"(?-u:\b)"),
                    ('d', false) => out.push_str("[0-9]"),
                    ('d', true) => out.push_str("0-9"),
                    ('D', false) => out.push_str("[^0-9]"),
                    ('w', false) => out.push_str("[A-Za-z0-9_]"),
                    ('w', true) => out.push_str("A-Za-z0-9_"),
                    ('W', false) => out.push_str("[^A-Za-z0-9_]"),
                    ('s', false) => {
                        out.push('[');
                        out.push_str(JS_SPACE);
                        out.push(']');
                    }
                    ('s', true) => out.push_str(JS_SPACE),
                    ('S', false) => {
                        out.push_str("[^");
                        out.push_str(JS_SPACE);
                        out.push(']');
                    }
                    // The regex crate rejects an ASCII \B on UTF-8 text: it could
                    // match between the bytes of one character.
                    ('B', _) => panic!("\\B is not supported: {source}"),
                    ('D' | 'S' | 'W', true) => {
                        panic!("negated class escape inside a class: {source}")
                    }
                    // ECMAScript allows escaping `/`; the regex crate does not need it.
                    ('/', _) => out.push('/'),
                    (other, _) => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                // A leading `^` or `]` belongs to the class syntax.
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '(' if !in_class && chars.peek() == Some(&'?') => {
                out.push('(');
                out.push('?');
                chars.next();
                match chars.peek() {
                    Some('=') | Some('!') => panic!("lookahead is not supported: {source}"),
                    Some('<') => {
                        let mut ahead = chars.clone();
                        ahead.next();
                        if matches!(ahead.peek(), Some('=') | Some('!')) {
                            panic!("lookbehind is not supported: {source}");
                        }
                    }
                    _ => {}
                }
            }
            // A `[` inside a class is a literal in ECMAScript, a nested class in Rust.
            '[' => out.push_str(r"\["),
            // So are `&&`, `--` and `~~` (class set operations in Rust).
            '&' | '~' if in_class => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// ASCII letters of `text` lower-cased, borrowed when it has none in upper case.
fn lower_cased(text: &str) -> std::borrow::Cow<'_, str> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(text.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

/// A text prepared for repeated searches: its ASCII-lower-cased form, which
/// case-insensitive patterns read, is computed once, on first use. ASCII
/// lower-casing keeps every byte offset, so ranges found in either form are
/// ranges of the text.
pub(crate) struct Haystack<'t> {
    raw: &'t str,
    lower: std::cell::OnceCell<std::borrow::Cow<'t, str>>,
}

impl<'t> Haystack<'t> {
    /// Prepare `raw`; nothing is computed until a pattern needs it.
    pub(crate) fn new(raw: &'t str) -> Self {
        Haystack {
            raw,
            lower: std::cell::OnceCell::new(),
        }
    }

    /// The text as given.
    pub(crate) fn raw(&self) -> &'t str {
        self.raw
    }

    /// The text with ASCII letters lower-cased.
    fn lower(&self) -> &str {
        self.lower.get_or_init(|| lower_cased(self.raw))
    }
}

/// A compiled pattern with ECMAScript semantics.
pub(crate) struct JsRegex {
    regex: Regex,
    /// The translated source, for the anchored search built on first use.
    translated: String,
    /// The search at candidate starts ([`crate::anchored`]), when the pattern has one.
    anchored: std::sync::OnceLock<Option<crate::anchored::AnchoredSearch>>,
    /// Case-insensitive: the pattern is written in lower case and matched
    /// against the haystack with ASCII letters lower-cased, as ECMAScript's
    /// `i` flag (without `u`) folds ASCII letters only. ASCII lower-casing
    /// keeps every byte offset.
    insensitive: bool,
}

impl JsRegex {
    /// Compile a case-sensitive pattern.
    ///
    /// # Panics
    ///
    /// When the translated pattern does not compile: the patterns are constants,
    /// and every one is compiled by the unit tests.
    pub(crate) fn new(source: &str) -> Self {
        let translated = translate(source);
        let regex = Regex::new(&translated)
            .unwrap_or_else(|error| panic!("invalid pattern {source}: {error}"));
        JsRegex {
            regex,
            translated,
            anchored: std::sync::OnceLock::new(),
            insensitive: false,
        }
    }

    /// Compile a case-insensitive pattern, written in lower case.
    pub(crate) fn insensitive(source: &str) -> Self {
        JsRegex {
            insensitive: true,
            ..JsRegex::new(source)
        }
    }

    fn haystack<'t>(&self, text: &'t str) -> std::borrow::Cow<'t, str> {
        if self.insensitive {
            lower_cased(text)
        } else {
            std::borrow::Cow::Borrowed(text)
        }
    }

    /// The text this pattern reads in `haystack`: lower-cased for a
    /// case-insensitive pattern, as is otherwise.
    fn view<'h>(&self, haystack: &'h Haystack<'_>) -> &'h str {
        if self.insensitive {
            haystack.lower()
        } else {
            haystack.raw()
        }
    }

    /// Byte ranges of the successive non-overlapping matches, as a global
    /// ECMAScript `exec` loop finds them.
    pub(crate) fn ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let haystack = self.haystack(text);
        self.regex
            .find_iter(&haystack)
            .map(|m| (m.start(), m.end()))
            .collect()
    }

    /// [`ranges`](Self::ranges), searched only at the candidate starts of
    /// `text` when the pattern begins with a word boundary and an indexed class
    /// (see [`crate::anchored`]): the same ranges, without a full scan.
    pub(crate) fn ranges_in(
        &self,
        text: &str,
        candidates: &crate::anchored::Candidates,
    ) -> Vec<(usize, usize)> {
        if !self.insensitive {
            let search = self
                .anchored
                .get_or_init(|| crate::anchored::AnchoredSearch::new(&self.translated));
            if let Some(found) = search.as_ref().and_then(|s| s.ranges(text, candidates)) {
                return found;
            }
        }
        self.ranges(text)
    }

    /// [`ranges_in`](Self::ranges_in) when `index` is enabled, a full scan otherwise.
    pub(crate) fn ranges_with(
        &self,
        text: &str,
        index: &crate::anchored::TextIndex<'_>,
    ) -> Vec<(usize, usize)> {
        match index.candidates() {
            Some(candidates) => self.ranges_in(text, candidates),
            None => self.ranges(text),
        }
    }

    /// Whether the pattern has a search at candidate starts.
    #[cfg(test)]
    pub(crate) fn is_anchored(&self) -> bool {
        !self.insensitive && crate::anchored::AnchoredSearch::new(&self.translated).is_some()
    }

    /// Whether the pattern matches anywhere in `text`.
    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(&self.haystack(text))
    }

    /// The capture groups of the leftmost match that starts at or after
    /// `start`; assertions see the text before `start`. Byte ranges of the
    /// groups, `None` for a group that did not participate.
    ///
    /// The haystack is prepared once by the caller, so that a loop over the
    /// candidates of a long text lower-cases it once, not once per candidate.
    pub(crate) fn captures_at(
        &self,
        haystack: &Haystack<'_>,
        start: usize,
    ) -> Option<Vec<Option<(usize, usize)>>> {
        self.regex
            .captures_at(self.view(haystack), start)
            .map(|caps: Captures<'_>| {
                caps.iter()
                    .map(|group| group.map(|m| (m.start(), m.end())))
                    .collect()
            })
    }
}

/// Define a lazily compiled [`JsRegex`] behind a function.
macro_rules! js_regex {
    ($(#[$meta:meta])* $name:ident = insensitive $source:expr) => {
        $(#[$meta])*
        fn $name() -> &'static $crate::jsregex::JsRegex {
            static CELL: std::sync::OnceLock<$crate::jsregex::JsRegex> = std::sync::OnceLock::new();
            CELL.get_or_init(|| $crate::jsregex::JsRegex::insensitive($source))
        }
    };
    ($(#[$meta:meta])* $name:ident = $source:expr) => {
        $(#[$meta])*
        fn $name() -> &'static $crate::jsregex::JsRegex {
            static CELL: std::sync::OnceLock<$crate::jsregex::JsRegex> = std::sync::OnceLock::new();
            CELL.get_or_init(|| $crate::jsregex::JsRegex::new($source))
        }
    };
}
pub(crate) use js_regex;

/// ECMAScript's `(?!\d)` after a match, as a consuming alternative: the end of
/// the text, or a character that is not a digit.
pub(crate) const NOT_BEFORE_DIGIT: &str = r"$|[^\d]";

/// ECMAScript's `(?![ ./-]?\d)` after a match: no digit next, nor after one
/// separator.
pub(crate) const NOT_BEFORE_SEPARATED_DIGIT: &str = r"$|[^\d ./-]|[ ./-](?:$|[^\d])";

/// A pattern with the lookarounds of ECMAScript that the `regex` crate cannot
/// express, emulated exactly:
///
/// - a negative lookahead at the end, `(?!X)`, becomes a consuming group with
///   its positive complement after the match (`tail`), cut off the result: a
///   backtracking engine takes the first path of the pattern whose lookahead
///   holds, and the `regex` crate takes the first path whose tail matches;
/// - a negative lookbehind of one character at the start, `(?<!X)`, is checked
///   on the candidate; a rejected candidate resumes the search one character
///   later, where the next attempt of a backtracking engine starts (no other
///   path can succeed at a start whose lookbehind fails).
pub(crate) struct Guarded {
    regex: JsRegex,
    /// Whether the text before a candidate fails the lookbehind.
    rejects: Lookbehind,
}

/// A lookbehind, tested on the text before a candidate.
#[derive(Clone, Copy)]
pub(crate) enum Lookbehind {
    /// No lookbehind.
    None,
    /// `(?<![X])`: the character before is not one of a class.
    Char(fn(char) -> bool),
    /// Anything longer, given the text before the candidate.
    Text(fn(&str) -> bool),
}

impl Guarded {
    /// `core` followed by `tail`; a match preceded by a character for which
    /// `not_after` holds is rejected.
    pub(crate) fn new(core: &str, tail: &str, not_after: fn(char) -> bool) -> Self {
        Self::with(core, tail, Lookbehind::Char(not_after), false)
    }

    /// `core` followed by `tail`, with any lookbehind; `insensitive` compiles a
    /// lower-case pattern for ECMAScript's `i` flag (see [`JsRegex::insensitive`]).
    pub(crate) fn with(core: &str, tail: &str, rejects: Lookbehind, insensitive: bool) -> Self {
        let source = if tail.is_empty() {
            format!("({core})")
        } else {
            format!("({core})(?:{tail})")
        };
        let regex = if insensitive {
            JsRegex::insensitive(&source)
        } else {
            JsRegex::new(&source)
        };
        Guarded { regex, rejects }
    }

    /// The candidate at or after `at`: the byte range of the match, and the
    /// groups of `core` (group 1 is the whole match).
    pub(crate) fn candidate(
        &self,
        haystack: &Haystack<'_>,
        at: usize,
    ) -> Option<Vec<Option<(usize, usize)>>> {
        self.regex.captures_at(haystack, at)
    }

    /// Whether a match may start at `start`: the lookbehind holds.
    pub(crate) fn may_start(&self, text: &str, start: usize) -> bool {
        let before = &text[..start];
        match self.rejects {
            Lookbehind::None => true,
            Lookbehind::Char(rejects) => !before.chars().next_back().is_some_and(rejects),
            Lookbehind::Text(rejects) => !rejects(before),
        }
    }

    /// The groups of every match, as a global `exec` loop finds them: a
    /// candidate that fails the lookbehind resumes one character later, a match
    /// resumes at its end. Checks the caller makes afterwards (the reference's
    /// `continue`) do not change where the next search starts.
    pub(crate) fn matches(&self, text: &str) -> Vec<Vec<Option<(usize, usize)>>> {
        let haystack = Haystack::new(text);
        let mut out = Vec::new();
        let mut at = 0;
        while at <= text.len() {
            let Some(groups) = self.candidate(&haystack, at) else {
                break;
            };
            let Some((start, end)) = groups[1] else {
                break;
            };
            if self.may_start(text, start) {
                at = if end > start {
                    end
                } else {
                    next_char(text, end)
                };
                out.push(groups);
            } else {
                at = next_char(text, start);
            }
        }
        out
    }

    /// The successive matches, as a global ECMAScript `exec` loop finds them,
    /// keeping those `accept` accepts (a check the regex crate cannot express,
    /// such as a backreference); a rejected candidate resumes one character later.
    pub(crate) fn ranges_where(
        &self,
        text: &str,
        accept: impl Fn(&[Option<(usize, usize)>]) -> bool,
    ) -> Vec<(usize, usize)> {
        let haystack = Haystack::new(text);
        let mut out = Vec::new();
        let mut at = 0;
        while at <= text.len() {
            let Some(groups) = self.candidate(&haystack, at) else {
                break;
            };
            let Some((start, end)) = groups[1] else {
                break;
            };
            if self.may_start(text, start) && accept(&groups) {
                out.push((start, end));
                at = if end > start {
                    end
                } else {
                    next_char(text, end)
                };
            } else {
                at = next_char(text, start);
            }
        }
        out
    }

    /// [`Guarded::ranges_where`] accepting every candidate.
    pub(crate) fn ranges(&self, text: &str) -> Vec<(usize, usize)> {
        self.ranges_where(text, |_| true)
    }
}

/// Whether `c` is a letter (`\p{L}`), as Unicode-aware ECMAScript patterns test it.
pub(crate) fn is_letter(c: char) -> bool {
    static LETTER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let mut buffer = [0; 4];
    LETTER
        .get_or_init(|| Regex::new(r"^\p{L}$").expect("valid pattern"))
        .is_match(c.encode_utf8(&mut buffer))
}

/// A letter (`\p{L}`) or an ASCII digit: what `(?<![\p{L}\d])` rejects.
pub(crate) fn is_letter_or_digit(c: char) -> bool {
    c.is_ascii_digit() || is_letter(c)
}

/// The byte offset of the character after the one that starts at `at`.
pub(crate) fn next_char(text: &str, at: usize) -> usize {
    text[at..]
        .chars()
        .next()
        .map_or(at + 1, |c| at + c.len_utf8())
}

/// Number of UTF-16 code units between two byte offsets (`from <= to`): the
/// distance the reference measures, as JavaScript strings count UTF-16 units.
pub(crate) fn utf16_distance(text: &str, from: usize, to: usize) -> usize {
    text[from..to].encode_utf16().count()
}

/// Whether `index` is at most `limit` UTF-16 units after `position`, as the
/// reference's `pos <= index && index - pos <= limit`.
pub(crate) fn within(text: &str, position: usize, index: usize, limit: usize) -> bool {
    if position > index {
        return false;
    }
    let bytes = index - position;
    // A UTF-16 unit takes one to three UTF-8 bytes (a surrogate pair, four for two).
    if bytes <= limit {
        return true;
    }
    if bytes > limit * 3 {
        return false;
    }
    utf16_distance(text, position, index) <= limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_ecmascript_escapes() {
        assert_eq!(translate(r"\b\d{3}\b"), r"(?-u:\b)[0-9]{3}(?-u:\b)");
        assert_eq!(translate(r"[\d\s-]"), format!("[0-9{JS_SPACE}-]"));
        assert_eq!(translate(r"a\/b"), "a/b");
        assert_eq!(translate(r"[[a]"), r"[\[a]");
        assert_eq!(translate(r"[^\w]"), "[^A-Za-z0-9_]");
        assert_eq!(translate(r"(?:x)"), "(?:x)");
    }

    #[test]
    #[should_panic(expected = "lookahead")]
    fn rejects_lookahead() {
        translate(r"(?!000)\d{3}");
    }

    #[test]
    #[should_panic(expected = "lookbehind")]
    fn rejects_lookbehind() {
        translate(r"(?<![a-z])x");
    }

    #[test]
    fn word_boundary_and_digits_are_ascii() {
        let re = JsRegex::new(r"\b\d+\b");
        // An Arabic-Indic digit is not \d, and é is not a word character.
        // ٣ (Arabic-Indic three) is not \d, so `٣4` is a match of `4` alone.
        assert_eq!(re.ranges("é12 ٣4"), vec![(2, 4), (7, 8)]);
    }

    #[test]
    fn white_space_is_ecmascript_white_space() {
        let re = JsRegex::new(r"a\sb");
        assert!(re.is_match("a\u{FEFF}b"));
        assert!(re.is_match("a\u{A0}b"));
        assert!(!re.is_match("a\u{85}b"));
    }

    #[test]
    fn case_insensitivity_folds_ascii_only() {
        let re = JsRegex::insensitive("pix|kelvin");
        assert_eq!(re.ranges("PIX Kelvin"), vec![(0, 3), (4, 10)]);
        // The Kelvin sign folds to `k` in Unicode, not in ECMAScript without `u`.
        assert!(!re.is_match("\u{212A}elvin"));
    }

    #[test]
    fn guarded_patterns_emulate_lookarounds() {
        // (?<!\d)\d{3}(?!\d): three digits, not inside a longer run.
        let three = Guarded::new(r"\d{3}", NOT_BEFORE_DIGIT, |c| c.is_ascii_digit());
        assert_eq!(three.ranges("123 4567 890"), vec![(0, 3), (9, 12)]);
        // (?![ ./-]?\d): no digit next, nor after one separator.
        let pair = Guarded::new(r"\d{2}", NOT_BEFORE_SEPARATED_DIGIT, |_| false);
        assert_eq!(pair.ranges("12 3"), Vec::<(usize, usize)>::new());
        assert_eq!(pair.ranges("12-x 34."), vec![(0, 2), (5, 7)]);
    }

    #[test]
    fn distances_count_utf16_units() {
        let text = "\u{1F600}ab";
        assert_eq!(utf16_distance(text, 0, text.len()), 4);
        assert!(within(text, 0, 4, 2));
        assert!(!within(text, 4, 0, 30));
        assert_eq!(next_char(text, 0), 4);
    }
}
