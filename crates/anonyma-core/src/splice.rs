//! Replacement of the matches of a text in one pass.

/// `text` with each span `(start, end)` replaced by its string. The spans are
/// byte offsets, without overlaps, in decreasing order: the order in which
/// strategies and token counters run, from the last match to the first.
///
/// The text is assembled once. Replacing the spans in place, one after the
/// other, moved the rest of the text for every span: O(n·m) for m matches in n
/// bytes.
pub(crate) fn replace_spans(text: &str, spans: &[(usize, usize, String)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, replacement) in spans.iter().rev() {
        out.push_str(&text[cursor..*start]);
        out.push_str(replacement);
        cursor = *end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_spans_given_last_first() {
        let spans = [(13, 18, "Z".to_string()), (0, 5, "[A]".to_string())];
        assert_eq!(
            replace_spans("alpha, beta, gamma!", &spans),
            "[A], beta, Z!"
        );
        assert_eq!(replace_spans("unchanged", &[]), "unchanged");
    }
}
