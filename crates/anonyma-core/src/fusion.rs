//! Batch fusion, as in the reference (`src/internal/fusion.ts`): the entries of
//! a batch are joined into one text, scanned once, and the matches split back
//! by entry, so one scan pays the fixed cost of the detectors for many entries.
//!
//! It is exact for the built-in detectors, which port the reference's patterns
//! with their semantics; the reference's `tests/batch-fusion.test.ts` states
//! why, and `tests/batch.rs` checks the port the same way:
//!
//! - every assertion at the edge of a match treats `\n` as the start or the end
//!   of the text, except `^` in the greetings of the name detector: entries that
//!   start with a greeting word are scanned alone;
//! - no pattern crosses the separator, which alternates `\n` and `\0`;
//! - labels count for a value at most 40 UTF-16 units after them, less than the
//!   43 units of the separator.

/// The text between two fused entries.
pub(crate) const SEPARATOR: &str =
    "\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n\0\n";

/// Entries of this many bytes or more are scanned alone: fusing them gains nothing.
const MAX_ENTRY: usize = 8192;

/// A fused text grows to about this many bytes, which keeps label lookups bounded.
const CHUNK: usize = 32 * 1024;

/// Words a greeting starts with; the name detector anchors greetings with `^`.
const GREETINGS: [&str; 5] = ["dear", "hi", "hello", "greetings", "hey"];

fn starts_with_greeting(text: &str) -> bool {
    GREETINGS.iter().any(|word| {
        text.len() >= word.len()
            && text.as_bytes()[..word.len()].eq_ignore_ascii_case(word.as_bytes())
    })
}

/// `f` of each item, in order: on rayon's pool with the `parallel` feature,
/// one after the other without it.
pub(crate) fn map_all<I: Send, O: Send>(items: Vec<I>, f: impl Fn(I) -> O + Sync + Send) -> Vec<O> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        items.into_par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.into_iter().map(f).collect()
    }
}

/// Run `scan` on fused texts of the entries that can be fused and split its
/// results back by entry. `scan` returns results sorted by start, each inside
/// one entry; `start` reads a result's start and `shift` moves it left. Fused
/// texts are scanned with [`map_all`], in parallel with the `parallel` feature.
///
/// Returns, per entry, its results, or `None` for an entry to scan alone (too
/// long, holding `\0`, a greeting when `names`), and for every entry when fewer
/// than two can be fused.
pub(crate) fn fuse_each<T: Send>(
    texts: &[&str],
    names: bool,
    scan: impl Fn(&str) -> Vec<T> + Sync + Send,
    start: impl Fn(&T) -> usize,
    shift: impl Fn(T, usize) -> T,
) -> Vec<Option<Vec<T>>> {
    let mut out: Vec<Option<Vec<T>>> = texts.iter().map(|_| None).collect();
    let members: Vec<usize> = (0..texts.len())
        .filter(|&i| {
            let text = texts[i];
            text.len() < MAX_ENTRY && !text.contains('\0') && !(names && starts_with_greeting(text))
        })
        .collect();
    if members.len() < 2 {
        return out;
    }

    // Group the members into fused texts of about CHUNK bytes.
    let mut chunks: Vec<Vec<usize>> = Vec::new();
    let mut chunk = Vec::new();
    let mut size = 0;
    for i in members {
        chunk.push(i);
        size += texts[i].len() + SEPARATOR.len();
        if size >= CHUNK {
            chunks.push(std::mem::take(&mut chunk));
            size = 0;
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }

    let scanned = map_all(chunks.clone(), |chunk| {
        let mut fused = String::new();
        for (n, &i) in chunk.iter().enumerate() {
            if n > 0 {
                fused.push_str(SEPARATOR);
            }
            fused.push_str(texts[i]);
        }
        scan(&fused)
    });
    for (chunk, results) in chunks.iter().zip(scanned) {
        let mut results = results.into_iter().peekable();
        let mut offset = 0;
        for &i in chunk {
            let limit = offset + texts[i].len() + SEPARATOR.len();
            let mut found = Vec::new();
            while let Some(result) = results.next_if(|r| start(r) < limit) {
                found.push(shift(result, offset));
            }
            out[i] = Some(found);
            offset = limit;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_separator_alternates_newlines_and_nuls_over_43_bytes() {
        assert_eq!(SEPARATOR.len(), 43);
        assert!(SEPARATOR
            .bytes()
            .enumerate()
            .all(|(i, b)| b == if i % 2 == 0 { b'\n' } else { 0 }));
    }

    #[test]
    fn greetings_are_recognised_in_any_case() {
        assert!(starts_with_greeting("Dear Ana"));
        assert!(starts_with_greeting("HELLO"));
        assert!(!starts_with_greeting("  Dear"));
        assert!(!starts_with_greeting("h"));
    }
}
