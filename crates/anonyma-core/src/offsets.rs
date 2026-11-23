//! Offset conversions. The core reports UTF-8 byte offsets; Python counts code
//! points, JavaScript and Java UTF-16 code units, Go bytes.

use std::cell::Cell;

/// Converts byte offsets of one text to code points or UTF-16 units. Build it
/// once per text: it keeps a cursor at the last offset it converted and moves
/// it by the distance to the next one, so converting the offsets of a text's
/// matches in order costs one pass over the text, not one pass per offset. An
/// ASCII text converts in constant time.
#[derive(Debug, Clone)]
pub struct OffsetMap<'t> {
    text: &'t str,
    ascii: bool,
    /// The byte offset of the cursor, and the code points and UTF-16 units before it.
    cursor: Cell<(usize, usize, usize)>,
}

impl<'t> OffsetMap<'t> {
    /// A converter for offsets into `text`.
    pub fn new(text: &'t str) -> Self {
        OffsetMap {
            text,
            ascii: text.is_ascii(),
            cursor: Cell::new((0, 0, 0)),
        }
    }

    /// The code-point offset of byte offset `byte` (a character boundary).
    pub fn code_points(&self, byte: usize) -> usize {
        self.seek(byte).0
    }

    /// The UTF-16 offset of byte offset `byte` (a character boundary).
    pub fn utf16(&self, byte: usize) -> usize {
        self.seek(byte).1
    }

    /// Moves the cursor to `byte` and returns the code points and UTF-16 units before it.
    fn seek(&self, byte: usize) -> (usize, usize) {
        if self.ascii {
            assert!(
                self.text.is_char_boundary(byte),
                "byte offset out of the text"
            );
            return (byte, byte);
        }
        let (at, mut points, mut units) = self.cursor.get();
        if byte >= at {
            for c in self.text[at..byte].chars() {
                points += 1;
                units += c.len_utf16();
            }
        } else {
            for c in self.text[byte..at].chars() {
                points -= 1;
                units -= c.len_utf16();
            }
        }
        self.cursor.set((byte, points, units));
        (points, units)
    }
}

/// The code-point offset of byte offset `byte` in `text`.
pub fn byte_to_code_point(text: &str, byte: usize) -> usize {
    OffsetMap::new(text).code_points(byte)
}

/// The UTF-16 offset of byte offset `byte` in `text`.
pub fn byte_to_utf16(text: &str, byte: usize) -> usize {
    OffsetMap::new(text).utf16(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        let text = "\u{1F4E7} alice@example.com";
        assert_eq!(byte_to_code_point(text, 5), 2);
        assert_eq!(byte_to_utf16(text, 5), 3);
    }

    #[test]
    fn a_map_converts_in_any_order() {
        let text = "a\u{e9}\u{1F4E7}b\u{1F4E7}c";
        let map = OffsetMap::new(text);
        let bytes: Vec<usize> = text
            .char_indices()
            .map(|(i, _)| i)
            .chain([text.len()])
            .collect();
        let expected = |byte: usize| {
            (
                text[..byte].chars().count(),
                text[..byte].encode_utf16().count(),
            )
        };
        let mut order = bytes.clone();
        order.extend(bytes.iter().rev());
        order.extend([bytes[3], bytes[1], bytes[5], bytes[0], bytes[6]]);
        for byte in order {
            assert_eq!(
                (map.code_points(byte), map.utf16(byte)),
                expected(byte),
                "at {byte}"
            );
        }
    }

    #[test]
    fn ascii_offsets_are_bytes() {
        let map = OffsetMap::new("alice@example.com");
        assert_eq!(
            (map.code_points(5), map.utf16(17), map.code_points(0)),
            (5, 17, 0)
        );
    }

    #[test]
    #[should_panic(expected = "byte offset out of the text")]
    fn ascii_offsets_are_checked() {
        OffsetMap::new("abc").utf16(4);
    }
}
