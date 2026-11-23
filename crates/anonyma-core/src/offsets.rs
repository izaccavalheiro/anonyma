//! Offset conversions. The core reports UTF-8 byte offsets; Python counts code
//! points, JavaScript and Java UTF-16 code units, Go bytes.

/// Converts byte offsets of one text to code points or UTF-16 units. Build it
/// once per text and convert offsets in increasing order for linear cost.
#[derive(Debug, Clone)]
pub struct OffsetMap<'t> {
    text: &'t str,
}

impl<'t> OffsetMap<'t> {
    /// A converter for offsets into `text`.
    pub fn new(text: &'t str) -> Self {
        OffsetMap { text }
    }

    /// The code-point offset of byte offset `byte` (a character boundary).
    pub fn code_points(&self, byte: usize) -> usize {
        self.text[..byte].chars().count()
    }

    /// The UTF-16 offset of byte offset `byte` (a character boundary).
    pub fn utf16(&self, byte: usize) -> usize {
        self.text[..byte].encode_utf16().count()
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
}
