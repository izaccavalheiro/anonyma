//! National identity numbers (`src/detectors/national-id.ts`): twenty
//! country formats, in the reference's order. The first entry to report a
//! range keeps it. Ambiguous formats need a label within 40 characters
//! before them, and a label raises any entry's confidence by 0.05.
//!
//! The reference compiles every entry with the `g` flag alone, dropping the
//! `i` of the UK, Chinese, Spanish and Italian patterns: they match upper
//! case only, here too. The strict variant drops a number whose check digits
//! fail.

use std::sync::OnceLock;

use super::{has_context, label_ends, Match};
use crate::anchored::TextIndex;
use crate::jsregex::JsRegex;
use crate::validators::{
    au_tfn, bsn, cn_resident_id, cpf, es_dni, fr_nir, it_fiscal_code, luhn, nino, pt_nif,
    se_personnummer, verhoeff,
};
use crate::Category;

/// The label of most entries.
const NATIONAL_ID_LABEL: &str = r"\b(?:national\s+(?:id|identification|identity)\s*(?:number|no\.?|card|#)?|id\s+(?:number|no\.?|#)|citizen(?:ship)?\s+(?:number|id)|personal\s+(?:id|identification)\s*(?:number|no\.?)?|identificat(?:ion|or))\s*:?\s*";

/// The label of the Brazilian RG, in lower case; `É` is spelled out, as only
/// ASCII letters are folded.
const RG_LABEL: &str = r"\b(?:rg|r\.g\.|registro\s+geral|(?:carteira|c[éÉe]dula)\s+de\s+identidade|identidade)\s*(?:n[º°o.]?\s*)?:?\s*";

struct Entry {
    pattern: JsRegex,
    confidence: f64,
    requires_label: bool,
    validate: Option<fn(&str) -> bool>,
    rg_label: bool,
    /// A match that is part of a longer number written in groups is not
    /// reported ([`in_longer_number`]).
    standalone: bool,
}

fn entry(
    source: &str,
    confidence: f64,
    requires_label: bool,
    validate: Option<fn(&str) -> bool>,
) -> Entry {
    Entry {
        pattern: JsRegex::new(source),
        confidence,
        requires_label,
        validate,
        rg_label: false,
        standalone: false,
    }
}

fn entries() -> &'static [Entry] {
    static CELL: OnceLock<Vec<Entry>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            // Canada SIN
            entry(r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b", 0.85, false, Some(luhn)),
            // Mexico CURP
            entry(
                r"\b[A-Z]{4}\d{6}[HM][A-Z]{2}[A-Z]{3}[A-Z0-9]\d\b",
                0.9,
                false,
                None,
            ),
            // Mexico RFC
            entry(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b", 0.78, true, None),
            // UK National Insurance number
            entry(
                r"\b[A-CEGHJ-PR-TW-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-D]\b",
                0.9,
                false,
                Some(nino),
            ),
            // India Aadhaar, never part of a longer number such as a card number
            Entry {
                standalone: true,
                ..entry(
                    r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b",
                    0.82,
                    false,
                    Some(verhoeff),
                )
            },
            // China resident ID
            entry(r"\b\d{17}[\dX]\b", 0.8, true, Some(cn_resident_id)),
            // South Korea RRN
            entry(r"\b\d{6}[\s-]\d{7}\b", 0.87, false, None),
            // Brazil CPF
            entry(r"\b\d{3}\.\d{3}\.\d{3}[-\s]\d{2}\b", 0.92, false, Some(cpf)),
            // Sweden personnummer
            entry(r"\b\d{6}[-+]\d{4}\b", 0.87, false, Some(se_personnummer)),
            // Spain DNI and NIE
            entry(
                r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b",
                0.82,
                false,
                Some(es_dni),
            ),
            // Italy codice fiscale
            entry(
                r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
                0.88,
                false,
                Some(it_fiscal_code),
            ),
            // France NIR
            entry(
                r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b",
                0.84,
                false,
                Some(fr_nir),
            ),
            // More ambiguous: a label is required.
            // Argentina DNI
            entry(r"\b\d{2,3}[.\s]?\d{3}[.\s]?\d{3}\b", 0.75, true, None),
            // South Africa ID
            entry(r"\b\d{13}\b", 0.72, true, Some(luhn)),
            // Nigeria NIN
            entry(r"\b\d{11}\b", 0.7, true, None),
            // Australia TFN
            entry(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b", 0.75, true, Some(au_tfn)),
            // Germany Personalausweis
            entry(r"\b[A-Z0-9]{9}\b", 0.75, true, None),
            // Portugal NIF
            entry(r"\b[1-9]\d{8}\b", 0.7, true, Some(pt_nif)),
            // Netherlands BSN
            entry(r"\b\d{9}\b", 0.7, true, Some(bsn)),
            // Brazil RG, after its own label
            Entry {
                rg_label: true,
                ..entry(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dXx]\b", 0.85, true, None)
            },
        ]
    })
}

fn labels() -> &'static (JsRegex, JsRegex) {
    static CELL: OnceLock<(JsRegex, JsRegex)> = OnceLock::new();
    CELL.get_or_init(|| {
        (
            JsRegex::insensitive(NATIONAL_ID_LABEL),
            JsRegex::insensitive(RG_LABEL),
        )
    })
}

/// True when the digits from `start` to `end` of `text` continue a longer
/// number: a digit and a space or hyphen come right before them, or a space or
/// hyphen and a digit right after.
fn in_longer_number(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let separator = |b: u8| b == b' ' || b == b'-';
    (start >= 2 && separator(bytes[start - 1]) && bytes[start - 2].is_ascii_digit())
        || (end + 1 < bytes.len() && separator(bytes[end]) && bytes[end + 1].is_ascii_digit())
}

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str, strict: bool) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true), strict)
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>, strict: bool) -> Vec<Match> {
    let (national, rg) = labels();
    let national_ends = label_ends(national.ranges(text));
    let rg_ends = label_ends(rg.ranges(text));
    // Every format begins with a word boundary and a digit, a capital, `&` or
    // `Ñ`: the call's index of those starts serves all twenty (src/anchored.rs).
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for entry in entries() {
        let ends = if entry.rg_label {
            &rg_ends
        } else {
            &national_ends
        };
        // Without a label, a format that requires one reports nothing.
        if entry.requires_label && ends.is_empty() {
            continue;
        }
        for (start, end) in entry.pattern.ranges_with(text, index) {
            if seen.contains(&(start, end)) {
                continue;
            }
            let labelled = has_context(text, ends, start, 40);
            if entry.requires_label && !labelled {
                continue;
            }
            if entry.standalone && in_longer_number(text, start, end) {
                continue;
            }
            // A number whose check digits fail may still be another country's number.
            if strict
                && entry
                    .validate
                    .is_some_and(|check| !check(&text[start..end]))
            {
                continue;
            }
            let confidence = if labelled {
                (entry.confidence + 0.05).min(0.97)
            } else {
                entry.confidence
            };
            seen.insert((start, end));
            found.push(Match::new(
                Category::NationalId,
                text,
                start,
                end,
                confidence,
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_is_searched_at_candidate_starts() {
        for entry in entries() {
            assert!(entry.pattern.is_anchored());
        }
        let (national, rg) = labels();
        // The labels are case-insensitive: they keep the full scan.
        assert!(!national.is_anchored() && !rg.is_anchored());
    }

    #[test]
    fn the_anchored_search_finds_what_a_full_scan_finds() {
        for entry in entries() {
            crate::anchored::parity::check(&entry.pattern);
        }
    }

    fn values(text: &str, strict: bool) -> Vec<String> {
        detect(text, strict).into_iter().map(|m| m.value).collect()
    }

    #[test]
    fn countries() {
        assert_eq!(
            values("CPF 529.982.247-25 cadastrado", false),
            ["529.982.247-25"]
        );
        assert_eq!(
            values("DNI 12345678Z, NIE X1234567L", false),
            ["12345678Z", "X1234567L"]
        );
        assert_eq!(values("RG nº 12.345.678-9", false), ["12.345.678-9"]);
        assert!(values("Resident 11010519491231002X", false).is_empty());
        assert_eq!(
            values("National ID: 11010519491231002X", false),
            ["11010519491231002X"]
        );
    }

    #[test]
    fn aadhaar_numbers_inside_longer_numbers() {
        assert!(values("card 4111 1111 1111 1112", false).is_empty());
        assert!(values("card 1234 2345 6789 0124", true).is_empty());
        assert!(values("ref 2345-6789-0124-5", false).is_empty());
        assert_eq!(
            values("Aadhaar 2345 6789 0124, phone", false),
            ["2345 6789 0124"]
        );
        assert_eq!(values("2345-6789-0124 a", false), ["2345-6789-0124"]);
    }

    #[test]
    fn upper_case_only_and_strict() {
        assert_eq!(
            values("NINO AB 12 34 56 A and ab 12 34 56 a", false),
            ["AB 12 34 56 A"]
        );
        assert_eq!(values("NIR 2 84 05 75 123 456 73", false).len(), 1);
        assert!(values("NIR 2 84 05 75 123 456 73", true).is_empty());
    }
}
