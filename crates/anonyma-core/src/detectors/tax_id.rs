//! Tax identification numbers (`src/detectors/tax-id.ts`): US EIN and ITIN,
//! EU VAT, Australian ABN, UK UTR and Brazilian CNPJ.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::anchored::TextIndex;
use crate::jsregex::js_regex;
use crate::validators::cnpj;
use crate::Category;

js_regex!(us_ein = r"\b\d{2}-\d{7}\b");
js_regex!(us_itin = r"\b9\d{2}[\s-](?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|90|91|92|9[4-9])[\s-]\d{4}\b");
js_regex!(uk_utr = r"\b\d{10}\b");
js_regex!(
    eu_vat = r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[\s-]?[A-Z0-9]{8,12}\b"
);
js_regex!(au_abn = r"\b\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3}\b");
// Case-insensitive in the reference: written in lower case.
js_regex!(br_cnpj = insensitive r"\b[a-z0-9]{2}\.[a-z0-9]{3}\.[a-z0-9]{3}\/[a-z0-9]{4}-\d{2}\b");
js_regex!(br_cnpj_bare = insensitive r"\b[a-z0-9]{12}\d{2}\b");
js_regex!(context = insensitive r"\b(?:tax(?:\s+(?:id(?:entification)?|number|no\.?|#|reference))?|t\.?i\.?n\.?|ein|itin|utr|vat(?:\s+(?:number|no\.?|reg(?:istration)?|#))?|abn|tfn|cnpj)\s*:?\s*");

/// [`detect_in`] with an index of its own, for tests.
#[cfg(test)]
pub(super) fn detect(text: &str) -> Vec<Match> {
    detect_in(text, &TextIndex::new(text, true))
}

pub(super) fn detect_in(text: &str, index: &TextIndex<'_>) -> Vec<Match> {
    let labels = label_ends(context().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::TaxId);

    for (start, end) in us_ein().ranges_with(text, index) {
        found.push(start, end, if labelled(start) { 0.92 } else { 0.8 });
    }
    for (start, end) in us_itin().ranges_with(text, index) {
        found.push(start, end, 0.9);
    }
    for (start, end) in eu_vat().ranges_with(text, index) {
        found.push(start, end, if labelled(start) { 0.9 } else { 0.78 });
    }
    for (start, end) in after_labels(&labels, || au_abn().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.82);
        }
    }
    for (start, end) in br_cnpj().ranges_with(text, index) {
        if cnpj(&text[start..end]) {
            found.push(start, end, 0.95);
        }
    }
    for (start, end) in after_labels(&labels, || br_cnpj_bare().ranges_with(text, index)) {
        if labelled(start) && cnpj(&text[start..end]) {
            found.push(start, end, 0.9);
        }
    }
    for (start, end) in after_labels(&labels, || uk_utr().ranges_with(text, index)) {
        if labelled(start) {
            found.push(start, end, 0.85);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_case_sensitive_patterns_are_searched_at_candidate_starts() {
        for pattern in [us_ein(), us_itin(), uk_utr(), au_abn()] {
            assert!(pattern.is_anchored());
            crate::anchored::parity::check(pattern);
        }
    }

    #[test]
    fn cnpj_needs_valid_check_digits() {
        assert_eq!(detect("CNPJ 11.222.333/0001-81")[0].confidence, 0.95);
        assert!(detect("CNPJ 11.222.333/0001-82").is_empty());
        assert_eq!(detect("Empresa 12.ABC.345/01DE-35").len(), 1);
    }

    #[test]
    fn a_bare_cnpj_needs_a_label() {
        assert_eq!(detect("CNPJ: 11222333000181")[0].confidence, 0.9);
        assert!(detect("Ref 11222333000181").is_empty());
    }

    #[test]
    fn ein_confidence_depends_on_the_label() {
        assert_eq!(detect("EIN 12-3456789")[0].confidence, 0.92);
        assert_eq!(detect("Ticket 12-3456789")[0].confidence, 0.8);
    }
}
