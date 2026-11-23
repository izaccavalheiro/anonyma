//! National identity numbers (`src/detectors/national-id.ts`): the Brazilian
//! CPF entry only, so far ([`crate::Support::Partial`]).
//!
//! The reference runs twenty country entries in order and keeps the first
//! match of each range. With the CPF entry alone, the results agree on any
//! text in which no other entry matches; the conformance cases that need only
//! this entry (`detect:national-id/br-cpf`) are such texts.

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::validators::cpf;
use crate::Category;

js_regex!(cpf_pattern = r"\b\d{3}\.\d{3}\.\d{3}[-\s]\d{2}\b");

// Labels within 40 characters before a number raise its confidence.
js_regex!(context = insensitive r"\b(?:national\s+(?:id|identification|identity)\s*(?:number|no\.?|card|#)?|id\s+(?:number|no\.?|#)|citizen(?:ship)?\s+(?:number|id)|personal\s+(?:id|identification)\s*(?:number|no\.?)?|identificat(?:ion|or))\s*:?\s*");

const CPF_CONFIDENCE: f64 = 0.92;

pub(super) fn detect(text: &str, strict: bool) -> Vec<Match> {
    let labels = label_ends(context().ranges(text));
    let mut found = Collector::new(text, Category::NationalId);
    for (start, end) in cpf_pattern().ranges(text) {
        // The default detector does not verify the check digits; the strict one does.
        if strict && !cpf(&text[start..end]) {
            continue;
        }
        let confidence = if has_context(text, &labels, start, 40) {
            (CPF_CONFIDENCE + 0.05).min(0.97)
        } else {
            CPF_CONFIDENCE
        };
        found.push(start, end, confidence);
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_digits_only_in_strict_mode() {
        assert_eq!(detect("CPF 529.982.247-26", false).len(), 1);
        assert!(detect("CPF 529.982.247-26", true).is_empty());
        assert_eq!(detect("CPF 529.982.247-25", true).len(), 1);
    }

    #[test]
    fn a_label_raises_the_confidence() {
        assert_eq!(
            detect("National ID: 529.982.247-25", false)[0].confidence,
            0.97
        );
        assert_eq!(detect("CPF 529.982.247-25", false)[0].confidence, 0.92);
    }
}
