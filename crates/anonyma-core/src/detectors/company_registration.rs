//! Company registration numbers (`src/detectors/company-registration.ts`):
//! US EINs, and UK, Australian and European registration numbers within 30
//! characters after a label.

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(label = insensitive r"\b(?:company\s+(?:registration|reg(?:istration)?)\s*(?:number|no\.?|#)?|companies\s+house\s*(?:number|no\.?|#)?|registered\s+(?:number|company\s+number|no\.?)|incorporation\s*(?:number|no\.?|#)?|company\s+(?:number|no\.?|#)|corporate\s+(?:id|number|no\.?|registration)|business\s+(?:registration|number)|abn|acn|cik)\s*:?\s*");
js_regex!(us_ein = r"\b\d{2}-\d{7}\b");
js_regex!(uk_companies_house = insensitive r"\b(?:[a-z]{2}\d{6}|\d{8})\b");
js_regex!(au_acn = r"\b\d{3}[\s]?\d{3}[\s]?\d{3}\b");
js_regex!(european = r"\b[A-Z]{2}[\s-]?[A-Z0-9]{5,12}\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::CompanyRegistration);
    for (start, end) in us_ein().ranges(text) {
        found.push(start, end, if labelled(start) { 0.88 } else { 0.72 });
    }
    for (start, end) in uk_companies_house().ranges(text) {
        if labelled(start) {
            found.push(start, end, 0.85);
        }
    }
    for (start, end) in au_acn().ranges(text) {
        if labelled(start) {
            found.push(start, end, 0.82);
        }
    }
    for (start, end) in european().ranges(text) {
        if labelled(start) {
            found.push(start, end, 0.78);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(detect("Company number: 01234567")[0].confidence, 0.85);
        let found = detect("Ref 12-3456789 and ACN 123 456 789");
        assert_eq!(found[0].confidence, 0.72);
        assert_eq!(found[1].value, "123 456 789");
    }
}
