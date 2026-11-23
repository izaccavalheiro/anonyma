//! Court case numbers (`src/detectors/case-number.ts`): US federal case
//! numbers on their own, other case numbers within 30 characters after a label.

use super::{after_labels, has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(label = insensitive r"\b(?:case(?:\s+(?:number|no\.?|#|id))?|docket(?:\s+(?:number|no\.?|#))?|civil\s+action|criminal\s+(?:case|no\.?|#)|court\s+(?:case|file(?:\s+no\.?)?)|matter\s+no\.?|file\s+(?:number|no\.?|#))\s*:?\s*");
js_regex!(federal = insensitive r"\b(?:\d:\s*)?\d{2}[\s-](?:cv|cr|civ|crim|mc|mj|po|br|ap|adv|bk)[\s-]\d{4,6}\b");
js_regex!(general = insensitive r"\b(?:[a-z]{1,4}[-\s])?\d{2,4}[-/]\d{2,6}(?:[-/][a-z0-9]{1,5})?\b");

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::CaseNumber);
    for (start, end) in federal().ranges(text) {
        found.push(start, end, if labelled(start) { 0.92 } else { 0.8 });
    }
    for (start, end) in after_labels(&labels, || general().ranges(text)) {
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
    fn case_numbers() {
        assert_eq!(
            detect("Case No. 1:23-cv-01234 filed")[0].value,
            "1:23-cv-01234"
        );
        assert_eq!(detect("Ref 23-cr-5678")[0].confidence, 0.8);
        assert_eq!(detect("Docket 2023-1234")[0].value, "2023-1234");
        assert!(detect("Ref 2023-1234").is_empty());
    }
}
