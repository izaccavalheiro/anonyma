//! API keys and tokens (`src/detectors/api-key.ts`): the formats of AWS,
//! Stripe, GitHub, Slack, Google, `sk-` keys and JSON Web Tokens on their own,
//! and any long token within 10 characters after a label.

use std::sync::OnceLock;

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::{js_regex, JsRegex};
use crate::Category;

// The reference writes `[_-\s]`, a literal `-` before a class escape; `[_\s-]`
// is the same set, in the syntax the regex crate reads.
js_regex!(label = insensitive r"\b(?:api[_\s-]?key|api[_\s-]?token|access[_\s-]?token|secret[_\s-]?key|auth(?:orization)?[_\s-]?(?:key|token)|bearer(?:\s+token)?|x-api-key|credential[s]?)\s*[:=]\s*");
js_regex!(generic = r"\b[a-zA-Z0-9_.-]{20,80}\b");

fn formats() -> &'static [(JsRegex, f64)] {
    static CELL: OnceLock<Vec<(JsRegex, f64)>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (r"\bAKIA[0-9A-Z]{16}\b", 0.99),
            (r"\bsk_live_[a-zA-Z0-9]{24,99}\b", 0.99),
            (r"\bpk_live_[a-zA-Z0-9]{24,99}\b", 0.99),
            (r"\b(?:sk|pk)_test_[a-zA-Z0-9]{24,99}\b", 0.97),
            (r"\bghp_[a-zA-Z0-9]{36}\b", 0.99),
            (r"\bgho_[a-zA-Z0-9]{36}\b", 0.99),
            (r"\bghs_[a-zA-Z0-9]{36}\b", 0.99),
            (r"\bghr_[a-zA-Z0-9]{36,76}\b", 0.99),
            (r"\bgithub_pat_[a-zA-Z0-9_]{59,}\b", 0.99),
            (r"\bxoxb-[0-9A-Za-z-]{40,}\b", 0.98),
            (r"\bxoxp-[0-9A-Za-z-]{40,}\b", 0.98),
            (r"\bxoxa-[0-9A-Za-z-]{40,}\b", 0.98),
            (r"\bxoxs-[0-9A-Za-z-]{40,}\b", 0.96),
            (r"\bsk-[a-zA-Z0-9]{32,}\b", 0.9),
            (r"\bAIza[0-9A-Za-z_-]{35}\b", 0.99),
            (
                r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,}\b",
                0.95,
            ),
        ]
        .into_iter()
        .map(|(source, confidence)| (JsRegex::new(source), confidence))
        .collect()
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let mut found = Collector::new(text, Category::ApiKey);
    for (pattern, confidence) in formats() {
        for (start, end) in pattern.ranges(text) {
            found.push(start, end, *confidence);
        }
    }
    for (start, end) in generic().ranges(text) {
        if has_context(text, &labels, start, 10) {
            found.push(start, end, 0.82);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_labels() {
        // Built from parts so that secret scanners do not flag this file.
        let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        assert_eq!(detect(&format!("Key {aws} leaked"))[0].confidence, 0.99);
        assert_eq!(
            detect("api_key = abcdefghijklmnopqrstuvwxyz012345")[0].confidence,
            0.82
        );
        assert!(detect("Hash abcdefghijklmnopqrstuvwxyz012345").is_empty());
    }
}
