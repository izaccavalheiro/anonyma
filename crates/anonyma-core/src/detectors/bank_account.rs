//! Bank account numbers (`src/detectors/bank-account.ts`): PIX payloads and
//! keys, US ABA routing numbers, UK sort codes, SWIFT/BIC codes and account
//! numbers after a label.

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::js_regex;
use crate::validators::{aba_routing, pix_payload};
use crate::Category;

js_regex!(context = insensitive r"\b(?:routing\s+(?:number|no\.?|#)|sort\s+code|account\s+(?:number|no\.?|#)|bank\s+account|iban|bic|swift|aba)\s*:?\s*");
js_regex!(us_aba = r"\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b");
js_regex!(uk_sort_code = r"\b\d{2}-\d{2}-\d{2}\b");
js_regex!(swift_bic = r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b");
// `ó` is not an ASCII letter: both cases are spelled out.
js_regex!(pix_context = insensitive r"\b(?:chave\s+(?:pix|aleat[óÓo]ria)|pix(?:\s+key)?)\s*:?\s*");
js_regex!(pix_random_key = insensitive r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b");
js_regex!(generic_account = r"\b\d{7,18}\b");

/// The PIX identifier with its EMV field id and length.
const PIX_GUI: &str = "0014br.gov.bcb.pix";

/// Longest payload looked for, in characters.
const PIX_PAYLOAD_MAX: usize = 512;

/// Every PIX "copia e cola" payload: it starts with the EMV header `000201`,
/// holds the PIX identifier and ends with a CRC field (`6304` and four
/// hexadecimal digits) that matches its content.
fn scan_pix_payloads(text: &str, found: &mut Collector<'_>) {
    let find = |needle: &str, from: usize| -> Option<usize> {
        text.get(from..)
            .and_then(|rest| rest.find(needle))
            .map(|i| from + i)
    };
    let mut start = find("000201", 0);
    while let Some(begin) = start {
        let mut end = None;
        let mut crc = find("6304", begin + 6);
        while let Some(at) = crc {
            if at + 8 - begin > PIX_PAYLOAD_MAX || at + 8 > text.len() {
                break;
            }
            let Some(candidate) = text.get(begin..at + 8) else {
                break;
            };
            // A payload is printable ASCII, so a longer candidate cannot be one either.
            if !candidate.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
                break;
            }
            if candidate.to_ascii_lowercase().contains(PIX_GUI) && pix_payload(candidate) {
                end = Some(at + 8);
                break;
            }
            crc = find("6304", at + 1);
        }
        match end {
            Some(stop) => {
                found.push(begin, stop, 0.97);
                start = find("000201", stop);
            }
            None => start = find("000201", begin + 1),
        }
    }
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(context().ranges(text));
    let labelled = |index: usize| has_context(text, &labels, index, 30);
    let mut found = Collector::new(text, Category::BankAccount);

    // PIX payloads: verified by their CRC, no label needed.
    scan_pix_payloads(text, &mut found);

    // PIX random keys: only after a PIX label.
    let pix_labels = label_ends(pix_context().ranges(text));
    if !pix_labels.is_empty() {
        for (start, end) in pix_random_key().ranges(text) {
            if has_context(text, &pix_labels, start, 30) {
                found.push(start, end, 0.9);
            }
        }
    }

    // US ABA routing numbers: only after a label; valid check digits raise the confidence.
    for (start, end) in us_aba().ranges(text) {
        if labelled(start) {
            let confidence = if aba_routing(&text[start..end]) {
                0.9
            } else {
                0.85
            };
            found.push(start, end, confidence);
        }
    }

    // UK sort codes and SWIFT/BIC codes: distinctive, no label needed.
    for (start, end) in uk_sort_code().ranges(text) {
        found.push(start, end, 0.8);
    }
    for (start, end) in swift_bic().ranges(text) {
        found.push(start, end, 0.82);
    }

    // Any account number: only after a label.
    for (start, end) in generic_account().ranges(text) {
        if labelled(start) {
            found.push(start, end, 0.8);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = "00020126400014br.gov.bcb.pix0118fulano@example.com5204000053039865802BR5913FULANO DE TAL6009SAO PAULO62070503***63049F63";

    #[test]
    fn pix_payload_verified_by_its_crc() {
        let text = format!("Pague com: {PAYLOAD}");
        let found = detect(&text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, PAYLOAD);
        let altered = format!("Pague com: {}0", &PAYLOAD[..PAYLOAD.len() - 1]);
        assert!(detect(&altered).is_empty());
    }

    #[test]
    fn pix_random_key_needs_a_label() {
        let key = "123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(detect(&format!("Chave PIX: {key}"))[0].confidence, 0.9);
        assert_eq!(
            detect(&format!("Chave aleatória: {key}"))[0].confidence,
            0.9
        );
        assert!(detect(&format!("Request {key}")).is_empty());
    }

    #[test]
    fn routing_numbers_and_sort_codes() {
        assert_eq!(detect("Routing number: 011000015")[0].confidence, 0.9);
        assert_eq!(detect("Sort code 12-34-56")[0].value, "12-34-56");
    }
}
