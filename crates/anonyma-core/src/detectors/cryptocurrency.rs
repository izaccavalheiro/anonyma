//! Cryptocurrency addresses (`src/detectors/cryptocurrency.ts`): Ethereum,
//! Bitcoin (legacy, P2SH, Bech32), Cardano, Litecoin and Monero on their own;
//! XRP and Solana-like addresses only within 40 characters after a label. A
//! label adds 0.03 to the confidence.

use std::sync::OnceLock;

use super::{has_context, label_ends, Collector, Match};
use crate::jsregex::{js_regex, JsRegex};
use crate::Category;

js_regex!(label = insensitive r"\b(?:wallet(?:\s+address)?|crypto(?:currency)?(?:\s+address)?|bitcoin|btc|ethereum|eth|litecoin|ltc|monero|xmr|ripple|xrp|solana|sol|cardano|ada|address)\s*:?\s*");

/// (pattern, confidence, label required), in the reference's order.
fn formats() -> &'static [(JsRegex, f64, bool)] {
    static CELL: OnceLock<Vec<(JsRegex, f64, bool)>> = OnceLock::new();
    CELL.get_or_init(|| {
        const B58: &str = "a-km-zA-HJ-NP-Z1-9";
        let rx = |source: &str| JsRegex::new(source);
        vec![
            (rx(r"\b0x[a-fA-F0-9]{40}\b"), 0.97, false),
            (rx(r"\bbc1[a-z0-9]{39,59}\b"), 0.95, false),
            (rx(r"\baddr1[a-z0-9]{58,98}\b"), 0.92, false),
            (rx(&format!(r"\b1[{B58}]{{25,34}}\b")), 0.88, false),
            (rx(&format!(r"\b3[{B58}]{{25,34}}\b")), 0.85, false),
            (rx(&format!(r"\bL[{B58}]{{26,33}}\b")), 0.83, false),
            (rx(&format!(r"\bM[{B58}]{{26,33}}\b")), 0.8, false),
            (rx(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), 0.9, false),
            (rx(&format!(r"\br[{B58}]{{24,33}}\b")), 0.78, true),
            (rx(r"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b"), 0.72, true),
        ]
    })
}

pub(super) fn detect(text: &str) -> Vec<Match> {
    let labels = label_ends(label().ranges(text));
    let mut found = Collector::new(text, Category::Cryptocurrency);
    for (pattern, confidence, requires_label) in formats() {
        for (start, end) in pattern.ranges(text) {
            let labelled = has_context(text, &labels, start, 40);
            if *requires_label && !labelled {
                continue;
            }
            let confidence = if labelled {
                (confidence + 0.03).min(0.99)
            } else {
                *confidence
            };
            found.push(start, end, confidence);
        }
    }
    found.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_labels() {
        let eth = format!("0x{}", "a1".repeat(20));
        assert_eq!(detect(&format!("Pay {eth} now"))[0].confidence, 0.97);
        let sol = "hBskUf5RRfWaHcx1ko8kybqJriN8KUBW1oyoHZqCZ7xh";
        assert!(detect(&format!("Hash {sol}")).is_empty());
        assert_eq!(detect(&format!("Wallet address: {sol}")).len(), 1);
    }
}
