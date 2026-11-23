//! Scaling gate of the core, run by CI: detection with every category must
//! grow linearly with the text. It times `detect` on two texts at 10 KB, 100 KB
//! and 1 MB, and fails when the log-log slope of time against size passes 1.15:
//!
//! - a label before every value, where a label check that is linear in the
//!   labels grows with labels × candidates (a slope of ~1.3 before #104);
//! - capitals and labelled addresses, where lower-casing the text once per
//!   candidate made detection quadratic (#86).
//!
//! ```text
//! cargo run --release -p anonyma-core --example scaling [-- limit]
//! ```
//!
//! Every value is synthetic.

use std::hint::black_box;
use std::time::Instant;

use anonyma_core::AnonymaEngine;

/// One line with a label before each value (as bench/corpus.mjs makeLabelledText).
const LABELLED: &str = "Passport: A1234567, tax id: 12-3456789, account number: 12345678, \
plate number AB12 CDE, MRN: 00123456, member id ABC123456789, Rx # 1234567, tracking number \
1Z999AA10123456784, case no. 13-cv-12345, company number 12345678, DL # D1234567, national id \
123.456.789-09, discord id 123456789012345678, Order 2026 Item 4512 Code AB12 Ref 77 Batch X91 \
Lot 3300\n";

/// One line with capitals and a labelled address (as tests/linear_time.rs).
const ADDRESSES: &str = "Shipped To: 123 Example Street, Springfield. Dear Ana Example, call \
(555) 010-0123 or pay GB82 WEST 1234 5698 7654 32.\n";

fn text(line: &str, size: usize) -> String {
    let mut out = String::with_capacity(size + line.len());
    while out.len() < size {
        out.push_str(line);
    }
    out.truncate(size);
    out
}

/// The fastest of several runs, in seconds.
fn best(engine: &AnonymaEngine, text: &str) -> f64 {
    engine.detect(text);
    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        black_box(engine.detect(text));
        best = best.min(start.elapsed().as_secs_f64());
    }
    best
}

/// Least-squares slope of ln(time) against ln(size).
fn slope(points: &[(f64, f64)]) -> f64 {
    let n = points.len() as f64;
    let xs: Vec<f64> = points.iter().map(|(x, _)| x.ln()).collect();
    let ys: Vec<f64> = points.iter().map(|(_, y)| y.ln()).collect();
    let (mx, my) = (xs.iter().sum::<f64>() / n, ys.iter().sum::<f64>() / n);
    let covariance: f64 = xs.iter().zip(&ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    let variance: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum();
    covariance / variance
}

fn main() {
    let limit: f64 = std::env::args()
        .nth(1)
        .map_or(1.15, |value| value.parse().expect("a number"));
    let engine = AnonymaEngine::builder().build().expect("every category");
    let mut failed = false;
    for (name, line) in [("labelled", LABELLED), ("addresses", ADDRESSES)] {
        let points: Vec<(f64, f64)> = [10_000, 100_000, 1_000_000]
            .iter()
            .map(|&size| (size as f64, best(&engine, &text(line, size))))
            .collect();
        let slope = slope(&points);
        let per_byte: Vec<String> = points
            .iter()
            .map(|(size, seconds)| format!("{:.1}", seconds * 1e9 / size))
            .collect();
        let status = if slope <= limit { "ok" } else { "NOT LINEAR" };
        println!(
            "{name:<10} slope {slope:.2} (limit {limit:.2}) {status}; ns/B at 10 KB, 100 KB, 1 MB: {}",
            per_byte.join(", ")
        );
        failed |= slope > limit;
    }
    if failed {
        std::process::exit(1);
    }
}
