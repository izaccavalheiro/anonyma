//! Where the core spends its time: every detector alone and all together, on
//! short entries (one call each) and on one long text.
//!
//! ```text
//! cargo run --release -p anonyma-core --example bench [-- --quick]
//! ```
//!
//! Prints, per detector, microseconds per 200-byte entry and nanoseconds per
//! byte on a long text, so a change can be judged on the fixed cost of a call
//! and on the cost of a byte separately. Every value is synthetic.

use std::hint::black_box;
use std::time::{Duration, Instant};

use anonyma_core::{AnonymaEngine, Category};

/// Synthetic values of most categories, one per entry in turn.
const VALUES: &[&str] = &[
    "user{i}@example.com",
    "+1 202 555 0{i3}",
    "SSN 123-45-6789",
    "card 4111 1111 1111 1111",
    "from 192.0.2.{i2}",
    "host 2001:db8::{i3}",
    "see https://example.com/u/{i}?ref=mail",
    "IBAN DE89370400440532013000",
    "born 1990-04-15",
    "Dear Ana Example",
    "lives at 123 Main Street",
    "Passport: A1234567",
    "DL # D1234567",
    "national id 123.456.789-09",
    "account number 12345678",
    "wallet 0xabababababababababababababababababababab",
    "Tax ID: 12-3456789",
    "MRN: 00123456",
    "member id ABC123456789",
    "Rx # 1234567",
    "api key = {key}",
    "follow @example_user",
    "VIN 1HGCM82633A004352",
    "plate number AB12 CDE",
    "tracking number 1Z999AA10123456784",
    "case no. 13-cv-12345",
    "company number 12345678",
];

/// About 200 bytes of log text with one value.
fn entry(i: usize) -> String {
    let value = VALUES[i % VALUES.len()]
        .replace("{i3}", &format!("{:03}", i % 1000))
        .replace("{i2}", &format!("{}", i % 250))
        .replace("{i}", &i.to_string())
        // Assembled here: the literal would look like a live credential to a secret scanner.
        .replace(
            "{key}",
            &["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_"),
        );
    let mut text = format!(
        "2026-11-23T10:{:02}:{:02}Z INFO Request {i:06} From The Gateway: {value}; \
         the cache was warm and the Queue held {} items",
        i / 60 % 60,
        i % 60,
        i % 17
    );
    while text.len() < 200 {
        text.push_str(" and Nothing Else happened");
    }
    text.truncate(200);
    text
}

/// A text of about `size` bytes: entries joined by newlines.
fn document(size: usize) -> String {
    let mut text = String::with_capacity(size + 256);
    let mut i = 0;
    while text.len() < size {
        text.push_str(&entry(i));
        text.push('\n');
        i += 1;
    }
    text
}

/// Median seconds of one run of `f`, over runs filling `budget` (at least 3).
fn median(budget: Duration, mut f: impl FnMut()) -> f64 {
    f();
    let mut samples = Vec::new();
    let start = Instant::now();
    while samples.len() < 3 || (start.elapsed() < budget && samples.len() < 50) {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64());
    }
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let (count, size, budget) = if quick {
        (2_000, 100_000, Duration::from_millis(300))
    } else {
        (10_000, 1_000_000, Duration::from_secs(1))
    };
    let entries: Vec<String> = (0..count).map(entry).collect();
    let long = document(size);

    let all = AnonymaEngine::builder().build().expect("every category");
    let found: usize = entries.iter().map(|e| all.detect(e).len()).sum();
    println!(
        "{count} entries of 200 B ({found} matches), one text of {} B ({} matches)",
        long.len(),
        all.detect(&long).len()
    );
    println!("{:<22} {:>12} {:>10}", "detector", "us/entry", "ns/B");

    let mut rows = Vec::new();
    for &category in Category::ALL {
        let engine = AnonymaEngine::builder()
            .categories([category])
            .build()
            .expect("a supported category");
        let short = median(budget, || {
            for e in &entries {
                black_box(engine.detect(e));
            }
        }) / count as f64;
        let per_byte = median(budget, || {
            black_box(engine.detect(&long));
        }) / long.len() as f64;
        rows.push((category.to_string(), short * 1e6, per_byte * 1e9));
    }
    rows.sort_by(|a, b| b.1.total_cmp(&a.1));
    let (mut sum_short, mut sum_byte) = (0.0, 0.0);
    for (name, short, byte) in &rows {
        println!("{name:<22} {short:>12.2} {byte:>10.2}");
        sum_short += short;
        sum_byte += byte;
    }
    println!(
        "{:<22} {sum_short:>12.2} {sum_byte:>10.2}",
        "sum of the above"
    );

    let short = median(budget, || {
        for e in &entries {
            black_box(all.detect(e));
        }
    }) / count as f64;
    let per_byte = median(budget, || {
        black_box(all.detect(&long));
    }) / long.len() as f64;
    let (short, per_byte) = (short * 1e6, per_byte * 1e9);
    println!("{:<22} {short:>12.2} {per_byte:>10.2}", "every category");
    let joined = entries.join("\n");
    let fused = median(budget, || {
        black_box(all.detect(&joined));
    }) / count as f64;
    println!("{:<22} {:>12.2}", "every category, joined", fused * 1e6);
}
