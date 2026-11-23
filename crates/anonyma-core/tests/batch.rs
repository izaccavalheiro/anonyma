//! detect_batch() and anonymize_batch() fuse short entries into one text (src/fusion.rs). These
//! tests check, as the reference's tests/batch-fusion.test.ts does, that every result equals the
//! per-entry call at the boundaries between entries, where fusion could change one.

use std::sync::Arc;

use anonyma_core::{AnonymaEngine, Category, Detector, Match};

/// Labels that give a value nearby a higher confidence, or make it a match at all.
const LABELS: &[&str] = &[
    "Passport:",
    "passport number",
    "Address:",
    "shipped to",
    "Tax ID:",
    "VAT",
    "tracking number",
    "case no.",
    "docket #",
    "MRN:",
    "patient id",
    "Rx #",
    "NDC",
    "member id",
    "NHS number",
    "Discord ID",
    "api key =",
    "bearer",
    "routing number",
    "account number:",
    "pix key",
    "RG:",
    "national id",
    "DL #",
    "driver's license",
    "plate number",
    "registration no.",
    "company number",
    "ABN",
    "wallet address",
    "bitcoin",
    "Dear",
    "Mr.",
    "message-id: <abc",
    "version",
    "https://user:",
    "section",
    "release",
    "Table",
    "nginx/",
    "ssn",
    "social security number",
    "patient",
    "regarding",
];

/// Values the built-in detectors recognise, all synthetic.
const VALUES: &[&str] = &[
    "A12345678",
    "AB123456",
    "123 Main Street",
    "Hauptstraße 5, 10115 Berlin",
    "12 rue de la Paix",
    "12-3456789",
    "912-70-1234",
    "1Z999AA10123456784",
    "940011189922385111111",
    "4111 1111 1111 1111",
    "4111111111111111",
    "**** **** **** 1111",
    "ana@example.com",
    "ana [at] example [dot] com",
    "192.0.2.1",
    "2001:db8::1",
    "+1 202 555 0102",
    "(202) 555-0102",
    "555-0102",
    "06 12 34 56 78",
    "Ana Example",
    "DE89370400440532013000",
    "GB82 WEST 1234 5698 7654 32",
    "123-45-6789",
    "123456789",
    "https://example.com/a/b?c=d#e",
    "1HGCM82633A004352",
    "AB12 CDE",
    "@example_user",
    "u/example_user",
    "linkedin.com/in/example-user",
    "13-cv-12345",
    "1990-04-15",
    "04/15/1990",
    "15 April 1990",
    "529.982.247-25",
    "12.345.678-9",
    "AB 12 34 56 C",
    "2345 6789 0124",
    "123456789012",
    "01-23-45",
    "021000021",
    "12345678-1234-1234-1234-123456789012",
];

/// What may precede or follow a value inside an entry.
const EDGES: &[&str] = &[
    "", " ", "  ", "\t", "\n", ".", ". ", ", ", ":", "-", "x", "9",
];

/// A key the scanners take for a live credential if written whole.
fn api_key() -> String {
    ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_")
}

fn values() -> Vec<String> {
    let mut out: Vec<String> = VALUES.iter().map(|v| v.to_string()).collect();
    out.push(api_key());
    out.push(format!("0x{}", "ab".repeat(20)));
    out
}

/// A label at the end of one entry and a value at the start of the next, with edges.
fn boundary_entries() -> Vec<String> {
    let mut entries = Vec::new();
    for label in LABELS {
        for value in values() {
            for edge in ["", " ", "\n"] {
                entries.push(format!("see {label}{edge}"));
                entries.push(format!("{value} done"));
                entries.push(value.clone());
                entries.push(format!("{edge}{label} {value}"));
            }
        }
    }
    entries
}

fn edge_entries() -> Vec<String> {
    let mut entries = Vec::new();
    for value in values() {
        for before in EDGES {
            for after in EDGES {
                entries.push(format!("{before}{value}{after}"));
            }
        }
    }
    entries
}

fn expect_same(engine: &AnonymaEngine, texts: &[String]) {
    let batch = engine.detect_batch(texts);
    assert_eq!(batch.len(), texts.len());
    for (text, found) in texts.iter().zip(&batch) {
        assert_eq!(found, &engine.detect(text), "{text:?}");
    }
}

fn engines() -> Vec<(&'static str, AnonymaEngine)> {
    vec![
        ("default", AnonymaEngine::builder().build().unwrap()),
        (
            "aggressive",
            AnonymaEngine::builder().aggressive(true).build().unwrap(),
        ),
        (
            "strict",
            AnonymaEngine::builder().strict(true).build().unwrap(),
        ),
        (
            "a few categories",
            AnonymaEngine::builder()
                .categories([Category::Email, Category::Phone, Category::CreditCard])
                .build()
                .unwrap(),
        ),
    ]
}

#[test]
fn matches_detect_when_a_label_ends_one_entry_and_a_value_starts_the_next() {
    let entries = boundary_entries();
    for (_, engine) in engines() {
        expect_same(&engine, &entries);
    }
}

#[test]
fn matches_detect_for_values_at_the_edges_of_entries() {
    let entries = edge_entries();
    for (_, engine) in engines() {
        expect_same(&engine, &entries);
    }
}

#[test]
fn scans_an_entry_that_starts_with_a_greeting_alone() {
    let engine = AnonymaEngine::builder().build().unwrap();
    let texts: Vec<String> = ["Thanks.", "Dear Ana Example, welcome", "Hello Bea Example"]
        .map(String::from)
        .to_vec();
    let batch = engine.detect_batch(&texts);
    assert!(batch[1].iter().any(|m| m.value == "Ana Example"));
    assert!(batch[2].iter().any(|m| m.value == "Bea Example"));
    expect_same(&engine, &texts);
}

#[test]
fn scans_alone_the_entries_it_cannot_fuse() {
    let engine = AnonymaEngine::builder().build().unwrap();
    let long = format!("{}ana@example.com", "word ".repeat(2000));
    let texts = vec![
        "a ana@example.com".to_string(),
        long,
        "b\0ana@example.com".to_string(),
        "c 192.0.2.1".to_string(),
        String::new(),
    ];
    expect_same(&engine, &texts);
    expect_same(&engine, &texts[..1]);
}

#[test]
fn splits_a_batch_larger_than_one_fused_text() {
    let engine = AnonymaEngine::builder().build().unwrap();
    let texts: Vec<String> = (0..2000)
        .map(|i| format!("row {i}: user{i}@example.com"))
        .collect();
    expect_same(&engine, &texts);
}

#[test]
fn scans_entry_by_entry_with_a_detector_of_its_own() {
    struct FirstByte;
    impl Detector for FirstByte {
        fn category(&self) -> Category {
            Category::Email
        }
        fn detect(&self, text: &str) -> Vec<Match> {
            if text.is_empty() {
                return Vec::new();
            }
            vec![Match {
                category: Category::Email,
                value: text[..1].to_string(),
                start: 0,
                end: 1,
                confidence: 1.0,
            }]
        }
    }
    let engine = AnonymaEngine::builder()
        .categories([Category::Email])
        .detector(Arc::new(FirstByte))
        .build()
        .unwrap();
    let texts = vec!["ab".to_string(), "cd".to_string()];
    let batch = engine.detect_batch(&texts);
    assert_eq!(batch[1][0].value, "c");
    expect_same(&engine, &texts);
}

#[test]
fn anonymizes_a_batch_as_anonymize_does() {
    let engine = AnonymaEngine::builder().build().unwrap();
    let texts: Vec<String> = boundary_entries().into_iter().take(1500).collect();
    for (text, result) in texts.iter().zip(engine.anonymize_batch(&texts)) {
        let one = engine.anonymize(text).unwrap();
        let batch = result.unwrap();
        assert_eq!(batch.text, one.text, "{text:?}");
        assert_eq!(batch.matches, one.matches, "{text:?}");
    }
}
