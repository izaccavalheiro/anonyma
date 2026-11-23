//! Runs the language-neutral conformance suite (`packages/conformance`)
//! against `anonyma-core`, through the JSON API every non-Rust binding uses:
//! every case whose capabilities the core declares must pass; the others are
//! listed as skipped.

use std::collections::HashSet;
use std::path::PathBuf;

use anonyma_ffi::api::call;
use serde_json::{json, Value};

fn suite() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/conformance/conformance-tests.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the suite is JSON")
}

fn capabilities() -> HashSet<String> {
    call("capabilities", &json!({})).expect("capabilities")["capabilities"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|c| c.as_str().map(String::from))
        .collect()
}

fn sorted(value: &Value) -> Value {
    let mut items = value.as_array().cloned().unwrap_or_default();
    items.sort_by_key(|item| item.to_string());
    Value::Array(items)
}

fn compare(op: &str, expected: &Value, actual: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    match op {
        "detect" => {
            let want = expected["matches"].as_array().cloned().unwrap_or_default();
            let got = actual["matches"].as_array().cloned().unwrap_or_default();
            if want.len() != got.len() {
                problems.push(format!(
                    "expected {} matches, got {}: {}",
                    want.len(),
                    got.len(),
                    actual["matches"]
                ));
                return problems;
            }
            for (i, (w, g)) in want.iter().zip(&got).enumerate() {
                for key in ["category", "value", "start", "end"] {
                    if w[key] != g[key] {
                        problems.push(format!(
                            "match {i} {key}: expected {}, got {}",
                            w[key], g[key]
                        ));
                    }
                }
                let (wc, gc) = (
                    w["confidence"].as_f64().unwrap_or(-1.0),
                    g["confidence"].as_f64().unwrap_or(-2.0),
                );
                if (wc - gc).abs() > 1e-9 {
                    problems.push(format!("match {i} confidence: expected {wc}, got {gc}"));
                }
            }
        }
        "anonymize" if expected.get("textPattern").is_some() => {
            let pattern =
                regex::Regex::new(expected["textPattern"].as_str().unwrap_or_default()).unwrap();
            if !pattern.is_match(actual["text"].as_str().unwrap_or_default()) {
                problems.push(format!(
                    "text {} does not match {}",
                    actual["text"], expected["textPattern"]
                ));
            }
        }
        "receipt.issue" => {
            for (key, value) in expected["receipt"].as_object().into_iter().flatten() {
                if &actual["receipt"][key] != value {
                    problems.push(format!(
                        "receipt.{key}: expected {value}, got {}",
                        actual["receipt"][key]
                    ));
                }
            }
            if actual["verified"] != json!(true) {
                problems.push("the issued receipt does not verify".into());
            }
        }
        _ => {
            for (key, value) in expected.as_object().into_iter().flatten() {
                let (want, got) = if key == "mapping" || key == "vault" {
                    (sorted(value), sorted(&actual[key]))
                } else {
                    (value.clone(), actual[key].clone())
                };
                if want != got {
                    problems.push(format!("{key}: expected {want}, got {got}"));
                }
            }
        }
    }
    problems
}

#[test]
fn conformance_suite() {
    let suite = suite();
    let provided = capabilities();
    let cases = suite["cases"].as_array().expect("cases");
    let (mut passed, mut skipped, mut failures) = (0, Vec::new(), Vec::new());

    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let requires: Vec<&str> = case["requires"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let missing: Vec<&str> = requires
            .iter()
            .copied()
            .filter(|c| !provided.contains(*c))
            .collect();
        if !missing.is_empty() {
            skipped.push(format!("{id} (needs {})", missing.join(", ")));
            continue;
        }
        let op = case["op"].as_str().unwrap_or_default();
        match call(op, &case["input"]) {
            Ok(actual) => {
                let problems = compare(op, &case["expected"], &actual);
                if problems.is_empty() {
                    passed += 1;
                } else {
                    failures.push(format!("{id}:\n    {}", problems.join("\n    ")));
                }
            }
            Err(error) => failures.push(format!("{id}: {error}")),
        }
    }

    println!(
        "conformance {}: {passed} passed, {} skipped, {} failed",
        suite["version"],
        skipped.len(),
        failures.len()
    );
    for case in &skipped {
        println!("  skipped {case}");
    }
    assert!(
        failures.is_empty(),
        "failed cases:\n{}",
        failures.join("\n")
    );
    // Guard against a suite that silently stops running: most cases need what the crate provides.
    assert!(passed >= 90, "only {passed} cases ran");
}
