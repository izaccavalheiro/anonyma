//! The JSON API of `anonyma-core`: one function, [`call`], that takes an
//! operation name and a JSON input and returns a JSON result.
//!
//! It is the boundary of the bindings that cannot share Rust types: the C ABI
//! (Go, and any language with a C FFI), WebAssembly and Node.js. The
//! operations and their inputs are those of the conformance suite
//! (`packages/conformance/README.md`), so the suite tests this layer, and the
//! core beneath it, directly.
//!
//! Serializing every call costs a copy of the text into and out of JSON:
//! microseconds for a prompt, and noticeable only for megabytes. The Python
//! binding avoids it on its hot paths (detect, anonymize, shield, restore) by
//! passing native strings.

use anonyma_core::offsets::OffsetMap;
use anonyma_core::receipt::parse_iso8601;
use anonyma_core::{
    canonicalize, capabilities, combine_presets, detokenize, restore, sha256_hex, validators,
    AnonymaEngine, Category, InMemoryVault, IssueOptions, Json, Preset, ReceiptIssuer,
    StrategySpec, Validator,
};
use serde_json::{json, Map, Value};

/// An error of the JSON API: a message for the caller.
pub type ApiError = String;

fn text<'a>(input: &'a Value, key: &str) -> Result<&'a str, ApiError> {
    input[key]
        .as_str()
        .ok_or_else(|| format!("input.{key} must be a string"))
}

fn strings(input: &Value, key: &str) -> Result<Vec<String>, ApiError> {
    input[key]
        .as_array()
        .ok_or_else(|| format!("input.{key} must be a list"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or_else(|| format!("input.{key} must hold strings"))
        })
        .collect()
}

fn categories(input: &Value) -> Result<Vec<Category>, ApiError> {
    strings(input, "categories")?
        .iter()
        .map(|name| name.parse::<Category>().map_err(|e| e.to_string()))
        .collect()
}

fn pairs(input: &Value, key: &str) -> Result<Vec<(String, String)>, ApiError> {
    if input[key].is_null() {
        return Ok(Vec::new());
    }
    input[key]
        .as_array()
        .ok_or_else(|| format!("input.{key} must be a list"))?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(a), Value::String(b)]) => Ok((a.clone(), b.clone())),
            _ => Err(format!("input.{key} must hold pairs of strings")),
        })
        .collect()
}

/// A JSON value as the core's [`Json`]. Numbers must be integers; an
/// integral float (`1.0`) counts as one, as in JavaScript.
pub fn to_json(value: &Value) -> Result<Json, ApiError> {
    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => Json::Int(i),
            (None, Some(f)) if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => {
                Json::Int(f as i64)
            }
            _ => return Err("only integers have a canonical form here".into()),
        },
        Value::String(s) => Json::String(s.clone()),
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect::<Result<_, _>>()?),
        Value::Object(members) => Json::Object(
            members
                .iter()
                .map(|(k, v)| Ok((k.clone(), to_json(v)?)))
                .collect::<Result<_, ApiError>>()?,
        ),
    })
}

/// The core's [`Json`] as a JSON value.
pub fn from_json(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => json!(n),
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(from_json).collect()),
        Json::Object(members) => Value::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), from_json(v)))
                .collect::<Map<_, _>>(),
        ),
    }
}

/// A strategy as the reference spells it: `{ "strategy": "mask", "keepTrailing": 4 }`.
pub fn strategy_from(value: &Value) -> Result<StrategySpec, ApiError> {
    let get_str = |key: &str| value.get(key).and_then(Value::as_str).map(String::from);
    let get_usize = |key: &str| value.get(key).and_then(Value::as_u64).map(|n| n as usize);
    match value.get("strategy").and_then(Value::as_str) {
        Some("redact") => Ok(StrategySpec::Redact {
            label: get_str("label"),
        }),
        Some("mask") => Ok(StrategySpec::Mask {
            mask_char: get_str("maskChar"),
            keep_leading: get_usize("keepLeading"),
            keep_trailing: get_usize("keepTrailing"),
            preserve_format: value.get("preserveFormat").and_then(Value::as_bool),
        }),
        Some("pseudonymize") => Ok(StrategySpec::Pseudonymize {
            seed: get_str("seed"),
            prefix: get_str("prefix"),
        }),
        Some(other) => Err(anonyma_core::Error::UnsupportedStrategy(other.to_string()).to_string()),
        None => Err("a strategy needs a \"strategy\" member".into()),
    }
}

/// A strategy in the reference's JSON form.
pub fn strategy_to(spec: &StrategySpec) -> Value {
    let mut out = Map::new();
    out.insert("strategy".into(), json!(spec.name()));
    let mut put = |key: &str, value: Value| {
        out.insert(key.into(), value);
    };
    match spec {
        StrategySpec::Redact { label } => {
            if let Some(label) = label {
                put("label", json!(label));
            }
        }
        StrategySpec::Mask {
            mask_char,
            keep_leading,
            keep_trailing,
            preserve_format,
        } => {
            if let Some(c) = mask_char {
                put("maskChar", json!(c));
            }
            if let Some(n) = keep_leading {
                put("keepLeading", json!(n));
            }
            if let Some(n) = keep_trailing {
                put("keepTrailing", json!(n));
            }
            if let Some(b) = preserve_format {
                put("preserveFormat", json!(b));
            }
        }
        StrategySpec::Pseudonymize { seed, prefix } => {
            if let Some(seed) = seed {
                put("seed", json!(seed));
            }
            if let Some(prefix) = prefix {
                put("prefix", json!(prefix));
            }
        }
    }
    Value::Object(out)
}

/// The engine an input describes: `categories`, `preset` (names), `rules`
/// (`[{ category, strategy }]`), `defaultStrategy`, `aggressive`, `strict`,
/// `allowPartial`.
pub fn engine(input: &Value) -> Result<AnonymaEngine, ApiError> {
    let mut builder = AnonymaEngine::builder()
        .aggressive(input["aggressive"].as_bool().unwrap_or(false))
        .strict(input["strict"].as_bool().unwrap_or(false))
        .allow_partial(input["allowPartial"].as_bool().unwrap_or(false));
    if !input["categories"].is_null() {
        builder = builder.categories(categories(input)?);
    }
    if !input["preset"].is_null() {
        for name in strings(input, "preset")? {
            builder = builder.preset(name.parse::<Preset>().map_err(|e| e.to_string())?);
        }
    }
    if let Some(rules) = input["rules"].as_array() {
        for rule in rules {
            let category = rule["category"]
                .as_str()
                .ok_or("rules[].category must be a string")?
                .parse::<Category>()
                .map_err(|e| e.to_string())?;
            builder = builder.rule(category, strategy_from(&rule["strategy"])?);
        }
    }
    if !input["defaultStrategy"].is_null() {
        builder = builder.default_strategy(strategy_from(&input["defaultStrategy"])?);
    }
    builder.build().map_err(|e| e.to_string())
}

/// The unit of offsets an input asks for: `code-points` (default), `utf-16` or `bytes`.
fn offset_of<'t>(input: &Value, text: &'t str) -> Result<impl Fn(usize) -> usize + 't, ApiError> {
    let unit = input["offsets"]
        .as_str()
        .unwrap_or("code-points")
        .to_string();
    if !matches!(unit.as_str(), "code-points" | "utf-16" | "bytes") {
        return Err(format!("unknown offsets unit \"{unit}\""));
    }
    let map = OffsetMap::new(text);
    Ok(move |byte: usize| match unit.as_str() {
        "utf-16" => map.utf16(byte),
        "bytes" => byte,
        _ => map.code_points(byte),
    })
}

/// Perform `op` on `input`, with `vault` for `shield` and `restore`: the
/// vault handle of a binding, or one built from `input.vault` when `None`.
pub fn call_with_vault(
    op: &str,
    input: &Value,
    vault: Option<&mut InMemoryVault>,
) -> Result<Value, ApiError> {
    match op {
        "shield" | "restore" => {
            let mut local;
            let vault = match vault {
                Some(vault) => vault,
                None => {
                    local = InMemoryVault::from_entries(pairs(input, "vault")?)
                        .map_err(|e| e.to_string())?;
                    &mut local
                }
            };
            if op == "shield" {
                let source = text(input, "text")?;
                let out = engine(&with_partial(input))?
                    .shield(source, vault)
                    .map_err(|e| e.to_string())?;
                let tokens: Vec<Value> = out
                    .tokens
                    .iter()
                    .map(|(token, category)| json!({ "token": token, "category": category.as_str() }))
                    .collect();
                Ok(json!({ "text": out.text, "tokens": tokens, "vault": vault.entries() }))
            } else {
                let out = restore(text(input, "text")?, vault);
                Ok(
                    json!({ "text": out.text, "restored": out.restored, "unresolved": out.unresolved }),
                )
            }
        }
        _ => call(op, input),
    }
}

/// `allowPartial` defaults to true where the conformance suite selects
/// categories explicitly (detect, tokenize, shield): those calls name the
/// categories they want, and get exactly the detectors that exist for them.
fn with_partial(input: &Value) -> Value {
    let mut input = input.clone();
    if input["allowPartial"].is_null() && !input["categories"].is_null() {
        input["allowPartial"] = Value::Bool(true);
    }
    input
}

/// Perform the operation `op` on `input`. The operations are those of the
/// conformance suite, plus `capabilities` and `validators`.
pub fn call(op: &str, input: &Value) -> Result<Value, ApiError> {
    match op {
        "capabilities" => Ok(json!({
            "version": anonyma_core::VERSION,
            "suite": anonyma_core::CONFORMANCE_SUITE,
            "capabilities": capabilities(),
        })),
        "validators" => Ok(json!({
            "validators": validators::CHECKSUMS.iter().map(|v| v.name()).collect::<Vec<_>>(),
        })),
        "validate" => {
            let name = text(input, "validator")?;
            let validator = validators::by_name(name)
                .ok_or_else(|| anonyma_core::Error::UnknownValidator(name.into()).to_string())?;
            Ok(json!({ "valid": validator.validate(text(input, "value")?) }))
        }
        "detect" => {
            let source = text(input, "text")?;
            let offset = offset_of(input, source)?;
            let matches: Vec<Value> = engine(&with_partial(input))?
                .detect(source)
                .into_iter()
                .map(|m| {
                    json!({
                        "category": m.category.as_str(),
                        "value": m.value,
                        "start": offset(m.start),
                        "end": offset(m.end),
                        "confidence": m.confidence,
                    })
                })
                .collect();
            Ok(json!({ "matches": matches }))
        }
        "tokenize" => {
            let out = engine(&with_partial(input))?.tokenize(text(input, "text")?);
            Ok(json!({ "text": out.text, "mapping": out.mapping }))
        }
        "detokenize" => {
            let out = detokenize(text(input, "text")?, &pairs(input, "mapping")?);
            Ok(json!({
                "text": out.text,
                "replacedCount": out.restored,
                "unresolved": out.unresolved,
            }))
        }
        "shield" | "restore" => call_with_vault(op, input, None),
        "anonymize" => {
            let out = engine(input)?
                .anonymize(text(input, "text")?)
                .map_err(|e| e.to_string())?;
            let counts: Map<String, Value> = out
                .counts()
                .into_iter()
                .map(|(category, n)| (category, json!(n)))
                .collect();
            Ok(json!({ "text": out.text, "counts": counts }))
        }
        "preset" => {
            let names = strings(input, "names")?
                .iter()
                .map(|n| n.parse::<Preset>().map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let combined = combine_presets(&names).map_err(|e| e.to_string())?;
            let rules: Vec<Value> = combined
                .rules
                .iter()
                .map(|(c, s)| json!({ "category": c.as_str(), "strategy": strategy_to(s) }))
                .collect();
            let categories: Vec<&str> = combined.categories.iter().map(|c| c.as_str()).collect();
            Ok(json!({
                "categories": categories,
                "defaultStrategy": strategy_to(&combined.default_strategy),
                "rules": rules,
            }))
        }
        "canonicalize" => Ok(json!({ "text": canonicalize(&to_json(&input["value"])?) })),
        "digest" => Ok(json!({ "hex": sha256_hex(text(input, "text")?) })),
        "receipt.sign" => {
            let issuer = ReceiptIssuer::new(text(input, "key")?).map_err(|e| e.to_string())?;
            Ok(json!({ "signature": issuer.sign(&to_json(&input["body"])?) }))
        }
        "receipt.verify" => {
            let issuer = ReceiptIssuer::new(text(input, "key")?).map_err(|e| e.to_string())?;
            let output = input["output"].as_str();
            let original = input["input"].as_str();
            Ok(
                match issuer.verify(&to_json(&input["receipt"])?, output, original) {
                    Ok(()) => json!({ "valid": true }),
                    Err(reason) => json!({ "valid": false, "reason": reason.as_str() }),
                },
            )
        }
        "receipt.issue" => {
            let mut issuer = ReceiptIssuer::new(text(input, "key")?).map_err(|e| e.to_string())?;
            if !input["presets"].is_null() {
                issuer = issuer.with_presets(strings(input, "presets")?);
            }
            if let Some(key_id) = input["keyId"].as_str() {
                issuer = issuer.with_key_id(key_id);
            }
            if let Some(library) = input["library"].as_str() {
                issuer = issuer.with_library(library);
            }
            let counts: Vec<(String, u64)> = input["counts"]
                .as_object()
                .ok_or("input.counts must be an object")?
                .iter()
                .map(|(k, v)| {
                    v.as_u64()
                        .map(|n| (k.clone(), n))
                        .ok_or_else(|| format!("input.counts.{k} must be a non-negative integer"))
                })
                .collect::<Result<_, ApiError>>()?;
            let timestamp_ms = match input["timestamp"].as_str() {
                Some(stamp) => Some(
                    parse_iso8601(stamp).ok_or("input.timestamp must be an ISO 8601 UTC time")?,
                ),
                None => None,
            };
            let options = IssueOptions {
                input: input["input"].as_str(),
                timestamp_ms,
            };
            let receipt = issuer
                .issue(text(input, "text")?, &counts, options)
                .map_err(|e| e.to_string())?;
            let as_json = receipt.to_json();
            let verified = issuer.verify(&as_json, None, None).is_ok();
            Ok(json!({ "receipt": from_json(&as_json), "verified": verified }))
        }
        other => Err(format!("unknown operation \"{other}\"")),
    }
}

/// [`call`] with JSON text in and out: `{"ok": result}` or `{"error": message}`.
pub fn call_json(op: &str, input: &str) -> String {
    call_json_with_vault(op, input, None)
}

/// [`call_with_vault`] with JSON text in and out.
pub fn call_json_with_vault(op: &str, input: &str, vault: Option<&mut InMemoryVault>) -> String {
    let outcome = serde_json::from_str::<Value>(input)
        .map_err(|e| format!("input is not JSON: {e}"))
        .and_then(|input| call_with_vault(op, &input, vault));
    match outcome {
        Ok(value) => json!({ "ok": value }).to_string(),
        Err(message) => json!({ "error": message }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_reported_not_thrown() {
        assert!(call_json("nope", "{}").contains("unknown operation"));
        assert!(call_json("digest", "not json").contains("not JSON"));
        let out: Value = serde_json::from_str(&call_json("digest", r#"{"text":""}"#)).unwrap();
        assert_eq!(
            out["ok"]["hex"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn offsets_in_the_unit_asked_for() {
        let input = |unit: &str| json!({ "text": "\u{1F4E7} a@example.com", "categories": ["email"], "offsets": unit });
        let start =
            |unit: &str| call("detect", &input(unit)).unwrap()["matches"][0]["start"].clone();
        assert_eq!(start("code-points"), 2);
        assert_eq!(start("utf-16"), 3);
        assert_eq!(start("bytes"), 5);
        assert!(call("detect", &input("words")).is_err());
    }

    #[test]
    fn a_vault_handle_persists_between_calls() {
        let mut vault = InMemoryVault::new();
        let shield = json!({ "text": "Mail ann@example.com", "categories": ["email"] });
        let out = call_with_vault("shield", &shield, Some(&mut vault)).unwrap();
        assert_eq!(out["text"], "Mail {{EMAIL_1}}");
        let restored = call_with_vault(
            "restore",
            &json!({ "text": "{{EMAIL_1}}" }),
            Some(&mut vault),
        )
        .unwrap();
        assert_eq!(restored["text"], "ann@example.com");
    }

    #[test]
    fn unknown_presets_are_errors() {
        let error = call("anonymize", &json!({ "text": "x", "preset": ["nope"] })).unwrap_err();
        assert!(error.contains("unknown compliance preset"));
    }
}
