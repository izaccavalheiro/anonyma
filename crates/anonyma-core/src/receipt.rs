//! Canonical JSON, digests and signed anonymization receipts
//! (`src/audit/canonical.ts`, `src/audit/receipt.ts`).
//!
//! A receipt states what an anonymization replaced (category counts) and
//! fingerprints its output, without any of the data, and is signed with
//! HMAC-SHA-256 so that it cannot be forged without the key.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// A JSON value. Numbers are integers: receipts hold counts only, and the
/// canonical form of other numbers is out of the conformance suite's scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object; member order does not matter.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Json::String(value.to_string())
    }
}

/// Write `text` as `JSON.stringify` writes a string.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(n) => out.push_str(&n.to_string()),
        Json::String(s) => write_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Json::Object(members) => {
            // Sorted by UTF-16 code units, as JavaScript sorts strings.
            let mut sorted: Vec<&(String, Json)> = members.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (key, member)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write(member, out);
            }
            out.push('}');
        }
    }
}

/// The canonical JSON of `value`: object members sorted by name, no white
/// space, strings escaped as `JSON.stringify` escapes them.
pub fn canonicalize(value: &Json) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

/// Lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// SHA-256 of the UTF-8 encoding of `text`, in lower-case hex.
pub fn sha256_hex(text: &str) -> String {
    hex(Sha256::digest(text.as_bytes()).as_slice())
}

/// HMAC-SHA-256 of `text` keyed with `key`, in lower-case hex.
pub fn hmac_sha256_hex(key: &[u8], text: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, text.as_bytes());
    hex(mac.finalize().into_bytes().as_slice())
}

/// Domain separator of receipt signatures.
pub const RECEIPT_DOMAIN: &str = "anonyma/receipt/v1\0";
/// Domain separator of input fingerprints.
pub const INPUT_DOMAIN: &str = "anonyma/receipt/input/v1\0";

/// The signature algorithm of every receipt.
pub const RECEIPT_ALG: &str = "HMAC-SHA-256";

/// A signed receipt of one anonymization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReceipt {
    /// Random identifier, 32 hexadecimal digits.
    pub id: String,
    /// When it was issued, ISO 8601 in UTC with milliseconds.
    pub timestamp: String,
    /// The implementation that issued it (`anonyma-core@0.1.0`).
    pub library: String,
    /// The presets applied.
    pub presets: Option<Vec<String>>,
    /// How many values of each category were replaced, sorted by category.
    pub stats: Vec<(String, u64)>,
    /// The sum of `stats`.
    pub total: u64,
    /// SHA-256 of the anonymized text.
    pub output: String,
    /// Keyed fingerprint of the original text, when asked for.
    pub input: Option<String>,
    /// Identifier of the signing key.
    pub key_id: Option<String>,
    /// HMAC-SHA-256 of the domain and the canonical body.
    pub signature: String,
}

impl AuditReceipt {
    /// The receipt without its signature, as JSON: what is signed.
    pub fn body(&self) -> Json {
        let mut members = vec![
            ("v".to_string(), Json::Int(1)),
            ("id".to_string(), Json::from(self.id.as_str())),
            ("timestamp".to_string(), Json::from(self.timestamp.as_str())),
            ("library".to_string(), Json::from(self.library.as_str())),
        ];
        if let Some(presets) = &self.presets {
            members.push((
                "presets".to_string(),
                Json::Array(presets.iter().map(|p| Json::from(p.as_str())).collect()),
            ));
        }
        members.push((
            "stats".to_string(),
            Json::Object(
                self.stats
                    .iter()
                    .map(|(category, count)| (category.clone(), Json::Int(*count as i64)))
                    .collect(),
            ),
        ));
        members.push(("total".to_string(), Json::Int(self.total as i64)));
        members.push(("output".to_string(), Json::from(self.output.as_str())));
        if let Some(input) = &self.input {
            members.push(("input".to_string(), Json::from(input.as_str())));
        }
        members.push(("alg".to_string(), Json::from(RECEIPT_ALG)));
        if let Some(key_id) = &self.key_id {
            members.push(("keyId".to_string(), Json::from(key_id.as_str())));
        }
        Json::Object(members)
    }

    /// The whole receipt as JSON.
    pub fn to_json(&self) -> Json {
        let Json::Object(mut members) = self.body() else {
            unreachable!("a receipt body is an object")
        };
        members.push(("signature".to_string(), Json::from(self.signature.as_str())));
        Json::Object(members)
    }
}

/// Why a receipt does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// It does not have the members of a receipt.
    Malformed,
    /// The signature does not match: altered, or another key.
    Signature,
    /// The text given is not the one the receipt fingerprints.
    Output,
    /// The original text given is not the one the receipt fingerprints.
    Input,
}

impl Invalid {
    /// The reason, as the reference spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Invalid::Malformed => "malformed",
            Invalid::Signature => "signature",
            Invalid::Output => "output",
            Invalid::Input => "input",
        }
    }
}

/// Issues and verifies receipts with one key.
#[derive(Clone)]
pub struct ReceiptIssuer {
    key: Vec<u8>,
    key_id: Option<String>,
    presets: Option<Vec<String>>,
    library: String,
}

impl std::fmt::Debug for ReceiptIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("ReceiptIssuer")
            .field("key_id", &self.key_id)
            .field("presets", &self.presets)
            .finish_non_exhaustive()
    }
}

/// What to put in a receipt.
#[derive(Debug, Clone, Default)]
pub struct IssueOptions<'a> {
    /// Fingerprint this original text too (keyed, so it cannot be guessed).
    pub input: Option<&'a str>,
    /// Issue at this time, in milliseconds since 1970 (now when `None`).
    pub timestamp_ms: Option<i64>,
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Constant-time comparison of two strings of equal length.
fn same_text(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

impl ReceiptIssuer {
    /// An issuer signing with `key` (its UTF-8 bytes are the HMAC key).
    pub fn new(key: &str) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::validation("key", "must be a non-empty string"));
        }
        Ok(ReceiptIssuer {
            key: key.as_bytes().to_vec(),
            key_id: None,
            presets: None,
            library: format!("anonyma-core@{}", crate::VERSION),
        })
    }

    /// Name the key in every receipt, for rotation.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Record the presets applied in every receipt.
    pub fn with_presets<I: IntoIterator<Item = S>, S: Into<String>>(mut self, presets: I) -> Self {
        self.presets = Some(presets.into_iter().map(Into::into).collect());
        self
    }

    /// Record another implementation name (`anonyma-python@0.1.0`).
    pub fn with_library(mut self, library: impl Into<String>) -> Self {
        self.library = library.into();
        self
    }

    /// The signature of a receipt body.
    pub fn sign(&self, body: &Json) -> String {
        hmac_sha256_hex(
            &self.key,
            &format!("{RECEIPT_DOMAIN}{}", canonicalize(body)),
        )
    }

    fn input_digest(&self, text: &str) -> String {
        hmac_sha256_hex(&self.key, &format!("{INPUT_DOMAIN}{text}"))
    }

    /// A receipt for `output`, the anonymized text, and the number of values
    /// replaced in each category. Category labels must be lower-case names
    /// (letters, digits, hyphens): a label is never a value.
    pub fn issue(
        &self,
        output: &str,
        counts: &[(String, u64)],
        options: IssueOptions<'_>,
    ) -> Result<AuditReceipt> {
        let mut stats: Vec<(String, u64)> = Vec::new();
        let mut total = 0u64;
        for (label, count) in counts {
            if !is_label(label) {
                return Err(Error::validation(
                    "counts",
                    "labels must be category names: lower-case letters, digits and hyphens",
                ));
            }
            match stats.iter_mut().find(|(l, _)| l == label) {
                Some((_, sum)) => *sum += count,
                None => stats.push((label.clone(), *count)),
            }
            total += count;
        }
        stats.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));

        let mut id = [0u8; 16];
        getrandom::fill(&mut id)
            .map_err(|error| Error::Unsupported(format!("no random source: {error}")))?;
        let timestamp_ms = match options.timestamp_ms {
            Some(ms) => ms,
            None => now_ms()?,
        };
        let mut receipt = AuditReceipt {
            id: hex(&id),
            timestamp: iso8601(timestamp_ms),
            library: self.library.clone(),
            presets: self.presets.clone(),
            stats,
            total,
            output: sha256_hex(output),
            input: options.input.map(|text| self.input_digest(text)),
            key_id: self.key_id.clone(),
            signature: String::new(),
        };
        receipt.signature = self.sign(&receipt.body());
        Ok(receipt)
    }

    /// Verify a receipt given as JSON; optionally check that it fingerprints
    /// `output` (the anonymized text) and `input` (the original).
    pub fn verify(
        &self,
        receipt: &Json,
        output: Option<&str>,
        input: Option<&str>,
    ) -> std::result::Result<(), Invalid> {
        let Json::Object(members) = receipt else {
            return Err(Invalid::Malformed);
        };
        if !is_receipt(receipt) {
            return Err(Invalid::Malformed);
        }
        let signature = receipt
            .get("signature")
            .and_then(Json::as_str)
            .unwrap_or_default();
        let body = Json::Object(
            members
                .iter()
                .filter(|(key, _)| key != "signature")
                .cloned()
                .collect(),
        );
        if !same_text(&self.sign(&body), signature) {
            return Err(Invalid::Signature);
        }
        if let Some(text) = output {
            if receipt.get("output").and_then(Json::as_str) != Some(sha256_hex(text).as_str()) {
                return Err(Invalid::Output);
            }
        }
        if let Some(text) = input {
            match receipt.get("input").and_then(Json::as_str) {
                Some(digest) if same_text(&self.input_digest(text), digest) => {}
                _ => return Err(Invalid::Input),
            }
        }
        Ok(())
    }
}

/// Whether `value` has the members of a receipt, as the reference checks them.
fn is_receipt(value: &Json) -> bool {
    let string = |key: &str| matches!(value.get(key), Some(Json::String(_)));
    let optional = |key: &str, check: &dyn Fn(&Json) -> bool| match value.get(key) {
        None => true,
        Some(member) => check(member),
    };
    matches!(value.get("v"), Some(Json::Int(1)))
        && string("id")
        && string("timestamp")
        && string("library")
        && optional(
            "presets",
            &|p| matches!(p, Json::Array(items) if items.iter().all(|i| matches!(i, Json::String(_)))),
        )
        && optional("policy", &|p| matches!(p.get("id"), Some(Json::String(_))))
        && matches!(value.get("stats"), Some(Json::Object(members)) if members.iter().all(|(_, c)| matches!(c, Json::Int(_))))
        && matches!(value.get("total"), Some(Json::Int(_)))
        && value
            .get("output")
            .and_then(Json::as_str)
            .is_some_and(is_hex64)
        && optional("input", &|i| i.as_str().is_some_and(is_hex64))
        && value.get("alg").and_then(Json::as_str) == Some(RECEIPT_ALG)
        && optional("keyId", &|k| matches!(k, Json::String(_)))
        && string("signature")
}

fn now_ms() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .map_err(|_| Error::Unsupported("the clock is before 1970".to_string()))
}

/// `Date.prototype.toISOString()`: `2026-01-01T00:00:00.000Z`.
pub fn iso8601(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let in_day = ms.rem_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        in_day / 3_600_000,
        in_day / 60_000 % 60,
        in_day / 1_000 % 60,
        in_day % 1_000
    )
}

/// Milliseconds since 1970 of an ISO 8601 UTC timestamp of the form
/// `toISOString()` writes (`2026-01-01T00:00:00.000Z`).
pub fn parse_iso8601(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> { text.get(range)?.parse().ok() };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second, milli) = (
        number(11..13)?,
        number(14..16)?,
        number(17..19)?,
        number(20..23)?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1_000 + milli)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(members: &[(&str, Json)]) -> Json {
        Json::Object(
            members
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn canonical_json_sorts_by_utf16_and_escapes_like_javascript() {
        let value = object(&[
            ("b", Json::Int(1)),
            (
                "a",
                Json::Array(vec![Json::Bool(true), Json::Null, Json::from("x")]),
            ),
            (
                "c",
                object(&[("z", Json::from("é\n\u{1}\"\\")), ("y", Json::Int(0))]),
            ),
        ]);
        assert_eq!(
            canonicalize(&value),
            r#"{"a":[true,null,"x"],"b":1,"c":{"y":0,"z":"é\n\u0001\"\\"}}"#
        );
        let astral = object(&[("\u{FB01}", Json::Int(2)), ("\u{1F600}", Json::Int(1))]);
        assert_eq!(canonicalize(&astral), "{\"\u{1F600}\":1,\"\u{FB01}\":2}");
    }

    #[test]
    fn digests() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn timestamps_round_trip() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        let ms = parse_iso8601("2026-01-01T00:00:00.000Z").unwrap();
        assert_eq!(iso8601(ms), "2026-01-01T00:00:00.000Z");
        assert_eq!(iso8601(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert!(parse_iso8601("2026-13-01T00:00:00.000Z").is_none());
    }

    #[test]
    fn issued_receipts_verify_and_detect_tampering() {
        let issuer = ReceiptIssuer::new("k").unwrap().with_presets(["lgpd"]);
        let counts = vec![("national-id".to_string(), 2), ("email".to_string(), 1)];
        let receipt = issuer
            .issue(
                "out",
                &counts,
                IssueOptions {
                    input: Some("in"),
                    timestamp_ms: Some(0),
                },
            )
            .unwrap();
        assert_eq!(receipt.stats[0].0, "email");
        assert_eq!(receipt.total, 3);
        let json = receipt.to_json();
        assert_eq!(issuer.verify(&json, Some("out"), Some("in")), Ok(()));
        assert_eq!(
            issuer.verify(&json, Some("other"), None),
            Err(Invalid::Output)
        );
        assert_eq!(
            issuer.verify(&json, None, Some("other")),
            Err(Invalid::Input)
        );
        let other = ReceiptIssuer::new("another").unwrap();
        assert_eq!(other.verify(&json, None, None), Err(Invalid::Signature));
        assert_eq!(
            issuer.verify(&Json::Null, None, None),
            Err(Invalid::Malformed)
        );
        assert!(issuer
            .issue(
                "out",
                &[("Ana Silva".to_string(), 1)],
                IssueOptions::default()
            )
            .is_err());
    }
}
