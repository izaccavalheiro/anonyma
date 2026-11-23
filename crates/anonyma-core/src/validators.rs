//! Checksum validators, under the names of the reference's `CHECKSUMS`.
//!
//! Each one is a port of the function of `src/validators.ts` with the same
//! name, and is conformance-tested against it (`validate:<name>`).

/// A check that a value is well formed, typically by its check digits.
pub trait Validator: Send + Sync {
    /// The name of the validator (`luhn`, `cpf`, `iban`, ...).
    fn name(&self) -> &str;
    /// Whether `value` passes.
    fn validate(&self, value: &str) -> bool;
}

/// A validator backed by a function.
#[derive(Clone, Copy)]
pub struct FnValidator {
    name: &'static str,
    check: fn(&str) -> bool,
}

impl Validator for FnValidator {
    fn name(&self) -> &str {
        self.name
    }

    fn validate(&self, value: &str) -> bool {
        (self.check)(value)
    }
}

/// The validators this crate provides.
pub const CHECKSUMS: &[FnValidator] = &[
    FnValidator {
        name: "luhn",
        check: luhn,
    },
    FnValidator {
        name: "verhoeff",
        check: verhoeff,
    },
    FnValidator {
        name: "iban",
        check: iban_mod97,
    },
    FnValidator {
        name: "cpf",
        check: cpf,
    },
    FnValidator {
        name: "cnpj",
        check: cnpj,
    },
    FnValidator {
        name: "aba-routing",
        check: aba_routing,
    },
    FnValidator {
        name: "pix",
        check: pix_payload,
    },
    FnValidator {
        name: "nhs",
        check: nhs,
    },
    FnValidator {
        name: "npi",
        check: npi,
    },
    FnValidator {
        name: "imei",
        check: imei,
    },
    FnValidator {
        name: "dea",
        check: dea,
    },
    FnValidator {
        name: "vin",
        check: vin,
    },
    FnValidator {
        name: "nino",
        check: nino,
    },
    FnValidator {
        name: "aadhaar",
        check: aadhaar,
    },
    FnValidator {
        name: "bsn",
        check: bsn,
    },
    FnValidator {
        name: "pt-nif",
        check: pt_nif,
    },
    FnValidator {
        name: "es-dni",
        check: es_dni,
    },
    FnValidator {
        name: "it-fiscal-code",
        check: it_fiscal_code,
    },
    FnValidator {
        name: "fr-nir",
        check: fr_nir,
    },
    FnValidator {
        name: "cn-resident-id",
        check: cn_resident_id,
    },
    FnValidator {
        name: "au-tfn",
        check: au_tfn,
    },
    FnValidator {
        name: "se-personnummer",
        check: se_personnummer,
    },
];

/// The validator called `name`, if this crate provides it.
pub fn by_name(name: &str) -> Option<&'static FnValidator> {
    CHECKSUMS.iter().find(|validator| validator.name == name)
}

/// The white space of ECMAScript's `\s`.
pub(crate) fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn strip(value: &str, remove: impl Fn(char) -> bool) -> String {
    value.chars().filter(|&c| !remove(c)).collect()
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn digits(text: &str) -> Vec<u32> {
    text.bytes().map(|b| u32::from(b - b'0')).collect()
}

/// Whether every character is the same one (`^(.)\1*$`; empty is not).
fn is_repeated(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => chars.all(|c| c == first),
        None => false,
    }
}

/// Luhn (mod 10), after removing white space and hyphens; at least two digits.
pub fn luhn(value: &str) -> bool {
    let stripped = strip(value, |c| is_js_space(c) || c == '-');
    if !all_digits(&stripped) || stripped.len() < 2 {
        return false;
    }
    luhn_digits(&stripped)
}

/// Luhn over a string of ASCII digits.
pub(crate) fn luhn_digits(stripped: &str) -> bool {
    let mut sum: u32 = 0;
    for (i, d) in digits(stripped).into_iter().rev().enumerate() {
        let mut d = d;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff, after removing white space and hyphens.
pub fn verhoeff(value: &str) -> bool {
    let stripped = strip(value, |c| is_js_space(c) || c == '-');
    if !all_digits(&stripped) {
        return false;
    }
    let mut c = 0usize;
    for (i, d) in digits(&stripped).into_iter().rev().enumerate() {
        let p = VERHOEFF_P[i % 8][d as usize];
        c = VERHOEFF_D[c][p as usize] as usize;
    }
    c == 0
}

/// Brazilian CPF: eleven digits, not all equal, two mod-11 check digits.
/// Dots, hyphens and white space are removed first.
pub fn cpf(value: &str) -> bool {
    let stripped = strip(value, |c| c == '.' || c == '-' || is_js_space(c));
    if stripped.len() != 11 || !all_digits(&stripped) || is_repeated(&stripped) {
        return false;
    }
    let d = digits(&stripped);
    let check = |count: usize| -> u32 {
        let sum: u32 = (0..count)
            .map(|i| d[i] * (count as u32 + 1 - i as u32))
            .sum();
        let remainder = (sum * 10) % 11;
        if remainder >= 10 {
            0
        } else {
            remainder
        }
    };
    check(9) == d[9] && check(10) == d[10]
}

/// Brazilian CNPJ, numeric or alphanumeric (from July 2026): twelve digits or
/// upper-case letters and two mod-11 check digits; each character counts as
/// its code minus 48. Dots, slashes, hyphens and white space are removed and
/// letters upper-cased first.
pub fn cnpj(value: &str) -> bool {
    let stripped: String = strip(value, |c| {
        c == '.' || c == '-' || c == '/' || is_js_space(c)
    })
    .to_uppercase();
    let bytes = stripped.as_bytes();
    let shaped = bytes.len() == 14
        && bytes[..12]
            .iter()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        && bytes[12..].iter().all(u8::is_ascii_digit);
    if !shaped || is_repeated(&stripped) {
        return false;
    }
    let values: Vec<u32> = bytes.iter().map(|&b| u32::from(b) - 48).collect();
    let digit = |values: &[u32], weights: &[u32]| -> u32 {
        let sum: u32 = weights.iter().zip(values).map(|(w, v)| w * v).sum();
        let remainder = sum % 11;
        if remainder < 2 {
            0
        } else {
            11 - remainder
        }
    };
    let first = digit(&values, &[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
    let mut with_first = values[..12].to_vec();
    with_first.push(first);
    let second = digit(&with_first, &[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
    values[12] == first && values[13] == second
}

/// ISO 13616 MOD-97 over an IBAN without white space, upper-cased, of
/// `min_len` to 34 characters.
pub(crate) fn mod97(value: &str, min_len: usize) -> bool {
    let cleaned: String = strip(value, is_js_space).to_uppercase();
    // Lengths in UTF-16 units, as the reference measures them.
    let length = cleaned.encode_utf16().count();
    if length < min_len || length > 34 {
        return false;
    }
    let (head, tail) = match cleaned.char_indices().nth(4) {
        Some((at, _)) => cleaned.split_at(at),
        None => (cleaned.as_str(), ""),
    };
    let mut remainder: u64 = 0;
    for c in tail.chars().chain(head.chars()) {
        let digits = if c.is_ascii_uppercase() {
            u64::from(c as u8 - 55)
        } else if c.is_ascii_digit() {
            u64::from(c as u8 - b'0')
        } else {
            // The reference would pass the character to BigInt() or parseInt()
            // and fail: not an IBAN.
            return false;
        };
        remainder = if digits >= 10 {
            (remainder * 100 + digits) % 97
        } else {
            (remainder * 10 + digits) % 97
        };
    }
    remainder == 1
}

/// IBAN: ISO 13616 MOD-97, 15 to 34 characters.
pub fn iban_mod97(value: &str) -> bool {
    mod97(value, 15)
}

/// US ABA routing number: nine digits, not all equal, weights 3-7-1.
pub fn aba_routing(value: &str) -> bool {
    let stripped = strip(value, |c| is_js_space(c) || c == '-');
    if stripped.len() != 9 || !all_digits(&stripped) || is_repeated(&stripped) {
        return false;
    }
    let sum: u32 = digits(&stripped)
        .iter()
        .zip([3, 7, 1, 3, 7, 1, 3, 7, 1])
        .map(|(d, w)| d * w)
        .sum();
    sum.is_multiple_of(10)
}

/// Brazilian PIX "copia e cola" payload: it ends with `6304` and the
/// CRC-16/CCITT-FALSE of everything before the CRC, in hexadecimal.
pub fn pix_payload(value: &str) -> bool {
    let bytes = value.as_bytes();
    let n = bytes.len();
    if n < 8 || &bytes[n - 8..n - 4] != b"6304" || !bytes[n - 4..].iter().all(u8::is_ascii_hexdigit)
    {
        return false;
    }
    // The reference feeds UTF-16 code units to the CRC; a payload is ASCII.
    let mut crc: u32 = 0xFFFF;
    for unit in value[..n - 4].encode_utf16() {
        crc ^= u32::from(unit) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                ((crc << 1) ^ 0x1021) & 0xFFFF
            } else {
                (crc << 1) & 0xFFFF
            };
        }
    }
    format!("{crc:04X}").eq_ignore_ascii_case(&value[n - 4..])
}

/// Σ value × weight, over ASCII digits.
fn weighted(text: &str, weights: &[i64]) -> i64 {
    text.bytes()
        .zip(weights)
        .map(|(b, w)| i64::from(b - b'0') * w)
        .sum()
}

/// UK NHS number: ten digits, mod-11 check digit (a remainder of 1 is never issued).
pub fn nhs(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-');
    if s.len() != 10 || !all_digits(&s) {
        return false;
    }
    let remainder = weighted(&s, &[10, 9, 8, 7, 6, 5, 4, 3, 2]) % 11;
    if remainder == 1 {
        return false;
    }
    let check = if remainder == 0 { 0 } else { 11 - remainder };
    i64::from(s.as_bytes()[9] - b'0') == check
}

/// US National Provider Identifier: ten digits starting with 1 or 2, Luhn
/// behind the prefix `80840`.
pub fn npi(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-');
    s.len() == 10
        && all_digits(&s)
        && matches!(s.as_bytes()[0], b'1' | b'2')
        && luhn(&format!("80840{s}"))
}

/// IMEI: fifteen digits, not all equal, Luhn.
pub fn imei(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-' || c == '/');
    s.len() == 15 && all_digits(&s) && !is_repeated(&s) && luhn(&s)
}

/// US DEA registration number: two letters, seven digits, check digit.
pub fn dea(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-').to_uppercase();
    let b = s.as_bytes();
    if b.len() != 9
        || !b"ABCDEFGHJKLMNPRSTUX".contains(&b[0])
        || !(b[1].is_ascii_uppercase() || b[1] == b'9')
        || !b[2..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let d: Vec<u32> = b[2..].iter().map(|x| u32::from(x - b'0')).collect();
    (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]
}

/// Vehicle Identification Number: ISO 3779 transliteration checksum at position 9.
pub fn vin(value: &str) -> bool {
    const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let upper = value.to_uppercase();
    let b = upper.as_bytes();
    let allowed =
        |c: u8| c.is_ascii_digit() || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'O' | b'Q'));
    if b.len() != 17 || !b.iter().all(|&c| allowed(c)) {
        return false;
    }
    let transliterate = |c: u8| -> u32 {
        match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'A'..=b'H' => u32::from(c - b'A') + 1,
            b'J'..=b'N' => u32::from(c - b'J') + 1,
            b'P' => 7,
            b'R' => 9,
            _ => u32::from(c - b'S') + 2,
        }
    };
    let remainder = b
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| transliterate(c) * w)
        .sum::<u32>()
        % 11;
    let expected = if remainder == 10 {
        b'X'
    } else {
        b'0' + remainder as u8
    };
    b[8] == expected
}

/// UK National Insurance number: format and issued prefixes.
pub fn nino(value: &str) -> bool {
    let s = strip(value, is_js_space).to_uppercase();
    let b = s.as_bytes();
    let first =
        |c: u8| c.is_ascii_uppercase() && !matches!(c, b'D' | b'F' | b'I' | b'Q' | b'U' | b'V');
    let second = |c: u8| first(c) && c != b'O';
    b.len() == 9
        && first(b[0])
        && second(b[1])
        && b[2..8].iter().all(u8::is_ascii_digit)
        && (b'A'..=b'D').contains(&b[8])
        && !["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"].contains(&&s[..2])
}

/// Indian Aadhaar number: twelve digits, not starting with 0 or 1, Verhoeff.
pub fn aadhaar(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-');
    s.len() == 12 && all_digits(&s) && !s.starts_with(['0', '1']) && verhoeff(value)
}

/// Dutch BSN: nine digits (shorter ones padded with zeros), eleven-test.
pub fn bsn(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '.' || c == '-');
    let s = format!("{s:0>9}");
    if s.len() != 9 || !all_digits(&s) || is_repeated(&s) {
        return false;
    }
    weighted(&s, &[9, 8, 7, 6, 5, 4, 3, 2, -1]) % 11 == 0
}

/// Portuguese NIF: nine digits, mod-11 check digit.
pub fn pt_nif(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '.' || c == '-');
    if s.len() != 9 || !all_digits(&s) || s.starts_with('0') || is_repeated(&s) {
        return false;
    }
    let remainder = weighted(&s, &[9, 8, 7, 6, 5, 4, 3, 2]) % 11;
    let check = if remainder < 2 { 0 } else { 11 - remainder };
    i64::from(s.as_bytes()[8] - b'0') == check
}

/// Spanish DNI or NIE: the check letter of the number (X, Y, Z count as 0, 1, 2).
pub fn es_dni(value: &str) -> bool {
    const LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let s = strip(value, |c| is_js_space(c) || c == '-').to_uppercase();
    let b = s.as_bytes();
    if b.len() != 9 || !b[8].is_ascii_uppercase() || !b[1..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let lead = match b[0] {
        b'X' => 0,
        b'Y' => 1,
        b'Z' => 2,
        d if d.is_ascii_digit() => u32::from(d - b'0'),
        _ => return false,
    };
    let number = b[1..8]
        .iter()
        .fold(lead, |n, &d| n * 10 + u32::from(d - b'0'));
    LETTERS[(number % 23) as usize] == b[8]
}

/// Italian fiscal code: the sixteenth character is the check letter of the first fifteen.
pub fn it_fiscal_code(value: &str) -> bool {
    const ODD: [u32; 36] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3,
        6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
    ];
    let s = strip(value, is_js_space).to_uppercase();
    let b = s.as_bytes();
    if b.len() != 16
        || !b[..15]
            .iter()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        || !b[15].is_ascii_uppercase()
    {
        return false;
    }
    let mut sum = 0;
    for (index, &c) in b[..15].iter().enumerate() {
        let ordinal = if c <= b'9' {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A') + 10
        };
        let even = if c <= b'9' { ordinal } else { ordinal - 10 };
        sum += if index % 2 == 0 {
            ODD[ordinal as usize]
        } else {
            even
        };
    }
    b'A' + (sum % 26) as u8 == b[15]
}

/// French NIR: 97 minus the number modulo 97 is the key (Corsica's 2A and 2B
/// count as 19 and 18).
pub fn fr_nir(value: &str) -> bool {
    let s = strip(value, is_js_space).to_uppercase();
    let b = s.as_bytes();
    if b.len() != 15 || !matches!(b[0], b'1' | b'2') || !s.is_ascii() {
        return false;
    }
    let department = match &s[5..7] {
        "2A" => "19",
        "2B" => "18",
        other => other,
    };
    let number = format!("{}{}{}", &s[..5], department, &s[7..13]);
    if !all_digits(&number) || !all_digits(&s[13..]) {
        return false;
    }
    let (Ok(n), Ok(key)) = (number.parse::<u64>(), s[13..].parse::<u64>()) else {
        return false;
    };
    97 - n % 97 == key
}

/// Chinese resident identity number: 17 digits and a check character (0-9 or X).
pub fn cn_resident_id(value: &str) -> bool {
    let s = strip(value, is_js_space).to_uppercase();
    let b = s.as_bytes();
    if b.len() != 18
        || !b[..17].iter().all(u8::is_ascii_digit)
        || !(b[17].is_ascii_digit() || b[17] == b'X')
    {
        return false;
    }
    let sum = weighted(
        &s[..17],
        &[7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2],
    );
    b"10X98765432"[(sum % 11) as usize] == b[17]
}

/// Australian Tax File Number: nine digits, weighted sum divisible by 11.
pub fn au_tfn(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-');
    s.len() == 9
        && all_digits(&s)
        && !is_repeated(&s)
        && weighted(&s, &[1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11 == 0
}

/// Swedish personnummer: ten or twelve digits, Luhn over the last ten.
pub fn se_personnummer(value: &str) -> bool {
    let s = strip(value, |c| is_js_space(c) || c == '-' || c == '+');
    (s.len() == 10 || s.len() == 12) && all_digits(&s) && luhn(&s[s.len() - 10..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_cases() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111111111111112"));
        assert!(!luhn("1"));
        assert!(!luhn("4111a1111"));
    }

    #[test]
    fn verhoeff_cases() {
        assert!(verhoeff("2363"));
        assert!(!verhoeff("2364"));
        assert!(!verhoeff(""));
    }

    #[test]
    fn cpf_cases() {
        assert!(cpf("529.982.247-25"));
        assert!(!cpf("529.982.247-26"));
        assert!(!cpf("111.111.111-11"));
    }

    #[test]
    fn cnpj_cases() {
        assert!(cnpj("11.222.333/0001-81"));
        assert!(!cnpj("11.222.333/0001-82"));
        assert!(cnpj("12.ABC.345/01DE-35"));
        assert!(cnpj("12.abc.345/01de-35"));
        assert!(!cnpj("00000000000000"));
    }

    #[test]
    fn iban_cases() {
        assert!(iban_mod97("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban_mod97("GB82 WEST 1234 5698 7654 33"));
        assert!(!iban_mod97("GB82WEST12345"));
        // The detector accepts shorter strings than the validator.
        assert!(!mod97("GB82", 5));
    }

    #[test]
    fn aba_cases() {
        assert!(aba_routing("011000015"));
        assert!(!aba_routing("011000016"));
        assert!(!aba_routing("000000000"));
    }

    #[test]
    fn pix_cases() {
        let payload = "00020126400014br.gov.bcb.pix0118fulano@example.com5204000053039865802BR5913FULANO DE TAL6009SAO PAULO62070503***63049F63";
        assert!(pix_payload(payload));
        let cut = payload.len() - 4;
        let lower_crc = format!("{}{}", &payload[..cut], payload[cut..].to_lowercase());
        assert!(pix_payload(&lower_crc));
        let altered = format!("{}0", &payload[..payload.len() - 1]);
        assert!(!pix_payload(&altered));
        assert!(!pix_payload("000201"));
    }

    #[test]
    fn national_and_health_validators() {
        let cases = [
            ("nino", "AB 12 34 56 A", "DA 12 34 56 A"),
            ("bsn", "111222333", "111222334"),
            ("pt-nif", "123456789", "123456788"),
            ("es-dni", "X1234567L", "12345678A"),
            ("it-fiscal-code", "RSSMRA85T10A562S", "RSSMRA85T10A562T"),
            ("fr-nir", "2 84 05 75 123 456 72", "2 84 05 75 123 456 73"),
            ("cn-resident-id", "11010519491231002X", "110105194912310021"),
            ("au-tfn", "123 456 782", "123 456 783"),
            ("se-personnummer", "811218-9876", "811218-9877"),
            ("nhs", "943 476 5919", "943 476 5918"),
            ("vin", "1HGBH41JXMN109186", "1HGBH41JXMN109187"),
            ("dea", "AB1234563", "AB1234564"),
            ("aadhaar", "2341 2341 2346", "2341 2341 2347"),
            ("npi", "1234567893", "1234567894"),
            ("imei", "49-015420-323751-8", "49-015420-323751-9"),
        ];
        for (name, valid, invalid) in cases {
            let validator = by_name(name).unwrap();
            assert!(validator.validate(valid), "{name} {valid}");
            assert!(!validator.validate(invalid), "{name} {invalid}");
        }
    }

    #[test]
    fn validators_by_name() {
        assert!(by_name("cpf").is_some_and(|v| v.validate("529.982.247-25")));
        assert!(by_name("not-a-validator").is_none());
    }
}
