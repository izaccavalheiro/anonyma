//! IPv4 and IPv6 addresses (`src/detectors/ip-address.ts`).

use super::Match;
use crate::jsregex::js_regex;
use crate::Category;

js_regex!(
    ipv4 = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/\d{1,2})?\b"
);

// The alternatives are tried in order, as in the reference: `2001:db8::1`
// matches `2001:db8::` through the second one.
js_regex!(
    ipv6 = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
);

pub(super) fn detect_ipv4(text: &str) -> Vec<Match> {
    ipv4()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| Match::new(Category::Ipv4, text, start, end, 0.98))
        .collect()
}

pub(super) fn detect_ipv6(text: &str) -> Vec<Match> {
    ipv6()
        .ranges(text)
        .into_iter()
        .map(|(start, end)| Match::new(Category::Ipv6, text, start, end, 0.98))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_addresses() {
        let found = detect_ipv4("Server 192.0.2.10 and 198.51.100.7/24");
        let values: Vec<&str> = found.iter().map(|m| m.value.as_str()).collect();
        assert_eq!(values, vec!["192.0.2.10", "198.51.100.7/24"]);
        assert!(detect_ipv4("Version 256.1.1.1 and 1.2.3").is_empty());
    }

    #[test]
    fn ipv6_alternatives_in_reference_order() {
        assert_eq!(detect_ipv6("Host 2001:db8::1 is up")[0].value, "2001:db8::");
        assert_eq!(
            detect_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")[0].value,
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        );
    }
}
