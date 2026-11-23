//! Vehicle Identification Numbers (`src/detectors/vin.ts`): seventeen
//! characters whose check character holds; the aggressive variant also
//! reports the others, with a lower confidence.

use super::Match;
use crate::jsregex::js_regex;
use crate::validators::vin as vin_checksum;
use crate::Category;

js_regex!(candidate = insensitive r"\b[a-hj-npr-z0-9]{17}\b");

pub(super) fn detect(text: &str, aggressive: bool) -> Vec<Match> {
    let ranges = candidate().ranges(text);
    let mut matches: Vec<Match> = ranges
        .iter()
        .filter(|&&(start, end)| vin_checksum(&text[start..end].to_uppercase()))
        .map(|&(start, end)| Match::new(Category::Vin, text, start, end, 0.95))
        .collect();
    if aggressive {
        let valid: Vec<(usize, usize)> = matches.iter().map(|m| (m.start, m.end)).collect();
        for &(start, end) in &ranges {
            if !valid.contains(&(start, end)) {
                matches.push(Match::new(Category::Vin, text, start, end, 0.7));
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_aggressive() {
        let text = "VIN 1HGBH41JXMN109186 and 1HGBH41JXMN109187";
        assert_eq!(detect(text, false).len(), 1);
        assert_eq!(detect(text, true)[1].confidence, 0.7);
    }
}
