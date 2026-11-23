//! [`Pipeline`]: the span engine of the reference (`anonyma/engine`):
//! `compilePipeline({ categories, detection, aggressive, minConfidence }).scan(text)`.
//!
//! It differs from [`crate::AnonymaEngine`], the classic API, in three ways:
//! precise detectors for the categories that have one, the redaction labels
//! allow-listed, and overlaps resolved by covering (a weaker detection keeps
//! the characters no stronger one claims, as residual spans).

use std::sync::Arc;

use crate::detectors::precise::{self, Hit};
use crate::detectors::{BuiltinDetector, Detector};
use crate::validators::is_js_space;
use crate::{Category, Error, Result, Support};

/// Which detectors a pipeline runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Detection {
    /// The precise detectors where there is one, the classic ones otherwise.
    #[default]
    Precise,
    /// The classic detectors only.
    Legacy,
}

/// A detection of a pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    /// The category of the value.
    pub category: Category,
    /// The detector that found it (`email`, `email/obfuscated`, `ssn/bare`, ...).
    pub detector: &'static str,
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset just past the span.
    pub end: usize,
    /// How likely the span is personal data, from 0 to 1.
    pub confidence: f64,
    /// `true` for the part of a detection left uncovered by a stronger
    /// overlapping one.
    pub residual: bool,
}

type Scan = Arc<dyn Fn(&str) -> Vec<Hit> + Send + Sync>;

#[derive(Clone)]
struct Source {
    id: &'static str,
    category: Category,
    scan: Scan,
}

/// Builds a [`Pipeline`].
#[derive(Debug, Clone, Default)]
pub struct PipelineBuilder {
    categories: Option<Vec<Category>>,
    detection: Detection,
    aggressive: bool,
    min_confidence: f64,
}

/// The categories whose precise detector is not ported yet: none. A category
/// the reference gives a precise detector first is listed here and refused in
/// precise mode until it is ported.
pub(crate) const PRECISE_PENDING: &[Category] = &[];

impl PipelineBuilder {
    /// Detect these categories, in this order (every category by default).
    pub fn categories(mut self, categories: impl IntoIterator<Item = Category>) -> Self {
        self.categories = Some(categories.into_iter().collect());
        self
    }

    /// Precise (default) or classic detectors.
    pub fn detection(mut self, detection: Detection) -> Self {
        self.detection = detection;
        self
    }

    /// Also run the aggressive detectors.
    pub fn aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        self
    }

    /// Drop detections below this confidence before resolving overlaps.
    pub fn min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Build the pipeline.
    ///
    /// # Errors
    ///
    /// [`Error::Validation`] for a `min_confidence` outside 0..=1, and
    /// [`Error::UnsupportedCategories`] for a category whose precise detector
    /// is not ported yet, in precise mode.
    pub fn build(self) -> Result<Pipeline> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(Error::validation(
                "minConfidence",
                "must be a number between 0 and 1",
            ));
        }
        let categories = self.categories.unwrap_or_else(|| Category::ALL.to_vec());
        let mut sources: Vec<Source> = Vec::new();
        let mut seen = Vec::new();
        let mut missing = Vec::new();
        for category in categories {
            if seen.contains(&category) {
                continue;
            }
            seen.push(category);
            if category.support() != Support::Full {
                missing.push(category);
                continue;
            }
            let precise = self.detection == Detection::Precise;
            let aggressive = self.aggressive;
            let add = |sources: &mut Vec<Source>, id: &'static str, scan: Scan| {
                sources.push(Source { id, category, scan });
            };
            match category {
                Category::Email if precise => {
                    add(&mut sources, "email", Arc::new(precise::email));
                    if aggressive {
                        add(
                            &mut sources,
                            "email/obfuscated",
                            Arc::new(precise::obfuscated_email),
                        );
                    }
                }
                Category::Ssn if precise => {
                    add(&mut sources, "ssn", Arc::new(precise::ssn));
                    if aggressive {
                        add(&mut sources, "ssn/bare", Arc::new(precise::bare_ssn));
                    }
                }
                Category::Iban if precise => add(&mut sources, "iban", Arc::new(precise::iban)),
                Category::Ipv4 if precise => add(&mut sources, "ipv4", Arc::new(precise::ipv4)),
                Category::Ipv6 if precise => add(&mut sources, "ipv6", Arc::new(precise::ipv6)),
                Category::CreditCard if precise => {
                    add(&mut sources, "credit-card", Arc::new(precise::card));
                    if aggressive {
                        add(
                            &mut sources,
                            "credit-card/masked",
                            Arc::new(precise::masked_card),
                        );
                    }
                }
                _ if precise && PRECISE_PENDING.contains(&category) => missing.push(category),
                _ => {
                    // The classic detector; national-id runs strict in precise mode.
                    let strict = precise && category == Category::NationalId;
                    let Some(detector) = BuiltinDetector::new(category, aggressive, strict) else {
                        missing.push(category);
                        continue;
                    };
                    add(
                        &mut sources,
                        category.as_str(),
                        Arc::new(move |text: &str| {
                            detector
                                .detect(text)
                                .into_iter()
                                .map(|m| (m.start, m.end, m.confidence))
                                .collect()
                        }),
                    );
                }
            }
        }
        if !missing.is_empty() {
            return Err(Error::UnsupportedCategories(missing));
        }
        Ok(Pipeline {
            sources,
            min_confidence: self.min_confidence,
        })
    }
}

/// The span engine: detects with several detectors and resolves their overlaps.
#[derive(Clone)]
pub struct Pipeline {
    sources: Vec<Source>,
    min_confidence: f64,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&str> = self.sources.iter().map(|s| s.id).collect();
        f.debug_struct("Pipeline")
            .field("detectors", &ids)
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    start: usize,
    end: usize,
    confidence: f64,
    detector: usize,
    allowed: bool,
}

/// The redaction label of the default strategy, allow-listed as the reference
/// does: a second pass leaves it alone.
fn is_redaction_label(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower == "[redacted]" || lower == "redacted"
}

impl Pipeline {
    /// Start building a pipeline.
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::default()
    }

    /// The ids of the detectors this pipeline runs, in order.
    pub fn detectors(&self) -> Vec<&'static str> {
        self.sources.iter().map(|s| s.id).collect()
    }

    /// Detect, filter and resolve: the spans a transform would replace, in
    /// document order.
    pub fn scan(&self, text: &str) -> Vec<Span> {
        let mut candidates = Vec::new();
        for (index, source) in self.sources.iter().enumerate() {
            for (start, end, confidence) in (source.scan)(text) {
                if confidence < self.min_confidence {
                    continue;
                }
                candidates.push(Candidate {
                    start,
                    end,
                    confidence,
                    detector: index,
                    allowed: is_redaction_label(&text[start..end]),
                });
            }
        }
        resolve_cover(text, candidates)
            .into_iter()
            .map(|(c, residual)| Span {
                category: self.sources[c.detector].category,
                detector: self.sources[c.detector].id,
                start: c.start,
                end: c.end,
                confidence: c.confidence,
                residual,
            })
            .collect()
    }
}

/// Resolve overlaps by covering: clusters of overlapping candidates, each
/// resolved by priority (confidence, length, start, detector).
fn resolve_cover(text: &str, mut candidates: Vec<Candidate>) -> Vec<(Candidate, bool)> {
    candidates.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    let mut out = Vec::new();
    let mut cluster: Vec<Candidate> = Vec::new();
    let mut cluster_end = 0;
    for candidate in candidates {
        if !cluster.is_empty() && candidate.start >= cluster_end {
            resolve_cluster(text, std::mem::take(&mut cluster), &mut out);
        }
        if cluster.is_empty() {
            cluster_end = candidate.end;
        }
        cluster_end = cluster_end.max(candidate.end);
        cluster.push(candidate);
    }
    if !cluster.is_empty() {
        resolve_cluster(text, cluster, &mut out);
    }
    out.sort_by_key(|(c, _)| c.start);
    out
}

fn resolve_cluster(text: &str, mut cluster: Vec<Candidate>, out: &mut Vec<(Candidate, bool)>) {
    if let [only] = cluster.as_slice() {
        if !only.allowed {
            out.push((*only, false));
        }
        return;
    }
    cluster.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
            .then(a.detector.cmp(&b.detector))
    });
    // Claimed byte ranges, kept sorted and disjoint.
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    for candidate in cluster {
        let gaps = gaps(&claimed, candidate.start, candidate.end);
        let untouched = gaps.len() == 1 && gaps[0] == (candidate.start, candidate.end);
        if untouched {
            claim(&mut claimed, candidate.start, candidate.end);
            if !candidate.allowed {
                out.push((candidate, false));
            }
            continue;
        }
        // A hit the caller allow-listed never produces partial replacements.
        if candidate.allowed {
            continue;
        }
        for (start, end) in gaps {
            // Keep the white space around a remainder, so words do not run together.
            let piece = &text[start..end];
            let trimmed_start = start + (piece.len() - piece.trim_start_matches(is_js_space).len());
            let trimmed_end = end - (piece.len() - piece.trim_end_matches(is_js_space).len());
            if trimmed_start >= trimmed_end {
                continue;
            }
            claim(&mut claimed, trimmed_start, trimmed_end);
            out.push((
                Candidate {
                    start: trimmed_start,
                    end: trimmed_end,
                    ..candidate
                },
                true,
            ));
        }
    }
}

/// The parts of `start..end` that no claimed range covers.
fn gaps(claimed: &[(usize, usize)], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = start;
    for &(s, e) in claimed {
        if e <= at || s >= end {
            continue;
        }
        if s > at {
            out.push((at, s));
        }
        at = at.max(e);
        if at >= end {
            break;
        }
    }
    if at < end {
        out.push((at, end));
    }
    out
}

fn claim(claimed: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    claimed.push((start, end));
    claimed.sort_unstable();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(pipeline: &Pipeline, text: &str) -> Vec<(String, &'static str, bool)> {
        pipeline
            .scan(text)
            .into_iter()
            .map(|s| (text[s.start..s.end].to_string(), s.detector, s.residual))
            .collect()
    }

    #[test]
    fn residual_spans_keep_what_a_stronger_detection_leaves() {
        let pipeline = Pipeline::builder()
            .categories([Category::Email, Category::Url])
            .build()
            .unwrap();
        let text = "see https://example.com/contact/ana@example.org";
        assert_eq!(
            spans(&pipeline, text),
            [
                ("https://example.com/contact/".to_string(), "url", true),
                ("ana@example.org".to_string(), "email", false),
            ]
        );
    }

    #[test]
    fn redaction_labels_are_allow_listed() {
        let pipeline = Pipeline::builder()
            .categories([Category::BankAccount])
            .build()
            .unwrap();
        let found = spans(&pipeline, "Already REDACTED, BIC DEUTDEFF");
        assert_eq!(found, [("DEUTDEFF".to_string(), "bank-account", false)]);
    }

    #[test]
    fn every_category_builds_in_both_modes() {
        assert!(Pipeline::builder().build().is_ok());
        assert!(Pipeline::builder()
            .detection(Detection::Legacy)
            .build()
            .is_ok());
        assert!(Pipeline::builder().min_confidence(1.5).build().is_err());
    }

    #[test]
    fn gaps_between_claims() {
        assert_eq!(gaps(&[(2, 4), (6, 8)], 0, 10), [(0, 2), (4, 6), (8, 10)]);
        assert!(gaps(&[(0, 10)], 2, 5).is_empty());
    }
}
