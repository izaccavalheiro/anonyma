/**
 * @module engine/resolve
 * @description Overlap resolution on spans. Turns the raw, possibly
 * overlapping hits of several detectors into a list of disjoint spans.
 */

import type { OverlapPolicy } from "./types.js";

/**
 * A raw detector hit.
 */
export interface Candidate {
  /** Start offset in the scanned text. */
  readonly start: number;
  /** Exclusive end offset in the scanned text. */
  readonly end: number;
  /** Confidence score in [0, 1]. */
  readonly confidence: number;
  /** Index of the reporting detector in the pipeline's detector list. */
  readonly detector: number;
  /** `true` when the hit matches an allow rule and must be left untouched. */
  readonly allowed: boolean;
}

/**
 * A span that survived overlap resolution.
 */
export interface Resolved {
  /** Start offset in the scanned text. */
  readonly start: number;
  /** Exclusive end offset in the scanned text. */
  readonly end: number;
  /** Confidence score in [0, 1]. */
  readonly confidence: number;
  /** Index of the reporting detector in the pipeline's detector list. */
  readonly detector: number;
  /** `true` for the uncovered remainder of a hit that lost to another one. */
  readonly residual: boolean;
}

const WHITESPACE = /\s/;

/**
 * The 1.x rule: earliest start wins, ties go to the higher confidence, and
 * every hit that overlaps an accepted one is dropped entirely.
 */
function resolveLegacy(candidates: readonly Candidate[]): Resolved[] {
  const sorted = [...candidates].sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  const out: Resolved[] = [];
  let cursor = 0;
  for (const candidate of sorted) {
    if (candidate.start < cursor) continue;
    cursor = candidate.end;
    if (candidate.allowed) continue;
    out.push({
      start: candidate.start,
      end: candidate.end,
      confidence: candidate.confidence,
      detector: candidate.detector,
      residual: false,
    });
  }
  return out;
}

/** Order in which overlapping hits are accepted. */
function byPriority(a: Candidate, b: Candidate): number {
  return (
    b.confidence - a.confidence ||
    b.end - b.start - (a.end - a.start) ||
    a.start - b.start ||
    a.detector - b.detector
  );
}

/**
 * Resolve one group of transitively overlapping hits, which lie in
 * `text[base, end)`. One flag per character records what has been claimed, so
 * the cost is the total length of the hits rather than their number squared.
 */
function resolveCluster(
  text: string,
  cluster: Candidate[],
  base: number,
  end: number,
  out: Resolved[],
): void {
  const [only] = cluster;
  if (cluster.length === 1 && only !== undefined) {
    if (!only.allowed) out.push({ ...stripAllowed(only), residual: false });
    return;
  }

  cluster.sort(byPriority);
  const claimed = new Uint8Array(end - base);

  for (const candidate of cluster) {
    // Collect what the candidate adds to the characters claimed so far.
    const gaps: { start: number; end: number }[] = [];
    let open = -1;
    for (let at = candidate.start; at < candidate.end; at++) {
      if (claimed[at - base] === 0) {
        if (open < 0) open = at;
      } else if (open >= 0) {
        gaps.push({ start: open, end: at });
        open = -1;
      }
    }
    if (open >= 0) gaps.push({ start: open, end: candidate.end });

    const [first] = gaps;
    const untouched =
      gaps.length === 1 && first?.start === candidate.start && first.end === candidate.end;

    if (untouched) {
      claimed.fill(1, candidate.start - base, candidate.end - base);
      if (!candidate.allowed) out.push({ ...stripAllowed(candidate), residual: false });
      continue;
    }

    // A hit the caller allow-listed never produces partial replacements.
    if (candidate.allowed) continue;

    for (const gap of gaps) {
      // Keep the whitespace around a remainder, so words do not run together.
      let { start, end: stop } = gap;
      while (start < stop && WHITESPACE.test(text.charAt(start))) start++;
      while (stop > start && WHITESPACE.test(text.charAt(stop - 1))) stop--;
      if (start === stop) continue;
      claimed.fill(1, start - base, stop - base);
      out.push({
        start,
        end: stop,
        confidence: candidate.confidence,
        detector: candidate.detector,
        residual: true,
      });
    }
  }
}

function stripAllowed(candidate: Candidate): Omit<Resolved, "residual"> {
  return {
    start: candidate.start,
    end: candidate.end,
    confidence: candidate.confidence,
    detector: candidate.detector,
  };
}

/**
 * The default rule: within each group of overlapping hits, hits are accepted
 * by priority, and whatever a losing hit covers beyond the accepted ones is
 * kept as a residual span. No detected character is left uncovered.
 */
function resolveCover(text: string, candidates: readonly Candidate[]): Resolved[] {
  const sorted = [...candidates].sort((a, b) => a.start - b.start || a.end - b.end);
  const out: Resolved[] = [];

  let cluster: Candidate[] = [];
  let clusterStart = 0;
  let clusterEnd = -1;
  for (const candidate of sorted) {
    if (cluster.length > 0 && candidate.start >= clusterEnd) {
      resolveCluster(text, cluster, clusterStart, clusterEnd, out);
      cluster = [];
    }
    if (cluster.length === 0) clusterStart = candidate.start;
    cluster.push(candidate);
    clusterEnd = Math.max(clusterEnd, candidate.end);
  }
  if (cluster.length > 0) resolveCluster(text, cluster, clusterStart, clusterEnd, out);

  return out.sort((a, b) => a.start - b.start);
}

/**
 * Resolve overlapping hits into disjoint spans in document order.
 *
 * @param text - The scanned text (used to trim whitespace from remainders).
 * @param candidates - Raw hits, in any order.
 * @param policy - The overlap policy.
 * @returns Disjoint spans sorted by start offset. Allow-listed hits are not returned.
 *
 * @example
 * ```ts
 * resolveSpans("a@b.co", [{ start: 0, end: 6, confidence: 0.99, detector: 0, allowed: false }], "cover");
 * // [{ start: 0, end: 6, confidence: 0.99, detector: 0, residual: false }]
 * ```
 */
export function resolveSpans(
  text: string,
  candidates: readonly Candidate[],
  policy: OverlapPolicy,
): Resolved[] {
  if (candidates.length === 0) return [];
  return policy === "legacy" ? resolveLegacy(candidates) : resolveCover(text, candidates);
}
