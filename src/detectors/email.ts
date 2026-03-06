/**
 * @module detectors/email
 * @description Detector for email addresses.
 */

import type { PiiMatch } from "../types.js";

/**
 * RFC 5321 / RFC 5322 inspired email pattern.
 * Deliberately conservative to keep false-positive rate very low.
 *
 * @internal
 */
const EMAIL_PATTERN =
  /\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b/g;

/**
 * Aggressive email pattern — catches obfuscated formats such as
 * `user [at] domain [dot] com` and `user(at)domain(dot)com`.
 *
 * Confidence is reduced to `0.75` due to higher false-positive risk.
 *
 * @internal
 */
const EMAIL_AGGRESSIVE_PATTERN =
  /\b[a-z0-9][a-z0-9._-]*\s*(?:@|\[at\]|\(at\))\s*[a-z0-9][\w.-]*\s*(?:\.|\[dot\]|\(dot\))\s*[a-z]{2,}\b/gi;

/**
 * Detect email addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "email"`.
 *
 * @example
 * ```ts
 * import { detectEmail } from "anonyma/detectors";
 *
 * detectEmail("Contact us at support@example.com.");
 * // [{ category: "email", value: "support@example.com", start: 14, end: 33, confidence: 0.99 }]
 * ```
 */
export function detectEmail(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(EMAIL_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "email",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.99,
    });
  }

  return matches;
}

/**
 * Aggressive variant of {@link detectEmail}.
 *
 * Catches obfuscated email formats such as `user [at] domain [dot] com` and
 * `user(at)domain(dot)com` in addition to standard RFC addresses.
 * Deduplicates results so a valid standard address isn't reported twice.
 *
 * Confidence is `0.75` for obfuscated matches, `0.99` for standard matches.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "email"`.
 *
 * @example
 * ```ts
 * import { detectEmailAggressive } from "anonyma/detectors";
 *
 * detectEmailAggressive("Email user [at] example [dot] com for help.");
 * // [{ category: "email", value: "user [at] example [dot] com", confidence: 0.75, ... }]
 * ```
 */
export function detectEmailAggressive(text: string): PiiMatch[] {
  const standard = detectEmail(text);
  const standardRanges = standard.map((m) => [m.start, m.end] as [number, number]);

  const extra: PiiMatch[] = [];
  const aggressivePattern = new RegExp(EMAIL_AGGRESSIVE_PATTERN.source, "gi");
  let match: RegExpExecArray | null;

  while ((match = aggressivePattern.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    // Skip if already covered by a standard match.
    const overlaps = standardRanges.some(([s, e]) => start < e && end > s);
    if (!overlaps) {
      extra.push({
        category: "email",
        value: match[0],
        start,
        end,
        confidence: 0.75,
      });
    }
  }

  return [...standard, ...extra];
}
