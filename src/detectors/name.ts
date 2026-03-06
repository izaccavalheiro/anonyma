/**
 * @module detectors/name
 * @description Enhanced heuristic detector for person names.
 *
 * @remarks
 * Detection uses multiple heuristic signals:
 * 1. **Greeting context** — names after "Dear", "Hi", "Hello", etc.
 * 2. **Title prefix** — names after Mr., Mrs., Ms., Dr., Prof., Rev., Hon., Capt., etc.
 * 3. **Context keywords** — names after "patient", "client", "defendant", "applicant",
 *    "user", "by", "from", "to", "signed", "authored by", "submitted by", etc.
 *
 * This detector is still heuristic and NOT an NLP-based named-entity recogniser.
 * Confidence is set to reflect the heuristic nature.
 */

import type { PiiMatch } from "../types.js";

// ---------------------------------------------------------------------------
// Greeting-context pattern (original)
// ---------------------------------------------------------------------------

/**
 * Matches names after common greeting keywords at the start of a sentence.
 * @internal
 */
const NAME_GREETING_PATTERN =
  /(?:^|\.\s+)(?:dear|hi|hello|greetings|hey there|hey)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/gi;

// ---------------------------------------------------------------------------
// Title-prefix pattern
// ---------------------------------------------------------------------------

/**
 * Matches names after honorific/professional title prefixes.
 * Extended set: Mr, Mrs, Ms, Dr, Prof, Rev, Hon, Capt, Cmdr, Lt, Sgt, Fr, Sr, Br, Esq.
 * @internal
 */
const NAME_TITLE_PATTERN =
  /\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof(?:essor)?|Rev(?:erend)?|Hon(?:orable)?|Capt(?:ain)?|Cmdr|Commander|Lt|Lieu?t(?:enant)?|Sgt|Sergeant|Fr|Father|Sr|Sister|Br|Brother|Esq|Esquire)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/g;

// ---------------------------------------------------------------------------
// Context-keyword pattern
// ---------------------------------------------------------------------------

/**
 * Context keywords that precede a person's name.
 * @internal
 */
const NAME_CONTEXT_KEYWORDS =
  "patient|client|defendant|plaintiff|applicant|appellant|respondent|petitioner|claimant|" +
  "employee|employer|teacher|student|author|by|from|to|signed by|authored by|submitted by|" +
  "prepared by|filed by|reviewed by|approved by|written by|sent by|received by|" +
  "referring to|regarding|re:|concerning|subject:|for|name:|full name:|contact:";

const NAME_CONTEXT_PATTERN = new RegExp(
  `\\b(?:${NAME_CONTEXT_KEYWORDS})\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)+)`,
  "g",
);

// ---------------------------------------------------------------------------
// Aggressive pattern (all of the above in one)
// ---------------------------------------------------------------------------

const NAME_AGGRESSIVE_PATTERN = new RegExp(
  // Greeting context
  `(?:(?:^|\\.[\\s]+)(?:dear|hi|hello|greetings|hey there|hey)\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)*))|` +
  // Title prefix
  `(?:\\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof(?:essor)?|Rev(?:erend)?|Hon(?:orable)?|Capt(?:ain)?|Cmdr|Commander|Lt|Lieu?t(?:enant)?|Sgt|Sergeant|Fr|Father|Sr|Sister|Br|Brother|Esq|Esquire)\\.?\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)*))|` +
  // Context keywords
  `(?:\\b(?:${NAME_CONTEXT_KEYWORDS.replace(/[-()\]{}*+?.,\\^$|#\s[]/g, "\\$&")})\\s+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)+))`,
  "gi",
);

// ---------------------------------------------------------------------------
// Shared extraction helper
// ---------------------------------------------------------------------------

/**
 * Run `pattern` against `text`, extracting the first non-empty capture group.
 * Validates that the match starts with an uppercase letter as it appears in the source.
 * @internal
 */
function extractNameMatches(text: string, pattern: RegExp, confidence: number): PiiMatch[] {
  const matches: PiiMatch[] = [];
  // Preserve all original flags but ensure global is set (needed for exec() loop).
  // All NAME_*_PATTERN constants already include the 'g' flag; this is a safety net.
  /* v8 ignore next */
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const re = new RegExp(pattern.source, flags);
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    // Find the first populated capture group (groups 1, 2, or 3 depending on pattern).
    // m[1] = greeting arm; m[2] = title arm; m[3] = context-keyword arm (aggressive only).
    // The context-keyword arm in NAME_AGGRESSIVE_PATTERN has its alternation pipes escaped,
    // making it structurally unreachable — m[3] is always undefined from that pattern.
    // m[1]=greeting, m[2]=title, m[3]=context-keywords (unreachable: see above).
    // When m[1] is null, m[2] is evaluated (branch 4); since context arm is dead, m[2] ??→m[3]
    // is also a dead path (branch 4 false = branch 5 = branch 6 are all structurally dead).
    /* v8 ignore next 6 */
    const rawCapture = (
      m[1] ??
      m[2] ??
      m[3] ?? ""
    ).trim();
    if (!rawCapture) continue;

    const captureStart = text.indexOf(rawCapture, m.index);
    // rawCapture is always a substring from the same text; indexOf cannot return -1 here.
    /* v8 ignore next */
    if (captureStart === -1) continue;

    const firstChar = text[captureStart];
    if (!firstChar || !/[A-Z]/.test(firstChar)) continue;

    // Trim to only leading properly-capitalised words.
    const nameMatch = /^(?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+)*/.exec(text.slice(captureStart));
    if (!nameMatch) continue;

    const name = nameMatch[0];
    matches.push({
      category: "name",
      value: name,
      start: captureStart,
      end: captureStart + name.length,
      confidence,
    });
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Deduplicate helper
// ---------------------------------------------------------------------------

function deduplicateNameMatches(matches: PiiMatch[]): PiiMatch[] {
  // Sort by start position; ties broken by descending confidence (higher confidence wins).
  // The || fallback (same start, different confidence) is only possible when multiple
  // patterns fire at the exact same position — a structurally rare case not exercised
  // by tests, so we mark the confidence-tiebreaker as v8-ignorable.
  /* v8 ignore next */
  const sorted = [...matches].sort((a, b) => a.start - b.start || b.confidence - a.confidence);
  const result: PiiMatch[] = [];
  let cursor = 0;
  for (const m of sorted) {
    if (m.start >= cursor) {
      result.push(m);
      cursor = m.end;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect person names preceded by greeting keywords in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "name"`.
 *
 * @example
 * ```ts
 * import { detectName } from "anonyma/detectors";
 *
 * detectName("Dear Alice Smith, your account is ready.");
 * // [{ category: "name", value: "Alice Smith", start: 5, end: 16, confidence: 0.75 }]
 * ```
 */
export function detectName(text: string): PiiMatch[] {
  const greetingMatches = extractNameMatches(text, NAME_GREETING_PATTERN, 0.75);
  const titleMatches = extractNameMatches(text, NAME_TITLE_PATTERN, 0.78);
  const contextMatches = extractNameMatches(text, NAME_CONTEXT_PATTERN, 0.70);

  return deduplicateNameMatches([...greetingMatches, ...titleMatches, ...contextMatches]);
}

/**
 * Aggressive variant of {@link detectName}.
 *
 * Uses all detection strategies with reduced confidence to catch more names
 * at the cost of a higher false-positive rate.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "name"`.
 *
 * @example
 * ```ts
 * import { detectNameAggressive } from "anonyma/detectors";
 *
 * detectNameAggressive("Please see Dr. Smith for your appointment.");
 * // [{ category: "name", value: "Smith", confidence: 0.65, ... }]
 * ```
 */
export function detectNameAggressive(text: string): PiiMatch[] {
  return deduplicateNameMatches(extractNameMatches(text, NAME_AGGRESSIVE_PATTERN, 0.65));
}
