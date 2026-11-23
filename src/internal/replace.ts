/**
 * @module internal/replace
 * @description Replacement of the matches of a text in one pass, shared by the
 * 1.x functions that rewrite a text (anonymize, anonymizeAsync, tokenize).
 * @internal
 */

/** A span of a text and the string that replaces it. */
export interface Replacement {
  /** Start of the span (UTF-16 offset, inclusive). */
  readonly start: number;
  /** End of the span (UTF-16 offset, exclusive). */
  readonly end: number;
  /** The string written in place of the span. */
  readonly replacement: string;
}

/**
 * Replace spans of `text`, given in increasing order and without overlaps, as
 * deduplicated matches are.
 *
 * The text is assembled once from the parts between the spans. Splicing each
 * replacement into the text in turn copied the whole text for every span: a
 * text of n characters with m matches cost O(n·m), seconds for a megabyte with
 * thousands of matches.
 *
 * @param text - The text the spans index.
 * @param replacements - The spans and their replacements, in increasing order.
 * @returns The text with every span replaced.
 * @internal
 */
export function replaceSpans(text: string, replacements: readonly Replacement[]): string {
  const parts: string[] = [];
  let cursor = 0;
  for (const { start, end, replacement } of replacements) {
    parts.push(text.slice(cursor, start), replacement);
    cursor = end;
  }
  parts.push(text.slice(cursor));
  return parts.join("");
}
