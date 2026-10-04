/**
 * @module audit/fields
 * @description Helpers that turn engine results into audit field entries.
 */

import type { AppliedSpan, DetectedSpan } from "../engine/types.js";
import type { AuditFieldEntry } from "./types.js";

/**
 * Build an RFC 6901 JSON Pointer from path segments.
 *
 * @param segments - Object keys and array indices, outermost first.
 * @returns The pointer; `""` for no segments.
 *
 * @example
 * ```ts
 * jsonPointer(["user", "emails", 0]); // "/user/emails/0"
 * jsonPointer(["a/b", "c~d"]);        // "/a~1b/c~0d"
 * ```
 */
export function jsonPointer(segments: readonly (string | number)[]): string {
  let out = "";
  for (const segment of segments) {
    out += `/${String(segment).replace(/~/g, "~0").replace(/\//g, "~1")}`;
  }
  return out;
}

/**
 * Summarise the spans of one transformed field as audit entries: one entry
 * per category and detector, with the number of replacements. The entries
 * contain no matched text.
 *
 * @param spans - Spans returned by a pipeline for the field.
 * @param options - `path` locates the field (a JSON Pointer, `""` by default);
 *   `rule` names the rule applied, fixed or per category.
 * @returns The entries, in order of first appearance.
 *
 * @example
 * ```ts
 * const result = pipeline.transform(text);
 * await audit.record({
 *   operation: "anonymize",
 *   fields: summarizeSpans(result.spans, { path: "/message", rule: "redact" }),
 * });
 * ```
 */
export function summarizeSpans(
  spans: readonly (DetectedSpan | AppliedSpan)[],
  options: { readonly path?: string; readonly rule: string | ((category: string) => string) },
): AuditFieldEntry[] {
  const { path = "", rule } = options;
  const entries = new Map<string, { category: string; detector: string; count: number }>();
  for (const span of spans) {
    const key = `${span.category}\0${span.detector}`;
    const entry = entries.get(key);
    if (entry === undefined) {
      entries.set(key, { category: span.category, detector: span.detector, count: 1 });
    } else {
      entry.count++;
    }
  }
  return [...entries.values()].map((entry) => ({
    path,
    category: entry.category,
    detector: entry.detector,
    rule: typeof rule === "function" ? rule(entry.category) : rule,
    count: entry.count,
  }));
}
