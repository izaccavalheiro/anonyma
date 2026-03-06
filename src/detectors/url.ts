/**
 * @module detectors/url
 * @description Detector for URLs (http and https).
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches http and https URLs including those with paths, query strings,
 * and fragments. Supports bare hostnames like `localhost` as well as FQDNs.
 * Deliberately does not match bare hostnames without a scheme to reduce false positives.
 *
 * @remarks
 * Only `http://` and `https://` schemes are matched. `ftp://` is intentionally
 * excluded — add a custom pattern via `customPatterns` if FTP URL detection is needed.
 *
 * @internal
 */
const URL_PATTERN =
  /\bhttps?:\/\/(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|localhost|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:\/[^\s,;'"<>()[\]{}]*)?(?:\?[^\s,;'"<>()[\]{}]*)?(?:#[^\s,;'"<>()[\]{}]*)?\b/g;

/**
 * Detect URLs in `text`.
 *
 * Matches `http://` and `https://` URLs. For `ftp://` detection, use `customPatterns`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "url"`.
 *
 * @example
 * ```ts
 * import { detectUrl } from "anonyma/detectors";
 *
 * detectUrl("Visit https://www.example.com/profile?id=42");
 * // [{ category: "url", value: "https://www.example.com/profile?id=42", ... }]
 * ```
 */
export function detectUrl(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(URL_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "url",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.95,
    });
  }

  return matches;
}
