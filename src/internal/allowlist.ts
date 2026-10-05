/**
 * @module internal/allowlist
 * @description Allowlist matching of the 1.x functions: the detected values
 * that the caller lists are left untouched.
 * @internal
 */

/**
 * Compile an allowlist into a predicate that tells whether a detected value
 * is allowlisted.
 *
 * A string entry matches a value equal to it, ignoring case unless
 * `caseSensitive` is set; a value that merely contains an entry does not
 * match. A pattern matches a value it finds a match in. Its `g` and `y` flags
 * are dropped, so that no value depends on the values tested before it and
 * the caller's `RegExp` keeps its `lastIndex`.
 *
 * @param entries - Exact values to leave untouched.
 * @param patterns - Patterns of values to leave untouched.
 * @param caseSensitive - Whether entries are compared case-sensitively.
 * @returns A predicate that returns `true` for an allowlisted value.
 * @internal
 */
export function compileAllowlist(
  entries: readonly string[],
  patterns: readonly RegExp[],
  caseSensitive: boolean,
): (value: string) => boolean {
  if (entries.length === 0 && patterns.length === 0) return () => false;

  const exact = new Set(entries.map((entry) => (caseSensitive ? entry : entry.toLowerCase())));
  const compiled = patterns.map(
    (pattern) => new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")),
  );

  return (value) =>
    exact.has(caseSensitive ? value : value.toLowerCase()) ||
    compiled.some((pattern) => pattern.test(value));
}
