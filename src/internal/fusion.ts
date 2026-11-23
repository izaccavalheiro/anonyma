/**
 * @module internal/fusion
 * @description Batch fusion: the entries of a batch are joined into one text,
 * scanned once, and the results split back by entry, so that one scan pays the
 * fixed cost of the detectors for many entries. `detectBatch()`,
 * `anonymizeBatch()` and `Pipeline.scanBatch()` use it.
 *
 * Fusion never changes a result. The built-in detectors, legacy and precise,
 * keep three properties, which `tests/batch-fusion.test.ts` checks, and a
 * detector added later must keep them too:
 *
 * - Every assertion at the edge of a match (`\b`, `(?<!\d)`, `(?![ ./-]?\d)`,
 *   `(?<![\p{L}\d])`, ...) treats `\n` as it treats the start and the end of
 *   the text. The one exception is `^` without the `m` flag in the greetings of
 *   the name detectors; entries that start with a greeting word are scanned
 *   alone (see {@link GREETING_START}).
 * - No pattern crosses the separator: it alternates `\n` and `\0`, so `\s`
 *   stops at the `\0` and `[^\n,]`, `.` and URL paths stop at the `\n`; no
 *   pattern repeats a class that holds both. Prefilters test for characters
 *   or runs that cannot span it either.
 * - Context reaches at most 40 UTF-16 units before a value (96 for the text the
 *   precise email and IPv4 detectors test, whose patterns stop at the
 *   separator), and card groups are joined by one or two characters, so the
 *   43 units of the separator keep every entry apart.
 *
 * @internal
 */

/**
 * The text between two fused entries.
 *
 * @internal
 */
export const FUSION_SEPARATOR = "\n" + "\u0000\n".repeat(21);

/**
 * Entries of this many UTF-16 units or more are scanned alone: their fixed cost
 * is under 5% of their scan, so fusing them gains nothing.
 *
 * @internal
 */
const FUSION_MAX_ENTRY = 8192;

/**
 * A fused text grows to about this many UTF-16 units. Detectors compare
 * candidates with the labels they found, so a bounded text keeps that work
 * proportional to the batch.
 *
 * @internal
 */
const FUSION_CHUNK = 32_768;

/**
 * Entries that start with one of these words could start a greeting, which the
 * name detectors anchor with `^`: only the first entry of a fused text would
 * see it. They are scanned alone when names are detected.
 *
 * @internal
 */
const GREETING_START = /^(?:dear|hi|hello|greetings|hey)/i;

/**
 * Run `scan` on fused texts of the entries that can be fused, and split its
 * results back by entry. `scan` must return its results sorted by start, each
 * inside one entry.
 *
 * @param texts - The entries of the batch, which may hold values that are not strings.
 * @param names - Whether the name detectors run (entries starting with a greeting word are then
 *   left out).
 * @param scan - Detection on one text.
 * @param shift - The result moved `offset` units to the left.
 * @returns Per entry, its results, or `undefined` for an entry the caller must process alone
 *   (not a string, too long, holding `\0`, starting with a greeting word), and for every entry
 *   when fewer than two can be fused.
 * @internal
 */
export function fuseEach<T extends { readonly start: number }>(
  texts: readonly unknown[],
  names: boolean,
  scan: (text: string) => readonly T[],
  shift: (result: T, offset: number) => T,
): (T[] | undefined)[] {
  const out = new Array<T[] | undefined>(texts.length).fill(undefined);
  const members: { readonly index: number; readonly text: string }[] = [];
  for (const [index, text] of texts.entries()) {
    if (
      typeof text === "string" &&
      text.length < FUSION_MAX_ENTRY &&
      !text.includes("\u0000") &&
      !(names && GREETING_START.test(text))
    ) {
      members.push({ index, text });
    }
  }
  if (members.length < 2) return out;

  let chunk: typeof members = [];
  let size = 0;
  const flush = (): void => {
    const results = scan(chunk.map(({ text }) => text).join(FUSION_SEPARATOR));
    // Results come sorted by start, and each lies inside one entry.
    const pending = results[Symbol.iterator]();
    let next = pending.next();
    let offset = 0;
    for (const { index, text } of chunk) {
      const limit = offset + text.length + FUSION_SEPARATOR.length;
      const found: T[] = [];
      while (next.done !== true && next.value.start < limit) {
        found.push(shift(next.value, offset));
        next = pending.next();
      }
      out[index] = found;
      offset = limit;
    }
    chunk = [];
    size = 0;
  };
  for (const member of members) {
    chunk.push(member);
    size += member.text.length + FUSION_SEPARATOR.length;
    if (size >= FUSION_CHUNK) flush();
  }
  if (chunk.length > 0) flush();
  return out;
}
