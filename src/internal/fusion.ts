/**
 * @module internal/fusion
 * @description Batch fusion: entries joined into one text, scanned once, and the results split
 * back by entry. It is exact for the built-in detectors; `tests/batch-fusion.test.ts` states and
 * checks why (separator, look-backs, `^` in the name greetings).
 *
 * @internal
 */

/** The text between two fused entries: `\n` and `\0` alternating, no pattern crosses it. @internal */
export const FUSION_SEPARATOR = "\n" + "\u0000\n".repeat(21);

/** Longer entries are scanned alone: fusing them gains nothing. @internal */
const FUSION_MAX_ENTRY = 8192;

/** The length a fused text grows to, which keeps label lookups bounded. @internal */
const FUSION_CHUNK = 32_768;

/** Greetings the name detectors anchor with `^`: such entries are scanned alone. @internal */
const GREETING_START = /^(?:dear|hi|hello|greetings|hey)/i;

/** The span detectors fusion is proven for; `engine/compile.ts` adds the built-in ones. @internal */
export const FUSABLE_SPAN_DETECTORS = new WeakSet();

/**
 * Run `scan` (results sorted by start) on fused texts and split the results by entry.
 *
 * @returns Per entry, its results, or `undefined` for an entry to process alone (not a string,
 *   too long, holding `\0`, a greeting when `names`), and for all when fewer than two fuse.
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
