/**
 * @module internal/labels
 * @internal
 */

/**
 * `ends.some((end) => end <= index && index - end <= limit)` by binary search:
 * `ends` ascend, as an `exec` loop finds them. tests/labels.test.ts compares both.
 *
 * @internal
 */
export function labelBefore(ends: readonly number[], index: number, limit: number): boolean {
  let low = 0;
  let high = ends.length;
  let last: number | undefined;
  while (low < high) {
    const middle = (low + high) >>> 1;
    const end = ends[middle];
    /* v8 ignore if -- middle is always an index of ends */
    if (end === undefined) break;
    if (end <= index) {
      last = end;
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return last !== undefined && index - last <= limit;
}
