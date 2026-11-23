/**
 * labelBefore() against the linear search it replaces.
 */
import { describe, expect, it } from "vitest";
import { labelBefore } from "../src/internal/labels.js";

describe("labelBefore()", () => {
  it("finds what the linear search finds, at every index", () => {
    const lists = [[], [0], [5], [3, 9, 10, 40], [0, 1, 2, 3], [12, 50, 51, 52, 90, 140]];
    for (const ends of lists) {
      for (let index = 0; index <= 160; index++) {
        for (const limit of [0, 1, 10, 20, 30, 40]) {
          const linear = ends.some((end) => end <= index && index - end <= limit);
          expect(labelBefore(ends, index, limit), `${JSON.stringify(ends)} ${index} ${limit}`).toBe(
            linear,
          );
        }
      }
    }
  });
});
