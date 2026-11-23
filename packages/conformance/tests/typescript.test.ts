import { describe, expect, it } from "vitest";

import { loadSuite, runCase, runSuite } from "../src/index.js";
import { typescriptAdapter } from "../src/typescript.js";

const suite = loadSuite();

describe("conformance suite against the TypeScript reference", () => {
  describe.each([...new Set(suite.cases.map((testCase) => testCase.op))])("%s", (op) => {
    const cases = suite.cases.filter((testCase) => testCase.op === op);
    it.each(cases.map((testCase) => [testCase.id, testCase] as const))(
      "%s",
      async (_id, testCase) => {
        const outcome = await runCase(testCase, typescriptAdapter);
        expect(outcome).toEqual({ id: testCase.id, status: "passed" });
      },
    );
  });

  it("passes every case: the reference skips nothing", async () => {
    const report = await runSuite(suite, typescriptAdapter);
    expect(report).toMatchObject({ failed: 0, skipped: 0, passed: suite.cases.length });
  });
});
