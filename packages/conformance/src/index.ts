/**
 * @module anonyma-conformance
 * @description Loads the language-neutral conformance suite and checks an
 * implementation of anonyma against it.
 *
 * An implementation is described by an {@link Adapter}: the capabilities it
 * provides and a function that performs one case's operation and returns its
 * result in the shape of the case's `expected` member. {@link runSuite}
 * compares the two with the rules of the specification (README.md) and
 * reports every difference. The Rust and Python runners implement the same
 * rules in their own languages.
 */

import { readFileSync } from "node:fs";

/** The operations of the suite. */
export const OPERATIONS = [
  "validate",
  "detect",
  "scan",
  "tokenize",
  "detokenize",
  "shield",
  "restore",
  "anonymize",
  "preset",
  "canonicalize",
  "digest",
  "receipt.sign",
  "receipt.verify",
  "receipt.issue",
] as const;

/** One operation of the suite. */
export type Operation = (typeof OPERATIONS)[number];

/** A JSON object. */
export type JsonObject = Readonly<Record<string, unknown>>;

/** One test case. */
export interface ConformanceCase {
  /** Unique, stable identifier. */
  readonly id: string;
  /** What the case checks, and why the expected value is what it is. */
  readonly description: string;
  /** The operation to perform. */
  readonly op: Operation;
  /** Capabilities an implementation must provide to run the case. */
  readonly requires: readonly string[];
  /** Arguments of the operation. */
  readonly input: JsonObject;
  /** The result the operation must produce. */
  readonly expected: JsonObject;
}

/** The suite. */
export interface ConformanceSuite {
  readonly suite: "anonyma-conformance";
  readonly version: string;
  readonly reference: string;
  readonly offsets: "code-points";
  readonly cases: readonly ConformanceCase[];
}

/** An implementation under test. */
export interface Adapter {
  /** Name used in reports, such as `typescript` or `rust`. */
  readonly name: string;
  /** Whether the implementation provides a capability. */
  readonly provides: (capability: string) => boolean;
  /**
   * Perform the operation of `testCase` and return its result in the shape of
   * `testCase.expected`. Throwing fails the case.
   */
  readonly run: (testCase: ConformanceCase) => unknown;
}

/** The outcome of one case. */
export type CaseOutcome =
  | { readonly id: string; readonly status: "passed" }
  | { readonly id: string; readonly status: "failed"; readonly problems: readonly string[] }
  | { readonly id: string; readonly status: "skipped"; readonly missing: readonly string[] };

/** The outcome of a whole run. */
export interface SuiteReport {
  readonly adapter: string;
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  readonly outcomes: readonly CaseOutcome[];
}

/** Confidence values are equal when they differ by no more than this. */
export const CONFIDENCE_TOLERANCE = 1e-9;

/** URL of the suite file, next to this package's `src/`. */
export const SUITE_URL = new URL("../conformance-tests.json", import.meta.url);

/** URL of the JSON Schema of the suite file. */
export const SCHEMA_URL = new URL("../conformance-tests.schema.json", import.meta.url);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOperation(value: unknown): value is Operation {
  return (OPERATIONS as readonly unknown[]).includes(value);
}

/**
 * Check the structure of a parsed suite file and return it typed.
 *
 * @param json - The parsed contents of `conformance-tests.json`.
 * @returns The suite.
 * @throws {Error} When the file does not have the structure of a suite, or two cases share an id.
 */
export function parseSuite(json: unknown): ConformanceSuite {
  if (!isObject(json)) throw new Error("the suite must be a JSON object");
  const { suite, version, reference, offsets, cases } = json;
  if (suite !== "anonyma-conformance") throw new Error('"suite" must be "anonyma-conformance"');
  if (typeof version !== "string" || typeof reference !== "string") {
    throw new Error('"version" and "reference" must be strings');
  }
  if (offsets !== "code-points") throw new Error('"offsets" must be "code-points"');
  if (!Array.isArray(cases)) throw new Error('"cases" must be an array');

  const seen = new Set<string>();
  const parsed = cases.map((entry: unknown, index): ConformanceCase => {
    if (!isObject(entry)) throw new Error(`case ${String(index)} must be an object`);
    const { id, description, op, requires, input, expected } = entry;
    if (typeof id !== "string" || id === "") throw new Error(`case ${String(index)} has no id`);
    if (seen.has(id)) throw new Error(`duplicate case id "${id}"`);
    seen.add(id);
    if (typeof description !== "string") throw new Error(`${id}: "description" must be a string`);
    if (!isOperation(op)) throw new Error(`${id}: unknown operation ${JSON.stringify(op)}`);
    if (
      !Array.isArray(requires) ||
      requires.length === 0 ||
      !requires.every((item) => typeof item === "string")
    ) {
      throw new Error(`${id}: "requires" must be a non-empty list of capabilities`);
    }
    if (!isObject(input) || !isObject(expected)) {
      throw new Error(`${id}: "input" and "expected" must be objects`);
    }
    return { id, description, op, requires: requires, input, expected };
  });

  return { suite, version, reference, offsets, cases: parsed };
}

/**
 * Read and parse the suite shipped with this package.
 *
 * @param url - Another suite file to read instead.
 * @returns The suite.
 */
export function loadSuite(url: URL = SUITE_URL): ConformanceSuite {
  return parseSuite(JSON.parse(readFileSync(url, "utf8")) as unknown);
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/** Deep equality of JSON values; the order of object members does not matter. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every((item, i) => jsonEqual(item, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const keys = Object.keys(a);
    return (
      keys.length === Object.keys(b).length &&
      keys.every((key) => Object.hasOwn(b, key) && jsonEqual(a[key], b[key]))
    );
  }
  return false;
}

function show(value: unknown): string {
  // JSON.stringify() returns undefined for undefined and functions.
  const json = JSON.stringify(value) as string | undefined;
  return json ?? String(value);
}

/** Pairs sorted by key then value, so that two lists compare as sets. */
function sortedPairs(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  return [...(value as unknown[])].sort((a, b) => {
    const left = show(a);
    const right = show(b);
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

function compareMatches(expected: unknown, actual: unknown, problems: string[]): void {
  if (!Array.isArray(expected) || !Array.isArray(actual)) {
    problems.push(`matches: expected ${show(expected)}, got ${show(actual)}`);
    return;
  }
  if (expected.length !== actual.length) {
    problems.push(`expected ${String(expected.length)} matches, got ${String(actual.length)}`);
  }
  const length = Math.min(expected.length, actual.length);
  for (let i = 0; i < length; i++) {
    const want: unknown = expected[i];
    const got: unknown = actual[i];
    if (!isObject(want) || !isObject(got)) {
      problems.push(`match ${String(i)}: expected ${show(want)}, got ${show(got)}`);
      continue;
    }
    for (const key of ["category", "detector", "value", "start", "end", "residual"]) {
      if (!Object.hasOwn(want, key)) continue;
      if (want[key] !== got[key]) {
        problems.push(
          `match ${String(i)} ${key}: expected ${show(want[key])}, got ${show(got[key])}`,
        );
      }
    }
    const confidence = got["confidence"];
    if (
      typeof confidence !== "number" ||
      Math.abs(confidence - Number(want["confidence"])) > CONFIDENCE_TOLERANCE
    ) {
      problems.push(
        `match ${String(i)} confidence: expected ${show(want["confidence"])}, got ${show(confidence)}`,
      );
    }
  }
  for (let i = length; i < actual.length; i++) {
    problems.push(`unexpected match ${show(actual[i])}`);
  }
  for (let i = length; i < expected.length; i++) {
    problems.push(`missing match ${show(expected[i])}`);
  }
}

/**
 * Compare the result of a case with its expected value.
 *
 * @param testCase - The case.
 * @param actual - What the implementation returned.
 * @returns The differences; empty when the case passes.
 */
export function compareResult(testCase: ConformanceCase, actual: unknown): string[] {
  const problems: string[] = [];
  const { expected } = testCase;
  if (!isObject(actual)) return [`expected an object, got ${show(actual)}`];

  switch (testCase.op) {
    case "detect":
      compareMatches(expected["matches"], actual["matches"], problems);
      return problems;
    case "scan":
      compareMatches(expected["spans"], actual["spans"], problems);
      return problems;
    case "anonymize": {
      const pattern = expected["textPattern"];
      if (typeof pattern === "string") {
        const text = actual["text"];
        if (typeof text !== "string" || !new RegExp(pattern).test(text)) {
          problems.push(`text ${show(text)} does not match /${pattern}/`);
        }
        return problems;
      }
      break;
    }
    case "receipt.issue": {
      const want = expected["receipt"];
      const got = actual["receipt"];
      if (!isObject(want) || !isObject(got)) return [`receipt: got ${show(got)}`];
      for (const [key, value] of Object.entries(want)) {
        if (!jsonEqual(value, got[key])) {
          problems.push(`receipt.${key}: expected ${show(value)}, got ${show(got[key])}`);
        }
      }
      if (actual["verified"] !== true) problems.push("the issued receipt does not verify");
      return problems;
    }
    default:
      break;
  }

  // Every other operation: each expected member must be equal; mappings and
  // vault contents compare as sets.
  for (const [key, value] of Object.entries(expected)) {
    const setLike = key === "mapping" || key === "vault";
    const want = setLike ? sortedPairs(value) : value;
    const got = setLike ? sortedPairs(actual[key]) : actual[key];
    if (!jsonEqual(want, got)) problems.push(`${key}: expected ${show(want)}, got ${show(got)}`);
  }
  return problems;
}

/**
 * Run one case.
 *
 * @param testCase - The case.
 * @param adapter - The implementation.
 * @returns The outcome.
 */
export async function runCase(testCase: ConformanceCase, adapter: Adapter): Promise<CaseOutcome> {
  const missing = testCase.requires.filter((capability) => !adapter.provides(capability));
  if (missing.length > 0) return { id: testCase.id, status: "skipped", missing };
  let actual: unknown;
  try {
    actual = await adapter.run(testCase);
  } catch (error) {
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    return { id: testCase.id, status: "failed", problems: [`threw ${message}`] };
  }
  const problems = compareResult(testCase, actual);
  return problems.length === 0
    ? { id: testCase.id, status: "passed" }
    : { id: testCase.id, status: "failed", problems };
}

/**
 * Run every case of a suite.
 *
 * @param suite - The suite.
 * @param adapter - The implementation.
 * @returns The report.
 */
export async function runSuite(suite: ConformanceSuite, adapter: Adapter): Promise<SuiteReport> {
  const outcomes: CaseOutcome[] = [];
  for (const testCase of suite.cases) outcomes.push(await runCase(testCase, adapter));
  const count = (status: CaseOutcome["status"]): number =>
    outcomes.filter((outcome) => outcome.status === status).length;
  return {
    adapter: adapter.name,
    passed: count("passed"),
    failed: count("failed"),
    skipped: count("skipped"),
    outcomes,
  };
}

// ---------------------------------------------------------------------------
// Offsets
// ---------------------------------------------------------------------------

/**
 * Convert an offset in UTF-16 code units (JavaScript string indices) to
 * Unicode code points, the unit of the suite.
 *
 * @param text - The text the offset points into.
 * @param index - The UTF-16 offset.
 * @returns The offset in code points.
 */
export function utf16ToCodePoints(text: string, index: number): number {
  let points = 0;
  for (let at = 0; at < index; at++) {
    const unit = text.charCodeAt(at);
    // The high half of a surrogate pair is followed by its low half: count the pair once.
    if (unit >= 0xd800 && unit <= 0xdbff && at + 1 < index) {
      const next = text.charCodeAt(at + 1);
      if (next >= 0xdc00 && next <= 0xdfff) at++;
    }
    points++;
  }
  return points;
}
