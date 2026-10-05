/**
 * @module ai/json
 * @description Structure-preserving sanitization of JSON values. The result
 * has the same nesting and the same array lengths as the input; what changes
 * is the content of string values, of long numbers, of values under key rules
 * and of object keys in which the pipeline detects something. The input is
 * never mutated. An object that is referenced more than once is processed
 * once and stays shared in the result.
 */

import { AsyncStrategyError, ValidationError } from "../errors.js";
import type { AuditFieldEntry } from "../audit/types.js";
import type { Pipeline, ReplaceContext } from "../engine/types.js";
import { parseJsonLossless, stringifyJsonLossless } from "../internal/json-numbers.js";

/**
 * Forces a category onto everything stored under a matching key, whether or
 * not a detector recognises it: the value itself, and every string, number
 * and boolean inside it when the value is an array or an object.
 */
export interface KeyRule {
  /**
   * What the key has to match: a string is compared with the key name
   * case-insensitively, a RegExp is tested against the key name.
   */
  readonly match: string | RegExp;
  /** The category the value is treated as. It selects the replacer. */
  readonly category: string;
}

/**
 * Options accepted by {@link sanitizeJson} and {@link sanitizeJsonAsync}.
 */
export interface JsonSanitizeOptions {
  /** The pipeline applied to every string value. */
  readonly pipeline: Pipeline;
  /** Keys whose values are replaced whole. */
  readonly keyRules?: readonly KeyRule[];
  /** Keys whose values are copied untouched, such as `role` or `type` in chat messages. */
  readonly skipKeys?: readonly string[];
  /**
   * Decides, member by member, whether a value is copied untouched: it
   * receives the key and the object that holds it. Use it for values that
   * must stay byte for byte what they are, such as a signature or a base64
   * payload. Unlike `skipKeys`, what it exempts is listed in
   * {@link JsonSanitizeResult.skipped}.
   */
  readonly skipMember?: (key: string, parent: Readonly<Record<string, unknown>>) => boolean;
  /**
   * Keys whose string values contain a JSON document (for example the
   * `arguments` of a tool call). The document is parsed, sanitized and
   * serialised again. A document in which nothing is replaced is returned as
   * it was written. A value that is not valid JSON is treated as text.
   */
  readonly jsonStringKeys?: readonly string[];
  /**
   * What happens to an object key in which the pipeline detects something,
   * such as the address in `{ "alice@example.com": { … } }`.
   *
   * - `"replace"` (default): the key is rewritten with the pipeline, like a
   *   value. Two keys that become equal are told apart with `#2`, `#3`, ….
   * - `"flag"`: the key is left as it is and only listed in
   *   {@link JsonSanitizeResult.flaggedKeys}.
   */
  readonly keys?: "replace" | "flag";
  /**
   * An integer with at least this many digits is scanned as text, and replaced
   * by a string when a detector matches it. Other numbers are never scanned. The default of `12` covers card
   * and account numbers and leaves timestamps, counters and phone-length
   * numbers alone; use a key rule for those. `0` scans every number,
   * `Infinity` none.
   */
  readonly numberDigits?: number;
  /** Deepest nesting accepted. Defaults to `512`. */
  readonly maxDepth?: number;
  /** Name recorded as the applied rule in {@link JsonSanitizeResult.fields}. Defaults to the category. */
  readonly ruleName?: (category: string) => string;
  /**
   * Prefix of strings that stand for numbers, as produced by the lossless JSON parser.
   * @internal
   */
  readonly rawNumberMarker?: string;
}

/**
 * Result of sanitizing a JSON value.
 */
export interface JsonSanitizeResult<T> {
  /** A deep copy of the input with the same structure and sanitized content. */
  readonly value: T;
  /** What was replaced where, without any of the replaced text. */
  readonly fields: readonly AuditFieldEntry[];
  /** Total number of replacements, replaced keys included. */
  readonly replaced: number;
  /**
   * JSON Pointers of the members whose key contained something the pipeline
   * detects. With `keys: "replace"` a pointer shows the new key; with
   * `keys: "flag"` the key is unchanged, so the pointer holds what was detected.
   */
  readonly flaggedKeys: readonly string[];
  /**
   * JSON Pointers of what was not inspected: objects that are not plain
   * (dates, maps, class instances), which are copied by reference; functions,
   * which are left out; and members that `skipMember` exempted.
   */
  readonly skipped: readonly string[];
}

/** One step of a JSON Pointer. A key that is replaced changes for every pointer through it. */
interface PathNode {
  readonly parent: PathNode | undefined;
  name: string;
}

/** A value that still has to be transformed, and where the result goes. */
interface Leaf {
  readonly node: PathNode;
  readonly text: string;
  /** `true` for an object key, whose replacement renames the member. */
  readonly isKey: boolean;
  /** Category forced by a key rule. */
  readonly forced?: string;
  /** Leaves of a nested JSON document found in this string. */
  readonly nested?: { readonly leaves: Leaf[]; readonly finish: (changed: boolean) => string };
  readonly assign: (value: string) => void;
}

/** An object of the result, whose members are added once their keys are final. */
interface PendingObject {
  readonly copy: Record<string, unknown>;
  readonly members: { readonly node: PathNode; value: unknown }[];
}

interface Plan {
  readonly root: { value: unknown };
  readonly leaves: Leaf[];
  readonly objects: PendingObject[];
  readonly flagged: PathNode[];
  readonly skipped: string[];
}

const NO_CATEGORY = "\0";
const DEFAULT_NUMBER_DIGITS = 12;
const INTEGER = /^-?\d+$/;

function isPlainObject(value: object): value is Record<string, unknown> {
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function pointer(node: PathNode): string {
  const segments: string[] = [];
  let at = node;
  while (at.parent !== undefined) {
    segments.push(at.name.replace(/~/g, "~0").replace(/\//g, "~1"));
    at = at.parent;
  }
  // `at` is now the root, whose name is the pointer everything hangs under.
  return segments.length === 0 ? at.name : `${at.name}/${segments.reverse().join("/")}`;
}

function setOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  // A plain assignment to "__proto__" would replace the prototype instead of creating a member.
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/** A deep copy of plain data; anything else is kept by reference. */
function plainCopy(value: unknown, seen: Map<object, unknown>): unknown {
  if (typeof value !== "object" || value === null) return value;
  const known = seen.get(value);
  if (known !== undefined) return known;
  if (Array.isArray(value)) {
    const copy: unknown[] = new Array<unknown>(value.length);
    seen.set(value, copy);
    for (const index of value.keys()) {
      if (index in value) copy[index] = plainCopy(value[index], seen);
    }
    return copy;
  }
  if (!isPlainObject(value)) return value;
  const copy: Record<string, unknown> = {};
  seen.set(value, copy);
  for (const key of Object.keys(value)) setOwn(copy, key, plainCopy(value[key], seen));
  return copy;
}

interface Shared {
  readonly options: JsonSanitizeOptions;
  readonly skipKeys: ReadonlySet<string>;
  readonly jsonKeys: ReadonlySet<string>;
  readonly keyRules: readonly { readonly category: string; test: (key: string) => boolean }[];
  /** Whether the pipeline detects something in a key, per distinct key. */
  readonly keyTests: Map<string, boolean>;
  /** Category forced by the key rules, per distinct key. */
  readonly forcedByKey: Map<string, string | undefined>;
}

function prepare(options: JsonSanitizeOptions): Shared {
  const { numberDigits } = options;
  if (numberDigits !== undefined && !(numberDigits >= 0)) {
    throw new ValidationError("numberDigits", "must be a non-negative number");
  }
  const keys: unknown = options.keys;
  if (keys !== undefined && keys !== "replace" && keys !== "flag") {
    throw new ValidationError("keys", 'must be "replace" or "flag"');
  }
  return {
    options,
    skipKeys: new Set(options.skipKeys ?? []),
    jsonKeys: new Set(options.jsonStringKeys ?? []),
    keyRules: (options.keyRules ?? []).map((rule) => {
      if (typeof rule.match === "string") {
        const expected = rule.match.toLowerCase();
        return { category: rule.category, test: (key: string) => key.toLowerCase() === expected };
      }
      const pattern = new RegExp(rule.match.source, rule.match.flags.replace(/[gy]/g, ""));
      return { category: rule.category, test: (key: string) => pattern.test(key) };
    }),
    keyTests: new Map(),
    forcedByKey: new Map(),
  };
}

function buildPlan(
  input: unknown,
  shared: Shared,
  base: PathNode,
  depthOffset: number,
  marker: string | undefined,
): Plan {
  const { options, skipKeys, jsonKeys, keyRules, keyTests, forcedByKey } = shared;
  const { pipeline, skipMember, maxDepth = 512, numberDigits = DEFAULT_NUMBER_DIGITS } = options;
  const replaceKeys = options.keys !== "flag";

  const plan: Plan = {
    root: { value: undefined },
    leaves: [],
    objects: [],
    flagged: [],
    skipped: [],
  };
  const ancestors = new Set<object>();
  /**
   * Copies of objects already visited, per forced category, so that a shared
   * object is processed once and stays shared — but never reused where a key
   * rule asks for another treatment.
   */
  const copies = new Map<string, Map<object, unknown>>();
  const untouched = new Map<object, unknown>();

  function forcedFor(key: string): string | undefined {
    if (keyRules.length === 0) return undefined;
    if (!forcedByKey.has(key)) {
      forcedByKey.set(key, keyRules.find((rule) => rule.test(key))?.category);
    }
    return forcedByKey.get(key);
  }

  function detectsInKey(key: string): boolean {
    let hit = keyTests.get(key);
    if (hit === undefined) {
      hit = key.length > 0 && pipeline.test(key);
      keyTests.set(key, hit);
    }
    return hit;
  }

  /** Scan the digits of a number, or of a marked string that stands for one. */
  function visitNumber(
    text: string,
    node: PathNode,
    forced: string | undefined,
    assign: (value: unknown) => void,
  ): void {
    if (forced !== undefined) {
      plan.leaves.push({ node, text, isKey: false, forced, assign });
      return;
    }
    // Only integers: the digits of a fraction or of a float's mantissa are noise.
    if (!INTEGER.test(text)) return;
    const digits = text.startsWith("-") ? text.length - 1 : text.length;
    if (digits >= numberDigits) plan.leaves.push({ node, text, isKey: false, assign });
  }

  function visit(
    value: unknown,
    node: PathNode,
    key: string | undefined,
    inherited: string | undefined,
    depth: number,
    assign: (value: unknown) => void,
  ): void {
    if (key !== undefined && skipKeys.has(key)) {
      assign(plainCopy(value, untouched));
      return;
    }
    const forced = (key === undefined ? undefined : forcedFor(key)) ?? inherited;

    if (typeof value === "string") {
      assign(value);
      if (marker !== undefined && value.startsWith(marker)) {
        visitNumber(value.slice(marker.length), node, forced, assign);
        return;
      }
      if (forced === undefined && key !== undefined && jsonKeys.has(key)) {
        let parsed: ReturnType<typeof parseJsonLossless> | undefined;
        try {
          parsed = parseJsonLossless(value);
        } catch {
          parsed = undefined;
        }
        if (parsed !== undefined && typeof parsed.value === "object" && parsed.value !== null) {
          const inner = parsed.marker;
          const nested = buildPlan(parsed.value, shared, node, depth, inner);
          plan.flagged.push(...nested.flagged);
          plan.leaves.push({
            node,
            text: value,
            isKey: false,
            nested: {
              leaves: nested.leaves,
              // A document in which nothing was replaced is kept exactly as it was written.
              finish: (changed) =>
                changed ? stringifyJsonLossless(materialise(nested), inner) : value,
            },
            assign,
          });
          return;
        }
      }
      plan.leaves.push({
        node,
        text: value,
        isKey: false,
        ...(forced !== undefined ? { forced } : {}),
        assign,
      });
      return;
    }

    if (typeof value === "number") {
      assign(value);
      visitNumber(String(value), node, forced, assign);
      return;
    }
    if (typeof value === "boolean") {
      assign(value);
      if (forced !== undefined) {
        plan.leaves.push({ node, text: String(value), isKey: false, forced, assign });
      }
      return;
    }
    if (typeof value === "function") {
      // Not JSON. Above all, a `toJSON` copied into the result would serialise the original.
      plan.skipped.push(pointer(node));
      assign(undefined);
      return;
    }
    if (typeof value !== "object" || value === null) {
      assign(value);
      return;
    }

    if (ancestors.has(value)) throw new ValidationError("value", "contains a circular reference");
    const cacheKey = forced ?? NO_CATEGORY;
    let cache = copies.get(cacheKey);
    if (cache === undefined) {
      cache = new Map();
      copies.set(cacheKey, cache);
    }
    if (cache.has(value)) {
      assign(cache.get(value));
      return;
    }
    if (depth >= maxDepth) throw new ValidationError("value", "is nested deeper than maxDepth");

    if (Array.isArray(value)) {
      const copy: unknown[] = new Array<unknown>(value.length);
      cache.set(value, copy);
      assign(copy);
      ancestors.add(value);
      for (const index of (value as unknown[]).keys()) {
        // A hole stays a hole.
        if (!(index in value)) continue;
        const child: PathNode = { parent: node, name: String(index) };
        visit(value[index], child, undefined, forced, depth + 1, (next) => {
          copy[index] = next;
        });
      }
      ancestors.delete(value);
      return;
    }

    if (!isPlainObject(value)) {
      plan.skipped.push(pointer(node));
      assign(value);
      return;
    }

    const pending: PendingObject = { copy: {}, members: [] };
    plan.objects.push(pending);
    cache.set(value, pending.copy);
    assign(pending.copy);
    ancestors.add(value);
    for (const memberKey of Object.keys(value)) {
      const child: PathNode = { parent: node, name: memberKey };
      const member = { node: child, value: undefined as unknown };
      pending.members.push(member);
      if (skipMember?.(memberKey, value) === true) {
        plan.skipped.push(pointer(child));
        member.value = plainCopy(value[memberKey], untouched);
        continue;
      }
      if (detectsInKey(memberKey)) {
        plan.flagged.push(child);
        if (replaceKeys) {
          plan.leaves.push({
            node: child,
            text: memberKey,
            isKey: true,
            assign: (renamed) => {
              child.name = unusedName(pending, child, renamed);
            },
          });
        }
      }
      visit(value[memberKey], child, memberKey, forced, depth + 1, (next) => {
        member.value = next;
      });
    }
    ancestors.delete(value);
  }

  visit(input, base, undefined, undefined, depthOffset, (next) => {
    plan.root.value = next;
  });
  return plan;
}

/** `name`, or `name#2`, `name#3`, … when another member of the object already has it. */
function unusedName(object: PendingObject, self: PathNode, name: string): string {
  const taken = new Set<string>();
  for (const member of object.members) if (member.node !== self) taken.add(member.node.name);
  if (!taken.has(name)) return name;
  let counter = 2;
  while (taken.has(`${name}#${String(counter)}`)) counter++;
  return `${name}#${String(counter)}`;
}

/** Give every object of the result its members, under their final keys, in the original order. */
function materialise(plan: Plan): unknown {
  for (const object of plan.objects) {
    for (const member of object.members) setOwn(object.copy, member.node.name, member.value);
  }
  return plan.root.value;
}

class Recorder {
  readonly #entries = new Map<string, AuditFieldEntry & { count: number }>();
  readonly #ruleName: (category: string) => string;
  /** Results per distinct string, so that a repeated value costs one scan. */
  public readonly cache = new Map<
    string,
    { readonly text: string; readonly spans: readonly { category: string; detector: string }[] }
  >();
  public replaced = 0;
  public ordinal = 0;

  public constructor(ruleName: ((category: string) => string) | undefined) {
    this.#ruleName = ruleName ?? ((category): string => category);
  }

  public add(node: PathNode, category: string, detector: string): void {
    this.replaced++;
    const path = pointer(node);
    const key = `${path}\0${category}\0${detector}`;
    const entry = this.#entries.get(key);
    if (entry === undefined) {
      this.#entries.set(key, {
        path,
        category,
        detector,
        rule: this.#ruleName(category),
        count: 1,
      });
    } else {
      entry.count++;
    }
  }

  public fields(): AuditFieldEntry[] {
    return [...this.#entries.values()];
  }
}

function forcedContext(leaf: Leaf, forced: string, recorder: Recorder): ReplaceContext {
  recorder.add(leaf.node, forced, "key-rule");
  return {
    category: forced,
    detector: "key-rule",
    confidence: 1,
    start: 0,
    end: leaf.text.length,
    ordinal: recorder.ordinal++,
    residual: false,
  };
}

/** Record the spans of a scanned leaf and store its replacement, if it has one. */
function settle(
  leaf: Leaf,
  result: {
    readonly text: string;
    readonly spans: readonly { category: string; detector: string }[];
  },
  recorder: Recorder,
): void {
  if (result.spans.length === 0) return;
  // A key is renamed first, so that the record carries the new key and not what was detected.
  if (leaf.isKey) leaf.assign(result.text);
  for (const span of result.spans) recorder.add(leaf.node, span.category, span.detector);
  recorder.ordinal += result.spans.length;
  if (!leaf.isKey) leaf.assign(result.text);
}

function runSync(leaves: readonly Leaf[], pipeline: Pipeline, recorder: Recorder): void {
  for (const leaf of leaves) {
    if (leaf.nested !== undefined) {
      const before = recorder.replaced;
      runSync(leaf.nested.leaves, pipeline, recorder);
      leaf.assign(leaf.nested.finish(recorder.replaced !== before));
    } else if (leaf.forced !== undefined) {
      const replacement = pipeline.replace(leaf.text, forcedContext(leaf, leaf.forced, recorder));
      if (typeof replacement !== "string") {
        void Promise.resolve(replacement).catch(() => undefined);
        throw new AsyncStrategyError(leaf.forced);
      }
      leaf.assign(replacement);
    } else {
      let result = recorder.cache.get(leaf.text);
      if (result === undefined) {
        result = pipeline.transform(leaf.text);
        recorder.cache.set(leaf.text, result);
      }
      settle(leaf, result, recorder);
    }
  }
}

async function runAsync(
  leaves: readonly Leaf[],
  pipeline: Pipeline,
  recorder: Recorder,
): Promise<void> {
  for (const leaf of leaves) {
    if (leaf.nested !== undefined) {
      const before = recorder.replaced;
      await runAsync(leaf.nested.leaves, pipeline, recorder);
      leaf.assign(leaf.nested.finish(recorder.replaced !== before));
    } else if (leaf.forced !== undefined) {
      leaf.assign(await pipeline.replace(leaf.text, forcedContext(leaf, leaf.forced, recorder)));
    } else {
      let result = recorder.cache.get(leaf.text);
      if (result === undefined) {
        result = await pipeline.transformAsync(leaf.text);
        recorder.cache.set(leaf.text, result);
      }
      settle(leaf, result, recorder);
    }
  }
}

function finish<T>(plan: Plan, recorder: Recorder): JsonSanitizeResult<T> {
  return {
    value: materialise(plan) as T,
    fields: recorder.fields(),
    replaced: recorder.replaced,
    flaggedKeys: plan.flagged.map(pointer),
    skipped: plan.skipped,
  };
}

/**
 * Sanitize every string in a JSON value with a pipeline whose replacers are
 * synchronous.
 *
 * @param value - Any JSON-serialisable value. It is not mutated.
 * @param options - The pipeline and optional key rules.
 * @returns A structural copy with sanitized content, and a PII-free account of what was replaced.
 * @throws {@link ValidationError} When the value contains a cycle or is nested deeper than
 *   `maxDepth`, or an option is invalid.
 * @throws {@link AsyncStrategyError} When a replacer is asynchronous.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { sanitizeJson } from "anonyma/ai";
 *
 * const { value, fields } = sanitizeJson(
 *   { user: { email: "alice@example.com", password: "hunter2" }, note: "call 555-867-5309" },
 *   { pipeline: compilePipeline(), keyRules: [{ match: /password|secret/i, category: "credential" }] },
 * );
 * // value:  { user: { email: "[REDACTED]", password: "[REDACTED]" }, note: "call [REDACTED]" }
 * // fields: [{ path: "/user/email", category: "email", detector: "email", rule: "email", count: 1 }, …]
 * ```
 */
export function sanitizeJson<T>(value: T, options: JsonSanitizeOptions): JsonSanitizeResult<T> {
  const plan = buildPlan(
    value,
    prepare(options),
    { parent: undefined, name: "" },
    0,
    options.rawNumberMarker,
  );
  const recorder = new Recorder(options.ruleName);
  runSync(plan.leaves, options.pipeline, recorder);
  return finish(plan, recorder);
}

/**
 * Asynchronous counterpart of {@link sanitizeJson} for pipelines with
 * asynchronous replacers. Values are processed one at a time, in document
 * order.
 *
 * @param value - Any JSON-serialisable value. It is not mutated.
 * @param options - The pipeline and optional key rules.
 * @returns A structural copy with sanitized content, and a PII-free account of what was replaced.
 * @throws {@link ValidationError} When the value contains a cycle or is nested deeper than
 *   `maxDepth`, or an option is invalid.
 *
 * @example
 * ```ts
 * const { value } = await sanitizeJsonAsync(record, { pipeline });
 * ```
 */
export async function sanitizeJsonAsync<T>(
  value: T,
  options: JsonSanitizeOptions,
): Promise<JsonSanitizeResult<T>> {
  const plan = buildPlan(
    value,
    prepare(options),
    { parent: undefined, name: "" },
    0,
    options.rawNumberMarker,
  );
  const recorder = new Recorder(options.ruleName);
  await runAsync(plan.leaves, options.pipeline, recorder);
  return finish(plan, recorder);
}
