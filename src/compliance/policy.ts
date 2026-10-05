/**
 * @module compliance/policy
 * @description The policy document parser: turns untrusted JSON into a checked
 * {@link Policy}, reporting every structural problem and every requirement of
 * an extended regulation that the document violates.
 */

import { PolicyError } from "../errors.js";
import { BUILTIN_CATEGORIES } from "../engine/builtin.js";
import type { PatternSpec, PipelineSpec, StrategySpec } from "../engine/types.js";
import type { PiiCategory } from "../types.js";
import { REGULATIONS, isRegulationId } from "./regulations.js";
import { checkRequirement, describeStrategy } from "./traits.js";
import type { TokenizationInfo } from "./traits.js";
import type { LegalReference, Policy, PolicyDocument, PolicyIssue, RegulationId } from "./types.js";

type Json = Record<string, unknown>;

const REDACT: StrategySpec = Object.freeze({ strategy: "redact" });

const TOP_LEVEL = new Set([
  "version",
  "id",
  "description",
  "extends",
  "categories",
  "defaultStrategy",
  "rules",
  "patterns",
  "minConfidence",
  "allow",
  "aggressive",
  "overlap",
]);

/** Allowed options per strategy, with the JSON type each must have. */
const STRATEGY_OPTIONS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  redact: { label: "string" },
  mask: {
    maskChar: "string",
    keepLeading: "count",
    keepTrailing: "count",
    preserveFormat: "boolean",
  },
  pseudonymize: { seed: "string", prefix: "string" },
  hash: { truncate: "count", pepper: "string" },
  generalize: { bucketSize: "count" },
  synthesize: { seed: "string", locale: "string", category: "string" },
  tokenize: {},
  encrypt: {},
};

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCategory(value: unknown): value is PiiCategory {
  return typeof value === "string" && (BUILTIN_CATEGORIES as readonly string[]).includes(value);
}

function escapePointer(segment: string): string {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Options accepted by {@link checkPolicy} and {@link parsePolicy}.
 */
export interface PolicyOptions {
  /**
   * The provider that will back `tokenize` strategies. Requirements such as
   * "not derived from the value" depend on it.
   */
  readonly tokenization?: TokenizationInfo;
}

/**
 * Result of {@link checkPolicy}.
 */
export interface PolicyCheck {
  /** The checked policy; absent when the document has errors. */
  readonly policy?: Policy;
  /** Every problem found, errors first. */
  readonly issues: readonly PolicyIssue[];
}

/**
 * Check a policy document without throwing.
 *
 * @param input - The document, typically the result of `JSON.parse`.
 * @param options - What is known about the runtime the policy will run in.
 * @returns The policy when there are no errors, and every issue found.
 *
 * @example
 * ```ts
 * const { policy, issues } = checkPolicy({
 *   version: 1,
 *   id: "payments",
 *   extends: ["pci-dss"],
 *   rules: { "credit-card": { strategy: "mask", keepLeading: 8, keepTrailing: 4 } },
 * });
 * // policy === undefined
 * // issues[0].code === "requirement-violated"
 * // issues[0].reference.citation === "PCI DSS v4.0.1 Req. 3.4.1"
 * ```
 */
export function checkPolicy(input: unknown, options: PolicyOptions = {}): PolicyCheck {
  const issues: PolicyIssue[] = [];
  const error = (path: string, code: string, message: string, reference?: LegalReference): void => {
    issues.push({
      severity: "error",
      path,
      code,
      message,
      ...(reference !== undefined ? { reference } : {}),
    });
  };
  const warning = (
    path: string,
    code: string,
    message: string,
    reference?: LegalReference,
  ): void => {
    issues.push({
      severity: "warning",
      path,
      code,
      message,
      ...(reference !== undefined ? { reference } : {}),
    });
  };

  if (!isObject(input)) {
    error("", "not-an-object", "A policy document must be a JSON object.");
    return { issues };
  }

  for (const key of Object.keys(input)) {
    if (!TOP_LEVEL.has(key))
      error(
        `/${escapePointer(key)}`,
        "unknown-member",
        "This member is not part of the policy format.",
      );
  }
  if (input["version"] !== 1)
    error("/version", "unsupported-version", "The only supported policy version is 1.");

  const id = input["id"];
  if (typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) {
    error(
      "/id",
      "invalid-id",
      "The id must be 1-64 characters of letters, digits, '.', '_' and '-'.",
    );
  }
  const description = input["description"];
  if (description !== undefined && typeof description !== "string") {
    error("/description", "invalid-type", "The description must be a string.");
  }

  // --- extends ---------------------------------------------------------------
  const regulations: RegulationId[] = [];
  const extended = input["extends"];
  if (extended !== undefined) {
    if (!Array.isArray(extended)) {
      error("/extends", "invalid-type", "extends must be an array of regulation identifiers.");
    } else {
      for (const [index, entry] of (extended as unknown[]).entries()) {
        if (!isRegulationId(entry)) {
          error(
            `/extends/${String(index)}`,
            "unknown-regulation",
            `Known regulations are: ${Object.keys(REGULATIONS).join(", ")}.`,
          );
        } else if (!regulations.includes(entry)) {
          regulations.push(entry);
        }
      }
    }
  }

  // --- categories -------------------------------------------------------------
  const readCategories = (value: unknown, path: string): PiiCategory[] => {
    const out: PiiCategory[] = [];
    if (value === undefined) return out;
    if (!Array.isArray(value)) {
      error(path, "invalid-type", "This member must be an array of category names.");
      return out;
    }
    for (const [index, entry] of (value as unknown[]).entries()) {
      if (isCategory(entry)) out.push(entry);
      else
        error(`${path}/${String(index)}`, "unknown-category", "This is not a built-in category.");
    }
    return out;
  };
  let include: PiiCategory[] = [];
  let exclude: PiiCategory[] = [];
  const categoriesMember = input["categories"];
  if (categoriesMember !== undefined) {
    if (!isObject(categoriesMember)) {
      error(
        "/categories",
        "invalid-type",
        "categories must be an object with include and/or exclude.",
      );
    } else {
      for (const key of Object.keys(categoriesMember)) {
        if (key !== "include" && key !== "exclude") {
          error(
            `/categories/${escapePointer(key)}`,
            "unknown-member",
            "This member is not part of the policy format.",
          );
        }
      }
      include = readCategories(categoriesMember["include"], "/categories/include");
      exclude = readCategories(categoriesMember["exclude"], "/categories/exclude");
    }
  }

  // --- strategies -------------------------------------------------------------
  const readStrategy = (value: unknown, path: string): StrategySpec | undefined => {
    if (!isObject(value)) {
      error(path, "invalid-type", "A strategy must be an object with a strategy name.");
      return undefined;
    }
    const name = value["strategy"];
    const allowed =
      typeof name === "string" && Object.hasOwn(STRATEGY_OPTIONS, name)
        ? STRATEGY_OPTIONS[name]
        : undefined;
    if (allowed === undefined) {
      error(
        `${path}/strategy`,
        "unknown-strategy",
        `Known strategies are: ${Object.keys(STRATEGY_OPTIONS).join(", ")}.`,
      );
      return undefined;
    }
    let valid = true;
    for (const [option, optionValue] of Object.entries(value)) {
      if (option === "strategy") continue;
      const expected = Object.hasOwn(allowed, option) ? allowed[option] : undefined;
      const fits =
        expected === "count"
          ? Number.isInteger(optionValue) && (optionValue as number) >= 0
          : expected !== undefined && typeof optionValue === expected;
      if (!fits) {
        valid = false;
        error(
          `${path}/${escapePointer(option)}`,
          expected === undefined ? "unknown-option" : "invalid-option",
          expected === undefined
            ? `The ${String(name)} strategy has no such option.`
            : `This option must be a ${expected === "count" ? "non-negative integer" : expected}.`,
        );
      }
    }
    return valid ? (Object.freeze({ ...value }) as StrategySpec) : undefined;
  };

  const defaultMember = input["defaultStrategy"];
  const explicitDefault =
    defaultMember === undefined ? undefined : readStrategy(defaultMember, "/defaultStrategy");

  const explicitRules = new Map<string, StrategySpec>();
  const rulesMember = input["rules"];
  if (rulesMember !== undefined) {
    if (!isObject(rulesMember)) {
      error("/rules", "invalid-type", "rules must be an object keyed by category.");
    } else {
      for (const [category, value] of Object.entries(rulesMember)) {
        const strategy = readStrategy(value, `/rules/${escapePointer(category)}`);
        if (strategy !== undefined) explicitRules.set(category, strategy);
      }
    }
  }

  // --- patterns ---------------------------------------------------------------
  const patterns: PatternSpec[] = [];
  const patternsMember = input["patterns"];
  if (patternsMember !== undefined) {
    if (!Array.isArray(patternsMember)) {
      error("/patterns", "invalid-type", "patterns must be an array.");
    } else {
      for (const [index, entry] of (patternsMember as unknown[]).entries()) {
        const path = `/patterns/${String(index)}`;
        if (
          !isObject(entry) ||
          typeof entry["source"] !== "string" ||
          typeof entry["category"] !== "string" ||
          entry["category"] === ""
        ) {
          error(
            path,
            "invalid-pattern",
            "A pattern needs a source string and a non-empty category.",
          );
          continue;
        }
        const flags = entry["flags"];
        const confidence = entry["confidence"];
        if (flags !== undefined && typeof flags !== "string") {
          error(`${path}/flags`, "invalid-type", "flags must be a string.");
          continue;
        }
        if (
          confidence !== undefined &&
          !(typeof confidence === "number" && confidence >= 0 && confidence <= 1)
        ) {
          error(
            `${path}/confidence`,
            "invalid-type",
            "confidence must be a number between 0 and 1.",
          );
          continue;
        }
        try {
          new RegExp(entry["source"], flags ?? "");
        } catch {
          error(
            path,
            "invalid-pattern",
            "The source and flags do not form a valid regular expression.",
          );
          continue;
        }
        patterns.push(
          Object.freeze({
            source: entry["source"],
            category: entry["category"],
            ...(flags !== undefined ? { flags } : {}),
            ...(confidence !== undefined ? { confidence } : {}),
          }),
        );
      }
    }
  }

  // --- scalars ----------------------------------------------------------------
  const minConfidence = input["minConfidence"];
  if (
    minConfidence !== undefined &&
    !(typeof minConfidence === "number" && minConfidence >= 0 && minConfidence <= 1)
  ) {
    error("/minConfidence", "invalid-type", "minConfidence must be a number between 0 and 1.");
  }
  const allow = input["allow"];
  if (
    allow !== undefined &&
    !(Array.isArray(allow) && (allow as unknown[]).every((entry) => typeof entry === "string"))
  ) {
    error("/allow", "invalid-type", "allow must be an array of strings.");
  }
  const aggressive = input["aggressive"];
  if (aggressive !== undefined && typeof aggressive !== "boolean") {
    error("/aggressive", "invalid-type", "aggressive must be a boolean.");
  }
  const overlap = input["overlap"];
  if (overlap !== undefined && overlap !== "cover" && overlap !== "legacy") {
    error("/overlap", "invalid-type", 'overlap must be "cover" or "legacy".');
  }

  // --- effective categories ---------------------------------------------------
  const required = new Map<PiiCategory, RegulationId>();
  for (const regulation of regulations) {
    for (const rule of REGULATIONS[regulation].rules) {
      if (!required.has(rule.category)) required.set(rule.category, regulation);
    }
  }
  for (const [index, category] of exclude.entries()) {
    const regulation = required.get(category);
    if (regulation !== undefined) {
      const rule = REGULATIONS[regulation].rules.find(
        (candidate) => candidate.category === category,
      );
      error(
        `/categories/exclude/${String(index)}`,
        "required-category-excluded",
        `${REGULATIONS[regulation].name} brings "${category}" into scope; it cannot be excluded.`,
        rule?.references[0],
      );
    }
  }
  const wanted =
    regulations.length === 0 && include.length === 0
      ? new Set<PiiCategory>(BUILTIN_CATEGORIES)
      : new Set<PiiCategory>([...required.keys(), ...include]);
  for (const category of exclude) wanted.delete(category);
  const categories = BUILTIN_CATEGORIES.filter((category) => wanted.has(category));

  for (const category of explicitRules.keys()) {
    const known = isCategory(category)
      ? wanted.has(category)
      : patterns.some((pattern) => pattern.category === category);
    if (!known) {
      warning(
        `/rules/${escapePointer(category)}`,
        "unused-rule",
        "No detector of this policy produces this category, so the rule never applies.",
      );
    }
  }

  // --- effective strategies and compliance ------------------------------------
  const defaultStrategy = explicitDefault ?? REDACT;
  const strategies: Record<string, StrategySpec> = {};
  for (const category of categories) {
    const explicit = explicitRules.get(category) ?? explicitDefault;
    const inherited = regulations
      .map(
        (regulation) =>
          REGULATIONS[regulation].rules.find((rule) => rule.category === category)?.recommended,
      )
      .find((recommended) => recommended !== undefined);
    const strategy = explicit ?? inherited ?? REDACT;
    Object.defineProperty(strategies, category, { value: strategy, enumerable: true });

    const path = explicitRules.has(category)
      ? `/rules/${escapePointer(category)}`
      : "/defaultStrategy";
    const traits = describeStrategy(strategy, options.tokenization);
    for (const regulation of regulations) {
      const rule = REGULATIONS[regulation].rules.find(
        (candidate) => candidate.category === category,
      );
      if (rule === undefined) continue;
      for (const reason of checkRequirement(traits, rule.requirement)) {
        error(
          path,
          "requirement-violated",
          `"${strategy.strategy}" is not sufficient for "${category}" under ${REGULATIONS[regulation].name}: ${reason}.`,
          rule.references[0],
        );
      }
    }
    if (strategy.strategy === "generalize") {
      warning(
        path,
        "generalize-non-numeric",
        `"generalize" only shortens numbers; "${category}" values are redacted instead.`,
      );
    }
    if (strategy.strategy === "hash" && strategy.pepper === undefined) {
      warning(
        path,
        "unkeyed-hash",
        "A hash without a pepper can be reversed by enumerating likely values.",
      );
    }
  }
  for (const [category, strategy] of explicitRules) {
    if (!Object.hasOwn(strategies, category)) {
      Object.defineProperty(strategies, category, { value: strategy, enumerable: true });
    }
  }

  // Report each problem once, even when several categories share the default strategy.
  const seen = new Set<string>();
  const unique = issues.filter((issue) => {
    const key = `${issue.severity}\0${issue.path}\0${issue.code}\0${issue.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  unique.sort((a, b) => Number(a.severity === "warning") - Number(b.severity === "warning"));

  if (unique.some((issue) => issue.severity === "error")) return { issues: unique };

  const document: PolicyDocument = Object.freeze({
    version: 1 as const,
    id: id as string,
    ...(typeof description === "string" ? { description } : {}),
    ...(regulations.length > 0 ? { extends: Object.freeze([...regulations]) } : {}),
    ...(include.length > 0 || exclude.length > 0
      ? {
          categories: Object.freeze({
            ...(include.length > 0 ? { include: Object.freeze([...include]) } : {}),
            ...(exclude.length > 0 ? { exclude: Object.freeze([...exclude]) } : {}),
          }),
        }
      : {}),
    ...(explicitDefault !== undefined ? { defaultStrategy: explicitDefault } : {}),
    ...(explicitRules.size > 0 ? { rules: Object.freeze(Object.fromEntries(explicitRules)) } : {}),
    ...(patterns.length > 0 ? { patterns: Object.freeze(patterns) } : {}),
    ...(typeof minConfidence === "number" ? { minConfidence } : {}),
    ...(Array.isArray(allow) ? { allow: Object.freeze([...(allow as string[])]) } : {}),
    ...(typeof aggressive === "boolean" ? { aggressive } : {}),
    ...(overlap === "cover" || overlap === "legacy" ? { overlap } : {}),
  });

  return {
    policy: Object.freeze({
      id: document.id,
      regulations: Object.freeze([...regulations]),
      categories: Object.freeze(categories),
      strategies: Object.freeze(strategies),
      defaultStrategy,
      document,
      warnings: Object.freeze(unique),
    }),
    issues: unique,
  };
}

/**
 * Parse and check a policy document.
 *
 * @param input - The document, typically the result of `JSON.parse`.
 * @param options - What is known about the runtime the policy will run in.
 * @returns The checked {@link Policy}.
 * @throws {@link PolicyError} When the document is malformed or violates a requirement of a
 *   regulation it extends. `issues` lists every problem.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { parsePolicy, policyToSpec } from "anonyma/compliance";
 *
 * const policy = parsePolicy(JSON.parse(await readFile("policy.json", "utf8")));
 * const pipeline = compilePipeline(policyToSpec(policy));
 * ```
 */
export function parsePolicy(input: unknown, options: PolicyOptions = {}): Policy {
  const { policy, issues } = checkPolicy(input, options);
  if (policy === undefined) throw new PolicyError(issues);
  return policy;
}

/**
 * Convert a checked policy into a pipeline specification for
 * `compilePipeline()`.
 *
 * @param policy - A policy returned by {@link parsePolicy} or {@link checkPolicy}.
 * @returns The equivalent {@link PipelineSpec}.
 *
 * @example
 * ```ts
 * const pipeline = compilePipeline(policyToSpec(policy), { tokenization });
 * ```
 */
export function policyToSpec(policy: Policy): PipelineSpec {
  const { document } = policy;
  return {
    categories: policy.categories,
    defaultStrategy: policy.defaultStrategy,
    rules: policy.strategies,
    ...(document.patterns !== undefined ? { patterns: document.patterns } : {}),
    ...(document.minConfidence !== undefined ? { minConfidence: document.minConfidence } : {}),
    ...(document.allow !== undefined ? { allow: document.allow } : {}),
    ...(document.aggressive !== undefined ? { aggressive: document.aggressive } : {}),
    ...(document.overlap !== undefined ? { overlap: document.overlap } : {}),
  };
}

/**
 * The policy document equivalent to a regulation profile with its recommended
 * strategies — a starting point for a custom policy.
 *
 * @param regulation - The regulation to start from.
 * @returns A policy document that extends the regulation.
 *
 * @example
 * ```ts
 * const document = { ...regulationPolicy("hipaa"), id: "clinic", allow: ["noreply@clinic.example"] };
 * const policy = parsePolicy(document);
 * ```
 */
export function regulationPolicy(regulation: RegulationId): PolicyDocument {
  return {
    version: 1,
    id: regulation,
    description: REGULATIONS[regulation].name,
    extends: [regulation],
  };
}
