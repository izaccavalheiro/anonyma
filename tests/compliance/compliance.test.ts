import { describe, expect, it } from "vitest";
import { PolicyError, ValidationError } from "../../src/errors.js";
import { anonymize } from "../../src/anonymize.js";
import { BUILTIN_CATEGORIES, compilePipeline } from "../../src/engine/index.js";
import { PRESET_REGISTRY } from "../../src/presets.js";
import {
  REGULATIONS,
  checkPolicy,
  checkRequirement,
  complianceMatrix,
  describeStrategy,
  getRegulation,
  isRegulationId,
  parsePolicy,
  planErasure,
  policyToSpec,
  regulationPolicy,
} from "../../src/compliance/index.js";
import type { RegulationId } from "../../src/compliance/index.js";
import type { StrategySpec } from "../../src/engine/index.js";

const IDS = Object.keys(REGULATIONS) as RegulationId[];

describe("compliance/regulations", () => {
  it("has a profile for each instrument named in the modernization plan", () => {
    expect(IDS.sort()).toEqual(["ccpa", "gdpr", "hipaa", "lgpd", "pci-dss", "pipeda"]);
    expect(isRegulationId("hipaa")).toBe(true);
    expect(isRegulationId("sox")).toBe(false);
    expect(isRegulationId("constructor")).toBe(false);
    expect(isRegulationId(1)).toBe(false);
    expect(getRegulation("gdpr")).toBe(REGULATIONS.gdpr);
    expect(() => getRegulation("nope" as RegulationId)).toThrow(ValidationError);
  });

  it("cites a provision, with a source, for every rule, gap and general reference", () => {
    for (const profile of Object.values(REGULATIONS)) {
      expect(Object.isFrozen(profile)).toBe(true);
      const references = [
        ...profile.references,
        ...profile.rules.flatMap((rule) => rule.references),
        ...profile.gaps.map((gap) => gap.reference),
        ...(profile.auditTrail ? [profile.auditTrail] : []),
        ...(profile.erasure ? [profile.erasure] : []),
      ];
      expect(references.length).toBeGreaterThan(5);
      for (const reference of references) {
        expect(reference.citation.length, profile.id).toBeGreaterThan(5);
        expect(reference.summary.length, reference.citation).toBeGreaterThan(5);
        expect(reference.url, reference.citation).toMatch(/^https:\/\//);
      }
      expect(profile.gaps.length, profile.id).toBeGreaterThan(0);
      for (const gap of profile.gaps) expect(gap.mitigation.length).toBeGreaterThan(10);
    }
  });

  it("lists each category at most once per profile, and only built-in categories", () => {
    for (const profile of Object.values(REGULATIONS)) {
      const categories = profile.rules.map((rule) => rule.category);
      expect(new Set(categories).size, profile.id).toBe(categories.length);
      for (const category of categories) expect(BUILTIN_CATEGORIES).toContain(category);
    }
  });

  it("is matched by the built-in presets: every category is detected with a sufficient strategy", () => {
    for (const profile of Object.values(REGULATIONS)) {
      const preset = PRESET_REGISTRY[profile.id];
      for (const rule of profile.rules) {
        expect(preset.categories, `${profile.id} detects ${rule.category}`).toContain(
          rule.category,
        );
        const applied =
          preset.rules?.find((candidate) => candidate.category === rule.category)?.strategy ??
          preset.defaultStrategy;
        expect(applied, `${profile.id}/${rule.category}`).toEqual(rule.recommended);
        expect(checkRequirement(describeStrategy(rule.recommended), rule.requirement)).toEqual([]);
      }
    }
  });

  it("maps the HIPAA Safe Harbor identifiers that have a detector to their paragraph", () => {
    const letters = new Map(
      REGULATIONS.hipaa.rules.map((rule) => [
        rule.category,
        /\(([A-R])\)$/.exec(rule.references[0]?.citation ?? "")?.[1],
      ]),
    );
    expect(Object.fromEntries(letters)).toMatchObject({
      name: "A",
      address: "B",
      "date-of-birth": "C",
      phone: "D",
      email: "F",
      ssn: "G",
      "medical-record": "H",
      "health-insurance": "I",
      "credit-card": "J",
      "license-plate": "L",
      url: "N",
      ipv4: "O",
    });
    const gaps = REGULATIONS.hipaa.gaps.map((gap) => gap.reference.citation).join(" ");
    for (const letter of ["(B)", "(C)", "(M)", "(P)"]) expect(gaps).toContain(letter);
  });

  it("produces the mapping matrix from the same data", () => {
    const matrix = complianceMatrix();
    expect(matrix).toHaveLength(
      Object.values(REGULATIONS).reduce((n, profile) => n + profile.rules.length, 0),
    );
    expect(
      matrix.find((row) => row.regulation === "pci-dss" && row.category === "credit-card"),
    ).toEqual({
      regulation: "pci-dss",
      category: "credit-card",
      citations: [
        "PCI DSS v4.0.1 Req. 3.4.1",
        "PCI DSS v4.0.1 Req. 3.5.1",
        "PCI DSS v4.0.1 Req. 3.5.1.1",
      ],
      requirement:
        "keyed if derived from the value; at most 6 leading and 4 trailing characters visible",
      recommended: "mask (keepTrailing: 4)",
    });
    expect(
      matrix.find((row) => row.regulation === "hipaa" && row.category === "ssn")?.requirement,
    ).toBe("not derived from the value; nothing left visible");
    expect(
      matrix.find((row) => row.regulation === "pipeda" && row.category === "name"),
    ).toMatchObject({
      requirement: "clear value removed",
      recommended: "redact",
    });
  });
});

describe("compliance/traits", () => {
  it("describes every strategy", () => {
    const none = { leading: 0, trailing: 0 };
    const cases: [StrategySpec, object][] = [
      [
        { strategy: "redact" },
        { reversible: false, derived: false, keyed: false, linkable: false, revealed: none },
      ],
      [
        { strategy: "mask", keepLeading: 2, keepTrailing: 4 },
        { derived: false, revealed: { leading: 2, trailing: 4 } },
      ],
      [{ strategy: "mask" }, { revealed: none }],
      [{ strategy: "generalize" }, { derived: true, keyed: false, revealed: "all" }],
      [{ strategy: "pseudonymize" }, { derived: false, linkable: false }],
      [
        { strategy: "pseudonymize", seed: "s" },
        { derived: true, keyed: false, linkable: true },
      ],
      [{ strategy: "synthesize" }, { derived: true, keyed: false }],
      [{ strategy: "hash" }, { derived: true, keyed: false, reversible: false }],
      [
        { strategy: "hash", pepper: "p" },
        { derived: true, keyed: true },
      ],
      [{ strategy: "encrypt" }, { reversible: true, derived: true, keyed: true }],
      [{ strategy: "tokenize" }, { reversible: true, derived: true, keyed: true }],
    ];
    for (const [spec, expected] of cases)
      expect(describeStrategy(spec), JSON.stringify(spec)).toMatchObject(expected);
    expect(
      describeStrategy({ strategy: "tokenize" }, { scheme: "session", reversible: true }),
    ).toMatchObject({
      reversible: true,
      derived: false,
      keyed: false,
    });
    expect(
      describeStrategy({ strategy: "tokenize" }, { scheme: "keyed", reversible: false }),
    ).toMatchObject({
      reversible: false,
      derived: true,
      keyed: true,
    });
  });

  it("reports each violated restriction", () => {
    const check = (
      spec: StrategySpec,
      requirement: Parameters<typeof checkRequirement>[1],
    ): number => checkRequirement(describeStrategy(spec), requirement).length;
    expect(
      check(
        { strategy: "redact" },
        {
          irreversible: true,
          notDerived: true,
          keyed: true,
          maxRevealed: { leading: 0, trailing: 0 },
        },
      ),
    ).toBe(0);
    expect(check({ strategy: "encrypt" }, { irreversible: true })).toBe(1);
    expect(check({ strategy: "hash", pepper: "p" }, { notDerived: true })).toBe(1);
    expect(check({ strategy: "hash" }, { keyed: true })).toBe(1);
    expect(check({ strategy: "hash", pepper: "p" }, { keyed: true })).toBe(0);
    expect(
      check(
        { strategy: "mask", keepLeading: 8, keepTrailing: 4 },
        { maxRevealed: { leading: 6, trailing: 4 } },
      ),
    ).toBe(1);
    expect(
      check(
        { strategy: "mask", keepLeading: 6, keepTrailing: 5 },
        { maxRevealed: { leading: 6, trailing: 4 } },
      ),
    ).toBe(1);
    expect(
      check(
        { strategy: "mask", keepLeading: 6, keepTrailing: 4 },
        { maxRevealed: { leading: 6, trailing: 4 } },
      ),
    ).toBe(0);
    expect(check({ strategy: "generalize" }, { maxRevealed: { leading: 0, trailing: 0 } })).toBe(1);
    expect(check({ strategy: "generalize" }, {})).toBe(0);
  });
});

describe("compliance/policy", () => {
  describe("parsePolicy", () => {
    it("builds the effective categories and strategies of a policy that extends regulations", () => {
      const policy = parsePolicy({
        version: 1,
        id: "clinic.eu",
        description: "Clinic support desk",
        extends: ["hipaa", "gdpr", "hipaa"],
        categories: { include: ["api-key"], exclude: ["api-key"] },
      });
      expect(policy.regulations).toEqual(["hipaa", "gdpr"]);
      expect(policy.categories).toContain("cryptocurrency"); // from GDPR
      expect(policy.categories).toContain("license-plate"); // from HIPAA
      expect(policy.categories).not.toContain("api-key");
      expect(policy.strategies["ssn"]).toEqual({ strategy: "redact" }); // the first listed regulation decides
      expect(policy.strategies["cryptocurrency"]).toEqual({ strategy: "pseudonymize" });
      expect(policy.warnings).toEqual([]);
      expect(Object.isFrozen(policy) && Object.isFrozen(policy.document)).toBe(true);
      expect(policy.document).toEqual({
        version: 1,
        id: "clinic.eu",
        description: "Clinic support desk",
        extends: ["hipaa", "gdpr"],
        categories: { include: ["api-key"], exclude: ["api-key"] },
      });
    });

    it("detects everything and redacts when nothing is specified", () => {
      const policy = parsePolicy({ version: 1, id: "default" });
      expect(policy.categories).toEqual([...BUILTIN_CATEGORIES]);
      expect(policy.defaultStrategy).toEqual({ strategy: "redact" });
      expect(new Set(Object.values(policy.strategies).map((s) => s.strategy))).toEqual(
        new Set(["redact"]),
      );
    });

    it("limits detection to included categories when no regulation is extended", () => {
      const policy = parsePolicy({
        version: 1,
        id: "p",
        categories: { include: ["email", "phone"] },
      });
      expect(policy.categories).toEqual(["email", "phone"]);
    });

    it("rejects strategies that fall short of a regulation, citing the provision", () => {
      const violations: [object, string, string][] = [
        [
          {
            extends: ["pci-dss"],
            rules: { "credit-card": { strategy: "mask", keepLeading: 8, keepTrailing: 4 } },
          },
          "/rules/credit-card",
          "PCI DSS v4.0.1 Req. 3.4.1",
        ],
        [
          { extends: ["pci-dss"], rules: { "credit-card": { strategy: "hash" } } },
          "/rules/credit-card",
          "PCI DSS v4.0.1 Req. 3.4.1",
        ],
        [
          { extends: ["hipaa"], defaultStrategy: { strategy: "hash", pepper: "p" } },
          "/defaultStrategy",
          "45 CFR § 164.514(b)(2)(i)(F)",
        ],
        [
          { extends: ["hipaa"], rules: { ssn: { strategy: "mask", keepTrailing: 4 } } },
          "/rules/ssn",
          "45 CFR § 164.514(b)(2)(i)(G)",
        ],
        [
          { extends: ["hipaa"], rules: { email: { strategy: "encrypt" } } },
          "/rules/email",
          "45 CFR § 164.514(b)(2)(i)(F)",
        ],
        [
          { extends: ["gdpr"], rules: { email: { strategy: "pseudonymize", seed: "s" } } },
          "/rules/email",
          "GDPR Art. 4(1)",
        ],
        [
          { extends: ["lgpd"], rules: { "national-id": { strategy: "hash" } } },
          "/rules/national-id",
          "LGPD Art. 5, I",
        ],
        [
          { extends: ["ccpa"], rules: { ssn: { strategy: "synthesize" } } },
          "/rules/ssn",
          "Cal. Civ. Code § 1798.140(ae)",
        ],
        [
          { extends: ["gdpr"], categories: { exclude: ["email"] } },
          "/categories/exclude/0",
          "GDPR Art. 4(1)",
        ],
      ];
      for (const [extra, path, citation] of violations) {
        const { policy, issues } = checkPolicy({ version: 1, id: "p", ...extra });
        expect(policy, JSON.stringify(extra)).toBe(undefined);
        const hit = issues.find((issue) => issue.severity === "error" && issue.path === path);
        expect(hit, JSON.stringify(issues)).toBeDefined();
        expect(hit?.reference?.citation).toBe(citation);
        expect(() => parsePolicy({ version: 1, id: "p", ...extra })).toThrow(PolicyError);
      }
    });

    it("accepts strategies that meet the requirement", () => {
      for (const extra of [
        {
          extends: ["pci-dss"],
          rules: { "credit-card": { strategy: "mask", keepLeading: 6, keepTrailing: 4 } },
        },
        {
          extends: ["pci-dss"],
          rules: { "credit-card": { strategy: "hash", pepper: "k", truncate: 64 } },
        },
        { extends: ["gdpr"], defaultStrategy: { strategy: "encrypt" } },
        { extends: ["gdpr", "lgpd", "pipeda", "ccpa"], defaultStrategy: { strategy: "tokenize" } },
        { extends: ["pipeda"], rules: { name: { strategy: "pseudonymize", seed: "s" } } },
      ]) {
        expect(
          () => parsePolicy({ version: 1, id: "p", ...extra }),
          JSON.stringify(extra),
        ).not.toThrow();
      }
    });

    it("takes the tokenization provider into account", () => {
      const document = {
        version: 1,
        id: "p",
        extends: ["hipaa"],
        defaultStrategy: { strategy: "tokenize" },
      };
      // A token computed from the value is not a permitted re-identification code under 45 CFR 164.514(c).
      expect(() => parsePolicy(document)).toThrow(PolicyError);
      expect(() =>
        parsePolicy(document, { tokenization: { scheme: "keyed", reversible: true } }),
      ).toThrow(PolicyError);
      expect(() =>
        parsePolicy(document, { tokenization: { scheme: "session", reversible: true } }),
      ).not.toThrow();
    });

    it("reports every structural problem with a JSON Pointer", () => {
      const { policy, issues } = checkPolicy({
        version: 2,
        id: "not valid!",
        description: 5,
        typo: true,
        "a/b": 1,
        extends: ["gdpr", "sox"],
        categories: { include: ["email", "emial"], exclude: "x", other: 1 },
        defaultStrategy: { strategy: "shred" },
        rules: {
          email: { strategy: "mask", keepTrailling: 4 },
          phone: { strategy: "mask", keepLeading: -1, maskChar: 5 },
          ssn: "redact",
        },
        patterns: [
          { source: "(", category: "c" },
          { source: "x" },
          { source: "x", category: "c", flags: 1 },
          { source: "x", category: "c", confidence: 2 },
          "nope",
        ],
        minConfidence: 2,
        allow: ["ok", 5],
        aggressive: "yes",
        overlap: "union",
      });
      expect(policy).toBe(undefined);
      const found = issues.map((issue) => `${issue.path} ${issue.code}`);
      for (const expected of [
        "/version unsupported-version",
        "/id invalid-id",
        "/description invalid-type",
        "/typo unknown-member",
        "/a~1b unknown-member",
        "/extends/1 unknown-regulation",
        "/categories/include/1 unknown-category",
        "/categories/exclude invalid-type",
        "/categories/other unknown-member",
        "/defaultStrategy/strategy unknown-strategy",
        "/rules/email/keepTrailling unknown-option",
        "/rules/phone/keepLeading invalid-option",
        "/rules/phone/maskChar invalid-option",
        "/rules/ssn invalid-type",
        "/patterns/0 invalid-pattern",
        "/patterns/1 invalid-pattern",
        "/patterns/2/flags invalid-type",
        "/patterns/3/confidence invalid-type",
        "/patterns/4 invalid-pattern",
        "/minConfidence invalid-type",
        "/allow invalid-type",
        "/aggressive invalid-type",
        "/overlap invalid-type",
      ]) {
        expect(found, expected).toContain(expected);
      }
      expect(issues.every((issue) => issue.severity === "error" || issues.indexOf(issue) > 0)).toBe(
        true,
      );
    });

    it("rejects documents that are not objects and members of the wrong type", () => {
      for (const input of [null, "x", 5, [], undefined]) {
        expect(checkPolicy(input).issues).toEqual([
          {
            severity: "error",
            path: "",
            code: "not-an-object",
            message: "A policy document must be a JSON object.",
          },
        ]);
      }
      const types = checkPolicy({
        version: 1,
        id: "p",
        extends: "gdpr",
        categories: [],
        rules: [],
        patterns: {},
      }).issues;
      expect(types.map((issue) => issue.path)).toEqual([
        "/extends",
        "/categories",
        "/rules",
        "/patterns",
      ]);
    });

    it("warns without failing about rules that never apply and weak choices", () => {
      const { policy, issues } = checkPolicy({
        version: 1,
        id: "p",
        categories: { include: ["email", "phone"] },
        defaultStrategy: { strategy: "hash" },
        rules: {
          ssn: { strategy: "redact" },
          widget: { strategy: "redact" },
          phone: { strategy: "generalize" },
        },
        patterns: [{ source: "ACME-\\d+", category: "order-id", flags: "i", confidence: 0.9 }],
      });
      expect(policy).toBeDefined();
      expect(issues.map((issue) => `${issue.severity} ${issue.path} ${issue.code}`).sort()).toEqual(
        [
          "warning /defaultStrategy unkeyed-hash",
          "warning /rules/phone generalize-non-numeric",
          "warning /rules/ssn unused-rule",
          "warning /rules/widget unused-rule",
        ],
      );
      expect(policy?.warnings).toHaveLength(4);
      const pattern = checkPolicy({
        version: 1,
        id: "p",
        rules: { "order-id": { strategy: "redact" } },
        patterns: [{ source: "ACME-\\d+", category: "order-id" }],
      });
      expect(pattern.issues).toEqual([]);
    });

    it("puts the first error in the message of PolicyError and lists all issues", () => {
      try {
        parsePolicy({
          version: 1,
          id: "p",
          extends: ["hipaa"],
          defaultStrategy: { strategy: "hash" },
        });
        throw new Error("unreachable");
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyError);
        const policyError = error as PolicyError;
        expect(policyError.code).toBe("POLICY_ERROR");
        expect(policyError.message).toMatch(
          /^Policy rejected with \d+ error\(s\): \/defaultStrategy /,
        );
        expect(policyError.issues.length).toBeGreaterThan(1);
      }
      expect(new PolicyError([]).message).toBe("Policy rejected with 0 error(s).");
      expect(
        new PolicyError([{ severity: "error", path: "", code: "c", message: "m" }]).message,
      ).toContain(": / m");
    });
  });

  describe("policyToSpec", () => {
    it("compiles into a pipeline that applies the policy", () => {
      const policy = parsePolicy({
        version: 1,
        id: "payments",
        extends: ["pci-dss"],
        patterns: [{ source: "ORD-\\d{4}", category: "order-id" }],
        rules: { "order-id": { strategy: "redact", label: "[ORDER]" } },
        allow: ["billing@example.com"],
        minConfidence: 0.5,
        aggressive: false,
        overlap: "cover",
      });
      const spec = policyToSpec(policy);
      expect(spec).toMatchObject({
        minConfidence: 0.5,
        allow: ["billing@example.com"],
        aggressive: false,
        overlap: "cover",
      });
      const out = compilePipeline(spec).transform(
        "ORD-1234 card 4111 1111 1111 1111, billing@example.com, other@example.com, SSN 123-45-6789",
      ).text;
      expect(out).toBe(
        "[ORDER] card ***************1111, billing@example.com, [REDACTED], SSN 123-45-6789",
      );
      expect(policyToSpec(parsePolicy({ version: 1, id: "p" }))).not.toHaveProperty("patterns");
    });

    it("regulationPolicy gives the same result as the built-in preset on the categories of the profile", () => {
      for (const id of IDS) {
        const document = regulationPolicy(id);
        expect(document).toMatchObject({ version: 1, id, extends: [id] });
        const policy = parsePolicy(document, {
          tokenization: { scheme: "session", reversible: true },
        });
        expect(policy.categories.length).toBe(REGULATIONS[id].rules.length);
      }
      const text = "Card 4111 1111 1111 1111 for jane@example.com";
      const viaPolicy = compilePipeline(
        policyToSpec(parsePolicy(regulationPolicy("pci-dss"))),
      ).transform(text).text;
      expect(viaPolicy).toBe("Card ***************1111 for [REDACTED]");
      // The 1.x detector includes the space after the number, so the 1.x preset shows three digits.
      expect(anonymize(text, { preset: "pci-dss" }).text).toBe(
        "Card ****************111 for [REDACTED]",
      );
    });
  });
});

describe("compliance/erasure", () => {
  it("separates outputs that are gone, outputs behind a key or vault, and outputs anyone can recompute", () => {
    expect(planErasure({ strategy: "redact" })).toMatchObject({
      action: "none",
      linkableAfterwards: false,
    });
    expect(planErasure({ strategy: "mask" })).toMatchObject({
      action: "none",
      linkableAfterwards: false,
    });
    expect(planErasure({ strategy: "mask", keepTrailing: 4 })).toMatchObject({
      action: "none",
      linkableAfterwards: true,
    });
    expect(planErasure({ strategy: "pseudonymize" })).toMatchObject({ action: "none" });
    expect(planErasure({ strategy: "hash" })).toMatchObject({
      action: "delete-outputs",
      linkableAfterwards: true,
    });
    expect(planErasure({ strategy: "pseudonymize", seed: "s" })).toMatchObject({
      action: "delete-outputs",
    });
    expect(planErasure({ strategy: "synthesize" })).toMatchObject({ action: "delete-outputs" });
    expect(planErasure({ strategy: "generalize" })).toMatchObject({ action: "delete-outputs" });
    expect(planErasure({ strategy: "hash", pepper: "p" })).toMatchObject({ action: "destroy-key" });
    expect(planErasure({ strategy: "encrypt" })).toMatchObject({
      action: "destroy-key",
      linkableAfterwards: false,
    });
    expect(planErasure({ strategy: "tokenize" })).toMatchObject({
      action: "delete-vault-entries",
      linkableAfterwards: true,
    });
    expect(
      planErasure({ strategy: "tokenize" }, { scheme: "session", reversible: true }),
    ).toMatchObject({
      action: "delete-vault-entries",
      linkableAfterwards: false,
    });
    expect(
      planErasure({ strategy: "tokenize" }, { scheme: "keyed", reversible: true }),
    ).toMatchObject({
      action: "delete-vault-entries",
      linkableAfterwards: true,
    });
    expect(
      planErasure({ strategy: "tokenize" }, { scheme: "sealed", reversible: true }),
    ).toMatchObject({ action: "destroy-key" });
    expect(
      planErasure({ strategy: "tokenize" }, { scheme: "keyed", reversible: false }),
    ).toMatchObject({ action: "destroy-key" });
    for (const spec of [
      { strategy: "redact" },
      { strategy: "hash" },
      { strategy: "encrypt" },
    ] as StrategySpec[]) {
      expect(planErasure(spec).reason.length).toBeGreaterThan(20);
    }
  });
});
