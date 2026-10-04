/**
 * @module compliance/types
 * @description Contracts of the compliance layer exposed as
 * `"anonyma/compliance"`: regulation profiles mapped to legal provisions, the
 * protection each provision requires, and the policy document format. This
 * module contains types only — it has no runtime code.
 *
 * The profiles encode technical measures that the cited provisions call for.
 * They are engineering aids, not legal advice, and using them does not by
 * itself make a system compliant.
 */

import type { PiiCategory } from "../types.js";
import type { OverlapPolicy, PatternSpec, StrategySpec } from "../engine/types.js";

// ---------------------------------------------------------------------------
// Regulations
// ---------------------------------------------------------------------------

/**
 * Regulations and standards for which a profile is available.
 */
export type RegulationId = "gdpr" | "lgpd" | "pipeda" | "ccpa" | "hipaa" | "pci-dss";

/**
 * A pointer to one legal provision or standard requirement.
 */
export interface LegalReference {
  /** Precise citation, e.g. `"GDPR Art. 32(1)(a)"` or `"45 CFR § 164.514(b)(2)(i)(A)"`. */
  readonly citation: string;
  /** Short description of what the provision says. */
  readonly summary: string;
  /** Link to an official or primary source. */
  readonly url?: string;
}

/**
 * Properties a transformed value must have, expressed independently of any
 * strategy name. Every member is a restriction; an empty object means "any
 * transformation that removes the clear value is acceptable".
 */
export interface ProtectionRequirement {
  /** Nobody — not even the key or vault holder — may be able to restore the value. */
  readonly irreversible?: boolean;
  /**
   * The output must not be computed from the value (no hash, keyed hash,
   * encryption, or deterministic pseudonym of it).
   */
  readonly notDerived?: boolean;
  /** When the output is computed from the value, a secret key must be involved. */
  readonly keyed?: boolean;
  /** Maximum number of original characters that may remain visible. */
  readonly maxRevealed?: {
    /** Leading characters. */
    readonly leading: number;
    /** Trailing characters. */
    readonly trailing: number;
  };
}

/**
 * What a strategy configuration actually does to a value, in the same terms
 * as {@link ProtectionRequirement}.
 */
export interface StrategyTraits {
  /** Someone holding the right key, vault or mapping can restore the value. */
  readonly reversible: boolean;
  /** The output is computed from the value. */
  readonly derived: boolean;
  /** A secret is involved in computing the output. */
  readonly keyed: boolean;
  /** Equal inputs yield equal outputs, so records can be linked. */
  readonly linkable: boolean;
  /** Original characters left visible; `"all"` when the value may pass through unchanged. */
  readonly revealed: { readonly leading: number; readonly trailing: number } | "all";
}

/**
 * The requirement a regulation places on one category of data.
 */
export interface CategoryRule {
  /** The category the rule applies to. */
  readonly category: PiiCategory;
  /** The provisions that bring this category into scope. */
  readonly references: readonly LegalReference[];
  /** The minimum protection the transformed value must have. */
  readonly requirement: ProtectionRequirement;
  /** The strategy the built-in preset applies. Satisfies `requirement`. */
  readonly recommended: StrategySpec;
  /** Why this requirement follows from the references. */
  readonly rationale: string;
}

/**
 * A data element the regulation names that the library cannot detect.
 */
export interface CoverageGap {
  /** The data element, as the regulation names it. */
  readonly element: string;
  /** The provision that names it. */
  readonly reference: LegalReference;
  /** What a deployment has to do about it. */
  readonly mitigation: string;
}

/**
 * Everything the library knows about one regulation.
 */
export interface RegulationProfile {
  /** Identifier, also usable as a preset name. */
  readonly id: RegulationId;
  /** Full name of the instrument. */
  readonly name: string;
  /** Where it applies. */
  readonly jurisdiction: string;
  /** Edition or consolidated version the profile was written against. */
  readonly edition: string;
  /** Provisions that apply to the processing as a whole (security, erasure, record keeping). */
  readonly references: readonly LegalReference[];
  /** Per-category requirements. */
  readonly rules: readonly CategoryRule[];
  /** Named data elements with no detector. */
  readonly gaps: readonly CoverageGap[];
  /** Whether an audit trail of anonymization operations is expected, and under which provision. */
  readonly auditTrail?: LegalReference;
  /** The provision that grants erasure, when the instrument has one. */
  readonly erasure?: LegalReference;
}

// ---------------------------------------------------------------------------
// Policy documents
// ---------------------------------------------------------------------------

/**
 * A policy as written by a user, typically in a JSON file. Everything is plain
 * data.
 */
export interface PolicyDocument {
  /** Policy format version. */
  readonly version: 1;
  /** Identifier recorded in audit events. */
  readonly id: string;
  /** Human-readable description. */
  readonly description?: string;
  /**
   * Regulations the policy must satisfy. Their categories are merged and, per
   * category, the requirements of all listed regulations apply together.
   */
  readonly extends?: readonly RegulationId[];
  /** Categories to add to, or remove from, those implied by `extends`. */
  readonly categories?: {
    /** Categories to detect in addition. */
    readonly include?: readonly PiiCategory[];
    /** Categories to stop detecting. Excluding a category a regulation requires is a violation. */
    readonly exclude?: readonly PiiCategory[];
  };
  /** Strategy for categories without a rule. */
  readonly defaultStrategy?: StrategySpec;
  /** Per-category strategies, keyed by category label. */
  readonly rules?: Readonly<Record<string, StrategySpec>>;
  /** Additional regular-expression detectors. */
  readonly patterns?: readonly PatternSpec[];
  /** Detections below this confidence are ignored. */
  readonly minConfidence?: number;
  /** Exact values to leave untouched. */
  readonly allow?: readonly string[];
  /** Use the aggressive variant of the built-in detectors. */
  readonly aggressive?: boolean;
  /** Overlap resolution policy. */
  readonly overlap?: OverlapPolicy;
}

/**
 * A problem found while parsing or checking a policy.
 */
export interface PolicyIssue {
  /**
   * - `"error"`: the document is malformed, or it violates a requirement of a
   *   regulation it extends.
   * - `"warning"`: the document is valid but weaker than recommended.
   */
  readonly severity: "error" | "warning";
  /** JSON Pointer to the offending member of the document. */
  readonly path: string;
  /** Machine-readable issue code. */
  readonly code: string;
  /** Human-readable explanation. Never contains values from the document's `allow` list. */
  readonly message: string;
  /** The provision that is violated, for compliance issues. */
  readonly reference?: LegalReference;
}

/**
 * A parsed and checked policy, ready to be compiled into a pipeline.
 */
export interface Policy {
  /** The policy identifier. */
  readonly id: string;
  /** The regulations the policy extends. */
  readonly regulations: readonly RegulationId[];
  /** The categories the policy detects, in a stable order. */
  readonly categories: readonly PiiCategory[];
  /** The effective strategy for every category in `categories`. */
  readonly strategies: Readonly<Record<string, StrategySpec>>;
  /** The effective default strategy. */
  readonly defaultStrategy: StrategySpec;
  /** The normalised source document. */
  readonly document: PolicyDocument;
  /** Warnings raised while checking. A `Policy` never carries errors. */
  readonly warnings: readonly PolicyIssue[];
}
