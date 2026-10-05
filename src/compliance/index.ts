/**
 * @module compliance
 * @description Regulation profiles, the policy document parser and the
 * erasure protocol, exposed as `"anonyma/compliance"`.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { REGULATIONS, parsePolicy, policyToSpec } from "anonyma/compliance";
 *
 * const policy = parsePolicy({ version: 1, id: "clinic", extends: ["hipaa", "gdpr"] });
 * const pipeline = compilePipeline(policyToSpec(policy));
 * REGULATIONS.hipaa.gaps.map((gap) => gap.element); // what the library cannot detect
 * ```
 */

export { REGULATIONS, complianceMatrix, getRegulation, isRegulationId } from "./regulations.js";
export type { MatrixRow } from "./regulations.js";
export { checkRequirement, describeStrategy } from "./traits.js";
export type { TokenizationInfo } from "./traits.js";
export { checkPolicy, parsePolicy, policyToSpec, regulationPolicy } from "./policy.js";
export type { PolicyCheck, PolicyOptions } from "./policy.js";
export { planErasure } from "./erasure.js";
export type { ErasureAction, ErasurePlan } from "./erasure.js";
export type {
  CategoryRule,
  CoverageGap,
  LegalReference,
  Policy,
  PolicyDocument,
  PolicyIssue,
  ProtectionRequirement,
  RegulationId,
  RegulationProfile,
  StrategyTraits,
} from "./types.js";
