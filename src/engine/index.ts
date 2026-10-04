/**
 * @module engine
 * @description The span-based anonymization engine, exposed as
 * `"anonyma/engine"`.
 *
 * - {@link createPipeline} builds a pipeline from detectors and replacers you
 *   import individually, so bundlers keep only what you use.
 * - {@link compilePipeline} builds one from plain data — a preset name,
 *   categories and strategies — for configuration files, workers and tools.
 * - {@link createChunkTransformer} and {@link createPipelineStream} run a
 *   pipeline over text that arrives in arbitrary chunks.
 *
 * @example
 * ```ts
 * import { compilePipeline, createPipelineStream } from "anonyma/engine";
 *
 * const pipeline = compilePipeline({ preset: "gdpr" });
 * const { text, spans } = pipeline.transform("Mail alice@example.com from 203.0.113.57");
 * const stream = source.pipeThrough(createPipelineStream(pipeline));
 * ```
 */

export { defineDetector, defineRegexDetector, fromLegacyDetector } from "./detector.js";
export type { LegacyDetectorOptions, RegexDetectorOptions } from "./detector.js";
export { resolveSpans } from "./resolve.js";
export type { Candidate, Resolved } from "./resolve.js";
export { createPipeline, spanText } from "./pipeline.js";
export {
  constant,
  encryptWith,
  generalizeWith,
  hashWith,
  maskWith,
  pseudonymizeWith,
  redactWith,
  strategyReplacer,
  synthesizeWith,
} from "./replacers.js";
export { builtinDetectors, compilePipeline } from "./compile.js";
export {
  createAsyncChunkTransformer,
  createChunkTransformer,
  createPipelineStream,
} from "./stream.js";
export {
  bareSsnDetector,
  creditCardDetector,
  emailDetector,
  ibanDetector,
  ipv4Detector,
  ipv6Detector,
  maskedCardDetector,
  obfuscatedEmailDetector,
  ssnDetector,
} from "./precise.js";
export {
  BUILTIN_CATEGORIES,
  LEGACY_AGGRESSIVE_DETECTORS,
  LEGACY_DETECTORS,
  addressDetector,
  apiKeyDetector,
  bankAccountDetector,
  caseNumberDetector,
  companyRegistrationDetector,
  cryptocurrencyDetector,
  dateOfBirthDetector,
  driversLicenseDetector,
  healthInsuranceDetector,
  legacyCreditCardAggressiveDetector,
  legacyCreditCardDetector,
  legacyEmailAggressiveDetector,
  legacyEmailDetector,
  legacyIbanDetector,
  legacyIpv4Detector,
  legacyIpv6Detector,
  legacySsnAggressiveDetector,
  legacySsnDetector,
  licensePlateDetector,
  medicalRecordDetector,
  nameAggressiveDetector,
  nameDetector,
  nationalIdDetector,
  passportDetector,
  phoneAggressiveDetector,
  phoneDetector,
  prescriptionDetector,
  socialMediaDetector,
  taxIdDetector,
  trackingNumberDetector,
  urlDetector,
  vinAggressiveDetector,
  vinDetector,
} from "./builtin.js";
export type {
  AllowRule,
  AppliedSpan,
  AsyncChunkTransformer,
  Category,
  ChunkOptions,
  ChunkTransformer,
  CompileDependencies,
  DetectedSpan,
  EmitSpan,
  OverlapPolicy,
  PatternSpec,
  Pipeline,
  PipelineOptions,
  PipelineSpec,
  ReplaceContext,
  ReplacementPlan,
  Replacer,
  SpanDetector,
  StrategySpec,
  TransformResult,
} from "./types.js";
