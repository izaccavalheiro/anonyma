/**
 * @module audit
 * @description The zero-PII, hash-chained audit logger, exposed as
 * `"anonyma/audit"`.
 *
 * @example
 * ```ts
 * import { createAuditLogger, memorySink, summarizeSpans, verifyAuditChain } from "anonyma/audit";
 *
 * const sink = memorySink();
 * const audit = createAuditLogger({ sinks: [sink] });
 * const result = pipeline.transform(text);
 * await audit.record({
 *   operation: "anonymize",
 *   policy: { id: "hipaa" },
 *   fields: summarizeSpans(result.spans, { rule: "redact" }),
 * });
 * (await verifyAuditChain(sink.records())).ok; // true
 * ```
 */

export { canonicalize, hmacSha256Hex, inputChecksum, sha256Hex } from "./canonical.js";
export { jsonPointer, summarizeSpans } from "./fields.js";
export { GENESIS_HASH, createAuditLogger } from "./logger.js";
export type { AuditLoggerOptions } from "./logger.js";
export { lineSink, memorySink, parseAuditLog } from "./sinks.js";
export type { MemoryAuditSink } from "./sinks.js";
export { verifyAuditChain } from "./verify.js";
export type { VerifyOptions } from "./verify.js";
export type {
  AuditChecksums,
  AuditEvent,
  AuditFailure,
  AuditFieldEntry,
  AuditHead,
  AuditLogger,
  AuditOperation,
  AuditPolicyRef,
  AuditRecord,
  AuditSink,
  AuditVerification,
} from "./types.js";
