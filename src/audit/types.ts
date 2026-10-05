/**
 * @module audit/types
 * @description Contracts of the zero-PII, hash-chained audit logger exposed as
 * `"anonyma/audit"`. This module contains types only — it has no runtime code.
 *
 * An audit record describes *what was done* (which fields, which categories,
 * which rules, how many replacements) and never *what the data was*. Records
 * form a hash chain so that removal, reordering or modification of any record
 * is detectable.
 */

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/**
 * The operation an audit record describes.
 */
export type AuditOperation =
  | "detect"
  | "anonymize"
  | "tokenize"
  | "detokenize"
  | "erase"
  | "key-rotate"
  | "key-destroy"
  | "policy-load";

/**
 * One group of replacements: everything a single rule did to a single field
 * for a single category.
 */
export interface AuditFieldEntry {
  /**
   * Location of the transformed field as an RFC 6901 JSON Pointer (`""` for a
   * bare string or the document root, `"/user/email"`, `"/items/0/note"`).
   * Object keys that themselves look like personal data are replaced by `*`.
   */
  readonly path: string;
  /** Category label of the replaced values. */
  readonly category: string;
  /** `id` of the detector that found them. */
  readonly detector: string;
  /** The rule that was applied: the strategy name, never its options or secrets. */
  readonly rule: string;
  /** Number of replacements in this group. */
  readonly count: number;
}

/**
 * Identifies the policy an operation ran under.
 */
export interface AuditPolicyRef {
  /** Policy identifier (e.g. `"hipaa"` or the `id` of a policy document). */
  readonly id: string;
  /** Policy version label, when it has one. */
  readonly version?: string;
  /** SHA-256 digest (hex) of the canonical policy document, when available. */
  readonly digest?: string;
}

/**
 * Digests that tie a record to the data it describes without containing it.
 */
export interface AuditChecksums {
  /**
   * Keyed checksum (hex) of the input, as returned by
   * `AuditLogger.inputChecksum()`. It is only ever produced when a key is
   * configured: an unkeyed hash of a short PII-bearing input could be reversed
   * by enumeration. Do not put a plain HMAC under the chain's key here: on an
   * input someone else chooses, that would be a valid record hash.
   */
  readonly input?: string;
  /** SHA-256 (hex) of the output. */
  readonly output?: string;
}

/**
 * What a caller reports to the logger. The logger adds sequencing, the
 * timestamp and the chain hashes.
 */
export interface AuditEvent {
  /** The operation performed. */
  readonly operation: AuditOperation;
  /** The component or service account that performed it. Must not be personal data. */
  readonly actor?: string;
  /** Opaque label of where the data came from (a route, a job name, a file id). */
  readonly source?: string;
  /** The policy in force. */
  readonly policy?: AuditPolicyRef;
  /** What was transformed. */
  readonly fields: readonly AuditFieldEntry[];
  /** Digests of the processed data. */
  readonly checksums?: AuditChecksums;
  /** Additional non-personal attributes (durations, counts, key ids). */
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

/**
 * A sealed audit record. Records are deeply frozen.
 */
export interface AuditRecord extends AuditEvent {
  /** Record format version. */
  readonly v: 1;
  /** Position in the chain, starting at `0`. */
  readonly seq: number;
  /** Time the record was sealed, ISO 8601 in UTC with millisecond precision. */
  readonly ts: string;
  /**
   * Number of string values the logger blanked because they looked like
   * personal data. Anything above `0` points to a caller bug.
   */
  readonly guarded: number;
  /** `hash` of the previous record; 64 zeros for the first record. */
  readonly prev: string;
  /**
   * Hex digest over the canonical JSON of every other member of the record:
   * SHA-256 by default, HMAC-SHA-256 when the logger has a key.
   */
  readonly hash: string;
}

// ---------------------------------------------------------------------------
// Logger and sinks
// ---------------------------------------------------------------------------

/**
 * Destination for sealed records. A sink must only ever append.
 */
export interface AuditSink {
  /** Persist one record. Called once per record, in chain order. */
  readonly append: (record: AuditRecord) => void | Promise<void>;
}

/**
 * The position of the most recent record in a chain. Storing it somewhere the
 * log writer cannot modify makes truncation and wholesale replacement of the
 * log detectable.
 */
export interface AuditHead {
  /** `seq` of the most recent record, or `-1` for an empty chain. */
  readonly seq: number;
  /** `hash` of the most recent record, or 64 zeros for an empty chain. */
  readonly hash: string;
}

/**
 * An append-only audit logger.
 */
export interface AuditLogger {
  /**
   * Seal `event` and append it to every sink. Records are sealed strictly in
   * call order, even when calls are not awaited.
   */
  readonly record: (event: AuditEvent) => Promise<AuditRecord>;
  /**
   * Resolves once every record submitted so far has been appended to every
   * sink. Rejects with the same error as the failed call when a sink rejected
   * a record, so a caller that does not await `record()` still learns of it.
   */
  readonly flush: () => Promise<void>;
  /** The current head of the chain: the last record every sink accepted. */
  readonly head: () => AuditHead;
  /**
   * What stopped the logger, or `undefined` while it is working. Sinks before
   * `sink` already hold `record`; to recover, append that same record to the
   * sinks that miss it and continue with a new logger whose `resume` is the
   * seq and hash of that record. Sealing another record with the same seq
   * would leave two records with one seq in the sinks that have it.
   */
  readonly failure: () => AuditFailure | undefined;
  /**
   * Keyed checksum of an input, for `AuditEvent.checksums.input`.
   *
   * @throws ValidationError When the logger has no key.
   */
  readonly inputChecksum: (text: string) => Promise<string>;
}

/**
 * The record a sink rejected, and which sink that was.
 */
export interface AuditFailure {
  /** The sealed record that could not be appended everywhere. */
  readonly record: AuditRecord;
  /** Index of the sink that rejected it. Earlier sinks hold the record. */
  readonly sink: number;
  /** What the sink threw. */
  readonly cause: unknown;
}

/**
 * Result of verifying a chain of records.
 */
export type AuditVerification =
  | {
      readonly ok: true;
      /** Number of records verified. */
      readonly count: number;
      /** Head of the verified chain. */
      readonly head: AuditHead;
    }
  | {
      readonly ok: false;
      /** Index of the first record that failed verification. */
      readonly index: number;
      /** Why it failed. */
      readonly reason: "bad-hash" | "bad-prev" | "bad-seq" | "malformed" | "head-mismatch";
    };
