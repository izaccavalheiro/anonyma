/**
 * @module audit/logger
 * @description The append-only, hash-chained, zero-PII audit logger.
 *
 * Guarantees
 * - **Zero PII by construction**: an event has no member for values. Every
 *   caller-supplied string (actor, source, policy reference, attribute, field
 *   path segment, category, detector, rule) is additionally checked by a guard
 *   and blanked if it looks like personal data.
 * - **Order**: records are sealed strictly in the order `record()` was called.
 * - **Tamper evidence**: each record's hash covers its content and the hash of
 *   its predecessor. With a key the hash is an HMAC, so someone who can rewrite
 *   the log but does not hold the key cannot recompute the chain. Without a
 *   key, anchor {@link AuditLogger.head} somewhere the log writer cannot reach.
 * - **Fail closed**: if a sink rejects a record, the logger stops accepting
 *   records instead of continuing with a gap.
 */

import { AuditIntegrityError, ValidationError } from "../errors.js";
import { compilePipeline } from "../engine/compile.js";
import { canonicalize, inputChecksum, recordHash } from "./canonical.js";
import type {
  AuditEvent,
  AuditFailure,
  AuditFieldEntry,
  AuditHead,
  AuditLogger,
  AuditOperation,
  AuditRecord,
  AuditSink,
} from "./types.js";

/** `prev` of the first record of a chain. */
export const GENESIS_HASH = "0".repeat(64);

const OPERATIONS: ReadonlySet<string> = new Set<AuditOperation>([
  "detect",
  "anonymize",
  "tokenize",
  "detokenize",
  "erase",
  "key-rotate",
  "key-destroy",
  "policy-load",
]);

const BLANK = "[GUARDED]";

/**
 * Options accepted by {@link createAuditLogger}.
 */
export interface AuditLoggerOptions {
  /** Where sealed records go. Each sink receives every record, in order. */
  readonly sinks: readonly AuditSink[];
  /**
   * HMAC-SHA-256 key that authenticates the chain, for example
   * `await keyring.deriveKey(keyId, "audit-mac")`. Without it the chain uses
   * plain SHA-256.
   */
  readonly key?: CryptoKey;
  /** Clock. Defaults to `Date.now`. */
  readonly now?: () => number;
  /**
   * Returns `true` for a string that looks like personal data. Defaults to the
   * validating detectors for email addresses, SSNs, IBANs, IP addresses and
   * card numbers.
   */
  readonly guard?: (value: string) => boolean;
  /** Continue an existing chain from its head. */
  readonly resume?: AuditHead;
}

let defaultGuard: ((value: string) => boolean) | undefined;

function builtinGuard(): (value: string) => boolean {
  defaultGuard ??= compilePipeline({
    categories: ["email", "ssn", "iban", "ipv4", "ipv6", "credit-card"],
  }).test;
  return defaultGuard;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const member of Object.values(value)) deepFreeze(member);
  }
  return value;
}

/**
 * Create an audit logger.
 *
 * @param options - Sinks, optional chain key, clock, guard and resume point.
 * @returns The {@link AuditLogger}.
 * @throws {@link ValidationError} When no sink is given or `resume` is malformed.
 *
 * @example
 * ```ts
 * import { createAuditLogger, lineSink, summarizeSpans } from "anonyma/audit";
 * import { appendFile } from "node:fs/promises";
 *
 * const audit = createAuditLogger({
 *   sinks: [lineSink((line) => appendFile("audit.ndjson", line))],
 *   key: await keyring.deriveKey(keyring.activeKeyId(), "audit-mac"),
 * });
 *
 * const result = pipeline.transform(body.message);
 * await audit.record({
 *   operation: "anonymize",
 *   actor: "support-api",
 *   policy: { id: "gdpr" },
 *   fields: summarizeSpans(result.spans, { path: "/message", rule: "redact" }),
 * });
 * ```
 */
export function createAuditLogger(options: AuditLoggerOptions): AuditLogger {
  const { sinks, key, resume } = options;
  const now = options.now ?? Date.now;
  const guard = options.guard ?? builtinGuard();

  if (!Array.isArray(sinks) || sinks.length === 0) {
    throw new ValidationError("sinks", "must contain at least one sink");
  }
  if (
    resume !== undefined &&
    (!Number.isInteger(resume.seq) || resume.seq < -1 || !/^[0-9a-f]{64}$/.test(resume.hash))
  ) {
    throw new ValidationError("resume", "is not a valid chain head");
  }

  let head: AuditHead = resume ?? { seq: -1, hash: GENESIS_HASH };
  let tail: Promise<unknown> = Promise.resolve();
  let failure: AuditIntegrityError | undefined;
  let failed: AuditFailure | undefined;

  /** Blank a caller-supplied string that looks like personal data. */
  function checked(value: unknown, field: string, counter: { guarded: number }): string {
    if (typeof value !== "string") throw new ValidationError(field, "must be a string");
    if (!guard(value)) return value;
    counter.guarded++;
    return BLANK;
  }

  function checkedPath(path: unknown, counter: { guarded: number }): string {
    if (typeof path !== "string" || (path !== "" && !path.startsWith("/"))) {
      throw new ValidationError(
        "fields[].path",
        'must be a JSON Pointer ("" or starting with "/")',
      );
    }
    if (path === "") return path;
    return path
      .split("/")
      .map((segment) => {
        const key = segment.replace(/~1/g, "/").replace(/~0/g, "~");
        if (!guard(key)) return segment;
        counter.guarded++;
        return "*";
      })
      .join("/");
  }

  function normalise(event: AuditEvent, counter: { guarded: number }): AuditEvent {
    if (typeof event !== "object" || (event as unknown) === null) {
      throw new ValidationError("event", "must be an object");
    }
    if (!OPERATIONS.has(event.operation)) {
      throw new ValidationError("operation", "is not a known audit operation");
    }
    if (!Array.isArray(event.fields)) throw new ValidationError("fields", "must be an array");

    const fields: AuditFieldEntry[] = event.fields.map((entry: AuditFieldEntry | null) => {
      if (typeof entry !== "object" || entry === null) {
        throw new ValidationError("fields[]", "must be an object");
      }
      if (!Number.isInteger(entry.count) || entry.count < 0) {
        throw new ValidationError("fields[].count", "must be a non-negative integer");
      }
      return {
        path: checkedPath(entry.path, counter),
        category: checked(entry.category, "fields[].category", counter),
        detector: checked(entry.detector, "fields[].detector", counter),
        rule: checked(entry.rule, "fields[].rule", counter),
        count: entry.count,
      };
    });

    let attributes: Record<string, string | number | boolean> | undefined;
    if (event.attributes !== undefined) {
      attributes = {};
      for (const [name, value] of Object.entries(event.attributes)) {
        const safeName = checked(name, "attributes", counter);
        if (typeof value === "string") {
          attributes[safeName] = checked(value, `attributes.${safeName}`, counter);
        } else if (typeof value === "number" && Number.isFinite(value)) {
          // A card or an account number passed as a number is still one.
          if (guard(String(value))) {
            counter.guarded++;
            attributes[safeName] = BLANK;
          } else {
            attributes[safeName] = value;
          }
        } else if (typeof value === "boolean") {
          attributes[safeName] = value;
        } else {
          throw new ValidationError(
            `attributes.${safeName}`,
            "must be a string, a finite number or a boolean",
          );
        }
      }
    }

    const hexDigest = (value: unknown, field: string): string => {
      if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
        throw new ValidationError(field, "must be 64 lower-case hexadecimal characters");
      }
      return value;
    };

    return {
      operation: event.operation,
      ...(event.actor !== undefined ? { actor: checked(event.actor, "actor", counter) } : {}),
      ...(event.source !== undefined ? { source: checked(event.source, "source", counter) } : {}),
      ...(event.policy !== undefined
        ? {
            policy: {
              id: checked(event.policy.id, "policy.id", counter),
              ...(event.policy.version !== undefined
                ? { version: checked(event.policy.version, "policy.version", counter) }
                : {}),
              ...(event.policy.digest !== undefined
                ? { digest: hexDigest(event.policy.digest, "policy.digest") }
                : {}),
            },
          }
        : {}),
      fields,
      ...(event.checksums !== undefined
        ? {
            checksums: {
              ...(event.checksums.input !== undefined
                ? { input: hexDigest(event.checksums.input, "checksums.input") }
                : {}),
              ...(event.checksums.output !== undefined
                ? { output: hexDigest(event.checksums.output, "checksums.output") }
                : {}),
            },
          }
        : {}),
      ...(attributes !== undefined ? { attributes } : {}),
    };
  }

  async function sealAndAppend(event: AuditEvent): Promise<AuditRecord> {
    if (failure !== undefined) throw failure;

    const counter = { guarded: 0 };
    const body = normalise(event, counter);
    const unsealed = {
      ...body,
      v: 1 as const,
      seq: head.seq + 1,
      ts: new Date(now()).toISOString(),
      guarded: counter.guarded,
      prev: head.hash,
    };
    const hash = await recordHash(canonicalize(unsealed), key);
    const record: AuditRecord = deepFreeze({ ...unsealed, hash });

    let position = 0;
    try {
      for (const sink of sinks) {
        await sink.append(record);
        position++;
      }
    } catch (cause) {
      failure = new AuditIntegrityError(
        `a sink rejected record ${String(record.seq)}; the logger accepts no further records`,
      );
      (failure as { cause?: unknown }).cause = cause;
      failed = Object.freeze({ record, sink: position, cause });
      throw failure;
    }
    head = { seq: record.seq, hash: record.hash };
    return record;
  }

  function record(event: AuditEvent): Promise<AuditRecord> {
    const sealed = tail.then(() => sealAndAppend(event));
    tail = sealed.catch(() => undefined);
    return sealed;
  }

  return Object.freeze({
    record,
    flush: async (): Promise<void> => {
      await tail;
      if (failure !== undefined) throw failure;
    },
    head: (): AuditHead => ({ ...head }),
    failure: (): AuditFailure | undefined => failed,
    inputChecksum(text: string): Promise<string> {
      if (typeof text !== "string") {
        return Promise.reject(new ValidationError("text", "must be a string"));
      }
      if (key === undefined) {
        return Promise.reject(
          new ValidationError(
            "key",
            "is required for input checksums: an unkeyed digest of a short input can be reversed",
          ),
        );
      }
      return inputChecksum(text, key);
    },
  });
}
