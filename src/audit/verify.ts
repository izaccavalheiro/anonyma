/**
 * @module audit/verify
 * @description Verification of an audit chain.
 */

import { canonicalize, recordHash } from "./canonical.js";
import { GENESIS_HASH } from "./logger.js";
import type { AuditHead, AuditVerification } from "./types.js";

/**
 * Options accepted by {@link verifyAuditChain}.
 */
export interface VerifyOptions {
  /** The HMAC key of the chain, when the logger had one. */
  readonly key?: CryptoKey;
  /** The head the records are expected to continue from. Defaults to an empty chain. */
  readonly after?: AuditHead;
  /**
   * The head the chain is expected to end at, taken from a trusted place.
   * Detects truncation and wholesale replacement of the log.
   */
  readonly expectedHead?: AuditHead;
}

/**
 * Verify a chain of audit records: sequence numbers, links and hashes.
 *
 * @param records - The records, in order. Entries may come from untrusted storage.
 * @param options - Chain key and expected boundaries.
 * @returns Whether the chain is intact and, if not, where and why it breaks.
 *
 * @example
 * ```ts
 * const result = await verifyAuditChain(sink.records(), { key, expectedHead: audit.head() });
 * if (!result.ok) throw new Error(`audit log broken at record ${result.index}: ${result.reason}`);
 * ```
 */
export async function verifyAuditChain(
  records: Iterable<unknown> | AsyncIterable<unknown>,
  options: VerifyOptions = {},
): Promise<AuditVerification> {
  const { key, expectedHead } = options;
  let head: AuditHead = options.after ?? { seq: -1, hash: GENESIS_HASH };
  let index = 0;

  for await (const entry of records) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      return { ok: false, index, reason: "malformed" };
    }
    const { hash, ...rest } = entry as Record<string, unknown>;
    if (typeof hash !== "string" || typeof rest["prev"] !== "string" || rest["v"] !== 1) {
      return { ok: false, index, reason: "malformed" };
    }
    if (rest["seq"] !== head.seq + 1) return { ok: false, index, reason: "bad-seq" };
    if (rest["prev"] !== head.hash) return { ok: false, index, reason: "bad-prev" };

    let canonical: string;
    try {
      canonical = canonicalize(rest);
    } catch {
      return { ok: false, index, reason: "malformed" };
    }
    if ((await recordHash(canonical, key)) !== hash) {
      return { ok: false, index, reason: "bad-hash" };
    }

    head = { seq: head.seq + 1, hash };
    index++;
  }

  if (
    expectedHead !== undefined &&
    (expectedHead.seq !== head.seq || expectedHead.hash !== head.hash)
  ) {
    return { ok: false, index, reason: "head-mismatch" };
  }
  return { ok: true, count: index, head };
}
