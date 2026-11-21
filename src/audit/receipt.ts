/**
 * @module audit/receipt
 * @description Signed receipts: proof, kept with the data or handed to a
 * third party, that a text was anonymized before it left the server, under
 * which policy and with how many values of each category replaced.
 *
 * A receipt holds counts and digests only, never a value: the categories that
 * were replaced, the number of each, a SHA-256 digest of the anonymized output
 * and, when asked for, a keyed digest of the input. Its signature is an
 * HMAC-SHA-256 under a key the issuer holds, so a receipt that was altered, or
 * made up by someone without the key, fails verification.
 */

import { ValidationError } from "../errors.js";
import { toHex, utf8 } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";
import type { PresetSelection } from "../types.js";
import { VERSION } from "../version.js";
import { canonicalize, hmacSha256Hex, sha256Hex } from "./canonical.js";
import { guardLabel } from "./logger.js";
import type { AuditPolicyRef } from "./types.js";

/** What a signature is computed over: this label, then the canonical receipt. */
const RECEIPT_DOMAIN = "anonyma/receipt/v1\0";
/** What the input digest is computed over: this label, then the input. */
const INPUT_DOMAIN = "anonyma/receipt/input/v1\0";

/**
 * A signed statement that a text was anonymized. It contains no personal
 * data: category labels, counts and digests.
 */
export interface AnonymaReceipt {
  /** Format version. */
  readonly v: 1;
  /** Random identifier of the receipt (32 hexadecimal characters). */
  readonly id: string;
  /** When the receipt was issued, ISO-8601 in UTC. */
  readonly timestamp: string;
  /** The library that anonymized the text: `"anonyma@<version>"`. */
  readonly library: string;
  /** The presets applied, when the issuer was told. */
  readonly presets?: readonly string[];
  /** The policy applied, when the issuer was told. */
  readonly policy?: AuditPolicyRef;
  /** Number of replaced values per category, e.g. `{ email: 2, "credit-card": 1 }`. */
  readonly stats: Readonly<Record<string, number>>;
  /** Number of replaced values in all. */
  readonly total: number;
  /** SHA-256 (hex) of the anonymized text, so the receipt names what was sent. */
  readonly output: string;
  /**
   * HMAC-SHA-256 (hex) of the original text under the issuer's key, present
   * when the input was given to {@link ReceiptIssuer.issue}. Whoever holds the
   * input and the key can show that the receipt is about it; without the key
   * it reveals nothing about the input.
   */
  readonly input?: string;
  /** Signature algorithm. */
  readonly alg: "HMAC-SHA-256";
  /** Identifier of the signing key, when one was given. */
  readonly keyId?: string;
  /** HMAC-SHA-256 (hex) of the canonical JSON of every other member. */
  readonly signature: string;
}

/**
 * What a receipt is issued for: the anonymized text and what was replaced in
 * it. A `TransformResult` of `"anonyma/engine"` has `spans`; an
 * `AnonymizeResult` of `anonymize(text, { includeMatches: true })` has
 * `matches`.
 */
export interface ReceiptSubject {
  /** The anonymized text. Give it or `outputDigest`. */
  readonly text?: string;
  /**
   * SHA-256 (lower-case hex) of the anonymized text, in place of `text`, for
   * an output too large to hold in memory, such as a file written as a stream.
   */
  readonly outputDigest?: string;
  /** The replaced spans; only their categories are read. */
  readonly spans?: readonly { readonly category: string }[];
  /** The replaced matches; only their categories are read. */
  readonly matches?: readonly { readonly category: string }[];
  /** The number of replaced values per category, in place of `spans` or `matches`. */
  readonly counts?: Readonly<Record<string, number>>;
}

/**
 * Options accepted by {@link createReceiptIssuer}.
 */
export interface ReceiptIssuerOptions {
  /**
   * HMAC-SHA-256 key that signs and verifies receipts, for example
   * `await keyring.deriveKey(keyId, "receipt-mac")`. A string is imported as
   * the raw key: use at least 32 random bytes, encoded.
   */
  readonly key: CryptoKey | string;
  /** Identifier of the key, written into each receipt so that a verifier can pick the key. */
  readonly keyId?: string;
  /** The presets the anonymization applies. */
  readonly presets?: PresetSelection;
  /** The policy the anonymization applies. */
  readonly policy?: AuditPolicyRef;
  /** Clock. Defaults to `Date.now`. */
  readonly now?: () => number;
  /**
   * Returns `true` for a category label that looks like personal data, which
   * the receipt then counts as `"[GUARDED]"`. Defaults to the guard of the
   * audit logger.
   */
  readonly guard?: (value: string) => boolean;
}

/** Options of a single {@link ReceiptIssuer.issue} call. */
export interface IssueOptions {
  /** The original text, to bind the receipt to it with a keyed digest. */
  readonly input?: string;
}

/**
 * The outcome of {@link ReceiptIssuer.verify}.
 *
 * - `"malformed"`: the value is not a receipt of this format.
 * - `"signature"`: the receipt was altered, or signed with another key.
 * - `"output"`: the receipt is genuine but names another output text.
 * - `"input"`: the receipt is genuine but was issued for another input, or for
 *   no input.
 */
export type ReceiptVerification =
  | { readonly valid: true; readonly receipt: AnonymaReceipt }
  | { readonly valid: false; readonly reason: "malformed" | "signature" | "output" | "input" };

/** Options of {@link ReceiptIssuer.verify}. */
export interface VerifyReceiptOptions {
  /** The text that was sent; the receipt must name it. */
  readonly output?: string;
  /** The original text; the receipt must have been issued for it. */
  readonly input?: string;
}

/**
 * Issues and verifies receipts under one key.
 */
export interface ReceiptIssuer {
  /**
   * Issue a receipt for an anonymized text.
   *
   * @throws {@link ValidationError} When `subject` has neither `text` nor `outputDigest`, or
   *   none of `spans`, `matches` and `counts`, or when `counts` holds something other than counts.
   */
  readonly issue: (subject: ReceiptSubject, options?: IssueOptions) => Promise<AnonymaReceipt>;
  /** Check a receipt's signature and, when given, the texts it names. */
  readonly verify: (
    receipt: unknown,
    options?: VerifyReceiptOptions,
  ) => Promise<ReceiptVerification>;
}

const HEX64 = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** `true` when `value` has the members and types of a receipt. */
function isReceipt(value: unknown): value is AnonymaReceipt {
  if (!isRecord(value)) return false;
  const { v, id, timestamp, library, presets, policy, stats, total, output, input, alg } = value;
  return (
    v === 1 &&
    typeof id === "string" &&
    typeof timestamp === "string" &&
    typeof library === "string" &&
    (presets === undefined ||
      (Array.isArray(presets) && presets.every((name) => typeof name === "string"))) &&
    (policy === undefined || (isRecord(policy) && typeof policy["id"] === "string")) &&
    isRecord(stats) &&
    Object.values(stats).every((count) => Number.isInteger(count)) &&
    Number.isInteger(total) &&
    typeof output === "string" &&
    HEX64.test(output) &&
    (input === undefined || (typeof input === "string" && HEX64.test(input))) &&
    alg === "HMAC-SHA-256" &&
    (value["keyId"] === undefined || typeof value["keyId"] === "string") &&
    typeof value["signature"] === "string"
  );
}

/** Compare two strings in time that depends only on their length. */
function sameText(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) {
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}

/**
 * Create an issuer of signed {@link AnonymaReceipt receipts}.
 *
 * @param options - The signing key and what the receipts should say about the policy.
 * @returns The issuer.
 * @throws {@link ValidationError} When the key is missing or is an empty string.
 *
 * @example
 * ```ts
 * import { compilePipeline } from "anonyma/engine";
 * import { createReceiptIssuer } from "anonyma/audit";
 *
 * const receipts = createReceiptIssuer({ key: process.env.RECEIPT_KEY!, presets: "lgpd" });
 * const result = compilePipeline({ preset: "lgpd" }).transform(text);
 * const receipt = await receipts.issue(result);
 * // { v: 1, id: "…", timestamp: "2026-11-21T10:00:00.000Z", library: "anonyma@1.3.0",
 * //   presets: ["lgpd"], stats: { email: 2, "national-id": 1 }, total: 3,
 * //   output: "…", alg: "HMAC-SHA-256", signature: "…" }
 *
 * (await receipts.verify(receipt, { output: result.text })).valid; // true
 * ```
 */
export function createReceiptIssuer(options: ReceiptIssuerOptions): ReceiptIssuer {
  const { key, keyId, policy, now = Date.now, guard } = options;
  if (!(typeof key === "string" ? key.length > 0 : isRecord(key))) {
    throw new ValidationError("key", "must be an HMAC CryptoKey or a non-empty string");
  }
  const presets =
    options.presets === undefined
      ? undefined
      : typeof options.presets === "string"
        ? [options.presets]
        : [...options.presets];

  let imported: Promise<CryptoKey> | undefined;
  function signingKey(): Promise<CryptoKey> {
    if (typeof key !== "string") return Promise.resolve(key);
    imported ??= webCrypto().then((crypto) =>
      crypto.subtle.importKey("raw", utf8(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    );
    return imported;
  }

  async function sign(body: Omit<AnonymaReceipt, "signature">): Promise<string> {
    return hmacSha256Hex(RECEIPT_DOMAIN + canonicalize(body), await signingKey());
  }

  async function inputDigest(text: string): Promise<string> {
    return hmacSha256Hex(INPUT_DOMAIN + text, await signingKey());
  }

  return {
    async issue(subject, issueOptions = {}): Promise<AnonymaReceipt> {
      const { text, outputDigest } = isRecord(subject) ? subject : ({} as ReceiptSubject);
      if (
        typeof text !== "string" &&
        !(typeof outputDigest === "string" && HEX64.test(outputDigest))
      ) {
        throw new ValidationError(
          "subject.text",
          "must be the anonymized text, or outputDigest its SHA-256 in lower-case hex",
        );
      }
      const listed = subject.spans ?? subject.matches;
      const tallies: [string, number][] = [];
      if (Array.isArray(listed)) {
        for (const item of listed)
          tallies.push([String((item as { category?: unknown }).category), 1]);
      } else if (isRecord(subject.counts)) {
        for (const [label, count] of Object.entries(subject.counts)) {
          if (!(Number.isInteger(count) && count >= 0)) {
            throw new ValidationError(`subject.counts.${label}`, "must be a non-negative integer");
          }
          tallies.push([label, count]);
        }
      } else {
        throw new ValidationError(
          "subject",
          "must list what was replaced in `spans`, `matches` or `counts` (pass includeMatches: true to anonymize())",
        );
      }
      const counts = new Map<string, number>();
      let total = 0;
      for (const [label, count] of tallies) {
        // A custom category label could be a value: the audit guard blanks it.
        const category = guard === undefined ? guardLabel(label) : guardLabel(label, guard);
        counts.set(category, (counts.get(category) ?? 0) + count);
        total += count;
      }
      const stats: Record<string, number> = {};
      for (const [category, count] of [...counts].sort(([a], [b]) => (a < b ? -1 : 1))) {
        Object.defineProperty(stats, category, { value: count, enumerable: true });
      }
      const crypto = await webCrypto();
      const body: Omit<AnonymaReceipt, "signature"> = {
        v: 1,
        id: toHex(crypto.getRandomValues(new Uint8Array(16))),
        timestamp: new Date(now()).toISOString(),
        library: `anonyma@${VERSION}`,
        ...(presets !== undefined ? { presets } : {}),
        ...(policy !== undefined ? { policy: { ...policy } } : {}),
        stats,
        total,
        output: typeof text === "string" ? await sha256Hex(text) : (outputDigest as string),
        ...(issueOptions.input !== undefined
          ? { input: await inputDigest(issueOptions.input) }
          : {}),
        alg: "HMAC-SHA-256",
        ...(keyId !== undefined ? { keyId } : {}),
      };
      return Object.freeze({ ...body, signature: await sign(body) });
    },

    async verify(receipt, verifyOptions = {}): Promise<ReceiptVerification> {
      if (!isReceipt(receipt)) return { valid: false, reason: "malformed" };
      const { signature, ...body } = receipt;
      if (!sameText(await sign(body), signature)) return { valid: false, reason: "signature" };
      if (
        verifyOptions.output !== undefined &&
        (await sha256Hex(verifyOptions.output)) !== receipt.output
      ) {
        return { valid: false, reason: "output" };
      }
      if (
        verifyOptions.input !== undefined &&
        (receipt.input === undefined ||
          !sameText(await inputDigest(verifyOptions.input), receipt.input))
      ) {
        return { valid: false, reason: "input" };
      }
      return { valid: true, receipt };
    },
  };
}
