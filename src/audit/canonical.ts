/**
 * @module audit/canonical
 * @description Canonical JSON and digests. Two values that are equal as data
 * always serialise to the same string, so a digest of that string identifies
 * the data.
 */

import { ValidationError } from "../errors.js";
import { toHex, utf8 } from "../internal/encoding.js";
import { webCrypto } from "../internal/webcrypto.js";

/**
 * Serialise a JSON value canonically: object members sorted by key, no
 * insignificant whitespace, `undefined` members omitted, array holes written
 * as `null`.
 *
 * @param value - A value made of plain objects, arrays, strings, finite
 *   numbers, booleans and `null`.
 * @returns The canonical JSON text.
 * @throws {@link ValidationError} When the value contains a non-finite number, a function,
 *   a symbol, a bigint, a cycle, or an object that is not plain data (a `Date`,
 *   a `Map`, a class instance): two such objects would otherwise share a text.
 *
 * @example
 * ```ts
 * canonicalize({ b: 1, a: [true, null] }); // '{"a":[true,null],"b":1}'
 * ```
 */
export function canonicalize(value: unknown): string {
  return write(value, new Set());
}

function write(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new ValidationError("value", "contains a number that JSON cannot represent");
      }
      return Object.is(value, -0) ? "0" : String(value);
    case "object":
      break;
    default:
      throw new ValidationError("value", `contains a ${typeof value}, which JSON cannot represent`);
  }

  if (ancestors.has(value)) throw new ValidationError("value", "contains a circular reference");
  ancestors.add(value);
  let out: string;
  if (Array.isArray(value)) {
    const items: string[] = [];
    // The iterator visits holes too, as undefined: both are written as null.
    for (const item of value as unknown[]) {
      items.push(item === undefined ? "null" : write(item, ancestors));
    }
    out = `[${items.join(",")}]`;
  } else {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ValidationError("value", "contains an object that is not plain data");
    }
    const record = value as Record<string, unknown>;
    const members: string[] = [];
    for (const key of Object.keys(record).sort()) {
      const member = record[key];
      if (member !== undefined) members.push(`${JSON.stringify(key)}:${write(member, ancestors)}`);
    }
    out = `{${members.join(",")}}`;
  }
  ancestors.delete(value);
  return out;
}

/**
 * SHA-256 of a text, as lower-case hex.
 *
 * @param text - The text to digest (encoded as UTF-8).
 * @returns 64 hexadecimal characters.
 *
 * @example
 * ```ts
 * await sha256Hex("abc"); // "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
 * ```
 */
export async function sha256Hex(text: string): Promise<string> {
  const crypto = await webCrypto();
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(text))));
}

/**
 * HMAC-SHA-256 of a text, as lower-case hex.
 *
 * @param text - The text to authenticate (encoded as UTF-8).
 * @param key - An HMAC-SHA-256 key.
 * @returns 64 hexadecimal characters.
 *
 * @remarks
 * Never call this with the key of an audit chain on text that someone else
 * chooses: the result would be a valid MAC under that key. For the checksum of
 * an input use {@link inputChecksum}, which cannot collide with a record hash.
 *
 * @example
 * ```ts
 * const mac = await hmacSha256Hex("message", key);
 * ```
 */
export async function hmacSha256Hex(text: string, key: CryptoKey): Promise<string> {
  const crypto = await webCrypto();
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(text))));
}

/** What a keyed chain hash is computed over: this label, then the canonical record. */
const RECORD_DOMAIN = "anonyma/audit/record/v1\0";
/** What an input checksum is computed over: this label, then the input. */
const INPUT_DOMAIN = "anonyma/audit/input/v1\0";

/**
 * Hash of a canonical record: SHA-256 without a key, HMAC-SHA-256 with one.
 * The keyed form is domain-separated from {@link inputChecksum}, so no
 * checksum the logger's key ever produced is a valid record hash.
 * @internal
 */
export function recordHash(canonical: string, key: CryptoKey | undefined): Promise<string> {
  return key === undefined ? sha256Hex(canonical) : hmacSha256Hex(RECORD_DOMAIN + canonical, key);
}

/**
 * Keyed checksum of an input, for `AuditEvent.checksums.input`. It ties a
 * record to the data it describes without storing the data, and without
 * letting whoever chose the input obtain a MAC that is valid anywhere else.
 *
 * @param text - The input text.
 * @param key - The HMAC-SHA-256 key of the audit chain.
 * @returns 64 hexadecimal characters.
 *
 * @example
 * ```ts
 * await audit.record({
 *   operation: "anonymize",
 *   fields: [],
 *   checksums: { input: await inputChecksum(text, key) },
 * });
 * ```
 */
export function inputChecksum(text: string, key: CryptoKey): Promise<string> {
  return hmacSha256Hex(INPUT_DOMAIN + text, key);
}
