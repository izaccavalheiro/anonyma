/**
 * @module internal/encoding
 * @description Byte and text encodings shared by the cryptographic modules.
 * They avoid `Buffer` so that they work in every runtime.
 * @internal
 */

const encoder = new TextEncoder();
// `ignoreBOM` keeps a leading U+FEFF: a decoded value must equal what was encoded.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
/** First byte of the fallback encoding of {@link encodeText}; it never starts a UTF-8 sequence. */
const UTF16_MARKER = 0xff;

/** Bytes backed by a plain `ArrayBuffer`, as the Web Crypto API requires. */
export type Bytes = Uint8Array<ArrayBuffer>;

/**
 * Encode a string as UTF-8.
 * @internal
 */
export function utf8(text: string): Bytes {
  const encoded = encoder.encode(text);
  const out = new Uint8Array(encoded.length);
  out.set(encoded);
  return out;
}

/**
 * Decode UTF-8 bytes. Returns `undefined` when the bytes are not valid UTF-8.
 * @internal
 */
export function fromUtf8(bytes: Uint8Array): string | undefined {
  try {
    return decoder.decode(bytes);
  } catch {
    return undefined;
  }
}

/**
 * Whether `text` is well-formed UTF-16, that is, has no lone surrogate.
 * @internal
 */
export function isWellFormed(text: string): boolean {
  return !LONE_SURROGATE.test(text);
}

/**
 * Encode a string without loss. Well-formed strings become UTF-8. A string
 * with a lone surrogate, which UTF-8 cannot represent, becomes a marker byte
 * followed by its UTF-16 code units, so that different strings never share an
 * encoding.
 * @internal
 */
export function encodeText(text: string): Bytes {
  if (isWellFormed(text)) return utf8(text);
  const out = new Uint8Array(1 + text.length * 2);
  out[0] = UTF16_MARKER;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    out[1 + i * 2] = unit & 0xff;
    out[2 + i * 2] = unit >>> 8;
  }
  return out;
}

/**
 * Reverse {@link encodeText}. Returns `undefined` for bytes it did not produce.
 * @internal
 */
export function decodeText(bytes: Uint8Array): string | undefined {
  if (bytes[0] !== UTF16_MARKER) return fromUtf8(bytes);
  if (bytes.length % 2 !== 1) return undefined;
  let out = "";
  for (let i = 1; i < bytes.length; i += 2) {
    /* v8 ignore next -- the length is odd, so i and i + 1 are always in range */
    out += String.fromCharCode((bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8));
  }
  return out;
}

/**
 * Concatenate byte arrays.
 * @internal
 */
export function concatBytes(...parts: readonly Uint8Array[]): Bytes {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Lower-case hexadecimal encoding.
 * @internal
 */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * URL-safe base64 without padding (RFC 4648 §5). Encodes in slices so that
 * large inputs never exceed the engine's argument limit.
 * @internal
 */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The URL-safe base64 alphabet, in value order. */
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Decode URL-safe base64 without padding. Returns `undefined` for malformed
 * input, including input whose last character carries bits that the encoder
 * would have left at zero: every byte string has exactly one accepted text.
 * @internal
 */
export function fromBase64Url(text: string): Bytes | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return undefined;
  const remainder = text.length % 4;
  if (remainder !== 0) {
    const last = BASE64_ALPHABET.indexOf(text.charAt(text.length - 1));
    if ((last & (remainder === 2 ? 0b1111 : 0b11)) !== 0) return undefined;
  }
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Crockford base32 of the first `chars * 5` bits of `bytes`. The alphabet has
 * no `I`, `L`, `O` or `U`, so identifiers survive being read aloud or retyped.
 * @internal
 */
export function toBase32(bytes: Uint8Array, chars: number): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < chars) {
      bits -= 5;
      out += CROCKFORD.charAt((buffer >>> bits) & 31);
    }
    if (out.length === chars) break;
    buffer &= (1 << bits) - 1;
  }
  return out;
}

/**
 * `length` cryptographically random bytes.
 * @internal
 */
export function randomBytes(crypto: Crypto, length: number): Bytes {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
