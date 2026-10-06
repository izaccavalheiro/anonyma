/**
 * @module internal/json-numbers
 * @description Parsing and serialising JSON text without changing numbers
 * that a JavaScript number cannot hold: integers beyond 2^53, numbers with
 * more than 17 significant digits and numbers out of range. `JSON.parse`
 * rounds the first two and turns the third into `Infinity`, which
 * `JSON.stringify` then writes as `null`.
 *
 * Such a number is parsed as a string that starts with a marker and holds the
 * number as it was written. Serialising writes the marked strings back as
 * numbers.
 * @internal
 */

const NUMBER = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
const MARKER_LENGTH = 12;

/**
 * A JSON text parsed without loss.
 * @internal
 */
export interface LosslessJson {
  /** The parsed value. Numbers that would lose precision are strings that start with `marker`. */
  readonly value: unknown;
  /** Prefix of the strings that stand for numbers; `undefined` when the text holds no such number. */
  readonly marker: string | undefined;
}

/** Twelve control characters no detector matches and no JSON text holds unescaped. */
function createMarker(): string {
  const random = new Uint8Array(MARKER_LENGTH);
  const source = (globalThis as { crypto?: Crypto }).crypto;
  if (source !== undefined) source.getRandomValues(random);
  else {
    // Node.js 18 scripts have no global crypto; the marker need not be secret.
    for (let i = 0; i < MARKER_LENGTH; i++) random[i] = Math.floor(Math.random() * 256);
  }
  let marker = "";
  for (const byte of random) marker += String.fromCharCode(1 + (byte & 7));
  return marker;
}

/** Whether a number literal changes when it goes through a JavaScript number. */
function losesPrecision(literal: string): boolean {
  if (!NUMBER.test(literal)) return false;
  const parsed = Number(literal);
  if (!Number.isFinite(parsed)) return true;
  if (!/[.eE]/.test(literal)) return !Number.isSafeInteger(parsed);
  const mantissa = literal
    .replace(/[eE].*$/, "")
    .replace(/[-.]/g, "")
    .replace(/^0+/, "");
  return mantissa.length > 17;
}

function isNumberCode(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    code === 43 ||
    code === 45 ||
    code === 46 ||
    code === 69 ||
    code === 101
  );
}

/**
 * Parse a JSON text, keeping numbers that JavaScript cannot represent.
 *
 * @throws SyntaxError When the text is not valid JSON.
 * @internal
 */
export function parseJsonLossless(text: string): LosslessJson {
  let marker: string | undefined;
  let rewritten = "";
  let copied = 0;
  let at = 0;
  while (at < text.length) {
    const code = text.charCodeAt(at);
    if (code === 34) {
      // A string: skip to its closing quote.
      at++;
      while (at < text.length) {
        const inner = text.charCodeAt(at);
        if (inner === 92) at += 2;
        else if (inner === 34) break;
        else at++;
      }
      at++;
    } else if (code === 45 || (code >= 48 && code <= 57)) {
      const start = at;
      at++;
      while (at < text.length && isNumberCode(text.charCodeAt(at))) at++;
      const literal = text.slice(start, at);
      if (losesPrecision(literal)) {
        marker ??= createMarker();
        rewritten += text.slice(copied, start) + JSON.stringify(marker + literal);
        copied = at;
      }
    } else {
      at++;
    }
  }
  if (marker === undefined) return { value: JSON.parse(text) as unknown, marker };
  return { value: JSON.parse(rewritten + text.slice(copied)) as unknown, marker };
}

/**
 * Serialise a value parsed by {@link parseJsonLossless}. A marked string that
 * still holds a number is written as that number; one whose content was
 * replaced is written as an ordinary string.
 * @internal
 */
export function stringifyJsonLossless(value: unknown, marker: string | undefined): string {
  const json = JSON.stringify(value) as string | undefined;
  if (json === undefined) return "null";
  if (marker === undefined) return json;
  const escaped = JSON.stringify(marker)
    .slice(1, -1)
    .replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
  const marked = new RegExp(`"${escaped}((?:[^"\\\\]|\\\\.)*)"`, "g");
  return json.replace(marked, (_whole: string, content: string) =>
    NUMBER.test(content) ? content : `"${content}"`,
  );
}
