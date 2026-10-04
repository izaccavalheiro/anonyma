/**
 * @module engine/precise
 * @description Native span detectors for the five identifier families whose
 * formats are defined by a standard: email addresses, US Social Security
 * Numbers, IBANs, IP addresses and payment card numbers.
 *
 * Unlike the 1.x detectors they validate what they match (issuer ranges and
 * Luhn for cards, the ISO 13616 country length table and mod-97 for IBANs,
 * SSA allocation rules for SSNs, the RFC 4291 text grammar for IPv6) and they
 * look at the surrounding text to reject look-alikes such as version strings,
 * ZIP+4 codes, file names and MAC addresses. Their patterns are compiled once.
 */

import { ibanMod97, luhn } from "../validators.js";
import { defineDetector } from "./detector.js";
import type { EmitSpan, SpanDetector } from "./types.js";

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

// The local part is bounded (RFC 5321 allows 64 octets), so that a long run of
// local-part characters costs a fixed amount per start position.
const EMAIL_PATTERN =
  /(?<![\p{L}\p{N}_%+-])[\p{L}\p{N}_%+-](?:[\p{L}\p{N}._%+'-]{0,62}[\p{L}\p{N}_%+-])?@((?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+)(xn--[a-z0-9-]{1,59}|\p{L}{2,24})(?!\p{L})/giu;

/** "Top-level domains" that are really asset or unit-file suffixes. */
const NOT_A_TLD: ReadonlySet<string> = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "webp",
  "ico",
  "bmp",
  "css",
  "js",
  "json",
  "map",
  "service",
  "socket",
  "timer",
  "mount",
  "target",
  "slice",
  "scope",
]);

/** Top-level domains common enough that `x@y.com(` is an address and not a method call. */
const COMMON_TLD: ReadonlySet<string> = new Set([
  "com",
  "org",
  "net",
  "edu",
  "gov",
  "mil",
  "int",
  "info",
  "biz",
  "name",
  "pro",
  "io",
  "co",
  "me",
  "dev",
  "app",
  "ai",
]);

/**
 * `scheme://user[:password]` immediately before the match: URL userinfo, not
 * an address. Only characters that occur in a user name or a password may sit
 * between the scheme and the match, so `"https://acme.com","email":"a@b.co"`
 * and `https://acme.com,a@b.co` are still addresses.
 */
const URL_USERINFO_BEFORE = /[a-z][a-z0-9+.-]*:\/\/[a-z0-9._~%!$*+:-]*$/i;
/** A mail header whose value is a list of `<message identifiers>`, not of addresses. */
const MESSAGE_ID_BEFORE =
  /\b(?:message-id|in-reply-to|references)\s*:\s*(?:<[^\s<>]*>\s*)*<[^\s<>@]*$/i;

function scanEmail(text: string, emit: EmitSpan): void {
  EMAIL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = EMAIL_PATTERN.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    const domain = match[1] ?? "";
    const tld = (match[2] ?? "").toLowerCase();

    if (NOT_A_TLD.has(tld)) continue;
    // "name@1.0.0-beta": a package version, not a domain.
    if (/^\d+\.\d+\./.test(domain)) continue;
    // "W@x.flatten()": a call on a short identifier, not an address.
    if (
      text.charCodeAt(end) === 40 &&
      match[0].indexOf("@") <= 2 &&
      tld.length > 2 &&
      !COMMON_TLD.has(tld)
    ) {
      continue;
    }
    // The account every Git remote uses ("git@github.com:org/repo.git") is nobody's address.
    if (match[0].startsWith("git@")) continue;

    const before = text.slice(Math.max(0, start - 96), start);
    if (URL_USERINFO_BEFORE.test(before) || MESSAGE_ID_BEFORE.test(before)) continue;

    emit(start, end, 0.99);
  }
}

/**
 * Email addresses, including internationalised ones (RFC 6531).
 *
 * @example
 * ```ts
 * import { createPipeline, emailDetector, redactWith } from "anonyma/engine";
 *
 * createPipeline({ detectors: [emailDetector], replace: { fallback: redactWith() } })
 *   .transform("Write to josé.garcia@example.com").text;
 * // "Write to [REDACTED]"
 * ```
 */
export const emailDetector: SpanDetector = defineDetector({
  id: "email",
  category: "email",
  prefilter: (text) => text.includes("@"),
  scan: scanEmail,
  maxMatchLength: 320,
});

const OBFUSCATED_EMAIL_PATTERN =
  /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}_%+-][\p{L}\p{N}._%+-]{0,63}(?:\s*(?:\[at\]|\(at\)|\{at\}|\[@\])\s*|[ \t]+@[ \t]*|@[ \t]+)[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\s*(?:\[dot\]|\(dot\)|\{dot\}|\[\.\]|\.)\s*[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\s*(?:\[dot\]|\(dot\)|\{dot\}|\[\.\]|\.)\s*\p{L}{2,24}(?![\p{L}\p{N}])/giu;

/**
 * Obfuscated email addresses such as `user [at] example [dot] com`,
 * `user[@]example[.]com` and `user @ example.com`. Used by aggressive
 * pipelines in addition to {@link emailDetector}.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [emailDetector, obfuscatedEmailDetector], replace: { fallback: redactWith() } });
 * ```
 */
export const obfuscatedEmailDetector: SpanDetector = defineDetector({
  id: "email/obfuscated",
  category: "email",
  prefilter: (text) => /\[at\]|\(at\)|\{at\}|@/i.test(text),
  scan(text, emit) {
    OBFUSCATED_EMAIL_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = OBFUSCATED_EMAIL_PATTERN.exec(text)) !== null) {
      emit(match.index, match.index + match[0].length, 0.75);
    }
  },
  maxMatchLength: 320,
});

// ---------------------------------------------------------------------------
// US Social Security Number
// ---------------------------------------------------------------------------

const SSN_SEPARATOR = String.raw`(?:\s?[-\u2010-\u2015\u2212.]\s?|\s{1,2})`;
const SSN_SEPARATED_PATTERN = new RegExp(
  String.raw`(?<!\d)(?<!\d[-\u2010-\u2015\u2212./])(\d{3})${SSN_SEPARATOR}(\d{2})${SSN_SEPARATOR}(\d{4})(?![-\u2010-\u2015\u2212.]?\d)`,
  "g",
);
// After the label, up to 24 characters that are neither digits nor the end of
// a sentence may precede the number: "SSN is", "SSN of the applicant:".
const SSN_LABELLED_PATTERN =
  /(?:\bssn|\bss#|\bsocial\s+security)(?:\s*(?:number|num\.?|no\.?|#))?[^\d\n.;!?]{0,24}(\d{9})(?!\d)/dgi;

/** SSA allocation rules: no area 000, 666 or 900-999, no group 00, no serial 0000. */
function isAssignableSsn(area: string, group: string, serial: string): boolean {
  return (
    area !== "000" && area !== "666" && !area.startsWith("9") && group !== "00" && serial !== "0000"
  );
}

function scanSsn(text: string, emit: EmitSpan): void {
  SSN_SEPARATED_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SSN_SEPARATED_PATTERN.exec(text)) !== null) {
    if (isAssignableSsn(match[1] ?? "", match[2] ?? "", match[3] ?? "")) {
      emit(match.index, match.index + match[0].length, 0.95);
    }
  }
  SSN_LABELLED_PATTERN.lastIndex = 0;
  while ((match = SSN_LABELLED_PATTERN.exec(text)) !== null) {
    const digits = match[1] ?? "";
    const bounds = match.indices?.[1];
    if (
      bounds !== undefined &&
      isAssignableSsn(digits.slice(0, 3), digits.slice(3, 5), digits.slice(5))
    ) {
      emit(bounds[0], bounds[1], 0.9);
    }
  }
}

/**
 * US Social Security Numbers written with separators (`123-45-6789`), and
 * unseparated nine-digit numbers only when a label such as `SSN` or
 * `social security number` precedes them in the same sentence. A bare
 * nine-digit number is not reported.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [ssnDetector], replace: { fallback: redactWith() } })
 *   .transform("SSN 123-45-6789, ZIP 10001-1234").text;
 * // "SSN [REDACTED], ZIP 10001-1234"
 * ```
 */
export const ssnDetector: SpanDetector = defineDetector({
  id: "ssn",
  category: "ssn",
  prefilter: (text) => /\d{4}/.test(text),
  scan: scanSsn,
  maxMatchLength: 48,
});

const SSN_BARE_PATTERN = /(?<![\d.,])(\d{3})(\d{2})(\d{4})(?![\d.,]?\d)/g;

/**
 * Unseparated nine-digit numbers that satisfy the SSA allocation rules. Most
 * such numbers are not SSNs, so the confidence is low. Used by aggressive
 * pipelines in addition to {@link ssnDetector}.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [ssnDetector, bareSsnDetector], replace: { fallback: redactWith() } });
 * ```
 */
export const bareSsnDetector: SpanDetector = defineDetector({
  id: "ssn/bare",
  category: "ssn",
  prefilter: (text) => /\d{9}/.test(text),
  scan(text, emit) {
    SSN_BARE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = SSN_BARE_PATTERN.exec(text)) !== null) {
      if (isAssignableSsn(match[1] ?? "", match[2] ?? "", match[3] ?? "")) {
        emit(match.index, match.index + 9, 0.5);
      }
    }
  },
  maxMatchLength: 12,
});

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

/**
 * IBAN length per country: the ISO 13616 registry, followed by the countries
 * that issue IBAN-format account numbers without being in the registry.
 */
const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BI: 27,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 22,
  CY: 28,
  CZ: 24,
  DE: 22,
  DJ: 27,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FK: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HN: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  LY: 25,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MN: 20,
  MR: 27,
  MT: 31,
  MU: 30,
  NI: 28,
  NL: 18,
  NO: 15,
  OM: 23,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  RU: 33,
  SA: 24,
  SC: 31,
  SD: 18,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  SO: 23,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
  YE: 30,
  // Not in the registry.
  AO: 25,
  BF: 28,
  BJ: 28,
  CF: 27,
  CG: 27,
  CI: 28,
  CM: 27,
  CV: 25,
  DZ: 26,
  GA: 27,
  GQ: 27,
  GW: 25,
  IR: 26,
  KM: 27,
  MA: 28,
  MG: 27,
  ML: 28,
  MZ: 25,
  NE: 28,
  SN: 28,
  TD: 27,
  TG: 28,
};

const IBAN_START_PATTERN = /(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}/g;

function isAlphanumeric(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/** Space, no-break space, hyphen, tab, line feed or carriage return. */
function isIbanSeparator(code: number): boolean {
  return code === 32 || code === 160 || code === 45 || code === 9 || code === 10 || code === 13;
}

function isValidIban(collected: string): boolean {
  const normalised = collected.toUpperCase();
  const checkDigits = Number(normalised.slice(2, 4));
  return checkDigits >= 2 && checkDigits <= 98 && ibanMod97(normalised);
}

/**
 * End offset of the IBAN that starts at `start`, or -1. Exactly `length`
 * alphanumerics are collected, with at most two separators in a row.
 */
function endOfIban(text: string, start: number, length: number): number {
  let collected = "";
  let at = start;
  let end = start;
  let separators = 2;
  while (collected.length < length && at < text.length) {
    const code = text.charCodeAt(at);
    if (isAlphanumeric(code)) {
      collected += text.charAt(at);
      separators = 0;
      end = at + 1;
    } else if (separators < 2 && isIbanSeparator(code)) {
      separators++;
    } else {
      break;
    }
    at++;
  }
  if (collected.length !== length || isAlphanumeric(text.charCodeAt(end))) return -1;
  return isValidIban(collected) ? end : -1;
}

function scanIban(text: string, emit: EmitSpan): void {
  IBAN_START_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IBAN_START_PATTERN.exec(text)) !== null) {
    const start = match.index;
    const country = match[0].slice(0, 2).toUpperCase();
    if (!Object.hasOwn(IBAN_LENGTHS, country)) continue;
    const end = endOfIban(text, start, IBAN_LENGTHS[country] ?? 0);
    if (end < 0) continue;

    emit(start, end, 0.99);
    IBAN_START_PATTERN.lastIndex = end;
  }
}

/**
 * International Bank Account Numbers, validated against the country's length
 * and the mod-97 check. Spaces or hyphens between groups and lower-case
 * letters are accepted. The length table holds the ISO 13616 registry and the
 * countries that issue IBAN-format numbers outside it.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [ibanDetector], replace: { fallback: redactWith() } })
 *   .transform("IBAN: BE68 5390 0754 7034 BIC: GKCCBEBB").text;
 * // "IBAN: [REDACTED] BIC: GKCCBEBB"
 * ```
 */
export const ibanDetector: SpanDetector = defineDetector({
  id: "iban",
  category: "iban",
  prefilter: (text) => /[A-Za-z]{2}\d{2}/.test(text),
  scan: scanIban,
  maxMatchLength: 72,
});

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

const IPV4_PATTERN =
  /(?<![\d.])((?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.)((?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(\/(?:3[0-2]|[12]?\d)(?![\w/.]))?(?!\.?\d)/g;

/** Words that always introduce a version number. */
const VERSION_BEFORE = /(?:\bv|version|\bver\.?|\bfirmware|\brev\.?)\s*[:=#("']{0,3}\s*$/i;
/**
 * A product token such as `Chrome/` directly before the value. A path segment
 * (`/geoip/203.0.113.57`) and a protocol name (`tcp/203.0.113.9`) are not
 * product tokens.
 */
const PRODUCT_BEFORE =
  /(?<![/\w.+-])(?!(?:tcp|udp|sctp|icmp|ip|ipv4|inet|ssh|dns|peer|host|addr|src|dst)\/)[a-z][\w.+-]*\/\s*$/i;
/** Words that introduce a section or clause number, or an object identifier. */
const NUMBERING_BEFORE =
  /(?:\bsection|\bsec\.|\bchapter|\bclause|\bappendix|\bannex|\boid|\u00a7)\s*[:=#("']{0,3}\s*$/i;
/** Words that introduce a version or a number, and just as often an address. */
const WEAK_VERSION_BEFORE = /(?:\brelease|\bbuild)\s*[:=#("']{0,3}\s*$/i;
/** Capitalised references ("Table 3.2.1.1", "ISO-27001 5.1.2.3"). */
const REFERENCE_BEFORE = /(?:\bTable|\bFigure|\bFig\.|\b[A-Z]{2,6}-\d+)\s*[:=#("']{0,3}\s*$/;
/** A suffix that makes the value a version or a file name ("1.2.3.4-beta", "1.2.3.4.tar"). */
const VERSION_SUFFIX_AFTER = /^(?:[-.][A-Za-z]|-\d+[A-Za-z])/;

/**
 * `true` for addresses in the private, loopback, link-local, shared and
 * documentation ranges. A value in one of them is an address even where the
 * surrounding words suggest a version or a reference number.
 */
function isReservedIpv4(octets: readonly string[]): boolean {
  const first = Number(octets[0]);
  const second = Number(octets[1]);
  const third = Number(octets[2]);
  return (
    first === 10 ||
    first === 127 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254) ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113)
  );
}

function scanIpv4(text: string, emit: EmitSpan): void {
  IPV4_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IPV4_PATTERN.exec(text)) !== null) {
    const start = match.index;
    let value = match[0];
    // Netmasks, broadcast and the unspecified address identify nobody.
    if (match[1] === "255." || value.startsWith("0.0.0.0")) continue;
    // Zero-padded octets are only credible when padded to three digits throughout
    // ("192.168.001.010"); "1.200.000.000" and "02.123.45.67" are numbers and phones.
    const octets = value.split("/", 1).join("").split(".");
    if (octets.some((octet) => octet.length === 2 && octet.startsWith("0"))) continue;
    if (octets.includes("000") && octets.some((octet) => octet.length !== 3)) continue;

    const before = text.slice(Math.max(0, start - 48), start);
    if (VERSION_BEFORE.test(before) || PRODUCT_BEFORE.test(before)) continue;
    // Section and clause numbers are small; an address after such a word usually is not.
    const small = octets.every((octet) => octet.length <= 2);
    if (small && NUMBERING_BEFORE.test(before)) continue;
    if (!isReservedIpv4(octets)) {
      if (WEAK_VERSION_BEFORE.test(before) || (small && REFERENCE_BEFORE.test(before))) continue;
      const end = start + value.length;
      if (VERSION_SUFFIX_AFTER.test(text.slice(end, end + 8))) continue;
    }
    // After "//" a slash starts a URL path, not a prefix length.
    if (match[3] !== undefined && before.endsWith("//")) {
      value = value.slice(0, -match[3].length);
    }
    emit(start, start + value.length, 0.95);
  }
}

/**
 * IPv4 addresses in dotted-decimal notation, with an optional CIDR prefix
 * length. Version strings, section numbers, OIDs, netmasks and numbers with
 * more than four parts are not reported.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [ipv4Detector], replace: { fallback: redactWith() } })
 *   .transform("client 203.0.113.57, Chrome/124.0.0.0").text;
 * // "client [REDACTED], Chrome/124.0.0.0"
 * ```
 */
export const ipv4Detector: SpanDetector = defineDetector({
  id: "ipv4",
  category: "ipv4",
  prefilter: (text) => /\d\.\d/.test(text),
  scan: scanIpv4,
  maxMatchLength: 40,
});

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

const IPV6_RUN_PATTERN = /[0-9A-Fa-f:.]{2,}/g;
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;
const DOTTED_QUAD =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Number of 16-bit groups in one side of an address, or -1 when it is malformed. */
function countGroups(side: string, allowIpv4Tail: boolean): number {
  if (side === "") return 0;
  const groups = side.split(":");
  let count = 0;
  for (const [index, group] of groups.entries()) {
    if (HEX_GROUP.test(group)) count += 1;
    else if (allowIpv4Tail && index === groups.length - 1 && DOTTED_QUAD.test(group)) count += 2;
    else return -1;
  }
  return count;
}

/** RFC 4291 §2.2 text representation. */
function isIpv6(candidate: string): boolean {
  const compression = candidate.indexOf("::");
  if (compression < 0) {
    const groups = candidate.split(":");
    // Eight groups of two hex digits is an EUI-64 / MAC-style identifier.
    if (groups.length === 8 && groups.every((group) => group.length === 2)) return false;
    return countGroups(candidate, true) === 8;
  }
  if (candidate.includes("::", compression + 1)) return false;
  const head = countGroups(candidate.slice(0, compression), false);
  const tail = countGroups(candidate.slice(compression + 2), true);
  return head >= 0 && tail >= 0 && head + tail <= 7 && head + tail > 0;
}

const WORD_CHARACTER = /[\p{L}\p{N}_]/u;

function scanIpv6(text: string, emit: EmitSpan): void {
  IPV6_RUN_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IPV6_RUN_PATTERN.exec(text)) !== null) {
    let start = match.index;
    let value = match[0];
    // A run that starts inside a label ("IPv6:2001:db8::1", "eth0:fe80::1") or
    // right after one ("addr:fe80::1"): the address begins after the first colon.
    // "x2001:db8::1" is a malformed token, not a label.
    const glued = start > 0 && WORD_CHARACTER.test(text.charAt(start - 1));
    const colon = value.indexOf(":");
    if (!value.startsWith("::") && (colon === 0 || (glued && colon > 0 && colon <= 2))) {
      start += colon + 1;
      value = value.slice(colon + 1);
    } else if (glued) {
      continue;
    }
    // Trailing sentence punctuation and a single trailing colon are not part of an address.
    while (value.endsWith(".")) value = value.slice(0, -1);
    if (value.endsWith(":") && !value.endsWith("::")) value = value.slice(0, -1);
    // No address is longer than 45 characters.
    if (value.length < 3 || value.length > 45) continue;
    if (value.indexOf(":") === value.lastIndexOf(":")) continue;

    const end = start + value.length;
    if (WORD_CHARACTER.test(text.charAt(end))) continue;
    // "Add::add" and "dead::beef" are identifiers and words, not addresses.
    if (!/\d/.test(value) && value.split(":").filter((group) => group !== "").length < 3) continue;
    if (!isIpv6(value)) continue;

    emit(start, end, 0.95);
  }
}

/**
 * IPv6 addresses in every RFC 4291 text form: full, `::`-compressed and with
 * an embedded IPv4 tail. MAC-style identifiers, times and `::` scope
 * operators are not reported.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [ipv6Detector], replace: { fallback: redactWith() } })
 *   .transform("from 2001:db8::1 at 12:30:45").text;
 * // "from [REDACTED] at 12:30:45"
 * ```
 */
export const ipv6Detector: SpanDetector = defineDetector({
  id: "ipv6",
  category: "ipv6",
  prefilter: (text) => text.includes(":"),
  scan: scanIpv6,
  maxMatchLength: 64,
});

// ---------------------------------------------------------------------------
// Payment cards
// ---------------------------------------------------------------------------

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

/** Digit-group layouts in which card numbers are written, longest first. */
const CARD_GROUPINGS: readonly (readonly number[])[] = [
  [4, 4, 4, 4, 3],
  [4, 4, 4, 4],
  [4, 4, 4, 3],
  [4, 4, 4, 2],
  [4, 4, 4, 1],
  [4, 6, 5],
  [4, 6, 4],
  [8, 8],
  [6, 13],
];

const SEPARATOR_NONE = 0;
const SEPARATOR_SPACE = 1;
const SEPARATOR_HYPHEN = 2;
const SEPARATOR_DOT = 3;
const SEPARATOR_NEWLINE = 4;

/** Kind of group separator in `text[from, to)`, or `SEPARATOR_NONE` when it is not one. */
function separatorKind(text: string, from: number, to: number): number {
  const first = text.charCodeAt(from);
  if (to - from === 1) {
    if (first === 32 || first === 160) return SEPARATOR_SPACE;
    if (first === 45) return SEPARATOR_HYPHEN;
    if (first === 46) return SEPARATOR_DOT;
    if (first === 10) return SEPARATOR_NEWLINE;
    return SEPARATOR_NONE;
  }
  if (to - from !== 2) return SEPARATOR_NONE;
  const second = text.charCodeAt(from + 1);
  if ((first === 32 || first === 160) && (second === 32 || second === 160)) return SEPARATOR_SPACE;
  if (first === 13 && second === 10) return SEPARATOR_NEWLINE;
  return SEPARATOR_NONE;
}

function inRange(digits: string, length: number, low: number, high: number): boolean {
  const prefix = Number(digits.slice(0, length));
  return prefix >= low && prefix <= high;
}

/**
 * `true` when the prefix and length belong to a card network (ISO/IEC 7812
 * issuer ranges). `grouped` tells whether the number was written in groups.
 */
function isIssuedRange(digits: string, grouped: boolean): boolean {
  const length = digits.length;
  if (digits.startsWith("4")) return length === 13 || length === 16 || length === 19;
  if (inRange(digits, 2, 51, 55) || inRange(digits, 4, 2221, 2720)) return length === 16;
  if (digits.startsWith("34") || digits.startsWith("37")) return length === 15;
  // UATP; an unseparated 15-digit number that starts with 1 is too often something else.
  if (digits.startsWith("1")) return grouped && length === 15;
  if (length === 14) return inRange(digits, 3, 300, 305) || /^3(?:095|6|8|9)/.test(digits);
  if (length < 16) return false;
  return (
    digits.startsWith("6011") ||
    inRange(digits, 3, 644, 649) ||
    digits.startsWith("65") ||
    digits.startsWith("62") ||
    inRange(digits, 4, 3528, 3589) ||
    inRange(digits, 3, 300, 305) ||
    /^3(?:095|6|8|9)/.test(digits) ||
    inRange(digits, 4, 2200, 2205) ||
    digits.startsWith("50") ||
    inRange(digits, 2, 56, 69) ||
    // RuPay, UzCard, Humo, Troy, NAPAS, T-Union.
    inRange(digits, 2, 81, 82) ||
    digits.startsWith("8600") ||
    digits.startsWith("9860") ||
    digits.startsWith("9792") ||
    digits.startsWith("9704") ||
    digits.startsWith("31")
  );
}

interface CardCandidate {
  /** Index of the first digit run of the candidate. */
  readonly run: number;
  readonly start: number;
  readonly end: number;
  readonly confidence: number;
}

/**
 * Every position at which a digit run begins is tried on its own, in every
 * layout, so a number that fails the checks never hides the one that starts
 * inside it ("2024\n4111 1111 1111 1111", a column of card numbers).
 */
function scanCard(text: string, emit: EmitSpan): void {
  // The digit runs of the text, found without a regular expression: a dense
  // text has one every few characters, and a match object for each adds up.
  const starts: number[] = [];
  const ends: number[] = [];
  for (let at = 0; at < text.length; at++) {
    if (!isDigit(text.charCodeAt(at))) continue;
    starts.push(at);
    while (at < text.length && isDigit(text.charCodeAt(at))) at++;
    ends.push(at);
  }

  const candidates: CardCandidate[] = [];
  /** Per first run: the furthest end of a candidate that starts there. */
  const reach = new Map<number, number>();
  const add = (run: number, end: number, confidence: number): void => {
    candidates.push({ run, start: starts[run] ?? 0, end, confidence });
    reach.set(run, Math.max(reach.get(run) ?? 0, end));
  };

  for (const [run, start] of starts.entries()) {
    const length = (ends[run] ?? start) - start;

    if (length >= 13 && length <= 19) {
      const digits = text.slice(start, start + length);
      if (isIssuedRange(digits, false) && luhn(digits)) add(run, start + length, 0.92);
      continue;
    }

    for (const grouping of CARD_GROUPINGS) {
      if (grouping[0] !== length) continue;
      let digits = "";
      let uniform = true;
      let kind = SEPARATOR_NONE;
      let fits = true;
      for (const [offset, size] of grouping.entries()) {
        const from = starts[run + offset];
        const to = ends[run + offset];
        if (from === undefined || to === undefined || to - from !== size) {
          fits = false;
          break;
        }
        if (offset > 0) {
          const between = separatorKind(text, ends[run + offset - 1] ?? from, from);
          if (between === SEPARATOR_NONE) {
            fits = false;
            break;
          }
          if (kind !== SEPARATOR_NONE && between !== kind) uniform = false;
          kind = between;
        }
        digits += text.slice(from, to);
      }
      if (!fits || !luhn(digits)) continue;

      const end = ends[run + grouping.length - 1] ?? start;
      if (isIssuedRange(digits, true)) {
        add(run, end, uniform ? 0.97 : 0.85);
      } else if (
        uniform &&
        digits.length === 16 &&
        grouping.length === 4 &&
        !/^(\d)\1+$/.test(digits)
      ) {
        // Four groups of four with a valid check digit: a card of a network outside the table.
        add(run, end, 0.6);
      }
    }
  }

  // Report the candidates that add something. One that only covers the end of
  // an accepted number and the beginning of the next candidate is the same
  // digits read out of phase.
  let covered = -1;
  for (const candidate of candidates) {
    if (candidate.end <= covered) continue;
    if (candidate.start < covered) {
      let next = candidate.run;
      while ((starts[next] ?? Infinity) < covered) next++;
      if ((reach.get(next) ?? 0) >= candidate.end) continue;
    }
    emit(candidate.start, candidate.end, candidate.confidence);
    covered = Math.max(covered, candidate.end);
  }
}

/**
 * Payment card numbers (PANs): 13 to 19 digits, unseparated or in the usual
 * groupings, that fall in an issuer range and pass the Luhn check. Four groups
 * of four digits that pass the Luhn check are reported with a low confidence
 * when no issuer range matches.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [creditCardDetector], replace: { fallback: redactWith() } })
 *   .transform("4111 1111 1111 1111 12/25, IMEI 490154203237518").text;
 * // "[REDACTED] 12/25, IMEI 490154203237518"
 * ```
 */
export const creditCardDetector: SpanDetector = defineDetector({
  id: "credit-card",
  category: "credit-card",
  prefilter: (text) => /\d{4}/.test(text),
  scan: scanCard,
  maxMatchLength: 48,
});

const MASKED_CARD_PATTERN =
  /(?<![\w*])(?:[*Xx\u2022]{4}[ -]?){2,3}(?:[*Xx\u2022]{2}\d{2}|\d{4})(?!\d)/g;

/**
 * Partially masked card numbers such as `****-****-****-1234` and
 * `XXXX XXXX XXXX 1234`. Used by aggressive pipelines in addition to
 * {@link creditCardDetector}.
 *
 * @example
 * ```ts
 * createPipeline({ detectors: [creditCardDetector, maskedCardDetector], replace: { fallback: redactWith() } });
 * ```
 */
export const maskedCardDetector: SpanDetector = defineDetector({
  id: "credit-card/masked",
  category: "credit-card",
  prefilter: (text) => /[*Xx\u2022]{4}/.test(text),
  scan(text, emit) {
    MASKED_CARD_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = MASKED_CARD_PATTERN.exec(text)) !== null) {
      emit(match.index, match.index + match[0].length, 0.8);
    }
  },
  maxMatchLength: 24,
});
