/**
 * @module detectors/ip-address
 * @description Detectors for IPv4 and IPv6 addresses.
 */

import type { PiiMatch } from "../types.js";

/**
 * Matches standard dotted-decimal IPv4 addresses with optional CIDR suffix.
 * Validates octet range (0–255) via lookahead structure.
 *
 * @internal
 */
const IPV4_PATTERN =
  /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/\d{1,2})?\b/g;

/**
 * Matches full and compressed IPv6 addresses.
 *
 * @internal
 */
const IPV6_PATTERN =
  /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;

/**
 * Detect IPv4 addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "ipv4"`.
 *
 * @example
 * ```ts
 * import { detectIpv4 } from "anonyma/detectors";
 *
 * detectIpv4("Client IP: 192.168.1.100");
 * // [{ category: "ipv4", value: "192.168.1.100", start: 11, end: 24, confidence: 0.98 }]
 * ```
 */
export function detectIpv4(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(IPV4_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "ipv4",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.98,
    });
  }

  return matches;
}

/**
 * Detect IPv6 addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "ipv6"`.
 *
 * @example
 * ```ts
 * import { detectIpv6 } from "anonyma/detectors";
 *
 * detectIpv6("Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
 * // [{ category: "ipv6", value: "2001:0db8:...", start: 9, end: 47, confidence: 0.98 }]
 * ```
 */
export function detectIpv6(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const pattern = new RegExp(IPV6_PATTERN.source, "g");
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    matches.push({
      category: "ipv6",
      value: match[0],
      start: match.index,
      end: match.index + match[0].length,
      confidence: 0.98,
    });
  }

  return matches;
}
