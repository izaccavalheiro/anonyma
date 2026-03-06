/**
 * @module detectors/tracking-number
 * @description Detector for parcel/shipment tracking numbers.
 *
 * Covered carriers:
 * - FedEx: 12 or 15 or 20 digits
 * - UPS: 1Z + 16 chars
 * - USPS: 20-22 digits or XX### ### ### US format
 * - DHL: 10 digits or 11 digits starting with JD
 * - Amazon: TBA + 12 digits
 */

import type { PiiMatch } from "../types.js";

/**
 * UPS: 1Z + 16 alphanumeric chars (checksum via mod-7)
 * @internal
 */
const UPS_PATTERN = /\b1Z[A-Z0-9]{16}\b/gi;

/**
 * USPS: 20-22 consecutive digits
 * @internal
 */
const USPS_LONG_PATTERN = /\b\d{20,22}\b/g;

/**
 * USPS: service code + digits + US (e.g., 94001116990045395947)
 * @internal
 */
const USPS_FORMAT_PATTERN =
  /\b(?:9[2-5]\d{18,20}|[A-Z]{2}\d{9}US)\b/gi;

/**
 * FedEx: 12-digit, 15-digit, or 20-22 digit number
 * @internal
 */
const FEDEX_PATTERN = /\b(?:\d{12}|\d{15}|\d{20,22})\b/g;

/**
 * DHL: 10-digit or JD + 9 digits
 * @internal
 */
const DHL_PATTERN = /\bJD\d{9}\b|\b\d{10,11}\b/gi;

/**
 * Amazon: TBA + 12 digits
 * @internal
 */
const AMAZON_PATTERN = /\bTBA\d{12}\b/gi;

/**
 * Context keywords for tracking numbers.
 * @internal
 */
const TRACKING_CONTEXT_RE =
  /\b(?:tracking(?:\s+(?:number|no\.?|#|id))?|shipment(?:\s+(?:number|id|tracking))?|parcel(?:\s+(?:number|id))?|package(?:\s+(?:number|id|tracking))?|(?:fedex|ups|usps|dhl|amazon)\s+(?:tracking|shipment)?)\s*:?\s*/gi;

/**
 * Detect parcel tracking numbers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "tracking-number"`.
 */
export function detectTrackingNumber(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(TRACKING_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "tracking-number", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // UPS — most distinctive (1Z prefix)
  const upsRe = new RegExp(UPS_PATTERN.source, "gi");
  while ((m = upsRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.96);
  }

  // Amazon — distinctive (TBA prefix)
  const amazonRe = new RegExp(AMAZON_PATTERN.source, "gi");
  while ((m = amazonRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.97);
  }

  // USPS service-format
  const uspsFormatRe = new RegExp(USPS_FORMAT_PATTERN.source, "gi");
  while ((m = uspsFormatRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.90);
  }

  // DHL JD prefix
  const dhlRe = new RegExp(DHL_PATTERN.source, "gi");
  while ((m = dhlRe.exec(text)) !== null) {
    if (m[0].startsWith("JD") || m[0].startsWith("jd")) {
      push(m[0], m.index, m.index + m[0].length, 0.88);
    } else if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.78);
    }
  }

  // Generic numeric tracking — requires context
  const uspsLongRe = new RegExp(USPS_LONG_PATTERN.source, "g");
  while ((m = uspsLongRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.80);
  }

  const fedexRe = new RegExp(FEDEX_PATTERN.source, "g");
  while ((m = fedexRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  return matches;
}
