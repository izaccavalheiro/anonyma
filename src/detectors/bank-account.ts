/**
 * @module detectors/bank-account
 * @description Detector for bank account numbers and routing information.
 *
 * Covered formats:
 * - US: ABA routing number (9 digits with specific prefix ranges) + account numbers
 * - UK: Sort code (XX-XX-XX) + 8-digit account number
 * - SWIFT/BIC codes (8 or 11 chars)
 * - Brazil PIX: "copia e cola" payloads (the EMV string behind a PIX QR code,
 *   which carries the key, the holder's name and city), verified by their CRC,
 *   and random keys (UUIDs) after a PIX label
 *
 * Context keywords are essential for reducing false positives.
 */

import type { PiiMatch } from "../types.js";
import { abaRoutingChecksum, pixPayloadChecksum } from "../validators.js";
import { labelBefore } from "../internal/labels.js";

/**
 * Context keywords for bank account information.
 * @internal
 */
const BANK_CONTEXT_RE =
  /\b(?:routing\s+(?:number|no\.?|#)|sort\s+code|account\s+(?:number|no\.?|#)|bank\s+account|IBAN|BIC|SWIFT|ABA)\s*:?\s*/gi;

/**
 * US ABA routing number: 9 digits, first two digits must be 01-12, 21-32, 61-72, or 80.
 * @internal
 */
const US_ABA_ROUTING_PATTERN = /\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b/g;

/**
 * UK sort code: XX-XX-XX
 * @internal
 */
const UK_SORT_CODE_PATTERN = /\b\d{2}-\d{2}-\d{2}\b/g;

/**
 * SWIFT/BIC code: 8 or 11 chars (4 bank + 2 country + 2 location + optional 3 branch)
 * @internal
 */
const SWIFT_BIC_PATTERN = /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;

/**
 * Labels of a PIX key.
 * @internal
 */
const PIX_CONTEXT_RE = /\b(?:chave\s+(?:pix|aleat[óo]ria)|pix(?:\s+key)?)\s*:?\s*/gi;

/**
 * A PIX random key (EVP): a UUID.
 * @internal
 */
const PIX_RANDOM_KEY_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

/**
 * The globally unique identifier of PIX inside a payload, with its EMV field
 * ID and length: `00`, `14`, `br.gov.bcb.pix`.
 * @internal
 */
const PIX_GUI = "0014br.gov.bcb.pix";

/**
 * Longest PIX payload looked for, in characters. The EMV format caps a
 * payload well below it.
 * @internal
 */
const PIX_PAYLOAD_MAX = 512;

/**
 * Report every PIX "copia e cola" payload in `text`: it starts with the EMV
 * header `000201`, holds the PIX identifier `br.gov.bcb.pix` and ends with a CRC
 * field (`6304` and four hexadecimal digits) that matches its content.
 * @internal
 */
function scanPixPayloads(
  text: string,
  push: (value: string, start: number, end: number, confidence: number) => void,
): void {
  let start = text.indexOf("000201");
  while (start !== -1) {
    let end = -1;
    for (
      let crc = text.indexOf("6304", start + 6);
      crc !== -1 && crc + 8 - start <= PIX_PAYLOAD_MAX;
      crc = text.indexOf("6304", crc + 1)
    ) {
      const candidate = text.slice(start, crc + 8);
      // A payload holds printable ASCII only, so a longer candidate cannot be one either.
      if (!/^[\x20-\x7E]*$/.test(candidate)) break;
      // The PIX GUI is the first sub-field of the merchant account: ID 00, length 14.
      if (candidate.toLowerCase().includes(PIX_GUI) && pixPayloadChecksum(candidate)) {
        end = crc + 8;
        break;
      }
    }
    if (end === -1) {
      start = text.indexOf("000201", start + 1);
    } else {
      push(text.slice(start, end), start, end, 0.97);
      start = text.indexOf("000201", end);
    }
  }
}

/**
 * Generic bank account number: 7-18 digits (only with context)
 * @internal
 */
const GENERIC_ACCOUNT_PATTERN = /\b\d{7,18}\b/g;

/**
 * Detect bank account numbers and related identifiers in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "bank-account"`.
 */
export function detectBankAccount(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(BANK_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContext(index: number): boolean {
    return labelBefore(contextPositions, index, 30);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "bank-account", value, start, end, confidence });
  }

  let m: RegExpExecArray | null;

  // PIX payloads — verified by their CRC, no context needed
  scanPixPayloads(text, push);

  // PIX random keys — only after a PIX label
  const pixLabels: number[] = [];
  const pixCtxRe = new RegExp(PIX_CONTEXT_RE.source, "gi");
  while ((cm = pixCtxRe.exec(text)) !== null) pixLabels.push(cm.index + cm[0].length);
  if (pixLabels.length > 0) {
    const keyRe = new RegExp(PIX_RANDOM_KEY_PATTERN.source, "gi");
    while ((m = keyRe.exec(text)) !== null) {
      const at = m.index;
      if (labelBefore(pixLabels, at, 30)) {
        push(m[0], at, at + m[0].length, 0.9);
      }
    }
  }

  // US ABA routing — only with context; valid check digits raise the confidence
  const abaRe = new RegExp(US_ABA_ROUTING_PATTERN.source, "g");
  // Matches count only after a label: without one, the scan is skipped.
  while (contextPositions.length > 0 && (m = abaRe.exec(text)) !== null) {
    if (hasContext(m.index)) {
      push(m[0], m.index, m.index + m[0].length, abaRoutingChecksum(m[0]) ? 0.9 : 0.85);
    }
  }

  // UK sort code — distinctive format, no context needed
  const scRe = new RegExp(UK_SORT_CODE_PATTERN.source, "g");
  while ((m = scRe.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.8);
  }

  // SWIFT/BIC — distinctive, no context needed
  const swiftRe = new RegExp(SWIFT_BIC_PATTERN.source, "g");
  while ((m = swiftRe.exec(text)) !== null) {
    // Basic SWIFT validity: country code must be valid 2-letter ISO
    const countryCode = m[0].slice(4, 6);
    /* v8 ignore else -- SWIFT_BIC_PATTERN already requires two letters at this position */
    if (/^[A-Z]{2}$/.test(countryCode)) {
      push(m[0], m.index, m.index + m[0].length, 0.82);
    }
  }

  // Generic account number — only with context
  const genericRe = new RegExp(GENERIC_ACCOUNT_PATTERN.source, "g");
  // Matches count only after a label: without one, the scan is skipped.
  while (contextPositions.length > 0 && (m = genericRe.exec(text)) !== null) {
    if (hasContext(m.index)) push(m[0], m.index, m.index + m[0].length, 0.8);
  }

  return matches;
}
