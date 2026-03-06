/**
 * @module detectors/cryptocurrency
 * @description Detector for cryptocurrency wallet addresses.
 *
 * Covered:
 * - Bitcoin: Legacy (1...), P2SH (3...), Bech32 (bc1...)
 * - Ethereum / EVM: 0x + 40 hex chars
 * - Litecoin: L... or M... (34-35 chars)
 * - Monero: 4... (95 chars)
 * - Ripple/XRP: r... (25-34 alphanumeric)
 * - Solana: Base58 44-45 chars
 * - Cardano: addr1... (58-103 chars)
 */

import type { PiiMatch } from "../types.js";

/**
 * Bitcoin legacy address: 1 + 25-34 base58 chars
 * @internal
 */
const BTC_LEGACY_PATTERN = /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;

/**
 * Bitcoin P2SH: 3 + 25-34 base58 chars
 * @internal
 */
const BTC_P2SH_PATTERN = /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;

/**
 * Bitcoin Bech32: bc1 + 39-59 lowercase bech32 chars
 * @internal
 */
const BTC_BECH32_PATTERN = /\bbc1[a-z0-9]{39,59}\b/g;

/**
 * Ethereum/EVM: 0x + 40 hex chars (case-insensitive)
 * @internal
 */
const ETH_PATTERN = /\b0x[a-fA-F0-9]{40}\b/g;

/**
 * Litecoin Legacy: L + 26-33 base58 chars
 * @internal
 */
const LTC_LEGACY_PATTERN = /\bL[a-km-zA-HJ-NP-Z1-9]{26,33}\b/g;

/**
 * Litecoin P2SH(SegWit): M + 26-33 base58 chars
 * @internal
 */
const LTC_M_PATTERN = /\bM[a-km-zA-HJ-NP-Z1-9]{26,33}\b/g;

/**
 * Monero: 4 + 94 base58 chars (primary address = 95 chars)
 * @internal
 */
const XMR_PATTERN = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;

/**
 * Ripple/XRP: r + 24-33 base58 chars
 * @internal
 */
const XRP_PATTERN = /\br[a-km-zA-HJ-NP-Z1-9]{24,33}\b/g;

/**
 * Solana (roughly): 32-44 Base58 chars starting with typical chars.
 * Hard to distinguish precisely without a library; use context to boost confidence.
 * @internal
 */
const SOL_PATTERN = /\b[1-9A-HJ-NP-Za-km-z]{43,44}\b/g;

/**
 * Cardano: addr1 + 58-98 bech32 chars
 * @internal
 */
const ADA_PATTERN = /\baddr1[a-z0-9]{58,98}\b/g;

interface CryptoEntry {
  readonly pattern: RegExp;
  readonly confidence: number;
  readonly requiresContext: boolean;
}

const CRYPTO_ENTRIES: readonly CryptoEntry[] = [
  { pattern: ETH_PATTERN, confidence: 0.97, requiresContext: false },
  { pattern: BTC_BECH32_PATTERN, confidence: 0.95, requiresContext: false },
  { pattern: ADA_PATTERN, confidence: 0.92, requiresContext: false },
  { pattern: BTC_LEGACY_PATTERN, confidence: 0.88, requiresContext: false },
  { pattern: BTC_P2SH_PATTERN, confidence: 0.85, requiresContext: false },
  { pattern: LTC_LEGACY_PATTERN, confidence: 0.83, requiresContext: false },
  { pattern: LTC_M_PATTERN, confidence: 0.80, requiresContext: false },
  { pattern: XMR_PATTERN, confidence: 0.90, requiresContext: false },
  { pattern: XRP_PATTERN, confidence: 0.78, requiresContext: true },
  { pattern: SOL_PATTERN, confidence: 0.72, requiresContext: true },
];

/**
 * Cryptocurrency address context keywords.
 * @internal
 */
const CRYPTO_CONTEXT_RE =
  /\b(?:wallet(?:\s+address)?|crypto(?:currency)?(?:\s+address)?|bitcoin|btc|ethereum|eth|litecoin|ltc|monero|xmr|ripple|xrp|solana|sol|cardano|ada|address)\s*:?\s*/gi;

/**
 * Detect cryptocurrency wallet addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "cryptocurrency"`.
 */
export function detectCryptocurrency(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(CRYPTO_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContext(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 40);
  }

  for (const entry of CRYPTO_ENTRIES) {
    // All current CRYPTO_ENTRIES patterns use only the "g" flag; "gi" arm is a future-proofing safety net.
    /* v8 ignore next */
    const re = new RegExp(entry.pattern.source, entry.pattern.flags.includes("i") ? "gi" : "g");
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      if (entry.requiresContext && !hasContext(m.index)) continue;
      const key = `${String(m.index)}-${String(m.index + m[0].length)}`;
      // Cryptocurrency patterns use distinct address formats; overlapping matches are not expected.
      /* v8 ignore next */
      if (seen.has(key)) continue;
      seen.add(key);

      const confidence = hasContext(m.index) ? Math.min(entry.confidence + 0.03, 0.99) : entry.confidence;

      matches.push({
        category: "cryptocurrency",
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        confidence,
      });
    }
  }

  return matches;
}
