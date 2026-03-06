/**
 * @module detectors/api-key
 * @description Detector for API keys and authentication tokens.
 *
 * Covered formats:
 * - AWS Access Key ID: AKIA... (20 chars)
 * - AWS Secret Access Key: 40 base64 chars (context required)
 * - Stripe live secret key: sk_live_...
 * - Stripe live publishable key: pk_live_...
 * - Stripe test keys: sk_test_..., pk_test_...
 * - GitHub tokens: ghp_, gho_, ghs_, ghr_, github_pat_
 * - Slack bot token: xoxb-...
 * - Slack user token: xoxp-...
 * - Slack app token: xoxa-...
 * - Slack workspace token: xoxs-...
 * - OpenAI API key: sk-...
 * - Google API key: AIza...
 * - JWT tokens: eyJ...
 * - Bearer tokens: Bearer + base64 string (context required)
 * - Generic API key with context keyword
 */

import type { PiiMatch } from "../types.js";

interface ApiKeyEntry {
  readonly pattern: RegExp;
  readonly confidence: number;
  readonly requiresContext: boolean;
}

const API_KEY_ENTRIES: readonly ApiKeyEntry[] = [
  // AWS Access Key ID
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // Stripe live secret key
  {
    pattern: /\bsk_live_[a-zA-Z0-9]{24,99}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // Stripe live publishable key
  {
    pattern: /\bpk_live_[a-zA-Z0-9]{24,99}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // Stripe test keys
  {
    pattern: /\b(?:sk|pk)_test_[a-zA-Z0-9]{24,99}\b/g,
    confidence: 0.97,
    requiresContext: false,
  },
  // GitHub personal access tokens (classic)
  {
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // GitHub OAuth tokens
  {
    pattern: /\bgho_[a-zA-Z0-9]{36}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // GitHub server-to-server tokens
  {
    pattern: /\bghs_[a-zA-Z0-9]{36}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // GitHub refresh tokens
  {
    pattern: /\bghr_[a-zA-Z0-9]{36,76}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // GitHub fine-grained PAT
  {
    pattern: /\bgithub_pat_[a-zA-Z0-9_]{59,}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // Slack bot tokens
  {
    pattern: /\bxoxb-[0-9A-Za-z-]{40,}\b/g,
    confidence: 0.98,
    requiresContext: false,
  },
  // Slack user tokens
  {
    pattern: /\bxoxp-[0-9A-Za-z-]{40,}\b/g,
    confidence: 0.98,
    requiresContext: false,
  },
  // Slack app tokens
  {
    pattern: /\bxoxa-[0-9A-Za-z-]{40,}\b/g,
    confidence: 0.98,
    requiresContext: false,
  },
  // Slack workspace tokens
  {
    pattern: /\bxoxs-[0-9A-Za-z-]{40,}\b/g,
    confidence: 0.96,
    requiresContext: false,
  },
  // OpenAI API keys
  {
    pattern: /\bsk-[a-zA-Z0-9]{32,}\b/g,
    confidence: 0.90,
    requiresContext: false,
  },
  // Google API keys
  {
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    confidence: 0.99,
    requiresContext: false,
  },
  // JWT tokens (only the full 3-part form)
  {
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,}\b/g,
    confidence: 0.95,
    requiresContext: false,
  },
];

/**
 * Context keywords for generic API key detection.
 * @internal
 */
const API_KEY_CONTEXT_RE =
  /\b(?:api[_-\s]?key|api[_-\s]?token|access[_-\s]?token|secret[_-\s]?key|auth(?:orization)?[_-\s]?(?:key|token)|bearer(?:\s+token)?|x-api-key|credential[s]?)\s*[:=]\s*/gi;

/**
 * Generic API key / secret: 20-80 alphanumeric + _ + - chars with context.
 * @internal
 */
const GENERIC_KEY_PATTERN = /\b[a-zA-Z0-9_.-]{20,80}\b/g;

/**
 * Detect API keys and authentication tokens in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "api-key"`.
 */
export function detectApiKey(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  const contextPositions: number[] = [];
  const ctxRe = new RegExp(API_KEY_CONTEXT_RE.source, "gi");
  let cm: RegExpExecArray | null;
  while ((cm = ctxRe.exec(text)) !== null) {
    contextPositions.push(cm.index + cm[0].length);
  }

  function hasContextAt(index: number): boolean {
    return contextPositions.some((pos) => pos <= index && index - pos <= 10);
  }

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "api-key", value, start, end, confidence });
  }

  // Specific known formats
  for (const entry of API_KEY_ENTRIES) {
    const re = new RegExp(entry.pattern.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      push(m[0], m.index, m.index + m[0].length, entry.confidence);
    }
  }

  // Generic with context
  const genericRe = new RegExp(GENERIC_KEY_PATTERN.source, "g");
  let m: RegExpExecArray | null;
  while ((m = genericRe.exec(text)) !== null) {
    if (hasContextAt(m.index)) {
      push(m[0], m.index, m.index + m[0].length, 0.82);
    }
  }

  return matches;
}
