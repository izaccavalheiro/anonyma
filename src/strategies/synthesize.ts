/**
 * @module strategies/synthesize
 * @description The `synthesize` anonymization strategy — replaces PII with
 * structurally valid, format-preserving synthetic data.
 *
 * The generator is **deterministic**: the same `(value, seed)` pair always
 * produces the same synthetic output. This means the same PII value is always
 * replaced with the same synthetic stand-in, which preserves referential
 * integrity across a dataset without retaining any real PII.
 *
 * No external libraries are used. All generators are self-contained.
 */

import type { SynthesizeOptions, PiiCategory } from "../types.js";

// ---------------------------------------------------------------------------
// PRNG — xorshift32 seeded by a string hash
// ---------------------------------------------------------------------------

/**
 * Simple non-cryptographic string hash → uint32 seed.
 * @internal
 */
function strHash(s: string): number {
  let h = 2166136261; // FNV offset basis
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 16777619) >>> 0;
  }
  // FNV hash producing h=0 is astronomically unlikely (probability ~1/2^32).
  /* v8 ignore next */
  return h === 0 ? 1 : h; // xorshift needs non-zero seed
}

/**
 * xorshift32 PRNG — returns a function that yields pseudo-random numbers in [0, 1).
 * @internal
 */
function makePrng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    state = state >>> 0;
    return state / 0x100000000;
  };
}

/**
 * Integer in [min, max] (inclusive) using the supplied PRNG.
 * @internal
 */
function randInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

/**
 * Pick a random element from an array.
 * @internal
 */
function pick<T>(rng: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rng() * arr.length)] as T;
}

// ---------------------------------------------------------------------------
// Per-category synthetic generators
// ---------------------------------------------------------------------------

const DOMAINS = ["example.com", "test.org", "sample.net", "demo.io", "placeholder.dev"] as const;
const NAMES_FIRST = [
  "Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank",
  "Irene", "Jack", "Karen", "Leo", "Mina", "Neal", "Olivia", "Paul",
  "Quinn", "Rosa", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xena", "Yuri", "Zoe",
] as const;
const NAMES_LAST = [
  "Smith", "Jones", "Williams", "Taylor", "Brown", "Davies", "Evans",
  "Wilson", "Thomas", "Roberts", "Johnson", "White", "Martin", "Anderson",
  "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez",
] as const;

function synthEmail(rng: () => number): string {
  const user = `${pick(rng, NAMES_FIRST).toLowerCase()}.${pick(rng, NAMES_LAST).toLowerCase()}${String(randInt(rng, 1, 99))}`;
  return `${user}@${pick(rng, DOMAINS)}`;
}

function synthPhone(rng: () => number): string {
  return `+1-${String(randInt(rng, 200, 999))}-${randInt(rng, 200, 999).toString().padStart(3, "0")}-${String(randInt(rng, 1000, 9999))}`;
}

function synthSsn(rng: () => number): string {
  // Real SSNs: AAA-BB-CCCC (A: 001-899 except 666, B: 01-99, C: 0001-9999)
  const area = randInt(rng, 100, 665);
  const group = randInt(rng, 10, 99);
  const serial = randInt(rng, 1000, 9999);
  return `${String(area)}-${String(group)}-${String(serial)}`;
}

function synthCreditCard(rng: () => number): string {
  // Synthetic Visa: starts with 4, 16 digits, no Luhn check intentionally omitted
  // for safety (we don't want to generate valid cards).
  const d = (): number => randInt(rng, 0, 9);
  const groups = [
    `4${String(d())}${String(d())}${String(d())}`,
    `${String(d())}${String(d())}${String(d())}${String(d())}`,
    `${String(d())}${String(d())}${String(d())}${String(d())}`,
    `${String(d())}${String(d())}${String(d())}${String(d())}`,
  ];
  return groups.join(" ");
}

function synthIpv4(rng: () => number): string {
  // Use TEST-NET-1 (192.0.2.0/24) per RFC 5737 — safe synthetic IP range.
  return `192.0.2.${String(randInt(rng, 1, 254))}`;
}

function synthIpv6(rng: () => number): string {
  const h = (): string => randInt(rng, 0, 65535).toString(16).padStart(4, "0");
  // Use documentation prefix 2001:db8::/32 per RFC 3849.
  return `2001:0db8:${h()}:${h()}:${h()}:${h()}:${h()}:${h()}`;
}

function synthUrl(rng: () => number): string {
  const paths = ["user", "profile", "data", "record", "item"];
  return `https://${pick(rng, DOMAINS)}/${pick(rng, paths)}/${String(randInt(rng, 1000, 9999))}`;
}

function synthIban(rng: () => number): string {
  // Synthetic GB IBAN structure: GB00 XXXX 0000 0000 0000 00
  const bank = `SYNTH${String(randInt(rng, 10, 99))}`;
  const sort = `${String(randInt(rng, 10, 99))}${String(randInt(rng, 10, 99))}${String(randInt(rng, 10, 99))}`;
  const acct = String(randInt(rng, 10000000, 99999999));
  return `GB00 ${bank.slice(0, 4)} ${sort.slice(0, 2)}${sort.slice(2, 4)} ${sort.slice(4, 6)}${acct.slice(0, 2)} ${acct.slice(2, 6)} ${acct.slice(6)}`;
}

function synthDob(rng: () => number): string {
  const year = 1940 + randInt(rng, 0, 64);
  const month = randInt(rng, 1, 12).toString().padStart(2, "0");
  const day = randInt(rng, 1, 28).toString().padStart(2, "0");
  return `${String(year)}-${month}-${day}`;
}

function synthName(rng: () => number): string {
  return `${pick(rng, NAMES_FIRST)} ${pick(rng, NAMES_LAST)}`;
}

function synthAddress(rng: () => number): string {
  const streets = ["Main St", "Oak Ave", "Pine Rd", "Elm Blvd", "Maple Dr", "Cedar Ln"];
  const cities = ["Springfield", "Shelbyville", "Riverdale", "Greenfield", "Maplewood"];
  const states = ["CA", "TX", "FL", "NY", "WA", "IL", "OH", "PA", "GA", "NC"];
  return `${String(randInt(rng, 1, 9999))} ${pick(rng, streets)}, ${pick(rng, cities)}, ${pick(rng, states)} ${String(randInt(rng, 10000, 99999))}`;
}

function synthApiKey(rng: () => number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "sk_test_";
  /* v8 ignore next -- chars index is always in-bounds for a 62-char string */
  for (let i = 0; i < 32; i++) key += chars[Math.floor(rng() * chars.length)] ?? "";
  return key;
}

function synthGeneric(rng: () => number, value: string): string {
  // Format-preserving generic: replace alphanumerics, keep structure.
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  return value
    .split("")
    .map((ch) => {
      if (/[a-z]/.test(ch)) return lowers[Math.floor(rng() * lowers.length)];
      if (/[A-Z]/.test(ch)) return uppers[Math.floor(rng() * uppers.length)];
      if (/\d/.test(ch)) return digits[Math.floor(rng() * digits.length)];
      return ch;
    })
    .join("");
}

// ---------------------------------------------------------------------------
// Dispatch table
// ---------------------------------------------------------------------------

const GENERATORS: Partial<Record<PiiCategory, (rng: () => number, value: string) => string>> = {
  email: (rng) => synthEmail(rng),
  phone: (rng) => synthPhone(rng),
  ssn: (rng) => synthSsn(rng),
  "credit-card": (rng) => synthCreditCard(rng),
  ipv4: (rng) => synthIpv4(rng),
  ipv6: (rng) => synthIpv6(rng),
  url: (rng) => synthUrl(rng),
  iban: (rng) => synthIban(rng),
  "date-of-birth": (rng) => synthDob(rng),
  name: (rng) => synthName(rng),
  address: (rng) => synthAddress(rng),
  "api-key": (rng) => synthApiKey(rng),
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Replace `value` with a structurally similar, format-preserving synthetic
 * substitute.
 *
 * @param value    - The original PII value to synthesize.
 * @param category - The PII category, used to select the generator.
 * @param options  - Synthesis options (`seed` overrides the deterministic default).
 * @returns A synthetic string that mirrors the format of `value`.
 *
 * @example
 * ```ts
 * import { synthesize } from "anonyma/strategies/synthesize";
 *
 * synthesize("alice@example.com", "email");
 * // "bob.smith42@test.org"  (deterministic for this input)
 *
 * synthesize("alice@example.com", "email", { seed: "custom-seed" });
 * // deterministic based on value + seed combination
 * ```
 */
export function synthesize(
  value: string,
  category: string,
  options: SynthesizeOptions = {},
): string {
  const seedStr = (options.seed ?? "") + category + ":" + value;
  const rng = makePrng(strHash(seedStr));

  const gen = GENERATORS[category as PiiCategory];
  if (gen) return gen(rng, value);
  return synthGeneric(rng, value);
}
