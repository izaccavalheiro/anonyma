/**
 * @module engine/replacers
 * @description Replacer factories for the span engine. Each factory can be
 * imported on its own, so a pipeline only pulls in the strategies it uses.
 *
 * Every built-in replacer fails closed: if a strategy would hand back the
 * original value unchanged, the value is redacted instead.
 */

import { ValidationError } from "../errors.js";
import { encrypt } from "../strategies/encrypt.js";
import { generalize } from "../strategies/generalize.js";
import { hash } from "../strategies/hash.js";
import { mask } from "../strategies/mask.js";
import { pseudonymize } from "../strategies/pseudonymize.js";
import { redact } from "../strategies/redact.js";
import { synthesize } from "../strategies/synthesize.js";
import type {
  EncryptOptions,
  GeneralizeOptions,
  HashOptions,
  MaskOptions,
  PseudonymizeOptions,
  RedactOptions,
  SynthesizeOptions,
} from "../types.js";
import type { CompileDependencies, Replacer, StrategySpec } from "./types.js";

/**
 * Replacement used when a strategy would otherwise return the original value.
 * @internal
 */
export const FAIL_CLOSED_LABEL = "[REDACTED]";

/** A range may show this many leading digits of a number; beyond that it is an identifier. */
const MAX_REVEALED_DIGITS = 3;

function failClosed(value: string, replacement: string): string {
  return replacement === value && value.length > 0 ? FAIL_CLOSED_LABEL : replacement;
}

/**
 * Replace every value with the same fixed string.
 *
 * @param replacement - The replacement text. Must not be empty.
 * @returns A synchronous {@link Replacer}.
 * @throws {@link ValidationError} When `replacement` is empty or whitespace only.
 *
 * @example
 * ```ts
 * constant("***")("alice@example.com", context); // "***"
 * ```
 */
export function constant(replacement: string): Replacer {
  if (typeof replacement !== "string" || replacement.trim().length === 0) {
    throw new ValidationError("replacement", "must be a non-empty string");
  }
  return () => replacement;
}

/**
 * Replace every value with a label (the `redact` strategy).
 *
 * @param options - Redaction options. The label defaults to `"[REDACTED]"`.
 * @returns A synchronous {@link Replacer}.
 * @throws {@link ValidationError} When the label is empty.
 *
 * @example
 * ```ts
 * redactWith({ label: "[EMAIL]" })("alice@example.com", context); // "[EMAIL]"
 * ```
 */
export function redactWith(options: RedactOptions = {}): Replacer {
  const label = redact("", options);
  return () => label;
}

/**
 * Mask every value (the `mask` strategy). A configuration that would leave a
 * value fully visible redacts it instead.
 *
 * @param options - Masking options.
 * @returns A synchronous {@link Replacer}.
 * @throws {@link ValidationError} When the options are invalid.
 *
 * @example
 * ```ts
 * maskWith({ keepTrailing: 4 })("4111 1111 1111 1111", context); // "***************1111"
 * ```
 */
export function maskWith(options: MaskOptions = {}): Replacer {
  mask("", options);
  return (value) => failClosed(value, mask(value, options));
}

/**
 * Replace every value with a pseudonym (the `pseudonymize` strategy).
 *
 * @param options - Pseudonymization options.
 * @returns A synchronous {@link Replacer}.
 * @throws {@link ValidationError} When the prefix is invalid.
 *
 * @remarks
 * The seeded form of this strategy is not cryptographic. For keyed,
 * deterministic pseudonyms use a keyed tokenizer from `"anonyma/vault"`.
 *
 * @example
 * ```ts
 * pseudonymizeWith({ prefix: "user_" })("alice@example.com", context); // "user_9d1ba6c1f89a49d9"
 * ```
 */
export function pseudonymizeWith(options: PseudonymizeOptions = {}): Replacer {
  pseudonymize("", options);
  return (value) => failClosed(value, pseudonymize(value, options));
}

/**
 * Replace numeric values with a range (the `generalize` strategy). Values that
 * are not numeric are redacted rather than passed through, and so is a number
 * whose range would still show more than three of its leading digits: a range
 * hides a quantity such as an age or a year, not an identifier such as an
 * account or a card number.
 *
 * @param options - Generalization options.
 * @returns A synchronous {@link Replacer}.
 * @throws {@link ValidationError} When `bucketSize` is invalid or `1`.
 *
 * @example
 * ```ts
 * generalizeWith({ bucketSize: 10 })("27", context);  // "20-29"
 * generalizeWith()("alice@example.com", context);      // "[REDACTED]"
 * generalizeWith()("123456789", context);              // "[REDACTED]"
 * ```
 */
export function generalizeWith(options: GeneralizeOptions = {}): Replacer {
  generalize("0", options);
  const bucketSize = options.bucketSize ?? 10;
  if (bucketSize < 2) {
    throw new ValidationError(
      "bucketSize",
      "must be at least 2: a range of one value hides nothing",
    );
  }
  const hiddenDigits = Math.floor(Math.log10(bucketSize));
  return (value) => {
    const parsed = Number(value);
    if (value.trim().length === 0 || !Number.isFinite(parsed)) return FAIL_CLOSED_LABEL;
    const digits = String(Math.abs(Math.trunc(parsed))).length;
    if (digits - hiddenDigits > MAX_REVEALED_DIGITS) return FAIL_CLOSED_LABEL;
    return failClosed(value, generalize(value, options));
  };
}

/**
 * Replace every value with format-preserving synthetic data (the `synthesize`
 * strategy), using the category of the span to pick the generator.
 *
 * @param options - Synthesis options.
 * @returns A synchronous {@link Replacer}.
 *
 * @example
 * ```ts
 * synthesizeWith({ seed: "s3cret" })("alice@example.com", context); // "grace.taylor95@demo.io"
 * ```
 */
export function synthesizeWith(options: SynthesizeOptions = {}): Replacer {
  return (value, context) => failClosed(value, synthesize(value, context.category, options));
}

/**
 * Replace every value with a SHA-256 digest (the `hash` strategy).
 *
 * @param options - Hashing options.
 * @returns An asynchronous {@link Replacer}.
 * @throws {@link ValidationError} When `truncate` is not an integer between 1 and 64.
 *
 * @remarks
 * A hash of a low-entropy identifier can be reversed by enumeration. Supply a
 * `pepper`, or prefer a keyed tokenizer from `"anonyma/vault"`.
 *
 * @example
 * ```ts
 * await hashWith({ pepper: "p", truncate: 32 })("alice@example.com", context);
 * ```
 */
export function hashWith(options: HashOptions = {}): Replacer {
  const { truncate = 16 } = options;
  if (!Number.isInteger(truncate) || truncate < 1 || truncate > 64) {
    throw new ValidationError("truncate", "must be an integer between 1 and 64 (inclusive)");
  }
  return (value) => hash(value, options);
}

/**
 * Replace every value with AES-GCM ciphertext in the 1.x `encrypt()` format.
 *
 * @param options - Key material and encoding.
 * @returns An asynchronous {@link Replacer}.
 * @throws {@link ValidationError} When neither `passphrase` nor `keyBytes` is given,
 *   `keyBytes` is not 16 or 32 bytes long, or `encoding` is unknown.
 *
 * @remarks
 * With a `passphrase` the key is derived again for every value, which costs
 * tens of milliseconds each. Pass `keyBytes`, or use a sealed tokenizer from
 * `"anonyma/vault"`, for anything but small inputs.
 *
 * @example
 * ```ts
 * await encryptWith({ keyBytes })("alice@example.com", context); // "base64:…:…"
 * ```
 */
export function encryptWith(options: EncryptOptions): Replacer {
  if (options.keyBytes === undefined && (options.passphrase ?? "") === "") {
    throw new ValidationError("encryption", "requires `passphrase` or `keyBytes`");
  }
  if (
    options.keyBytes !== undefined &&
    options.keyBytes.length !== 16 &&
    options.keyBytes.length !== 32
  ) {
    throw new ValidationError("encryption.keyBytes", "must be 16 or 32 bytes long");
  }
  const encoding: unknown = options.encoding;
  if (encoding !== undefined && encoding !== "base64" && encoding !== "hex") {
    throw new ValidationError("encryption.encoding", 'must be "base64" or "hex"');
  }
  return (value) => encrypt(value, options);
}

/**
 * Build the replacer for a strategy given as data.
 *
 * @param spec - The strategy.
 * @param dependencies - Provider and secrets for strategies that need them.
 * @returns The {@link Replacer} implementing the strategy.
 * @throws {@link ValidationError} When the strategy needs a dependency that was not supplied,
 *   or its options are invalid.
 *
 * @example
 * ```ts
 * const replacer = strategyReplacer({ strategy: "mask", keepTrailing: 4 });
 * ```
 */
export function strategyReplacer(
  spec: StrategySpec,
  dependencies: CompileDependencies = {},
): Replacer {
  const secrets = dependencies.secrets ?? {};
  switch (spec.strategy) {
    case "redact":
      return redactWith(spec);
    case "mask":
      return maskWith(spec);
    case "generalize":
      return generalizeWith(spec);
    case "pseudonymize":
      return pseudonymizeWith(
        spec.seed === undefined && secrets.pseudonymizeSeed !== undefined
          ? { ...spec, seed: secrets.pseudonymizeSeed }
          : spec,
      );
    case "synthesize":
      return synthesizeWith(
        spec.seed === undefined && secrets.synthesizeSeed !== undefined
          ? { ...spec, seed: secrets.synthesizeSeed }
          : spec,
      );
    case "hash":
      return hashWith(
        spec.pepper === undefined && secrets.hashPepper !== undefined
          ? { ...spec, pepper: secrets.hashPepper }
          : spec,
      );
    case "encrypt": {
      if (dependencies.encryption === undefined) {
        throw new ValidationError("encryption", "is required by the `encrypt` strategy");
      }
      return encryptWith(dependencies.encryption);
    }
    case "tokenize": {
      const provider = dependencies.tokenization;
      if (provider === undefined) {
        throw new ValidationError("tokenization", "is required by the `tokenize` strategy");
      }
      return (value, context) => provider.tokenize(value, { category: context.category });
    }
    default: {
      const unknown: never = spec;
      throw new ValidationError(
        "strategy",
        `"${String((unknown as { strategy?: unknown }).strategy)}" is not a known strategy`,
      );
    }
  }
}
