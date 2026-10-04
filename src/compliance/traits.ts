/**
 * @module compliance/traits
 * @description Describes what a strategy configuration does to a value, and
 * checks it against the protection a regulation requires.
 */

import type { StrategySpec } from "../engine/types.js";
import type { TokenizationProvider } from "../vault/types.js";
import type { ProtectionRequirement, StrategyTraits } from "./types.js";

/**
 * What is known about the tokenization provider behind a `tokenize` strategy.
 */
export type TokenizationInfo = Pick<TokenizationProvider, "scheme" | "reversible">;

const NOTHING_REVEALED = Object.freeze({ leading: 0, trailing: 0 });

/**
 * Describe what a strategy does to a value.
 *
 * @param spec - The strategy.
 * @param tokenization - The provider behind a `tokenize` strategy. When it is
 *   not given, `tokenize` is described as its most permissive form: reversible
 *   and computed from the value with a key.
 * @returns The traits of the strategy.
 *
 * @remarks
 * - `pseudonymize` with a seed is described as derived and **not** keyed: the
 *   1.x construction is a non-cryptographic hash that can be recomputed from
 *   one known pair.
 * - `generalize` is described as revealing everything, because numeric input
 *   keeps all but its last digits.
 *
 * @example
 * ```ts
 * describeStrategy({ strategy: "mask", keepTrailing: 4 });
 * // { reversible: false, derived: false, keyed: false, linkable: false, revealed: { leading: 0, trailing: 4 } }
 * ```
 */
export function describeStrategy(
  spec: StrategySpec,
  tokenization?: TokenizationInfo,
): StrategyTraits {
  switch (spec.strategy) {
    case "redact":
      return {
        reversible: false,
        derived: false,
        keyed: false,
        linkable: false,
        revealed: NOTHING_REVEALED,
      };
    case "mask":
      return {
        reversible: false,
        derived: false,
        keyed: false,
        linkable: false,
        revealed: { leading: spec.keepLeading ?? 0, trailing: spec.keepTrailing ?? 0 },
      };
    case "generalize":
      return { reversible: false, derived: true, keyed: false, linkable: true, revealed: "all" };
    case "pseudonymize":
      return spec.seed === undefined
        ? {
            reversible: false,
            derived: false,
            keyed: false,
            linkable: false,
            revealed: NOTHING_REVEALED,
          }
        : {
            reversible: false,
            derived: true,
            keyed: false,
            linkable: true,
            revealed: NOTHING_REVEALED,
          };
    case "synthesize":
      return {
        reversible: false,
        derived: true,
        keyed: false,
        linkable: true,
        revealed: NOTHING_REVEALED,
      };
    case "hash":
      return {
        reversible: false,
        derived: true,
        keyed: spec.pepper !== undefined,
        linkable: true,
        revealed: NOTHING_REVEALED,
      };
    case "encrypt":
      return {
        reversible: true,
        derived: true,
        keyed: true,
        linkable: false,
        revealed: NOTHING_REVEALED,
      };
    case "tokenize": {
      const derived = tokenization?.scheme !== "session";
      return {
        reversible: tokenization?.reversible ?? true,
        derived,
        keyed: derived,
        linkable: true,
        revealed: NOTHING_REVEALED,
      };
    }
  }
}

/**
 * Check traits against a requirement.
 *
 * @param traits - What the strategy does.
 * @param requirement - What the regulation requires.
 * @returns One short reason per violated restriction; empty when the requirement is met.
 *
 * @example
 * ```ts
 * checkRequirement(describeStrategy({ strategy: "hash" }), { keyed: true });
 * // ["the output is computed from the value without a secret key"]
 * ```
 */
export function checkRequirement(
  traits: StrategyTraits,
  requirement: ProtectionRequirement,
): string[] {
  const reasons: string[] = [];
  if (requirement.irreversible === true && traits.reversible) {
    reasons.push("the value can be restored by whoever holds the key or vault");
  }
  if (requirement.notDerived === true && traits.derived) {
    reasons.push("the output is computed from the value");
  }
  if (requirement.keyed === true && traits.derived && !traits.keyed) {
    reasons.push("the output is computed from the value without a secret key");
  }
  if (requirement.maxRevealed !== undefined) {
    const { leading, trailing } = requirement.maxRevealed;
    if (traits.revealed === "all") {
      reasons.push("the value can pass through unchanged");
    } else if (traits.revealed.leading > leading || traits.revealed.trailing > trailing) {
      reasons.push(
        `more than ${String(leading)} leading and ${String(trailing)} trailing characters stay visible`,
      );
    }
  }
  return reasons;
}
