/**
 * @module compliance/erasure
 * @description The right-to-be-forgotten protocol: what has to happen for an
 * erasure request to be honoured, depending on how the data was transformed.
 */

import type { StrategySpec } from "../engine/types.js";
import { describeStrategy } from "./traits.js";
import type { TokenizationInfo } from "./traits.js";

/**
 * What an erasure request requires for data transformed with a given strategy.
 *
 * - `"none"`: the output is not computed from the value and cannot be
 *   restored, so nothing about the person remains to erase.
 * - `"delete-vault-entries"`: delete the vault records of the data subject
 *   (`KeyedTokenizer.forgetSubject()` or `forgetToken()`); the tokens left in
 *   downstream data no longer resolve.
 * - `"destroy-key"`: discard the key version (`shredKey()`); everything
 *   sealed or keyed under it becomes unrecoverable or unlinkable. This affects
 *   every data subject under that key.
 * - `"delete-outputs"`: the outputs themselves have to be deleted or
 *   re-processed, because anyone can recompute them from a guessed value.
 */
export type ErasureAction = "none" | "delete-vault-entries" | "destroy-key" | "delete-outputs";

/**
 * How to honour an erasure request for one strategy.
 */
export interface ErasurePlan {
  /** What has to be done. */
  readonly action: ErasureAction;
  /** Whether outputs that stay in downstream data can still be linked to the person afterwards. */
  readonly linkableAfterwards: boolean;
  /** Why, in one sentence. */
  readonly reason: string;
}

/**
 * Determine what an erasure request requires for data transformed with `spec`.
 *
 * The distinction that matters is between outputs that are gone for good
 * (redaction, masking, random pseudonyms), outputs that only a key or vault
 * can connect back to the person (tokens, ciphertext, keyed hashes), and
 * outputs that anyone can connect back by recomputing them (unkeyed hashes).
 *
 * @param spec - The strategy the data was transformed with.
 * @param tokenization - The provider behind a `tokenize` strategy.
 * @returns The erasure plan.
 *
 * @example
 * ```ts
 * planErasure({ strategy: "redact" }).action;                                      // "none"
 * planErasure({ strategy: "hash" }).action;                                        // "delete-outputs"
 * planErasure({ strategy: "tokenize" }, { scheme: "keyed", reversible: true }).action; // "delete-vault-entries"
 * planErasure({ strategy: "encrypt" }).action;                                     // "destroy-key"
 * ```
 */
export function planErasure(spec: StrategySpec, tokenization?: TokenizationInfo): ErasurePlan {
  const traits = describeStrategy(spec, tokenization);

  if (spec.strategy === "tokenize" && traits.reversible) {
    const stateless = tokenization?.scheme === "sealed";
    return stateless
      ? {
          action: "destroy-key",
          linkableAfterwards: false,
          reason:
            "Sealed tokens carry the value; only destroying the key version makes them unrecoverable.",
        }
      : {
          action: "delete-vault-entries",
          linkableAfterwards: traits.derived,
          reason: traits.derived
            ? "Deleting the vault records makes the tokens unresolvable; the key holder can still recompute a token from a guessed value until the key version is destroyed."
            : "Deleting the session or vault records makes the tokens unresolvable, and the tokens say nothing about the value.",
        };
  }
  if (traits.reversible || (traits.derived && traits.keyed)) {
    return {
      action: "destroy-key",
      linkableAfterwards: false,
      reason:
        "The output can only be restored or recomputed with the key; destroying the key version ends that.",
    };
  }
  if (traits.derived || traits.revealed === "all") {
    return {
      action: "delete-outputs",
      linkableAfterwards: true,
      reason:
        "The output is computed from the value without a secret, so anyone can recompute it from a guessed value; it remains personal data.",
    };
  }
  const partial = traits.revealed.leading + traits.revealed.trailing > 0;
  return {
    action: "none",
    linkableAfterwards: partial,
    reason: partial
      ? "The value cannot be restored, but the characters left visible may still help to single a person out."
      : "The output is not computed from the value and cannot be restored.",
  };
}
