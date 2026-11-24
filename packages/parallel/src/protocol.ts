/**
 * @module anonyma-parallel/protocol
 * @description The messages between the pool and its workers.
 * @internal
 */

import type { AnonymizeOptions, PiiCategory } from "anonyma";
import type { PipelineSpec } from "anonyma/engine";

/** A chunk of a batch, sent to a worker. */
export type Task =
  | {
      readonly id: number;
      readonly op: "detect";
      readonly texts: readonly string[];
      readonly categories?: readonly PiiCategory[];
    }
  | {
      readonly id: number;
      readonly op: "anonymize";
      readonly texts: readonly string[];
      readonly options: AnonymizeOptions;
    }
  | {
      readonly id: number;
      readonly op: "scan";
      readonly texts: readonly string[];
      readonly spec: PipelineSpec;
    };

/** A worker's answer: the chunk's results, or the error the call threw. */
export type Reply =
  | { readonly id: number; readonly ok: true; readonly value: unknown[] }
  | { readonly id: number; readonly ok: false; readonly error: unknown };
