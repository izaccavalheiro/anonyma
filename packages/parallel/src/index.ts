/**
 * @module anonyma-parallel
 * @description A pool of worker threads that runs anonyma's batch functions on
 * every core. A batch is cut into chunks of about 256 KB, each chunk runs in a
 * worker with anonyma's own batch function (which already joins short texts),
 * and the results come back in input order, as the function returns them in
 * one thread. Node.js, Bun and Deno provide `node:worker_threads`; runtimes
 * without threads (Cloudflare Workers, browsers) use anonyma directly.
 */

import { availableParallelism, cpus } from "node:os";
import { Worker } from "node:worker_threads";

import type {
  AnonymizeOptions,
  AnonymizeResult,
  BatchResult,
  PiiCategory,
  PiiMatch,
} from "anonyma";
import type { DetectedSpan, PipelineSpec } from "anonyma/engine";

import type { Reply, Task } from "./protocol.js";

/** Options of {@link createPool}. */
export interface PoolOptions {
  /** Worker threads; by default one per core but one, and at least one. */
  readonly threads?: number;
  /** About how many characters each chunk of a batch holds. Defaults to 262,144. */
  readonly chunkSize?: number;
}

/** A pool of worker threads; see {@link createPool}. */
export interface Pool {
  /** The number of worker threads. */
  readonly threads: number;
  /** `detectBatch(texts, categories)` of anonyma, on the pool. */
  detectBatch(
    texts: readonly string[],
    categories?: readonly PiiCategory[],
  ): Promise<BatchResult<PiiMatch[]>[]>;
  /** `anonymizeBatch(texts, options)` of anonyma, on the pool. */
  anonymizeBatch(
    texts: readonly string[],
    options?: AnonymizeOptions,
  ): Promise<BatchResult<AnonymizeResult>[]>;
  /** `compilePipeline(spec).scanBatch(texts)` of anonyma/engine, on the pool. */
  scanBatch(texts: readonly string[], spec?: PipelineSpec): Promise<DetectedSpan[][]>;
  /** Stop the workers; later calls reject. */
  close(): Promise<void>;
}

/** Thrown for options a worker cannot receive: they hold a function. */
export class PoolOptionsError extends TypeError {
  public constructor(path: string) {
    super(
      `anonyma-parallel: ${path} is a function, which cannot reach a worker thread; ` +
        "call anonyma directly for custom detectors, plugins and allow callbacks",
    );
    this.name = "PoolOptionsError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Refuse options holding a function: a worker thread cannot receive one. */
function assertCloneable(value: unknown, path: string): void {
  if (typeof value === "function") throw new PoolOptionsError(path);
  if (typeof value !== "object" || value === null || value instanceof RegExp) return;
  for (const [key, member] of Object.entries(value)) {
    assertCloneable(member, `${path}.${key}`);
  }
}

/** Whether `value` is an array (without narrowing a typed array to `any[]`). */
function isArray(value: unknown): boolean {
  return Array.isArray(value);
}

/** Chunks of `texts` of about `size` characters, each with its offset. */
function chunks(
  texts: readonly string[],
  size: number,
): { readonly offset: number; readonly texts: string[] }[] {
  const out: { offset: number; texts: string[] }[] = [];
  let current: string[] = [];
  let length = 0;
  let offset = 0;
  for (const [index, text] of texts.entries()) {
    if (current.length === 0) offset = index;
    current.push(text);
    length += typeof text === "string" ? text.length : 1;
    if (length >= size) {
      out.push({ offset, texts: current });
      current = [];
      length = 0;
    }
  }
  if (current.length > 0) out.push({ offset, texts: current });
  return out;
}

interface Job {
  readonly task: Task;
  readonly resolve: (value: unknown[]) => void;
  readonly reject: (error: unknown) => void;
}

interface Slot {
  readonly worker: Worker;
  job: Job | undefined;
}

/**
 * Create a pool of worker threads for anonyma's batch functions. Workers start
 * on the first call and do not keep the process alive while idle; call
 * `close()` to stop them.
 *
 * Results equal those of the batch functions called in one thread, in input
 * order. A text that fails gives a failed entry, as in `anonymizeBatch()`; its
 * error is a copy made by the structured clone algorithm, with the original
 * message and name.
 *
 * @example
 * ```ts
 * import { createPool } from "anonyma-parallel";
 *
 * const pool = createPool();
 * const results = await pool.anonymizeBatch(lines, { preset: "gdpr" });
 * await pool.close();
 * ```
 */
export function createPool(options: PoolOptions = {}): Pool {
  // availableParallelism() arrived in Node.js 18.14.
  const cores = typeof availableParallelism === "function" ? availableParallelism() : cpus().length;
  const threads = Math.max(1, Math.floor(options.threads ?? cores - 1));
  const chunkSize = Math.max(1, Math.floor(options.chunkSize ?? 262_144));
  const slots: Slot[] = [];
  const queue: Job[] = [];
  let nextId = 0;
  let closed = false;

  function start(): Slot {
    const worker = new Worker(new URL("./worker.js", import.meta.url));
    const slot: Slot = { worker, job: undefined };
    worker.unref();
    worker.on("message", (reply: Reply) => {
      const job = slot.job;
      slot.job = undefined;
      if (job !== undefined) {
        if (reply.ok) job.resolve(reply.value);
        else job.reject(reply.error);
      }
      dispatch();
    });
    const fail = (error: unknown): void => {
      const index = slots.indexOf(slot);
      if (index >= 0) slots.splice(index, 1);
      slot.job?.reject(error);
      slot.job = undefined;
      dispatch();
    };
    worker.on("error", fail);
    worker.on("exit", (code) => {
      if (slots.includes(slot)) {
        fail(new Error(`anonyma-parallel: a worker stopped with code ${String(code)}`));
      }
    });
    slots.push(slot);
    return slot;
  }

  function dispatch(): void {
    while (queue.length > 0) {
      const idle = slots.find((slot) => slot.job === undefined);
      const slot = idle ?? (slots.length < threads ? start() : undefined);
      const job = slot === undefined ? undefined : queue.shift();
      if (slot === undefined || job === undefined) break;
      slot.job = job;
      slot.worker.postMessage(job.task);
    }
    // Busy workers keep the process alive until their answer comes; idle ones do not.
    for (const slot of slots) {
      if (slot.job === undefined) slot.worker.unref();
      else slot.worker.ref();
    }
  }

  function run(
    make: (id: number, texts: string[]) => Task,
    texts: readonly string[],
  ): Promise<{ offset: number; value: unknown[] }[]> {
    if (closed) return Promise.reject(new Error("anonyma-parallel: the pool is closed"));
    if (!isArray(texts)) {
      return Promise.reject(new TypeError("anonyma-parallel: texts must be an array"));
    }
    const total = texts.reduce((n, text) => n + (typeof text === "string" ? text.length : 1), 0);
    // Enough chunks to keep every worker busy, none much larger than chunkSize.
    const size = Math.max(4096, Math.min(chunkSize, Math.ceil(total / threads)));
    const parts = chunks(texts, size);
    return Promise.all(
      parts.map(
        (part) =>
          new Promise<{ offset: number; value: unknown[] }>((resolve, reject) => {
            queue.push({
              task: make(nextId++, part.texts),
              resolve: (value) => {
                resolve({ offset: part.offset, value });
              },
              reject,
            });
            dispatch();
          }),
      ),
    );
  }

  /** The entries of every chunk, their `index` moved to the batch's. */
  const flattenBatch = <T>(parts: { offset: number; value: unknown[] }[]): BatchResult<T>[] =>
    parts.flatMap(({ offset, value }) =>
      (value as BatchResult<T>[]).map((entry) => ({ ...entry, index: entry.index + offset })),
    );

  return {
    threads,
    async detectBatch(texts, categories): Promise<BatchResult<PiiMatch[]>[]> {
      if (categories !== undefined) assertCloneable(categories, "categories");
      const parts = await run(
        (id, chunk) =>
          categories === undefined
            ? { id, op: "detect", texts: chunk }
            : { id, op: "detect", texts: chunk, categories },
        texts,
      );
      return flattenBatch<PiiMatch[]>(parts);
    },
    async anonymizeBatch(texts, anonymizeOptions = {}): Promise<BatchResult<AnonymizeResult>[]> {
      assertCloneable(anonymizeOptions, "options");
      const parts = await run(
        (id, chunk) => ({ id, op: "anonymize", texts: chunk, options: anonymizeOptions }),
        texts,
      );
      return flattenBatch<AnonymizeResult>(parts);
    },
    async scanBatch(texts, spec = {}): Promise<DetectedSpan[][]> {
      assertCloneable(spec, "spec");
      const parts = await run((id, chunk) => ({ id, op: "scan", texts: chunk, spec }), texts);
      return parts.flatMap(({ value }) => value as DetectedSpan[][]);
    },
    async close(): Promise<void> {
      closed = true;
      for (const job of queue.splice(0))
        job.reject(new Error("anonyma-parallel: the pool is closed"));
      const stopping = slots.splice(0).map((slot) => {
        slot.job?.reject(new Error("anonyma-parallel: the pool is closed"));
        return slot.worker.terminate();
      });
      await Promise.all(stopping);
    },
  };
}
