/**
 * @module anonyma-parallel/worker
 * @description The code each worker thread runs: anonyma's batch functions on
 * the chunks the pool sends.
 * @internal
 */

import { parentPort } from "node:worker_threads";

import { anonymizeBatch, detectBatch } from "anonyma";
import { compilePipeline } from "anonyma/engine";

import type { Reply, Task } from "./protocol.js";

const port = parentPort;
if (port === null) throw new Error("anonyma-parallel: worker.js runs in a worker thread");

port.on("message", (task: Task) => {
  let reply: Reply;
  try {
    const value: unknown[] =
      task.op === "detect"
        ? detectBatch(task.texts, task.categories)
        : task.op === "anonymize"
          ? anonymizeBatch(task.texts, task.options)
          : compilePipeline(task.spec).scanBatch(task.texts);
    reply = { id: task.id, ok: true, value };
  } catch (error) {
    reply = { id: task.id, ok: false, error };
  }
  port.postMessage(reply);
});
