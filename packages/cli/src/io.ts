/**
 * @module anonyma-cli/io
 * @description Streams in and out of the command: decoding, line splitting,
 * writing with backpressure, gzip, and an output file that only appears once
 * it is complete.
 */

import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { rename, rm } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import { createGunzip, createGzip } from "node:zlib";

/** A line of text and the line ending that followed it (`""` for the last line of a file without one). */
export interface Line {
  readonly text: string;
  readonly eol: string;
}

/**
 * Decode a byte stream as UTF-8, in chunks, without splitting a character
 * between two of them.
 */
export async function* decode(stream: AsyncIterable<unknown>): AsyncGenerator<string> {
  const decoder = new StringDecoder("utf8");
  for await (const chunk of stream) {
    const text = typeof chunk === "string" ? chunk : decoder.write(chunk as Buffer);
    if (text !== "") yield text;
  }
  const rest = decoder.end();
  if (rest !== "") yield rest;
}

/** Split text chunks into lines, keeping each line's ending (`\n` or `\r\n`). */
export async function* lines(chunks: AsyncIterable<string>): AsyncGenerator<Line> {
  let pending = "";
  for await (const chunk of chunks) {
    pending += chunk;
    let from = 0;
    for (let at = pending.indexOf("\n"); at !== -1; at = pending.indexOf("\n", from)) {
      const crlf = at > from && pending.charCodeAt(at - 1) === 13;
      yield { text: pending.slice(from, crlf ? at - 1 : at), eol: crlf ? "\r\n" : "\n" };
      from = at + 1;
    }
    pending = pending.slice(from);
  }
  if (pending !== "") yield { text: pending, eol: "" };
}

/** The input of a command: a file, or standard input for `-`. */
export function openInput(path: string | undefined, stdin: Readable): AsyncIterable<string> {
  if (path === undefined || path === "-") return decode(stdin);
  const file = createReadStream(path);
  return decode(path.endsWith(".gz") ? file.pipe(createGunzip()) : file);
}

/** Where output text goes, with the SHA-256 of everything written. */
export interface Sink {
  /** Write text, waiting when the destination is full. */
  readonly write: (text: string) => Promise<void>;
  /** Finish the output; a file appears under its name only now. */
  readonly close: () => Promise<void>;
  /** Remove a partial output file after a failure. */
  readonly abort: () => Promise<void>;
  /** SHA-256 (hex) of the text written, available after `close()`. */
  readonly digest: () => string;
}

/** Wait until `stream` emits `event` or an error, whichever comes first. */
function settle(stream: Writable, event: "drain" | "finish"): Promise<void> {
  return new Promise((resolve) => {
    const done = (): void => {
      stream.off(event, done);
      stream.off("error", done);
      resolve();
    };
    stream.once(event, done);
    stream.once("error", done);
  });
}

/**
 * Open the output of a command: a file, written under a temporary name and
 * renamed when complete, or standard output for `-` or no path. A path that
 * ends in `.gz` is compressed.
 */
export function openOutput(path: string | undefined, stdout: Writable): Sink {
  const hash = createHash("sha256");
  let digest: string | undefined;
  const toFile = path !== undefined && path !== "-";
  const partial = toFile ? `${path}.partial-${String(process.pid)}` : undefined;
  const file = partial === undefined ? undefined : createWriteStream(partial);
  const gzip = toFile && path.endsWith(".gz") ? createGzip() : undefined;
  if (gzip !== undefined && file !== undefined) gzip.pipe(file);
  const target: Writable = gzip ?? file ?? stdout;
  let failure: Error | undefined;
  const remember = (error: Error): void => {
    failure ??= error;
  };
  target.on("error", remember);
  if (gzip !== undefined) file?.on("error", remember);
  const check = (): void => {
    if (failure !== undefined) throw failure;
  };

  return {
    async write(text): Promise<void> {
      check();
      hash.update(text, "utf8");
      if (text !== "" && !target.write(text, "utf8")) await settle(target, "drain");
      check();
    },
    async close(): Promise<void> {
      digest = hash.digest("hex");
      if (file === undefined || partial === undefined || path === undefined) {
        check();
        return;
      }
      const finished = settle(file, "finish");
      target.end();
      if (!file.writableFinished) await finished;
      check();
      await rename(partial, path);
    },
    async abort(): Promise<void> {
      if (file === undefined || partial === undefined) return;
      gzip?.destroy();
      // The file is opened asynchronously: removing it before the stream has
      // closed could run before the open, which would then create it again.
      if (!file.closed) {
        const closed = new Promise<void>((resolve) =>
          file.once("close", () => {
            resolve();
          }),
        );
        file.destroy();
        await closed;
      }
      await rm(partial, { force: true });
    },
    digest(): string {
      return digest ?? hash.copy().digest("hex");
    },
  };
}
