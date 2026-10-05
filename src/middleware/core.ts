/**
 * @module middleware/core
 * @description Framework-independent payload scrubbing for HTTP services:
 * one object that sanitizes JSON values, text and Fetch API responses with a
 * pipeline, and records what it did in the audit log.
 */

import { ValidationError } from "../errors.js";
import { sanitizeJson } from "../ai/json.js";
import type { KeyRule } from "../ai/json.js";
import { summarizeSpans } from "../audit/fields.js";
import type { AuditFieldEntry, AuditLogger } from "../audit/types.js";
import { compilePipeline } from "../engine/compile.js";
import type { Pipeline, PipelineSpec } from "../engine/types.js";
import type { Bytes } from "../internal/encoding.js";
import { parseJsonLossless, stringifyJsonLossless } from "../internal/json-numbers.js";

/**
 * Options shared by every middleware.
 */
export interface ScrubberOptions {
  /** The pipeline to apply. Its replacers must be synchronous. Takes precedence over `spec`. */
  readonly pipeline?: Pipeline;
  /** A pipeline specification, compiled once. Defaults to detecting every category and redacting it. */
  readonly spec?: PipelineSpec;
  /** Keys whose values are replaced whole, such as `password` or `ssn`. */
  readonly keyRules?: readonly KeyRule[];
  /**
   * What happens to a JSON object key in which the pipeline detects something:
   * `"replace"` (default) rewrites it like a value, `"flag"` leaves it.
   */
  readonly keys?: "replace" | "flag";
  /**
   * A JSON integer with at least this many digits is scanned as text and
   * becomes a string when a detector matches it. Defaults to `12`; shorter
   * numbers (phone numbers, timestamps) need a key rule.
   */
  readonly numberDigits?: number;
  /** Records every scrubbed payload, without its content. */
  readonly audit?: AuditLogger;
  /** Name of the service, recorded as the actor in audit records. */
  readonly actor?: string;
  /** Identifier of the policy in force, recorded in audit records. */
  readonly policyId?: string;
  /**
   * Largest text body, in characters, that is scrubbed. A larger body is not
   * sent on: scrubbing fails. For a `text/event-stream` response the limit
   * applies to each event. Defaults to 5,000,000.
   */
  readonly maxBodyLength?: number;
  /** Called when an audit record cannot be written. Defaults to ignoring the failure. */
  readonly onAuditError?: (error: unknown) => void;
}

/**
 * Scrubs payloads and reports to the audit log.
 */
export interface Scrubber {
  /**
   * Scrub a value that is about to be serialised as JSON. Returns a
   * structural copy. A value that is not plain JSON data (a class instance,
   * an object with `toJSON`, a `Date`) is first reduced to what
   * `JSON.stringify` would write, so the copy is what gets sent.
   */
  readonly json: <T>(value: T, source: string) => T;
  /** Scrub a text. */
  readonly text: (text: string, source: string) => string;
  /**
   * Scrub a serialised body according to its content type: JSON is parsed,
   * scrubbed and serialised again (a body in which nothing is replaced is
   * returned exactly as it was); textual types are scrubbed as text; anything
   * else is returned unchanged.
   */
  readonly body: (body: string, contentType: string | null | undefined, source: string) => string;
  /**
   * Scrub a body held as bytes. Returns the scrubbed text, or `undefined`
   * when the content type is not one the scrubber handles and the bytes
   * should be sent as they are.
   *
   * @throws ValidationError When the bytes are not text in the declared character set.
   */
  readonly bytes: (
    bytes: Uint8Array,
    contentType: string | null | undefined,
    source: string,
  ) => string | undefined;
  /**
   * Scrub a Fetch API `Response` with a JSON or text body. A
   * `text/event-stream` response is scrubbed event by event as it streams;
   * any other body is read to its end first. Other responses are returned as
   * they are.
   */
  readonly response: (response: Response, source: string) => Promise<Response>;
}

const JSON_TYPE = /^application\/(?:[\w.+-]*\+)?json\b/i;
const TEXT_TYPE =
  /^(?:text\/|application\/(?:(?:[\w.-]*\+)?xml|x-ndjson|ndjson|jsonl|javascript|x-javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|x-yaml|csv)\b)/i;
const EVENT_STREAM_TYPE = /^text\/event-stream\b/i;
const CHARSET = /;\s*charset\s*=\s*"?([^";\s]+)"?/i;
/** The blank line that ends a server-sent event. */
const EVENT_END = /\r\n\r\n|\n\n|\r\r/;

function tooLarge(): ValidationError {
  return new ValidationError("body", "is larger than maxBodyLength and was not scrubbed");
}

/** Decode `bytes` in the character set `contentType` declares (UTF-8 when it declares none). */
function decode(bytes: Uint8Array, contentType: string): string {
  const label = CHARSET.exec(contentType)?.[1] ?? "utf-8";
  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(label, { fatal: true });
  } catch {
    throw new ValidationError("body", "is in a character set that cannot be decoded");
  }
  try {
    return decoder.decode(bytes);
  } catch {
    throw new ValidationError("body", "is not text in its declared character set");
  }
}

/** `contentType` with its character set changed to UTF-8, which is what a scrubbed body is. */
function asUtf8(contentType: string): string {
  return CHARSET.test(contentType) ? contentType.replace(CHARSET, "; charset=utf-8") : contentType;
}

/** Read a body to its end, giving up as soon as it is longer than `limit` bytes. */
async function readBytes(stream: ReadableStream<Uint8Array>, limit: number): Promise<Bytes> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > limit) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** The format `DecompressionStream` needs for bytes that really are compressed, if any. */
function compressionOf(bytes: Uint8Array, encoding: string): "gzip" | "deflate" | undefined {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return "gzip";
  const zlib = bytes[0] === 0x78 && ((bytes[0] << 8) | (bytes[1] ?? 0)) % 31 === 0;
  return encoding === "deflate" && zlib ? "deflate" : undefined;
}

/**
 * Create a scrubber.
 *
 * @param options - Pipeline, key rules and audit settings.
 * @returns The {@link Scrubber}.
 * @throws {@link ValidationError} When the spec is invalid.
 *
 * @example
 * ```ts
 * import { createScrubber } from "anonyma/middleware";
 *
 * const scrubber = createScrubber({ spec: { preset: "gdpr" } });
 *
 * // A Next.js route handler, a Cloudflare Worker, or any other Fetch API handler:
 * export async function GET(request: Request): Promise<Response> {
 *   return scrubber.response(await upstream(request), "GET /api/tickets");
 * }
 * ```
 */
export function createScrubber(options: ScrubberOptions = {}): Scrubber {
  const pipeline = options.pipeline ?? compilePipeline(options.spec ?? {});
  const {
    keyRules,
    keys,
    numberDigits,
    audit,
    actor,
    policyId,
    maxBodyLength = 5_000_000,
  } = options;
  const onAuditError = options.onAuditError ?? ((): void => undefined);
  const jsonOptions = {
    pipeline,
    ...(keyRules !== undefined ? { keyRules } : {}),
    ...(keys !== undefined ? { keys } : {}),
    ...(numberDigits !== undefined ? { numberDigits } : {}),
  };
  // Fail on an invalid option now, not on the first response.
  sanitizeJson(null, jsonOptions);

  function report(fields: readonly AuditFieldEntry[], source: string): void {
    if (audit === undefined || fields.length === 0) return;
    audit
      .record({
        operation: "anonymize",
        source,
        fields,
        ...(actor !== undefined ? { actor } : {}),
        ...(policyId !== undefined ? { policy: { id: policyId } } : {}),
      })
      .catch(onAuditError);
  }

  function json<T>(value: T, source: string): T {
    let result = sanitizeJson(value, jsonOptions);
    if (result.skipped.length > 0) {
      // Not plain data: scrub what JSON.stringify would write, since that is what is sent.
      const serialised = JSON.stringify(value) as string | undefined;
      if (serialised === undefined) return value;
      result = sanitizeJson(JSON.parse(serialised) as T, jsonOptions);
    }
    report(result.fields, source);
    return result.value;
  }

  function text(input: string, source: string): string {
    if (input.length > maxBodyLength) throw tooLarge();
    const result = pipeline.transform(input);
    report(summarizeSpans(result.spans, { rule: (category) => category }), source);
    return result.text;
  }

  function body(input: string, contentType: string | null | undefined, source: string): string {
    const type = contentType ?? "";
    if (JSON_TYPE.test(type)) {
      if (input.length > maxBodyLength) throw tooLarge();
      let parsed: ReturnType<typeof parseJsonLossless>;
      try {
        parsed = parseJsonLossless(input);
      } catch {
        // Mislabelled or truncated JSON: still scrub it, as text.
        return text(input, source);
      }
      const result = sanitizeJson(parsed.value, {
        ...jsonOptions,
        ...(parsed.marker !== undefined ? { rawNumberMarker: parsed.marker } : {}),
      });
      report(result.fields, source);
      // Nothing replaced: the body goes out exactly as it came in.
      return result.replaced === 0 ? input : stringifyJsonLossless(result.value, parsed.marker);
    }
    return TEXT_TYPE.test(type) ? text(input, source) : input;
  }

  function bytes(
    input: Uint8Array,
    contentType: string | null | undefined,
    source: string,
  ): string | undefined {
    const type = contentType ?? "";
    if (!JSON_TYPE.test(type) && !TEXT_TYPE.test(type)) return undefined;
    // Four bytes are at most four characters, so this bound never rejects a body that fits.
    if (input.length > maxBodyLength * 4) throw tooLarge();
    return body(decode(input, type), type, source);
  }

  /** Scrub a stream of server-sent events one event at a time. */
  function events(source: string): TransformStream<string, string> {
    let pending = "";
    return new TransformStream<string, string>({
      transform(chunk, controller): void {
        pending += chunk;
        for (;;) {
          const end = EVENT_END.exec(pending);
          if (end === null) break;
          const length = end.index + end[0].length;
          controller.enqueue(text(pending.slice(0, length), source));
          pending = pending.slice(length);
        }
        if (pending.length > maxBodyLength) throw tooLarge();
      },
      flush(controller): void {
        if (pending.length > 0) controller.enqueue(text(pending, source));
      },
    });
  }

  async function response(original: Response, source: string): Promise<Response> {
    const type = original.headers.get("content-type");
    if (
      original.body === null ||
      type === null ||
      !(JSON_TYPE.test(type) || TEXT_TYPE.test(type))
    ) {
      return original;
    }
    const headers = new Headers(original.headers);
    headers.delete("content-length");
    headers.delete("content-encoding");
    headers.delete("etag");
    const init = { status: original.status, statusText: original.statusText, headers };

    if (EVENT_STREAM_TYPE.test(type)) {
      // A stream is never read to its end first: it may not have one.
      const stream = original.body
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(events(source))
        .pipeThrough(new TextEncoderStream());
      return new Response(stream, init);
    }

    let raw = await readBytes(original.body, maxBodyLength * 4);
    const encoding = (original.headers.get("content-encoding") ?? "").trim().toLowerCase();
    if (encoding !== "" && encoding !== "identity") {
      // fetch() hands over a decoded body under the original header; a handler may hand over compressed bytes.
      const format = compressionOf(raw, encoding);
      if (format !== undefined) {
        const inflated = new Blob([raw]).stream().pipeThrough(new DecompressionStream(format));
        raw = await readBytes(inflated, maxBodyLength * 4);
      }
    }
    headers.set("content-type", asUtf8(type));
    return new Response(body(decode(raw, type), type, source), init);
  }

  return Object.freeze({ json, text, body, bytes, response });
}
