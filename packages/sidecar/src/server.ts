/**
 * @module anonyma-sidecar/server
 * @description The HTTP service: detection, anonymization, vault tokens and
 * MCP over localhost, for applications in any language.
 */

import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { AnonymaError, PRESET_REGISTRY, VERSION, combinePresets, restore } from "anonyma";
import type { CompliancePreset } from "anonyma";
import { BUILTIN_CATEGORIES, compilePipeline } from "anonyma/engine";
import type { PipelineSpec, StrategySpec } from "anonyma/engine";
import { createMcpServer } from "anonyma/mcp";
import { createVaultTokenizer } from "anonyma/vault";

import { SessionStore } from "./sessions.js";
import type { SessionStoreOptions } from "./sessions.js";

/** Options of {@link createSidecar}. */
export interface SidecarOptions extends SessionStoreOptions {
  /**
   * Bearer token every request must carry (`Authorization: Bearer <token>`),
   * except `GET /healthz`. Set it whenever the port is reachable from another
   * host or container.
   */
  readonly token?: string;
  /** Largest request body, in bytes. Defaults to 1 MiB. */
  readonly maxBodyBytes?: number;
  /** Serve MCP (JSON-RPC) at `POST /mcp`. Defaults to `true`. */
  readonly mcp?: boolean;
}

/** A sidecar: a request handler and its sessions. */
export interface Sidecar {
  /** Handles one HTTP request; pass it to `http.createServer()`. */
  readonly handle: (request: IncomingMessage, response: ServerResponse) => void;
  /** The token vaults of the conversations in progress. */
  readonly sessions: SessionStore;
}

/** A request the client got wrong: answered with its status and message. */
class HttpError extends Error {
  public constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

type Body = Record<string, unknown>;

const JSON_TYPE = /^application\/(?:[\w.+-]+\+)?json\s*(?:;|$)/i;

function isObject(value: unknown): value is Body {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameSecret(given: string, expected: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Converts UTF-16 offsets of `text` to code-point offsets: the unit of the sidecar, as of the
 * conformance suite. Offsets asked for in ascending order (the spans of a scan, start and end)
 * cost one pass over the text in all; a smaller offset than the last starts again from the
 * beginning. An offset between the two halves of a surrogate pair counts the pair as one
 * code point.
 */
function codePointCounter(text: string): (index: number) => number {
  let at = 0;
  let points = 0;
  return (index) => {
    if (index < at) {
      at = 0;
      points = 0;
    }
    while (at < index) {
      const unit = text.charCodeAt(at);
      if (unit >= 0xd800 && unit <= 0xdbff && at + 1 < text.length) {
        const next = text.charCodeAt(at + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          // The offset splits the pair: count it without moving past its first half.
          if (at + 1 >= index) return points + 1;
          at += 2;
          points++;
          continue;
        }
      }
      at++;
      points++;
    }
    return points;
  };
}

function text(body: Body): string {
  const value = body["text"];
  if (typeof value !== "string") throw new HttpError(400, "text must be a string");
  return value;
}

function names(body: Body, key: string): string[] | undefined {
  const value = body[key];
  if (value === undefined) return undefined;
  const list = typeof value === "string" ? [value] : value;
  if (!Array.isArray(list) || !list.every((item) => typeof item === "string")) {
    throw new HttpError(400, `${key} must be a string or a list of strings`);
  }
  return list;
}

function presetsOf(body: Body): CompliancePreset[] | undefined {
  const list = names(body, "preset");
  if (list === undefined) return undefined;
  for (const name of list) {
    if (!Object.hasOwn(PRESET_REGISTRY, name)) throw new HttpError(400, `unknown preset "${name}"`);
  }
  return list as CompliancePreset[];
}

/** The pipeline specification of a request body. */
function specOf(body: Body): PipelineSpec {
  const preset = presetsOf(body);
  const categories = names(body, "categories");
  const spec: Record<string, unknown> = {};
  if (preset !== undefined) spec["preset"] = preset;
  if (categories !== undefined) spec["categories"] = categories;
  for (const key of ["defaultStrategy", "rules", "minConfidence", "aggressive", "detection"]) {
    if (body[key] !== undefined) spec[key] = body[key];
  }
  // compilePipeline() validates every member and throws a ValidationError.
  return spec;
}

/** Categories to shield: the request's, else those of its presets, else all. */
function shieldCategories(body: Body): PipelineSpec["categories"] {
  const categories = names(body, "categories");
  if (categories !== undefined) return categories as PipelineSpec["categories"];
  const preset = presetsOf(body);
  return preset === undefined ? undefined : combinePresets(preset).categories;
}

function counts(spans: readonly { readonly category: string }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const span of spans) out[span.category] = (out[span.category] ?? 0) + 1;
  return out;
}

async function readBody(request: IncomingMessage, limit: number): Promise<string> {
  const declared = Number(request.headers["content-length"] ?? "0");
  if (declared > limit) throw new HttpError(413, `body larger than ${String(limit)} bytes`);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, `body larger than ${String(limit)} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(response: ServerResponse, status: number, body?: unknown): void {
  const payload = body === undefined ? "" : JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(payload);
}

/**
 * Create a sidecar. It keeps every value in the process: nothing is logged,
 * written or sent anywhere, and the vaults are dropped when they expire.
 *
 * @param options - Authentication, limits and session settings.
 * @returns The request handler and its sessions.
 *
 * @example
 * ```ts
 * import { createServer } from "node:http";
 * import { createSidecar } from "anonyma-sidecar";
 *
 * const sidecar = createSidecar({ token: process.env.ANONYMA_SIDECAR_TOKEN });
 * createServer(sidecar.handle).listen(7878, "127.0.0.1");
 * ```
 */
export function createSidecar(options: SidecarOptions = {}): Sidecar {
  const { token, maxBodyBytes = 1024 * 1024, mcp: serveMcp = true } = options;
  if (token?.length === 0) throw new RangeError("token must not be empty");
  const sessions = new SessionStore(options);
  const mcp = serveMcp
    ? createMcpServer({ serverInfo: { name: "anonyma-sidecar", version: VERSION } })
    : undefined;

  const routes: Record<string, (body: Body) => unknown> = {
    "/v1/detect": (body) => {
      const input = text(body);
      const spans = compilePipeline(specOf(body)).scan(input);
      const codePoints = codePointCounter(input);
      return {
        matches: spans.map((span) => ({
          category: span.category,
          value: input.slice(span.start, span.end),
          start: codePoints(span.start),
          end: codePoints(span.end),
          confidence: span.confidence,
        })),
      };
    },

    "/v1/anonymize": async (body) => {
      const result = await compilePipeline(specOf(body)).transformAsync(text(body));
      return { text: result.text, counts: counts(result.spans) };
    },

    "/v1/shield": (body) => {
      const input = text(body);
      const requested = body["session"];
      if (requested !== undefined && typeof requested !== "string") {
        throw new HttpError(400, "session must be a string");
      }
      const session = requested === undefined ? sessions.create() : sessions.get(requested);
      if (session === undefined) throw new HttpError(404, "unknown or expired session");
      const tokenization = createVaultTokenizer({ vault: session.vault });
      const categories = shieldCategories(body);
      const tokenize: StrategySpec = { strategy: "tokenize" };
      const spec: PipelineSpec = {
        ...(categories !== undefined ? { categories } : {}),
        defaultStrategy: tokenize,
      };
      const result = compilePipeline(spec, { tokenization }).transform(input);
      return { text: result.text, session: session.id, counts: counts(result.spans) };
    },

    "/v1/restore": (body) => {
      const id = body["session"];
      if (typeof id !== "string") throw new HttpError(400, "session must be a string");
      const session = sessions.get(id);
      if (session === undefined) throw new HttpError(404, "unknown or expired session");
      const result = restore(text(body), session.vault);
      return { text: result.text, restored: result.restored, unresolved: result.unresolved };
    },
  };

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = new URL(request.url ?? "/", "http://sidecar").pathname;
    const method = request.method ?? "GET";

    if (path === "/healthz") {
      if (method !== "GET") throw new HttpError(405, "use GET");
      send(response, 200, { status: "ok" });
      return;
    }

    if (token !== undefined) {
      const given = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1] ?? "";
      if (!sameSecret(given, token)) {
        response.setHeader("www-authenticate", "Bearer");
        throw new HttpError(401, "missing or wrong bearer token");
      }
    }
    sessions.sweep();

    if (path === "/v1/info") {
      if (method !== "GET") throw new HttpError(405, "use GET");
      send(response, 200, {
        name: "anonyma-sidecar",
        anonyma: VERSION,
        categories: BUILTIN_CATEGORIES,
        presets: Object.keys(PRESET_REGISTRY),
        offsets: "code-points",
        sessions: sessions.size,
        mcp: mcp !== undefined,
      });
      return;
    }

    const session = /^\/v1\/sessions\/([^/]+)$/.exec(path)?.[1];
    if (session !== undefined) {
      if (method !== "DELETE") throw new HttpError(405, "use DELETE");
      send(response, sessions.delete(decodeURIComponent(session)) ? 204 : 404);
      return;
    }

    const handler = routes[path];
    if (handler === undefined && !(path === "/mcp" && mcp !== undefined)) {
      throw new HttpError(404, "no such endpoint");
    }
    if (method !== "POST") throw new HttpError(405, "use POST");
    // A JSON content type keeps browsers from posting here without a CORS preflight.
    if (!JSON_TYPE.test(request.headers["content-type"] ?? "")) {
      throw new HttpError(415, "send application/json");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(await readBody(request, maxBodyBytes));
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, "the body is not JSON");
    }

    if (handler === undefined) {
      // POST /mcp: one JSON-RPC message or a batch.
      const answer = await mcp?.handle(parsed);
      if (answer === undefined) send(response, 202);
      else send(response, 200, answer);
      return;
    }
    if (!isObject(parsed)) throw new HttpError(400, "the body must be a JSON object");
    send(response, 200, await handler(parsed));
  }

  function handle(request: IncomingMessage, response: ServerResponse): void {
    route(request, response).catch((error: unknown) => {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        send(response, error.status, { error: error.message });
      } else if (error instanceof AnonymaError) {
        // Validation messages name arguments, never the text.
        send(response, 400, { error: error.message });
      } else {
        send(response, 500, { error: "internal error" });
      }
    });
  }

  return { handle, sessions };
}
