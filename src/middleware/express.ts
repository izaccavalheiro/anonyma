/**
 * @module middleware/express
 * @description Express middleware that scrubs personal data from responses
 * and, optionally, from parsed request bodies. It also works as NestJS
 * functional middleware on the Express platform.
 *
 * The module has no dependency on Express: it is typed against the few
 * members of the request and response objects it uses.
 */

import { createScrubber } from "./core.js";
import type { ScrubberOptions } from "./core.js";

/**
 * The members of an Express request the middleware uses.
 */
export interface ExpressRequestLike {
  readonly method: string;
  body?: unknown;
  readonly baseUrl?: string;
  readonly route?: { readonly path?: unknown };
}

/**
 * The members of an Express response the middleware uses.
 */
export interface ExpressResponseLike {
  json: (body?: unknown) => unknown;
  send: (body?: unknown) => unknown;
  status: (code: number) => ExpressResponseLike;
  getHeader: (name: string) => unknown;
  readonly headersSent?: boolean;
}

/**
 * Options accepted by {@link anonymaExpress}.
 */
export interface ExpressMiddlewareOptions extends ScrubberOptions {
  /** Scrub what `res.json()` and `res.send()` send. Defaults to `true`. */
  readonly response?: boolean;
  /**
   * Replace `req.body` (as parsed by `express.json()`) with a scrubbed copy.
   * Enable it on routes that forward the body to a model, a log or a third
   * party. Defaults to `false`.
   */
  readonly request?: boolean;
}

/**
 * The route pattern (`/users/:id`), never the concrete URL, because URLs can
 * carry personal data.
 */
function sourceOf(req: ExpressRequestLike): string {
  const path =
    typeof req.route?.path === "string" ? `${req.baseUrl ?? ""}${req.route.path}` : "(unmatched)";
  return `${req.method} ${path}`;
}

/**
 * Create Express middleware that scrubs personal data from payloads.
 *
 * If scrubbing a response fails, the response is withheld and a generic 500
 * is sent instead: the middleware never falls back to sending the original.
 *
 * Only `res.json()` and `res.send()` (and what is built on them, such as
 * `res.jsonp()` and `res.render()`) are covered. An object passed to them is
 * scrubbed as the JSON it serialises to, so class instances and objects with
 * `toJSON` are covered; a `Buffer` is scrubbed when the response's content
 * type says it holds JSON or text. Bodies written with `res.write()`,
 * `res.end()`, `res.sendFile()` or a piped stream are not scrubbed, and
 * neither are the bodies Express writes itself: its default error page and
 * the body of `res.redirect()`.
 *
 * With `request: true` the body is scrubbed before the router runs, so the
 * audit record of a request names the method only (`POST (unmatched)`).
 *
 * @param options - Scrubber options and which directions to scrub.
 * @returns An Express request handler.
 * @throws ValidationError When the pipeline specification is invalid.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { anonymaExpress } from "anonyma/middleware/express";
 *
 * const app = express();
 * app.use(express.json());
 * app.use("/support", anonymaExpress({ spec: { preset: "gdpr" }, request: true }));
 *
 * app.post("/support/tickets", (req, res) => {
 *   // req.body is already scrubbed; so is whatever is sent back.
 *   res.json({ received: req.body });
 * });
 * ```
 */
export function anonymaExpress(
  options: ExpressMiddlewareOptions = {},
): (req: ExpressRequestLike, res: ExpressResponseLike, next: (error?: unknown) => void) => void {
  const { response = true, request = false } = options;
  const scrubber = createScrubber(options);

  return (req, res, next) => {
    try {
      if (request && typeof req.body === "object" && req.body !== null) {
        req.body = scrubber.json(req.body, sourceOf(req));
      } else if (request && typeof req.body === "string") {
        req.body = scrubber.text(req.body, sourceOf(req));
      }
    } catch (error) {
      next(error);
      return;
    }

    if (response) {
      const sendJson = res.json.bind(res);
      const send = res.send.bind(res);
      // While set, a body is on its way out and must not be scrubbed a second
      // time. A flag rather than swapped methods: when serialising throws, the
      // wrappers are still in place for what the error handler sends.
      let passthrough = false;
      const direct = <T>(action: () => T): T => {
        passthrough = true;
        try {
          return action();
        } finally {
          passthrough = false;
        }
      };
      const withhold = (): unknown =>
        direct(() =>
          sendJson.call(res.status(500), {
            error: "The response could not be sanitized and was withheld.",
          }),
        );
      const contentType = (fallback: string): string => {
        const header = res.getHeader("content-type");
        return typeof header === "string" ? header : fallback;
      };

      res.json = (body?: unknown): unknown => {
        if (passthrough) return sendJson(body);
        let scrubbed: unknown;
        try {
          scrubbed = scrubber.json(body, sourceOf(req));
        } catch {
          return withhold();
        }
        // res.json() calls res.send() with the serialised body.
        return direct(() => sendJson(scrubbed));
      };

      res.send = (body?: unknown): unknown => {
        if (passthrough) return send(body);
        let scrubbed: unknown;
        try {
          if (typeof body === "string") {
            scrubbed = scrubber.body(body, contentType("text/html"), sourceOf(req));
          } else if (ArrayBuffer.isView(body)) {
            // A buffer is scrubbed when the content type says it is JSON or text.
            const bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
            scrubbed =
              scrubber.bytes(bytes, contentType("application/octet-stream"), sourceOf(req)) ?? body;
          } else if (body !== null && typeof body === "object") {
            // Express routes other objects through res.json().
            return res.json(body);
          } else {
            scrubbed = body;
          }
        } catch {
          return withhold();
        }
        return direct(() => send(scrubbed));
      };
    }
    next();
  };
}
