/**
 * @module middleware/hono
 * @description Hono middleware that scrubs personal data from responses and,
 * optionally, makes a scrubbed copy of the JSON request body available to
 * handlers. It runs wherever Hono runs: Node.js, Bun, Deno, Cloudflare
 * Workers and other edge runtimes.
 *
 * The module has no dependency on Hono: it is typed against the few members
 * of the context it uses.
 */

import { createScrubber } from "./core.js";
import type { ScrubberOptions } from "./core.js";

/**
 * The members of a Hono context the middleware uses.
 */
export interface HonoContextLike {
  readonly req: {
    readonly method: string;
    readonly routePath?: string;
    readonly matchedRoutes?: readonly { readonly path?: unknown }[];
    readonly raw: Request;
  };
  get res(): Response;
  /** Hono merges the headers of the response being replaced, unless it is cleared first. */
  set res(response: Response | undefined);
  set: (key: string, value: unknown) => void;
}

/**
 * Options accepted by {@link anonymaHono}.
 */
export interface HonoMiddlewareOptions extends ScrubberOptions {
  /** Scrub the body of JSON and text responses. Defaults to `true`. */
  readonly response?: boolean;
  /**
   * Parse a JSON request body, scrub it, and store the result in the context
   * under `"anonymaBody"` for handlers to read with `c.get("anonymaBody")`.
   * The request itself is left untouched. Defaults to `false`.
   */
  readonly request?: boolean;
}

/**
 * Create Hono middleware that scrubs personal data from payloads.
 *
 * If scrubbing a response fails, the response is replaced by a generic 500:
 * the middleware never falls back to sending the original.
 *
 * A `text/event-stream` response is scrubbed event by event as it streams.
 * Any other JSON or text response is read to its end first, so a streamed
 * `text/plain` body is delivered when it is complete.
 *
 * @param options - Scrubber options and which directions to scrub.
 * @returns A Hono middleware handler.
 * @throws ValidationError When the pipeline specification is invalid.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { anonymaHono } from "anonyma/middleware/hono";
 *
 * const app = new Hono();
 * app.use("/support/*", anonymaHono({ spec: { preset: "gdpr" }, request: true }));
 *
 * app.post("/support/tickets", (c) => c.json({ received: c.get("anonymaBody") }));
 * ```
 */
export function anonymaHono(
  options: HonoMiddlewareOptions = {},
): (context: HonoContextLike, next: () => Promise<void>) => Promise<void> {
  const { response = true, request = false } = options;
  const scrubber = createScrubber(options);

  return async (context, next) => {
    // The route pattern, never the concrete URL, because URLs can carry personal data.
    // The last matched route is the handler; `routePath` alone names this middleware's own pattern.
    const handlerPath = context.req.matchedRoutes?.at(-1)?.path;
    const pattern = typeof handlerPath === "string" ? handlerPath : context.req.routePath;
    const source = `${context.req.method} ${pattern ?? "(unmatched)"}`;

    if (request) {
      const type = context.req.raw.headers.get("content-type") ?? "";
      if (/^application\/(?:[\w.+-]*\+)?json\b/i.test(type)) {
        let parsed: unknown;
        try {
          parsed = await context.req.raw.clone().json();
        } catch {
          parsed = undefined;
        }
        if (parsed !== undefined) context.set("anonymaBody", scrubber.json(parsed, source));
      }
    }

    await next();

    if (response) {
      let scrubbed: Response;
      try {
        scrubbed = await scrubber.response(context.res, source);
      } catch {
        scrubbed = new Response(
          JSON.stringify({ error: "The response could not be sanitized and was withheld." }),
          { status: 500, headers: { "content-type": "application/json" } },
        );
      }
      if (scrubbed !== context.res) {
        // Cleared first: otherwise Hono copies the old Content-Length, ETag and
        // Content-Encoding, which describe the unscrubbed body, onto the new response.
        context.res = undefined;
        context.res = scrubbed;
      }
    }
  };
}
