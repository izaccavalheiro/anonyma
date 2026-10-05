/**
 * @module middleware
 * @description HTTP payload scrubbing, exposed as `"anonyma/middleware"`.
 * The framework adapters live in `"anonyma/middleware/express"` and
 * `"anonyma/middleware/hono"`; this entry holds the framework-independent
 * scrubber they are built on, which serves Fetch API handlers directly.
 *
 * @example
 * ```ts
 * import { createScrubber } from "anonyma/middleware";
 *
 * const scrubber = createScrubber({ spec: { preset: "hipaa" } });
 * const safe = scrubber.json({ note: "Patient SSN 123-45-6789" }, "job:export");
 * ```
 */

export { createScrubber } from "./core.js";
export type { Scrubber, ScrubberOptions } from "./core.js";
