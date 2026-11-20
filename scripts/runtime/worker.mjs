/**
 * A Cloudflare Worker that runs the runtime-neutral feature checks and
 * answers with the report. Loaded by scripts/runtime/workerd.mjs without the
 * `nodejs_compat` flag, so nothing Node.js-specific is available to it.
 */

import { runChecks } from "./checks.mjs";

export default {
  async fetch() {
    const report = await runChecks();
    return new globalThis.Response(JSON.stringify(report), {
      status: report.ok ? 200 : 500,
      headers: { "content-type": "application/json" },
    });
  },
};
