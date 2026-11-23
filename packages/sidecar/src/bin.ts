#!/usr/bin/env node
/**
 * anonyma-sidecar: serve the sidecar over HTTP.
 *
 * Settings come from the environment (and the flags of the same name):
 *   ANONYMA_SIDECAR_HOST         --host          127.0.0.1
 *   ANONYMA_SIDECAR_PORT         --port          7878
 *   ANONYMA_SIDECAR_TOKEN        (environment only: a flag would show in `ps`)
 *   ANONYMA_SIDECAR_MAX_BODY     --max-body      1048576 bytes
 *   ANONYMA_SIDECAR_SESSION_TTL  --session-ttl   1800 seconds
 *   ANONYMA_SIDECAR_MAX_SESSIONS --max-sessions  1000
 *   ANONYMA_SIDECAR_MCP          --no-mcp        on
 */

import { createServer } from "node:http";
import { parseArgs } from "node:util";

import { createSidecar } from "./server.js";

const { values } = parseArgs({
  options: {
    host: { type: "string" },
    port: { type: "string" },
    "max-body": { type: "string" },
    "session-ttl": { type: "string" },
    "max-sessions": { type: "string" },
    "no-mcp": { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help === true) {
  process.stdout.write(
    "Usage: anonyma-sidecar [--host 127.0.0.1] [--port 7878] [--max-body bytes]\n" +
      "                       [--session-ttl seconds] [--max-sessions n] [--no-mcp]\n" +
      "Set ANONYMA_SIDECAR_TOKEN to require a bearer token.\n",
  );
  process.exit(0);
}

const env = process.env;

function integer(flag: string | undefined, variable: string | undefined, fallback: number): number {
  const raw = flag ?? variable;
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    process.stderr.write(`anonyma-sidecar: ${raw} is not a positive integer\n`);
    process.exit(2);
  }
  return value;
}

const host = values.host ?? env["ANONYMA_SIDECAR_HOST"] ?? "127.0.0.1";
const port = integer(values.port, env["ANONYMA_SIDECAR_PORT"], 7878);
const token = env["ANONYMA_SIDECAR_TOKEN"];
const loopback = host === "127.0.0.1" || host === "::1" || host === "localhost";

const sidecar = createSidecar({
  ...(token !== undefined && token !== "" ? { token } : {}),
  maxBodyBytes: integer(values["max-body"], env["ANONYMA_SIDECAR_MAX_BODY"], 1024 * 1024),
  ttlMs: integer(values["session-ttl"], env["ANONYMA_SIDECAR_SESSION_TTL"], 1800) * 1000,
  maxSessions: integer(values["max-sessions"], env["ANONYMA_SIDECAR_MAX_SESSIONS"], 1000),
  mcp: values["no-mcp"] !== true && env["ANONYMA_SIDECAR_MCP"] !== "off",
});

if (!loopback && (token === undefined || token === "")) {
  process.stderr.write(
    `anonyma-sidecar: listening on ${host} without ANONYMA_SIDECAR_TOKEN; ` +
      "anyone who reaches the port can restore tokens of a session they know\n",
  );
}

const server = createServer(sidecar.handle);
server.listen(port, host, () => {
  process.stderr.write(`anonyma-sidecar: listening on http://${host}:${String(port)}\n`);
});

function stop(): void {
  sidecar.sessions.clear();
  server.close(() => process.exit(0));
  // Connections left open by clients do not hold the process.
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
