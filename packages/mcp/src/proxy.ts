/**
 * @module @anonyma/mcp/proxy
 * @description A stdio MCP proxy: the MCP host launches the proxy instead of
 * the server, the proxy launches the server, and every message between the
 * two goes through an {@link McpGuard}.
 *
 * ```
 * host (Claude, Cursor, …) ⇄ stdin/stdout ⇄ proxy + guard ⇄ stdin/stdout ⇄ server
 * ```
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { createMcpGuard } from "./guard.js";
import type { McpGuard, McpGuardOptions } from "./guard.js";

/** JSON-RPC error code for an internal error. */
const INTERNAL_ERROR = -32603;

/**
 * Options accepted by {@link runStdioProxy}.
 */
export interface StdioProxyOptions extends McpGuardOptions {
  /** The command that starts the MCP server. */
  readonly command: string;
  /** Its arguments. */
  readonly args?: readonly string[];
  /** Its environment. Defaults to the environment of this process. */
  readonly env?: NodeJS.ProcessEnv;
  /** Its working directory. */
  readonly cwd?: string;
  /** Where the host's messages arrive. Defaults to `process.stdin`. */
  readonly input?: Readable;
  /** Where messages for the host go. Defaults to `process.stdout`. */
  readonly output?: Writable;
  /**
   * Receives diagnostics of the proxy — never message content. Defaults to
   * writing to `process.stderr`, which MCP hosts show in their logs.
   */
  readonly log?: (line: string) => void;
}

/**
 * A running proxy.
 */
export interface StdioProxy {
  /** The guard of the connection. */
  readonly guard: McpGuard;
  /** Settles with the exit code of the server once it has exited. */
  readonly exited: Promise<number>;
  /** Stop the server. */
  readonly close: () => void;
}

/** The id of a JSON-RPC message, when it has one. */
function idOf(message: unknown): string | number | undefined {
  if (typeof message !== "object" || message === null) return undefined;
  const { id } = message as { id?: unknown };
  return typeof id === "string" || typeof id === "number" ? id : undefined;
}

/**
 * Start an MCP server behind a privacy guard and relay messages between it
 * and the host over newline-delimited JSON-RPC (the MCP stdio transport).
 *
 * A message that cannot be processed is never forwarded as it is: a request
 * gets an error response, anything else is dropped and logged without its
 * content. Lines from the server that are not JSON are dropped the same way.
 *
 * @param options - The server to start, and the guard options.
 * @returns The running {@link StdioProxy}.
 *
 * @example
 * ```ts
 * import { runStdioProxy } from "@anonyma/mcp";
 *
 * const proxy = runStdioProxy({ command: "npx", args: ["-y", "@example/crm-mcp-server"] });
 * process.exitCode = await proxy.exited;
 * ```
 */
export function runStdioProxy(options: StdioProxyOptions): StdioProxy {
  const {
    command,
    args = [],
    env,
    cwd,
    input = process.stdin,
    output = process.stdout,
    log = (line: string): void => void process.stderr.write(`[anonyma-mcp-proxy] ${line}\n`),
    ...guardOptions
  } = options;
  const guard = createMcpGuard(guardOptions);

  const server = spawn(command, [...args], {
    stdio: ["pipe", "pipe", "inherit"],
    ...(env !== undefined ? { env } : {}),
    ...(cwd !== undefined ? { cwd } : {}),
    shell: process.platform === "win32",
  });

  const send = (stream: Writable, message: unknown): void => {
    if (!stream.writableEnded) stream.write(`${JSON.stringify(message)}\n`);
  };

  /** Answer a request that could not be relayed. */
  const fail = (id: string | number | undefined, to: Writable, what: string): void => {
    log(`${what}; the message was not forwarded`);
    if (id !== undefined) {
      send(to, {
        jsonrpc: "2.0",
        id,
        error: { code: INTERNAL_ERROR, message: `anonyma-mcp-proxy: ${what}` },
      });
    }
  };

  /**
   * Process one line from `sender` and forward it to `receiver`. When that
   * fails, whoever waits for an answer gets an error instead: the sender of a
   * request, or the receiver of a response.
   */
  const relay = (
    line: string,
    process: (message: unknown) => unknown,
    receiver: Writable,
    sender: Writable,
    side: string,
  ): void => {
    if (line.trim() === "") return;
    let message: unknown;
    try {
      message = JSON.parse(line) as unknown;
    } catch {
      log(`dropped a line from the ${side} that is not JSON`);
      return;
    }
    try {
      send(receiver, process(message));
    } catch (error) {
      const reason = error instanceof Error ? error.name : "error";
      const isRequest =
        typeof message === "object" &&
        message !== null &&
        typeof (message as { method?: unknown }).method === "string";
      fail(
        idOf(message),
        isRequest ? sender : receiver,
        `could not process a message from the ${side} (${reason})`,
      );
    }
  };

  const fromHost = createInterface({ input, crlfDelay: Infinity });
  fromHost.on("line", (line) => {
    relay(line, guard.fromClient, server.stdin, output, "host");
  });
  fromHost.on("close", () => server.stdin.end());

  const fromServer = createInterface({ input: server.stdout, crlfDelay: Infinity });
  fromServer.on("line", (line) => {
    relay(line, guard.fromServer, output, server.stdin, "server");
  });

  const exited = new Promise<number>((resolve) => {
    server.on("error", (error) => {
      log(`could not start the server: ${error.message}`);
      resolve(1);
    });
    server.on("close", (code, signal) => {
      fromHost.close();
      resolve(code ?? (signal === null ? 0 : 1));
    });
  });

  return Object.freeze({
    guard,
    exited,
    close: (): void => {
      server.kill();
    },
  });
}
