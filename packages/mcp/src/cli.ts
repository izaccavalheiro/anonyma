/**
 * @module @anonyma/mcp/cli
 * @description `anonyma-mcp-proxy`: puts any stdio MCP server behind a
 * privacy guard. Configure it in an MCP host in place of the server:
 *
 * ```json
 * {
 *   "mcpServers": {
 *     "crm": {
 *       "command": "npx",
 *       "args": ["-y", "@anonyma/mcp", "--", "npx", "-y", "@example/crm-mcp-server"]
 *     }
 *   }
 * }
 * ```
 */

import { runStdioProxy } from "./proxy.js";
import type { StdioProxyOptions } from "./proxy.js";

const USAGE = `Usage: anonyma-mcp-proxy [options] -- <command> [args...]

Starts <command> as an MCP server and relays its stdio messages. Personal data
in what the server returns becomes tokens before it reaches the model; tokens in
what the model sends back become the original values before they reach the server.

Options:
  --categories <list>  Comma-separated categories to detect (default: all built-in)
  --preset <name>      A compliance preset, such as gdpr or hipaa
  --format <shape>     Token shape: bracket ([EMAIL_0001], default), angle or brace
  --tag <tag>          2-12 letters or digits inserted into every token
  --strict             Restore only exact tokens, not spellings a model changed
  --quiet              Do not log what was replaced (counts only, never content)
  -h, --help           Show this help`;

/** The parsed command line. */
interface Parsed {
  readonly options: StdioProxyOptions;
  readonly quiet: boolean;
}

/**
 * Parse the arguments of `anonyma-mcp-proxy`.
 *
 * @param argv - The arguments after the program name.
 * @returns The proxy options, or a message to print and an exit code.
 */
export function parseArguments(
  argv: readonly string[],
): Parsed | { readonly message: string; readonly code: number } {
  const separator = argv.indexOf("--");
  const own = separator === -1 ? argv : argv.slice(0, separator);
  const [command, ...args] = separator === -1 ? [] : argv.slice(separator + 1);
  if (own.includes("-h") || own.includes("--help")) return { message: USAGE, code: 0 };
  if (command === undefined) return { message: USAGE, code: 2 };

  let categories: string[] | undefined;
  let preset: string | undefined;
  let format: string | undefined;
  let tag: string | undefined;
  let lenient = true;
  let quiet = false;
  for (let i = 0; i < own.length; i++) {
    const flag = own[i];
    const value = (): string => {
      const next = own[++i];
      if (next === undefined) throw new Error(`${String(flag)} needs a value`);
      return next;
    };
    try {
      if (flag === "--categories") categories = value().split(",").filter(Boolean);
      else if (flag === "--preset") preset = value();
      else if (flag === "--format") format = value();
      else if (flag === "--tag") tag = value();
      else if (flag === "--strict") lenient = false;
      else if (flag === "--quiet") quiet = true;
      else return { message: `Unknown option ${String(flag)}\n\n${USAGE}`, code: 2 };
    } catch (error) {
      return { message: `${(error as Error).message}\n\n${USAGE}`, code: 2 };
    }
  }

  return {
    quiet,
    options: {
      command,
      args,
      // Values are checked by the guard, which reports what is wrong.
      spec: {
        ...(categories !== undefined ? { categories: categories as never } : {}),
        ...(preset !== undefined ? { preset: preset as never } : {}),
      },
      session: {
        lenient,
        ...(format !== undefined ? { format: format as never } : {}),
        ...(tag !== undefined ? { tag } : {}),
      },
    },
  };
}

/**
 * Run the proxy for the given arguments.
 *
 * @param argv - The arguments after the program name.
 * @returns The exit code.
 */
export async function main(argv: readonly string[]): Promise<number> {
  const parsed = parseArguments(argv);
  if ("message" in parsed) {
    (parsed.code === 0 ? process.stdout : process.stderr).write(`${parsed.message}\n`);
    return parsed.code;
  }
  const log = (line: string): void => void process.stderr.write(`[anonyma-mcp-proxy] ${line}\n`);
  try {
    const proxy = runStdioProxy({
      ...parsed.options,
      log,
      ...(parsed.quiet
        ? {}
        : {
            onEvent: (event): void => {
              log(`${event.method}: ${String(event.replaced)} replaced (${event.direction})`);
            },
          }),
    });
    const stop = (): void => {
      proxy.close();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    return await proxy.exited;
  } catch (error) {
    log(error instanceof Error ? error.message : String(error));
    return 2;
  }
}
