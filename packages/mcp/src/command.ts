/**
 * @module anonyma-mcp/command
 * @description How the stdio proxy starts the server command on each platform.
 * Internal: not exported from the package.
 */

import { statSync } from "node:fs";
import { win32 } from "node:path";

/** How to start a command that exists. */
export interface Launch {
  /** Whether the command needs a shell: a batch file or another script on Windows. */
  readonly shell: boolean;
}

/** Where a command is looked up. */
export interface LaunchContext {
  /** The platform, as `process.platform` names it. */
  readonly platform: NodeJS.Platform;
  /** The environment the command starts with, which holds `PATH` and `PATHEXT`. */
  readonly env: NodeJS.ProcessEnv;
  /** The working directory the command starts in. */
  readonly cwd: string;
  /** Whether a path names a file. Defaults to asking the file system. */
  readonly isFile?: (path: string) => boolean;
}

/** The extensions Windows tries when `PATHEXT` is not set. */
const DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD";

/** Extensions that Windows starts directly, without a shell. */
const EXECUTABLE = /^\.(?:exe|com)$/i;

/** Whether `path` names a file, according to the file system. */
function fileExists(path: string): boolean {
  return statSync(path, { throwIfNoEntry: false })?.isFile() === true;
}

/** The value of an environment variable, whatever the case of its name (Windows ignores it). */
function variable(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const key = Object.keys(env).find((candidate) => candidate.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

/**
 * Decide how to start `command`, or report that it cannot be found.
 *
 * Elsewhere than on Windows, the command is started without a shell, and `spawn` reports a
 * command it cannot find. On Windows, batch files (`npx.cmd`) only start through `cmd.exe`, and
 * `cmd.exe` starts even when the command does not exist, so `spawn` cannot tell. The command is
 * therefore looked up the way `cmd.exe` does: in the working directory, then in each directory of
 * `PATH` (unless the command names a directory itself), as given when it has an extension, then
 * with each extension of `PATHEXT`. Only a command found as `.exe` or `.com` starts without a
 * shell.
 *
 * @param command - The command, as given to the proxy.
 * @param context - The platform, environment and working directory it starts with.
 * @returns How to start it, or `undefined` when Windows would not find it.
 */
export function launchOf(command: string, context: LaunchContext): Launch | undefined {
  if (context.platform !== "win32") return { shell: false };
  const isFile = context.isFile ?? fileExists;

  const extensions = (variable(context.env, "PATHEXT") ?? DEFAULT_PATHEXT)
    .split(";")
    .filter((extension) => extension !== "");
  const names = [...(win32.extname(command) !== "" ? [command] : [])];
  for (const extension of extensions) names.push(command + extension);

  const named = win32.isAbsolute(command) || /[\\/]/.test(command);
  const directories = named
    ? [context.cwd]
    : [
        context.cwd,
        ...(variable(context.env, "PATH") ?? "").split(";").filter((entry) => entry !== ""),
      ];

  for (const directory of directories) {
    for (const name of names) {
      const path = win32.resolve(directory, name);
      if (isFile(path)) return { shell: !EXECUTABLE.test(win32.extname(path)) };
    }
  }
  return undefined;
}
