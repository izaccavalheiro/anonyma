import { describe, expect, it } from "vitest";
import { launchOf } from "../src/command.js";

/** A Windows file system holding exactly `files` (compared without regard to case). */
function files(...paths: string[]): (path: string) => boolean {
  const present = new Set(paths.map((path) => path.toLowerCase()));
  return (path) => present.has(path.toLowerCase());
}

const windows = {
  platform: "win32",
  cwd: "C:\\work",
  env: { Path: "C:\\tools;;C:\\Program Files\\nodejs", PATHEXT: ".COM;.EXE;.BAT;.CMD" },
} as const;

describe("anonyma-mcp", () => {
  describe("launchOf", () => {
    it("starts a command without a shell outside Windows, and lets spawn report it", () => {
      const isFile = (): boolean => {
        throw new Error("not looked up");
      };
      expect(launchOf("anything", { platform: "linux", env: {}, cwd: "/", isFile })).toEqual({
        shell: false,
      });
      expect(launchOf("anything", { platform: "darwin", env: {}, cwd: "/", isFile })).toEqual({
        shell: false,
      });
    });

    it("returns undefined for a command Windows would not find", () => {
      expect(launchOf("no-such-server", { ...windows, isFile: files() })).toBeUndefined();
      expect(
        launchOf("no-such-server", { ...windows, env: {}, isFile: files("C:\\tools\\x.exe") }),
      ).toBeUndefined();
    });

    it("starts an executable on PATH without a shell, and a batch file through one", () => {
      const isFile = files(
        "C:\\Program Files\\nodejs\\node.exe",
        "C:\\Program Files\\nodejs\\npx.cmd",
      );
      expect(launchOf("node", { ...windows, isFile })).toEqual({ shell: false });
      expect(launchOf("npx", { ...windows, isFile })).toEqual({ shell: true });
    });

    it("reads PATH and PATHEXT whatever the case of their names", () => {
      const env = { pAtH: "C:\\tools", pathext: ".PS1" };
      expect(
        launchOf("server", { ...windows, env, isFile: files("C:\\tools\\server.ps1") }),
      ).toEqual({ shell: true });
      expect(launchOf("server", { ...windows, env, isFile: files("C:\\tools\\server.exe") })).toBe(
        undefined,
      );
    });

    it("uses the default PATHEXT when it is not set", () => {
      const env = { PATH: "C:\\tools" };
      expect(
        launchOf("server", { ...windows, env, isFile: files("C:\\tools\\server.com") }),
      ).toEqual({ shell: false });
      expect(
        launchOf("server", { ...windows, env, isFile: files("C:\\tools\\server.bat") }),
      ).toEqual({ shell: true });
    });

    it("looks in the working directory before PATH, as cmd.exe does", () => {
      const isFile = files("C:\\work\\server.cmd", "C:\\tools\\server.exe");
      expect(launchOf("server", { ...windows, isFile })).toEqual({ shell: true });
    });

    it("takes a command with an extension as given, before adding one", () => {
      const isFile = files("C:\\tools\\server.js", "C:\\tools\\server.exe");
      expect(launchOf("server.js", { ...windows, isFile })).toEqual({ shell: true });
      expect(launchOf("server.EXE", { ...windows, isFile })).toEqual({ shell: false });
    });

    it("resolves a command that names a directory against the working directory only", () => {
      const isFile = files("C:\\work\\bin\\server.exe", "C:\\tools\\bin\\server.exe");
      expect(launchOf("bin\\server", { ...windows, isFile })).toEqual({ shell: false });
      expect(launchOf("./bin/server", { ...windows, isFile })).toEqual({ shell: false });
      expect(launchOf("bin/other", { ...windows, isFile })).toBeUndefined();
      expect(launchOf("D:\\servers\\crm", { ...windows, isFile })).toBeUndefined();
      expect(
        launchOf("D:\\servers\\crm", { ...windows, isFile: files("D:\\servers\\crm.cmd") }),
      ).toEqual({ shell: true });
    });

    it("asks the file system when no lookup is given", () => {
      expect(launchOf("anonyma-test-no-such-command", { ...windows })).toBeUndefined();
    });
  });
});
