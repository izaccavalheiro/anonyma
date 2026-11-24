"use strict";
/**
 * Loads the addon of this platform: the prebuilt package of its platform
 * (installed as an optional dependency), or a build in this directory
 * (`npm run build`).
 */
const { existsSync } = require("node:fs");
const { join } = require("node:path");

/** The platforms with a prebuilt addon, by `${platform}-${arch}`. */
const PLATFORMS = {
  "linux-x64": "linux-x64-gnu",
  "linux-arm64": "linux-arm64-gnu",
  "darwin-x64": "darwin-x64",
  "darwin-arm64": "darwin-arm64",
  "win32-x64": "win32-x64-msvc",
};

/** Whether this Linux uses musl (Alpine), whose prebuilt addon does not exist. */
function isMusl() {
  if (process.platform !== "linux") return false;
  const report = typeof process.report?.getReport === "function" ? process.report.getReport() : {};
  return report.header !== undefined && report.header.glibcVersionRuntime === undefined;
}

function load() {
  const key = `${process.platform}-${process.arch}`;
  const suffix = PLATFORMS[key];
  const local = join(__dirname, "..", `anonyma-native.${key}.node`);
  if (existsSync(local)) return require(local);
  if (suffix === undefined || isMusl()) {
    throw new Error(
      `anonyma-native: no prebuilt addon for ${key}${isMusl() ? " (musl)" : ""}; ` +
        "use the TypeScript engine of anonyma, which runs everywhere",
    );
  }
  try {
    return require(`anonyma-native-${suffix}`);
  } catch (error) {
    throw new Error(
      `anonyma-native: the package anonyma-native-${suffix} is missing; ` +
        "reinstall without --no-optional (or --omit=optional)",
      { cause: error },
    );
  }
}

module.exports = load();
