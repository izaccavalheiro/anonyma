#!/usr/bin/env node
/**
 * Lays out the npm packages of a release of anonyma-native: one package per
 * platform, holding its addon, and the main package, whose optional
 * dependencies name them at the same version.
 *
 *   node scripts/package-platforms.mjs --version <version> --addons <dir> --out <dir>
 *
 * <dir of addons> holds anonyma-native.<platform>-<arch>.node for every
 * platform below; a missing one fails the release. Each package lands in
 * <out>/<name>/, ready for `npm publish`.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The platforms of a release: `${platform}-${arch}` and the package suffix. */
export const PLATFORMS = [
  { key: "linux-x64", suffix: "linux-x64-gnu", os: "linux", cpu: "x64", libc: "glibc" },
  { key: "linux-arm64", suffix: "linux-arm64-gnu", os: "linux", cpu: "arm64", libc: "glibc" },
  { key: "darwin-x64", suffix: "darwin-x64", os: "darwin", cpu: "x64" },
  { key: "darwin-arm64", suffix: "darwin-arm64", os: "darwin", cpu: "arm64" },
  { key: "win32-x64", suffix: "win32-x64-msvc", os: "win32", cpu: "x64" },
];

const args = process.argv.slice(2);
const option = (name) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 ? args[at + 1] : undefined;
};
const version = option("version");
const addons = option("addons");
const out = option("out");
if (version === undefined || addons === undefined || out === undefined) {
  console.error(
    "usage: node scripts/package-platforms.mjs --version <version> --addons <dir> --out <dir>",
  );
  process.exit(2);
}

const here = dirname(dirname(fileURLToPath(import.meta.url)));
const main = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
if (main.version !== version) {
  console.error(`bindings/node/package.json is at ${String(main.version)}, the tag at ${version}`);
  process.exit(1);
}

for (const platform of PLATFORMS) {
  const name = `anonyma-native-${platform.suffix}`;
  if (main.optionalDependencies?.[name] !== version) {
    console.error(`optionalDependencies.${name} must be ${version}`);
    process.exit(1);
  }
  const addon = join(addons, `anonyma-native.${platform.key}.node`);
  if (!existsSync(addon)) {
    console.error(`missing ${addon}`);
    process.exit(1);
  }
  const dir = join(out, name);
  mkdirSync(dir, { recursive: true });
  const file = `anonyma-native.${platform.key}.node`;
  copyFileSync(addon, join(dir, file));
  writeFileSync(
    join(dir, "package.json"),
    `${JSON.stringify(
      {
        name,
        version,
        description: `The ${platform.key} addon of anonyma-native; install anonyma-native, which depends on it.`,
        license: main.license,
        repository: main.repository,
        main: file,
        files: [file, "README.md"],
        os: [platform.os],
        cpu: [platform.cpu],
        ...(platform.libc === undefined ? {} : { libc: [platform.libc] }),
        engines: main.engines,
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(dir, "README.md"),
    `# ${name}\n\nThe prebuilt addon of [anonyma-native](https://www.npmjs.com/package/anonyma-native) for ${platform.key}. Install \`anonyma-native\`, which installs this package on ${platform.key} as an optional dependency.\n`,
  );
  console.log(`packed ${name}@${version}`);
}

// The main package, as bindings/node holds it, without its build scripts and tests.
const dir = join(out, "anonyma-native");
mkdirSync(join(dir, "lib"), { recursive: true });
for (const file of ["README.md", "CHANGELOG.md", "package.json"]) {
  copyFileSync(join(here, file), join(dir, file));
}
for (const file of ["index.cjs", "index.mjs", "index.d.ts", "load.cjs"]) {
  copyFileSync(join(here, "lib", file), join(dir, "lib", file));
}
console.log(`packed anonyma-native@${version}`);
