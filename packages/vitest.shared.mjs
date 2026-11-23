/**
 * Vitest settings shared by the packages of this repository.
 *
 * `anonyma` resolves to the build of the repository root (`npm run build`
 * there first), not to whatever npm placed in node_modules: the packages are
 * tested against the code they will run with, through its export map.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

export const anonymaAlias = [
  { find: /^anonyma$/, replacement: join(dist, "index.js") },
  // Subpaths built from a single file rather than a directory.
  {
    find: /^anonyma\/(validators|schemas|crypto|stream)$/,
    replacement: join(dist, "$1.js"),
  },
  { find: /^anonyma\/(.+)$/, replacement: join(dist, "$1", "index.js") },
];
