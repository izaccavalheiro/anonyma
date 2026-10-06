import { defineConfig } from "vitest/config";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import type { Plugin } from "vite";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Remap `.js` relative imports to `.ts` when the file system only contains `.ts` source files.
 * This is required for TypeScript ESM projects where `.js` extensions are used in source imports
 * (per TypeScript's `NodeNext` module resolution) but test files are run directly by Vitest.
 */
function typescriptEsmResolver(): Plugin {
  return {
    name: "anonyma:typescript-esm-resolver",
    enforce: "pre",
    resolveId(id: string, importer: string | undefined) {
      // Only remap relative imports that end with .js
      if (!id.startsWith(".") || !id.endsWith(".js")) return undefined;
      if (!importer) return undefined;

      // Resolve the JavaScript path relative to the importer, then swap extension.
      const jsAbsolute = resolve(dirname(importer), id);
      const tsAbsolute = jsAbsolute.replace(/\.js$/, ".ts");
      return tsAbsolute;
    },
  };
}

export default defineConfig({
  plugins: [typescriptEsmResolver()],
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "json-summary", "html", "lcov"],
      include: ["src/**/*.ts"],
      // Barrels and type-only modules contain no logic of their own.
      exclude: ["src/index.ts", "src/schemas.ts", "src/types.ts", "src/**/types.ts"],
      // Every line, branch and function is covered. Code that no input can reach carries a
      // `v8 ignore` hint that says why (see AGENTS.md).
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
});
