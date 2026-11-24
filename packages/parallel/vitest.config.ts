import { defineConfig } from "vitest/config";
import { anonymaAlias } from "../vitest.shared.mjs";

// The tests run against the build (npm test runs tsup first): the pool starts
// dist/worker.js in each worker thread.
export default defineConfig({
  resolve: { alias: anonymaAlias },
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 60_000,
  },
});
