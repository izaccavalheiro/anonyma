import { defineConfig } from "vitest/config";
import { anonymaAlias } from "../vitest.shared.mjs";

export default defineConfig({
  resolve: { alias: anonymaAlias },
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    testTimeout: 20_000,
  },
});
