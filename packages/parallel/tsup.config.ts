import tsup from "tsup";

const shared = {
  sourcemap: true,
  treeshake: true,
  outDir: "dist",
  target: "es2022",
  removeNodeProtocol: false,
  // The peer dependency stays an import: the application provides it.
  external: [/^anonyma(\/.*)?$/],
} as const;

export default tsup.defineConfig([
  // shims: import.meta.url in the CommonJS build, to find the worker next to it.
  {
    ...shared,
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
    shims: true,
  },
  // The worker runs as an ES module only.
  { ...shared, entry: { worker: "src/worker.ts" }, format: ["esm"], dts: false, clean: false },
]);
