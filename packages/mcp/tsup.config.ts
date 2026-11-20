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
  { ...shared, entry: { index: "src/index.ts" }, format: ["esm", "cjs"], dts: true, clean: true },
  // The command-line entry point runs as an ES module only.
  { ...shared, entry: { bin: "src/bin.ts" }, format: ["esm"], dts: false, clean: false },
]);
