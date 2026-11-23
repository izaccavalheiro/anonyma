import tsup from "tsup";

const shared = {
  sourcemap: true,
  treeshake: true,
  outDir: "dist",
  target: "es2022",
  removeNodeProtocol: false,
  // anonyma stays an import: the container image installs the root build next to it.
  external: [/^anonyma(\/.*)?$/],
} as const;

export default tsup.defineConfig([
  { ...shared, entry: { index: "src/index.ts" }, format: ["esm"], dts: true, clean: true },
  { ...shared, entry: { bin: "src/bin.ts" }, format: ["esm"], dts: false, clean: false },
]);
