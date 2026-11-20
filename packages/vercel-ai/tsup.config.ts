import tsup from "tsup";

export default tsup.defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  outDir: "dist",
  target: "es2022",
  // Peer dependencies stay imports: the application provides them.
  external: ["ai", /^anonyma(\/.*)?$/],
});
