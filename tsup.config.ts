import tsup from "tsup";

export default tsup.defineConfig({
  entry: {
    index: "src/index.ts",
    schemas: "src/schemas.ts",
    validators: "src/validators.ts",
    crypto: "src/crypto.ts",
    stream: "src/stream.ts",
    "detectors/index": "src/detectors/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  outDir: "dist",
  target: "es2022",
});
