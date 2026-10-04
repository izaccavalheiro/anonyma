import tsup from "tsup";

export default tsup.defineConfig({
  entry: {
    index: "src/index.ts",
    schemas: "src/schemas.ts",
    validators: "src/validators.ts",
    crypto: "src/crypto.ts",
    stream: "src/stream.ts",
    "detectors/index": "src/detectors/index.ts",
    "engine/index": "src/engine/index.ts",
    "vault/index": "src/vault/index.ts",
    "audit/index": "src/audit/index.ts",
    "compliance/index": "src/compliance/index.ts",
    "ai/index": "src/ai/index.ts",
    "mcp/index": "src/mcp/index.ts",
    "middleware/index": "src/middleware/index.ts",
    "middleware/express": "src/middleware/express.ts",
    "middleware/hono": "src/middleware/hono.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  // Shared code is emitted once as chunks, so every entry point uses the same
  // module instances (one `AnonymaError` class, one copy of each detector).
  splitting: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  outDir: "dist",
  target: "es2022",
});
