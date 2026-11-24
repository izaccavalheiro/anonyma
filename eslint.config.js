// @ts-check
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/coverage/**",
      "**/node_modules/**",
      "tests/**",
      "packages/*/tests/**",
      "vitest.config.ts",
      "packages/*/vitest.config.ts",
      // The site has its own TypeScript configuration and is type-checked by `tsc` there.
      "website/**",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",
      "@typescript-eslint/explicit-function-return-type": "error",
      "@typescript-eslint/explicit-module-boundary-types": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
      "no-console": "error",
      "no-prototype-builtins": "error",
      "prefer-const": "error",
      "no-var": "error",
    },
  },
  {
    files: [
      "tests/**/*.ts",
      "vitest.config.ts",
      "tsup.config.ts",
      "packages/*/tsup.config.ts",
      "eslint.config.js",
      "commitlint.config.js",
    ],
    extends: [tseslint.configs.disableTypeChecked],
    rules: {
      "@typescript-eslint/explicit-function-return-type": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
    },
  },
  {
    // anonyma-native's package: hand-written CommonJS and its declarations, without a tsconfig.
    files: ["bindings/node/lib/**"],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "writable",
        __dirname: "readonly",
        process: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/explicit-function-return-type": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-require-imports": "off",
    },
  },
  {
    // Node.js scripts of the repository: plain JavaScript, run directly, free to print.
    files: [
      "scripts/**/*.mjs",
      "bench/**/*.mjs",
      "packages/*.mjs",
      "packages/*/bench.mjs",
      "bindings/node/scripts/**/*.mjs",
      "bindings/node/test/**/*.mjs",
    ],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: {
        console: "readonly",
        process: "readonly",
        performance: "readonly",
        URL: "readonly",
        globalThis: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        Buffer: "readonly",
        fetch: "readonly",
      },
    },
    rules: {
      "no-console": "off",
      "@typescript-eslint/explicit-function-return-type": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
    },
  },
);
