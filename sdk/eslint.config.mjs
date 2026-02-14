import js from "@eslint/js";
import tseslint from "typescript-eslint";

/** @type {import("eslint").Linter.Config} */
export default [
  {
    ignores: ["src/generated/**", "*.config.ts", "dist/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
];
