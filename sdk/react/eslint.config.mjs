import { config } from "@workspace/eslint-config/react-internal";

/** @type {import("eslint").Linter.Config} */
export default [
  {
    ignores: ["src/generated/**", "*.config.ts", "dist/**"],
  },
  ...config,
];
