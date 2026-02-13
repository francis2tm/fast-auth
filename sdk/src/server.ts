import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  authConfigParseAndValidateToml,
  type FastAuthTomlConfig,
} from "./config";

/**
 * Default path to fast-auth.toml, relative to the monorepo root.
 * Located at: frontend/packages/auth/fast-auth/fast-auth.toml
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
export const FAST_AUTH_TOML_PATH = join(__dirname, "../../fast-auth.toml");

/**
 * Parse fast-auth.toml and return validated config.
 *
 * Throws a detailed error when TOML parsing or validation fails.
 *
 * @param tomlPath - Path to fast-auth.toml (defaults to FAST_AUTH_TOML_PATH)
 * @returns Strict fast-auth configuration
 */
export function parseFastAuthToml(
  tomlPath: string = FAST_AUTH_TOML_PATH,
): FastAuthTomlConfig {
  const absolutePath = resolve(tomlPath);
  const tomlText = readFileSync(absolutePath, "utf-8");

  try {
    return authConfigParseAndValidateToml(tomlText);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown config parse error";
    throw new Error(`Invalid fast-auth.toml configuration:\n  - ${message}`);
  }
}

export type { FastAuthTomlConfig } from "./config";
