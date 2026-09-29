import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Load Cloudflare deployment inputs from the repository's `.env.cloudflare`.
 *
 * Wrangler does not read this file itself, so the config and deployment
 * scripts load it explicitly.
 *
 * Semantics (matching Node's --env-file): a variable already present in the
 * environment is NEVER overridden, so CI secrets/vars always win and the file
 * only fills in what is missing. A missing file is skipped silently for CI.
 */
const scriptDir = dirname(fileURLToPath(import.meta.url));
const controllerRoot = resolve(scriptDir, "..");
const repoRoot = resolve(controllerRoot, "..");
const deployEnvPath = resolve(repoRoot, ".env.cloudflare");

/** @returns {string[]} the env files that were actually loaded */
export function loadDeployEnv() {
  if (!existsSync(deployEnvPath)) return [];
  // process.loadEnvFile does not override existing variables.
  process.loadEnvFile(deployEnvPath);
  return [deployEnvPath];
}
