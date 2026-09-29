import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDeployEnv } from "./load-env.mjs";
import { verifyReleaseArtifacts } from "./verify-release-artifacts.mjs";

/**
 * Deploy the Worker, loading .env.cloudflare first.
 *
 * wrangler does not read env files, so this wrapper exists to feed it
 * CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN (and anything else) from the
 * same file used to render wrangler.jsonc. Existing environment variables win,
 * so CI secrets still take precedence.
 *
 * Run via `pnpm deploy:cf`, which renders wrangler.jsonc first.
 */
const loaded = loadDeployEnv();
const scriptDir = dirname(fileURLToPath(import.meta.url));
const controllerRoot = resolve(scriptDir, "..");
const config = resolve(controllerRoot, "wrangler.jsonc");

execFileSync(process.execPath, [resolve(scriptDir, "generate-db-schema.mjs")], { stdio: "inherit" });

if (!existsSync(config)) {
  console.error(`${config} not found — run \`pnpm wrangler:config\` first.`);
  process.exit(1);
}
try {
  verifyReleaseArtifacts(resolve(controllerRoot, "frontend", "dist"));
} catch (error) {
  console.error(`release assets unavailable: ${error.message}`);
  console.error("Run `pnpm build:cf` before deploying.");
  process.exit(1);
}
if (loaded.length > 0) {
  console.log(`loaded env: ${loaded.join(", ")}`);
}

const wranglerBin = resolve(controllerRoot, "node_modules", "wrangler", "bin", "wrangler.js");
const result = spawnSync(
  process.execPath,
  [wranglerBin, "deploy", "--config", config, "--autoconfig=false", "--keep-vars", ...process.argv.slice(2)],
  { cwd: controllerRoot, stdio: "inherit", env: process.env },
);
process.exit(result.status ?? 1);
