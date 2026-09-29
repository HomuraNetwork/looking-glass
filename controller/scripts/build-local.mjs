import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// Bundle the local runtime entry into a single file Node can run. The core
// (../src) uses extensionless relative imports, which Node's ESM loader cannot
// resolve directly, so bundling is required.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outfile = resolve(root, "local/dist/server.cjs");

await build({
  entryPoints: [resolve(root, "local/entry.ts")],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "cjs",
  outfile,
  logLevel: "info",
});

console.log(`wrote ${outfile}`);
