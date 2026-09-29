import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * Worker test config. The only thing it needs beyond defaults is an alias for
 * `cloudflare:sockets`: the Cloudflare runtime adapter imports it, but tests run
 * in Node where that module does not exist. The stub throws if a test actually
 * attempts a live TCP connection (tests inject a fake TcpRuntime instead).
 */
export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:sockets": fileURLToPath(new URL("./test/stubs/cloudflare-sockets.ts", import.meta.url)),
    },
  },
});
