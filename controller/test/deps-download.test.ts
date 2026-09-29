import { describe, expect, it } from "vitest";
import { handleDepsRequest } from "../src/deps-download";
import type { Env } from "../src/config";

const name = "hlg-iperf3-linux-amd64";
const upstream = ["amd64", "arm64"].map((arch) => ({ tool: "nexttrace" as const, arch: arch as "amd64" | "arm64", version: "v1.7.3", name: `nexttrace_linux_${arch}`, sha256: "b".repeat(64), size: 12 }));
const manifest = JSON.stringify({ tools: { [name]: { tool: "iperf3", arch: "amd64", sha256: "a".repeat(64), size_bytes: 6 } } });
const env: Env = {
  ASSETS: {
    async fetch(request: Request) {
      const path = new URL(request.url).pathname;
      if (path === "/_deps/manifest.json") return new Response(manifest);
      if (path === `/_deps/${name}`) return new Response("binary");
      return new Response("missing", { status: 404 });
    },
  },
};

describe("iperf3 fallback assets", () => {
  it("publishes the hash and serves only the two allowed architectures", async () => {
    const index = await handleDepsRequest(new Request("https://lg.example/deps/manifest.json"), env, async () => upstream);
    const data = await index.json() as { version: number; static: Array<{ name: string; sha256: string }>; upstream: Array<{ name: string; url: string; sha256: string }> };
    expect(data.version).toBe(2);
    expect(data.static).toEqual([{ name, tool: "iperf3", arch: "amd64", sha256: "a".repeat(64), size: 6, url: `/deps/${name}` }]);
    expect(data.upstream).toEqual(upstream.map((entry) => ({ ...entry, url: `https://github.com/nxtrace/NTrace-core/releases/download/v1.7.3/${entry.name}` })));
    const binary = await handleDepsRequest(new Request(`https://lg.example/deps/${name}`), env);
    expect(binary.status).toBe(200);
    expect(await binary.text()).toBe("binary");
    expect((await handleDepsRequest(new Request("https://lg.example/deps/hlg-mtr-linux-amd64"), env)).status).toBe(404);
  });

  it("rejects incomplete or malformed upstream digest metadata", async () => {
    const badEnv: Env = { ASSETS: { async fetch() {
      return new Response(JSON.stringify({ tools: { [name]: { tool: "iperf3", arch: "amd64", sha256: "a".repeat(64), size_bytes: 6 } }, upstream: [{ ...upstream[0], sha256: "bad" }, upstream[1]] }));
    } } };
    const response = await handleDepsRequest(new Request("https://lg.example/deps/manifest.json"), badEnv, async () => [upstream[0], { ...upstream[1], sha256: "bad" }]);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ static: [{ name }], upstream: [] });
  });

  it("keeps bundled iperf3 available when GitHub is unreachable", async () => {
    const response = await handleDepsRequest(new Request("https://lg.example/deps/manifest.json"), env, async () => {
      throw new Error("upstream unavailable");
    });
    expect(response.status).toBe(200);
    const data = await response.json() as { static: Array<{ name: string }>; upstream: unknown[] };
    expect(data.static.map((entry) => entry.name)).toEqual([name]);
    expect(data.upstream).toEqual([]);
  });

  it("reports missing assets cleanly when SPA fallback returns HTML", async () => {
    const missingAssets: Env = {
      ASSETS: {
        async fetch() {
          return new Response("<!doctype html>", { headers: { "content-type": "text/html" } });
        },
      },
    };
    const index = await handleDepsRequest(new Request("https://lg.example/deps/manifest.json"), missingAssets, async () => upstream);
    expect(index.status).toBe(200);
    expect(await index.json()).toMatchObject({ static: [], upstream });
    const binary = await handleDepsRequest(new Request(`https://lg.example/deps/${name}`), missingAssets);
    expect(binary.status).toBe(404);
  });
});
