import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export const AGENT_TARGETS = ["hlg-agent-linux-amd64", "hlg-agent-linux-arm64"];
export const IPERF_ARCHES = ["amd64", "arm64"];

function digest(path) {
  const bytes = readFileSync(path);
  return { sha256: createHash("sha256").update(bytes).digest("hex"), size_bytes: bytes.length };
}

export function writeAgentManifest(outDir, buildId) {
  const targets = AGENT_TARGETS.map((name) => ({ name, ...digest(resolve(outDir, name)) }));
  writeFileSync(resolve(outDir, "manifest.json"), `${JSON.stringify({ build_id: buildId, targets }, null, 2)}\n`);
}

export function writeIperfManifest(outDir) {
  const tools = {};
  for (const arch of IPERF_ARCHES) {
    const name = `hlg-iperf3-linux-${arch}`;
    tools[name] = { tool: "iperf3", arch, ...digest(resolve(outDir, name)) };
  }
  writeFileSync(resolve(outDir, "manifest.json"), `${JSON.stringify({ tools }, null, 2)}\n`);
}
