import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const AGENTS = ["hlg-agent-linux-amd64", "hlg-agent-linux-arm64"];
const IPERF = ["amd64", "arm64"];

function readManifest(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`cannot read ${path}: ${error.message}`);
  }
}

function verifyBinary(path, entry, expectedName, expectedMachine) {
  const bytes = readFileSync(path);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (bytes.length < 20 || bytes.subarray(0, 4).toString("hex") !== "7f454c46" || bytes.readUInt16LE(18) !== expectedMachine) {
    throw new Error(`${expectedName} is not the expected Linux ELF binary`);
  }
  if (entry?.sha256 !== sha256 || entry?.size_bytes !== bytes.length) {
    throw new Error(`${expectedName} does not match its manifest`);
  }
  return bytes;
}

export function verifyReleaseArtifacts(dist) {
  readFileSync(resolve(dist, "index.html"));
  const notices = readFileSync(resolve(dist, "THIRD_PARTY_LICENSES.txt"), "utf8");
  if (!notices.includes("=== HLG ===") || !notices.includes("Copyright (c) 2023 shadcn") || !notices.includes("=== iPerf3 ===")) {
    throw new Error("distribution license notices are incomplete");
  }

  const agentDir = resolve(dist, "_agent");
  const agent = readManifest(resolve(agentDir, "manifest.json"));
  if (typeof agent.build_id !== "string" || !agent.build_id) throw new Error("agent release manifest has no build_id");
  for (const [name, machine] of [[AGENTS[0], 62], [AGENTS[1], 183]]) {
    const entry = agent.targets?.find((target) => target.name === name);
    const bytes = verifyBinary(resolve(agentDir, name), entry, name, machine);
    if (!bytes.includes(Buffer.from("=== HLG ===")) || !bytes.includes(Buffer.from("=== Go runtime and standard library"))) {
      throw new Error(`${name} has no embedded license notices`);
    }
  }

  const depsDir = resolve(dist, "_deps");
  const deps = readManifest(resolve(depsDir, "manifest.json"));
  for (const [arch, machine] of [[IPERF[0], 62], [IPERF[1], 183]]) {
    const name = `hlg-iperf3-linux-${arch}`;
    const entry = deps.tools?.[name];
    if (entry?.tool !== "iperf3" || entry.arch !== arch) throw new Error(`${name} has an invalid manifest entry`);
    if (entry.license_url !== "/THIRD_PARTY_LICENSES.txt") throw new Error(`${name} has no distribution license URL`);
    verifyBinary(resolve(depsDir, name), entry, name, machine);
  }
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const dist = process.argv[2] ? resolve(process.argv[2]) : resolve(dirname(scriptPath), "../frontend/dist");
  try {
    verifyReleaseArtifacts(dist);
  } catch (error) {
    console.error(`release artifact verification failed: ${error.message}`);
    process.exit(1);
  }
}
