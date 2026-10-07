import { readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeAgentManifest, writeIperfManifest } from "./release-manifests.mjs";
import { writeThirdPartyLicenses } from "./build-licenses.mjs";

const controllerRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const dist = resolve(controllerRoot, "frontend", "dist");
const agentDir = resolve(dist, "_agent");
const depsDir = resolve(dist, "_deps");
const buildId = readFileSync(resolve(agentDir, ".build_id"), "utf8").trim();

writeAgentManifest(agentDir, buildId);
writeIperfManifest(depsDir);
await writeThirdPartyLicenses({ requireIperf3: true });
rmSync(resolve(agentDir, ".build_id"));
