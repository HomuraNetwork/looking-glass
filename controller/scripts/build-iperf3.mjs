#!/usr/bin/env node
// Build the native iperf3 fallback or write the manifest over both CI artifacts.
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeIperfManifest } from "./release-manifests.mjs";
import { iperfLicensePath, writeThirdPartyLicenses } from "./build-licenses.mjs";

const controllerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(controllerRoot, "..");
const outDir = resolve(controllerRoot, "frontend", "dist", "_deps");
const arches = ["amd64", "arm64"];
const [docker, ...dockerPrefix] = process.env.DOCKER?.split(" ").filter(Boolean) ?? ["docker"];
function execDocker(args, options) {
  return execFileSync(docker, [...dockerPrefix, ...args], options);
}

async function manifest() {
  writeIperfManifest(outDir);
  await writeThirdPartyLicenses({ requireIperf3: true });
  console.log(`wrote iperf3 dependency manifest (${arches.join(", ")})`);
}

mkdirSync(outDir, { recursive: true });
function buildArch(arch) {
  if (!arches.includes(arch)) throw new Error(`unsupported architecture: ${arch}`);
  const image = `hlg-iperf3-${arch}:build`;
  const platform = `linux/${arch}`;
  execDocker(["buildx", "build", "--platform", platform, "--target", "artifact", "--load", "-t", image, "-f", "controller/deps/Dockerfile", "."], { cwd: repoRoot, stdio: "inherit" });
  execDocker(["run", "--rm", "--platform", platform, image, "/iperf3", "--version"], { stdio: "inherit" });
  // iperf3 maps a temporary buffer file for each stream, so scratch needs /tmp.
  const server = execDocker(["run", "-d", "--rm", "--platform", platform, "--tmpfs", "/tmp", image, "/iperf3", "-s", "-p", "5201"], { encoding: "utf8" }).trim();
  try {
    let connected = false;
    for (let attempt = 0; attempt < 5 && !connected; attempt++) {
      try {
        execDocker(["run", "--rm", "--platform", platform, "--tmpfs", "/tmp", "--network", `container:${server}`, image, "/iperf3", "-c", "127.0.0.1", "-p", "5201", "-t", "1"], { stdio: "inherit" });
        connected = true;
      } catch (error) {
        if (attempt === 4) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  } finally {
    execDocker(["stop", server], { stdio: "ignore" });
  }
  const id = execDocker(["create", "--platform", platform, image, "/iperf3"], { encoding: "utf8" }).trim();
  try {
    execDocker(["cp", `${id}:/iperf3`, resolve(outDir, `hlg-iperf3-linux-${arch}`)], { stdio: "inherit" });
    const notice = iperfLicensePath(arch);
    mkdirSync(dirname(notice), { recursive: true });
    execDocker(["cp", `${id}:/iperf3-LICENSE.txt`, notice], { stdio: "inherit" });
  } finally {
    execDocker(["rm", "-f", id], { stdio: "ignore" });
  }
}

if (process.argv.includes("--manifest-only")) {
  await manifest();
} else if (process.argv.includes("--all")) {
  for (const arch of arches) buildArch(arch);
  await manifest();
} else {
  buildArch(process.env.IPERF3_ARCH || (process.arch === "x64" ? "amd64" : process.arch === "arm64" ? "arm64" : ""));
}
