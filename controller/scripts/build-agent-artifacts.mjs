#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENT_TARGETS, writeAgentManifest } from "./release-manifests.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const controllerRoot = resolve(scriptDir, "..");
const repoRoot = resolve(controllerRoot, "..");
const agentRoot = resolve(repoRoot, "agent");
const outDir = resolve(controllerRoot, "frontend", "dist", "_agent");
const targets = AGENT_TARGETS.map((name) => ({ goarch: name.endsWith("amd64") ? "amd64" : "arm64", name }));

// Build identity for the agent binaries, injected via ldflags and recorded in
// the manifest so the controller can tell whether a node runs the build it
// distributes.
//
// It must change ONLY when the agent (Go) source changes: using the repo HEAD
// would flip it for every frontend/controller commit too, falsely flagging every
// node as needing an upgrade although the binary is identical. So the id is the
// commit that last touched agent/, plus "-dirty" when agent/ has uncommitted
// changes. Falls back to a timestamp when git is unavailable.
const buildId = resolveBuildId();

function resolveBuildId() {
  try {
    const agentDirty = execFileSync("git", ["status", "--porcelain", "--", "agent"], { cwd: repoRoot, encoding: "utf8" }).trim();
    const commit = execFileSync("git", ["log", "-1", "--format=%h", "--", "agent"], { cwd: repoRoot, encoding: "utf8" }).trim();
    if (!commit) return `${new Date().toISOString().split(".")[0]}Z`;
    return agentDirty ? `${commit}-dirty` : commit;
  } catch {
    return `${new Date().toISOString().split(".")[0]}Z`;
  }
}

mkdirSync(outDir, { recursive: true });

execFileSync("go", ["generate", "./internal/licenses"], {
  cwd: agentRoot,
  stdio: "inherit",
});

for (const target of targets) {
  const out = resolve(outDir, target.name);
  execFileSync(
    "go",
    ["build", "-trimpath", `-ldflags=-s -w -X hlg/internal/runtime.BuildID=${buildId}`, "-o", out, "./cmd/hlg-agent"],
    {
      cwd: agentRoot,
      stdio: "inherit",
      env: {
        ...process.env,
        CGO_ENABLED: "0",
        GOOS: "linux",
        GOARCH: target.goarch,
      },
    },
  );
}

writeAgentManifest(outDir, buildId);
console.log(`wrote ${targets.length} agent artifact(s) to ${outDir} (build_id=${buildId})`);
