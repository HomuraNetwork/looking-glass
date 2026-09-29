import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentInstallerScript, nodeManualInstall, nodePullCommand } from "../src/agent-download";

const install = {
  installDir: "/opt/looking-glass",
  dataDir: "/opt/looking-glass/data",
  binaryName: "hlg-agent",
  serviceName: "hlg-agent",
  runUser: "homelg",
};
const targets = {
  "hlg-agent-linux-amd64": { sha256: "a".repeat(64), size: 100 },
  "hlg-agent-linux-arm64": { sha256: "b".repeat(64), size: 200 },
};

describe("agent installer script", () => {
  it("treats a re-run on an enrolled node as an in-place upgrade", () => {
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", install, targets });
    // An existing node token switches the run into the upgrade path...
    expect(script).toContain("existing installation detected");
    // ...which only replaces the binary and restarts the service; it must not
    // call init (that would rewrite config/bootstrap and re-register) nor run a
    // fresh registration.
    const upgradeBranch = script.slice(script.indexOf("if [ \"$existing_install\" -eq 1 ]"));
    const body = upgradeBranch.slice(0, upgradeBranch.indexOf("\nfi\n"));
    expect(body).not.toContain(" init ");
    expect(body).not.toContain("--key");
    expect(body).toContain("retry_service_restart");
  });

  it("keeps the fresh-install path for nodes without a token", () => {
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", install, targets });
    expect(script).toContain('[ -s "$DATA_DIR/node-token" ]');
    expect(script).toContain("Fresh install: write config/bootstrap and register with the controller.");
    expect(script).toContain('"$INSTALL_DIR/$BINARY_NAME" init');
    expect(script).toContain('--key "$CONTROLLER_ORIGIN/$DOWNLOAD_KEY"');
    expect(script).toContain("doctor passed");
    expect(script).toContain("sha256sum -c -");
    expect(script).toContain("--binary-sha256 is required with --binary-url");
  });

  it("uses root as the default service user without provisioning an account", () => {
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", targets });
    expect(script).toContain('RUN_USER="root"');
    expect(script).toContain('--user "$RUN_USER"');
  });

  it("leaves the agent listener port to the init prompt, with a non-interactive default", () => {
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", install, targets });
    expect(script).toContain('BIND_ADDR=""');
    expect(script).toContain("Default: chosen during init (port 443)");
    expect(script).toContain("{ : </dev/tty; }");
    expect(script).toContain("--install-deps-yes --yes");
  });

  it("never emits a token into the script for the pull command", () => {
    // The pull command embeds the one-time key, but the script body itself does
    // not hardcode it: the key is passed via the shell `-k` argument.
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", install, targets });
    expect(script).not.toContain("lginittoken");
    expect(nodePullCommand("https://lg.example", "lginit_secret")).toContain("lginit_secret");
  });

  it("is valid bash (a syntax error would only surface on a real node)", () => {
    const script = agentInstallerScript({ controllerOrigin: "https://lg.example", nodeID: "n1", install, targets });
    const dir = mkdtempSync(join(tmpdir(), "lg-installer-"));
    const path = join(dir, "install.sh");
    writeFileSync(path, script);
    expect(() => execFileSync("bash", ["-n", path])).not.toThrow();
  });

  it("builds manual install steps with an explicit checksum step per arch", () => {
    const steps = nodeManualInstall("https://lg.example", "lginit_secret", {
      "hlg-agent-linux-amd64": { sha256: "a".repeat(64), size: 100 },
      "hlg-agent-linux-arm64": { sha256: "b".repeat(64), size: 200 },
    });
    expect(steps.map((s) => s.arch)).toEqual(["amd64", "arm64"]);
    const amd64 = steps[0];
    expect(amd64.steps).toHaveLength(4);
    // 1: download (single-use key authorizes it), 2: checksum, 3: chmod, 4: init -k <init string>.
    expect(amd64.steps[0]).toContain("/_agent/binary/hlg-agent-linux-amd64?init-key=");
    expect(amd64.steps[1]).toBe(`echo '${"a".repeat(64)}  /tmp/hlg-agent-linux-amd64' | sha256sum -c -`);
    expect(amd64.steps[2]).toContain("chmod +x");
    expect(amd64.steps[3]).toContain("init -k");
    expect(amd64.steps[3]).toContain("lg.example/lginit_secret");
    expect(amd64.steps[3]).not.toContain("--port");
  });

  it("omits archs the controller does not serve", () => {
    const steps = nodeManualInstall("https://lg.example", "k", {
      "hlg-agent-linux-amd64": { sha256: "a".repeat(64), size: 1 },
    });
    expect(steps.map((s) => s.arch)).toEqual(["amd64"]);
  });
});
