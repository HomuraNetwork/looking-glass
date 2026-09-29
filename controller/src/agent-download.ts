import { Env } from "./config";
import { json, methodNotAllowed } from "./http";
import { bearerToken, validateNodeInitToken, validateNodeToken } from "./node-tokens";
import {
  AGENT_RELEASE_ARCHES,
  AGENT_RELEASE_TTL_SECONDS,
  agentReleaseManifest,
  agentReleaseSigningInput,
  agentReleaseSigningKey,
  signAgentRelease,
  type AgentReleaseArch,
  type AgentReleaseManifest,
} from "./agent-release";
import { kidFromJWK } from "./signing";
import { encodeInitString } from "./init-string";
import {
  DEFAULT_AGENT_BINARY_NAME,
  DEFAULT_AGENT_INSTALL_DIR,
  DEFAULT_AGENT_RUN_USER,
  DEFAULT_AGENT_SERVICE_NAME,
  getStringProjectSetting,
} from "./project-settings";
import type { SqlDatabase } from "./runtime";

const AGENT_ARTIFACTS = new Set(["hlg-agent-linux-amd64", "hlg-agent-linux-arm64", "manifest.json"]);

/** Build timestamp of the agent binaries this controller currently serves. */
export interface AgentReleaseInfo extends AgentReleaseManifest {}

/**
 * Read the build_id recorded in the distributed agent manifest (written at
 * build time alongside the binaries). Used to flag nodes whose reported build
 * is older than what the controller would install now. Best-effort: any read
 * failure means "unknown" and callers must not treat that as "outdated".
 */
export async function agentReleaseInfo(env: Env, origin: string): Promise<AgentReleaseInfo> {
  return agentReleaseManifest(env, origin);
}

export interface AgentInstallConfig {
  installDir: string;
  dataDir: string;
  binaryName: string;
  serviceName: string;
  runUser: string;
}

export async function handleAgentDownload(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });

  const url = new URL(request.url);
  const initKey = url.searchParams.get("init-key") || url.searchParams.get("init") || "";
  const init = await validateNodeInitToken(env.DB, initKey);
  if (!init) return json({ error: "invalid_init_key" }, { status: 401 });

  const body = agentInstallerScript({
    controllerOrigin: url.origin,
    nodeID: init.nodeID,
    install: await getAgentInstallConfig(env.DB),
    targets: (await agentReleaseManifest(env, url.origin)).targets,
  });
  return new Response(body, {
    headers: {
      "content-type": "text/x-shellscript; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export async function handleAgentArtifact(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  if (!env.ASSETS) return json({ error: "assets_required" }, { status: 503 });

  const url = new URL(request.url);
  // Two credentials can fetch a binary: a one-time init key (fresh install) or
  // a node token (an enrolled node running `hlg-agent update`). The node token
  // is what lets an agent re-fetch its own binary without a new init key; the
  // release signature still authenticates the bytes.
  const initKey = url.searchParams.get("init-key") || url.searchParams.get("init") || "";
  const authorized = (await validateNodeInitToken(env.DB, initKey)) !== null || (await validateNodeToken(env.DB, bearerToken(request))) !== null;
  if (!authorized) return json({ error: "invalid_init_key" }, { status: 401 });

  const artifact = artifactName(url.pathname);
  if (!artifact) return json({ error: "agent_artifact_not_found" }, { status: 404 });

  const assetURL = new URL(`/_agent/${artifact}`, url.origin);
  const response = await env.ASSETS.fetch(new Request(assetURL, request));
  if (response.status === 404) return json({ error: "agent_artifact_not_found" }, { status: 404 });

  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Describe the current agent release to an enrolled node, signed with the
 * config key so the agent can verify it before downloading or replacing the
 * binary. `hlg-agent update` calls this with its node token; nothing here is
 * reachable without a valid node (or init) credential.
 */
export async function handleAgentUpdate(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  if (!env.ASSETS) return json({ error: "assets_required" }, { status: 503 });

  const url = new URL(request.url);
  const initKey = url.searchParams.get("init-key") || url.searchParams.get("init") || "";
  const bearer = bearerToken(request);
  const init = await validateNodeInitToken(env.DB, initKey);
  const node = init ?? (await validateNodeToken(env.DB, bearer));
  if (!node) return json({ error: "invalid_node_token" }, { status: 401 });

  const arch = url.searchParams.get("arch")?.trim() || "";
  if (!isAgentReleaseArch(arch)) return json({ error: "unsupported_arch" }, { status: 400 });

  const target = `hlg-agent-linux-${arch}`;
  const manifest = await agentReleaseManifest(env, url.origin);
  if (!manifest.build_id) return json({ error: "agent_release_unavailable" }, { status: 503 });
  const artifact = manifest.targets[target];
  if (!artifact?.sha256 || !(artifact.size > 0)) return json({ error: "agent_release_unavailable" }, { status: 503 });

  const configJwk = await agentReleaseSigningKey(env);
  const descriptor = {
    build_id: manifest.build_id,
    target,
    sha256: artifact.sha256.toLowerCase(),
    size: artifact.size,
    path: `/_agent/binary/${target}`,
    node_id: node.nodeID,
    expires_at: Math.floor(Date.now() / 1000) + AGENT_RELEASE_TTL_SECONDS,
  };
  return json({
    ...descriptor,
    config_kid: await kidFromJWK(configJwk),
    signature: await signAgentRelease(configJwk, descriptor),
    signing_input: agentReleaseSigningInput(descriptor),
  });
}

function isAgentReleaseArch(value: string): value is AgentReleaseArch {
  return (AGENT_RELEASE_ARCHES as readonly string[]).includes(value);
}

export async function getAgentInstallConfig(db: SqlDatabase | undefined): Promise<AgentInstallConfig> {
  const installDir = await getStringProjectSetting(db, "AGENT_INSTALL_DIR") ?? DEFAULT_AGENT_INSTALL_DIR;
  const cleanInstallDir = installDir.replace(/\/+$/, "") || DEFAULT_AGENT_INSTALL_DIR;
  return {
    installDir: cleanInstallDir,
    dataDir: `${cleanInstallDir}/data`,
    binaryName: await getStringProjectSetting(db, "AGENT_BINARY_NAME") ?? DEFAULT_AGENT_BINARY_NAME,
    serviceName: await getStringProjectSetting(db, "AGENT_SERVICE_NAME") ?? DEFAULT_AGENT_SERVICE_NAME,
    runUser: await getStringProjectSetting(db, "AGENT_RUN_USER") ?? DEFAULT_AGENT_RUN_USER,
  };
}

/**
 * Assemble the deploy payload returned to the admin panel for a one-time init
 * key: the piped install command, the one-line init string, and the manual
 * per-arch "download + verify checksum + init" steps. Shared by the node-create
 * and re-issue-init endpoints so they never drift.
 */
export async function buildNodeInitPayload(
  env: Env,
  origin: string,
  token: string,
  providedManifest?: AgentReleaseManifest,
): Promise<{
  pull_command: string;
  init_string: string;
  manual: ManualInstallArch[];
}> {
  const manifest = providedManifest ?? await agentReleaseManifest(env, origin);
  return {
    pull_command: nodePullCommand(origin, token),
    init_string: encodeInitString(origin, token),
    manual: nodeManualInstall(origin, token, manifest.targets),
  };
}

export function nodePullCommand(origin: string, token: string): string {  // The one-line install only needs the init string: the script derives the bare
  // download key from it, and its install/service defaults come from the
  // controller's project settings (change them with -d/-u/--name/--service-name).
  const initString = encodeInitString(origin, token);
  return `curl -fsSL '${origin}/_agent/download?init-key=${encodeURIComponent(token)}' | bash -s -- -k '${shCommandArg(initString)}'`;
}

export interface ManualInstallArch {
  arch: AgentReleaseArch;
  /** Where to download this arch's binary (single-use init key authorizes it). */
  binary_url: string;
  /** Expected SHA-256 of the downloaded binary, for the checksum step. */
  sha256: string;
  size: number;
  /**
   * Ordered steps for a manual install: download, verify the checksum, chmod,
   * then install with `init`. Each entry is one command; the frontend renders
   * them numbered and highlights the checksum step.
   */
  steps: string[];
}

/**
 * Build the manual "download the binary, verify its checksum, then `init`"
 * install instructions per architecture. Unlike the piped install script this
 * surfaces the binary SHA-256 as an explicit, separate verification step.
 */
export function nodeManualInstall(
  origin: string,
  token: string,
  targets: Record<string, { sha256: string; size: number }>,
): ManualInstallArch[] {
  const initString = encodeInitString(origin, token);
  const out: ManualInstallArch[] = [];
  for (const arch of AGENT_RELEASE_ARCHES) {
    const target = `hlg-agent-linux-${arch}`;
    const artifact = targets[target];
    if (!artifact?.sha256) continue;
    const binaryURL = `${origin}/_agent/binary/${target}?init-key=${encodeURIComponent(token)}`;
    out.push({
      arch,
      binary_url: binaryURL,
      sha256: artifact.sha256,
      size: artifact.size,
      steps: [
        `curl -fsSL '${binaryURL}' -o /tmp/${target}`,
        `echo '${artifact.sha256}  /tmp/${target}' | sha256sum -c -`,
        `chmod +x /tmp/${target}`,
        `sudo /tmp/${target} init -k '${shCommandArg(initString)}'`,
      ],
    });
  }
  return out;
}


export function agentInstallerScript(input: {
  controllerOrigin: string;
  nodeID: string;
  install?: Partial<AgentInstallConfig>;
  targets?: Record<string, { sha256: string; size: number }>;
}): string {
  const controller = shSingleQuote(input.controllerOrigin);
  const nodeID = shSingleQuote(input.nodeID);
  const binaryBase = shSingleQuote(`${input.controllerOrigin}/_agent/binary`);
  const installDir = shDoubleQuote(input.install?.installDir || DEFAULT_AGENT_INSTALL_DIR);
  const dataDir = shDoubleQuote(input.install?.dataDir || `${DEFAULT_AGENT_INSTALL_DIR}/data`);
  const runUser = shDoubleQuote(input.install?.runUser || DEFAULT_AGENT_RUN_USER);
  const binaryName = shDoubleQuote(input.install?.binaryName || DEFAULT_AGENT_BINARY_NAME);
  const serviceName = shDoubleQuote(input.install?.serviceName || DEFAULT_AGENT_SERVICE_NAME);
  const amd64SHA256 = shSingleQuote(input.targets?.["hlg-agent-linux-amd64"]?.sha256 || "");
  const arm64SHA256 = shSingleQuote(input.targets?.["hlg-agent-linux-arm64"]?.sha256 || "");
  return `#!/usr/bin/env bash
set -euo pipefail

CONTROLLER_ORIGIN=${controller}
DEFAULT_AGENT_BINARY_BASE=${binaryBase}
NODE_ID_HINT=${nodeID}
INSTALL_DIR=${installDir}
DATA_DIR=${dataDir}
RUN_USER=${runUser}
BINARY_NAME=${binaryName}
SERVICE_NAME=${serviceName}
SERVICE_MODE=""
BIND_ADDR=""
INIT_KEY=""
AGENT_BINARY_URL=""
AGENT_BINARY_SHA256=""
CUSTOM_BINARY_URL=0

usage() {
  cat >&2 <<'USAGE'
Usage: bash install.sh -k HOST[:PORT]/lginit_<key> [options]

Options:
  -k, --init-key STRING    Init string: host[:port]/lginit_<key> (or the bare key).
  -d, --dir PATH           Agent install directory. Default: controller setting.
      --data-dir PATH      Agent state directory.
  -s, --service MODE       systemd, init.d, or none. Default: auto
  -u, --user USER          Existing service user. Default: controller setting (root).
      --binary-name NAME   Installed agent binary name. Default: controller setting.
      --service-name NAME  Service name for systemd/OpenRC. Default: controller setting.
      --controller URL     Controller origin override.
      --binary-url URL     Agent binary URL override.
      --binary-sha256 HEX  SHA-256 for a custom binary URL.
      --bind ADDR          Agent bind address. Default: chosen during init (port 443).
  -h, --help               Show this help.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -k|--init-key) INIT_KEY="\${2:-}"; shift 2 ;;
    -d|--dir) INSTALL_DIR="\${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="\${2:-}"; shift 2 ;;
    -s|--service) SERVICE_MODE="\${2:-}"; shift 2 ;;
    -u|--user) RUN_USER="\${2:-}"; shift 2 ;;
    --binary-name) BINARY_NAME="\${2:-}"; shift 2 ;;
    --service-name) SERVICE_NAME="\${2:-}"; shift 2 ;;
    --controller) CONTROLLER_ORIGIN="\${2:-}"; shift 2 ;;
    --binary-url) AGENT_BINARY_URL="\${2:-}"; shift 2 ;;
    --binary-sha256) AGENT_BINARY_SHA256="\${2:-}"; shift 2 ;;
    --bind) BIND_ADDR="\${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$INIT_KEY" ]; then
  echo "missing required -k INIT_STRING" >&2
  usage
  exit 2
fi

# ACCEPT a bare key or the full init string. The full form is
# [scheme://]host[:port]/lginit_<key>; the bare download key is the part after
# the last "/", and the host (when present) is the controller origin.
DOWNLOAD_KEY="$INIT_KEY"
case "$INIT_KEY" in
  */*)
    DOWNLOAD_KEY="\${INIT_KEY##*/}"
    INIT_HOST="\${INIT_KEY%/*}"
    INIT_SCHEME="https"
    case "$INIT_HOST" in
      http://*) INIT_SCHEME="http"; INIT_HOST="\${INIT_HOST#http://}" ;;
      https://*) INIT_SCHEME="https"; INIT_HOST="\${INIT_HOST#https://}" ;;
    esac
    if [ -n "$INIT_HOST" ]; then
      CONTROLLER_ORIGIN="$INIT_SCHEME://\$INIT_HOST"
    fi
    ;;
esac

if [ -z "$AGENT_BINARY_URL" ]; then
  case "$(uname -m)" in
    x86_64|amd64) agent_arch="amd64"; AGENT_BINARY_SHA256=${amd64SHA256} ;;
    aarch64|arm64) agent_arch="arm64"; AGENT_BINARY_SHA256=${arm64SHA256} ;;
    *) echo "unsupported architecture: $(uname -m); pass --binary-url" >&2; exit 2 ;;
  esac
  AGENT_BINARY_URL="$DEFAULT_AGENT_BINARY_BASE/hlg-agent-linux-$agent_arch?init-key=$DOWNLOAD_KEY"
else
  CUSTOM_BINARY_URL=1
fi
if [ "$CUSTOM_BINARY_URL" -eq 1 ] && [ -z "$AGENT_BINARY_SHA256" ]; then
  echo "--binary-sha256 is required with --binary-url" >&2
  exit 2
fi
if ! [[ "$AGENT_BINARY_SHA256" =~ ^[a-fA-F0-9]{64}$ ]]; then
  echo "agent release checksum is unavailable or invalid" >&2
  exit 2
fi
if [ -z "$SERVICE_MODE" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_MODE="systemd"
  elif command -v rc-update >/dev/null 2>&1; then
    SERVICE_MODE="init.d"
  else
    SERVICE_MODE="none"
  fi
fi
case "$SERVICE_MODE" in
  systemd|init.d|none) ;;
  *) echo "--service must be systemd, init.d or none" >&2; exit 2 ;;
esac

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "root privileges are required; re-run as root or install sudo" >&2
    exit 1
  fi
}

log() {
  printf '[lg-install] %s\n' "$*"
}

# Ensure the tools the bootstrap itself needs: curl to download the binary, and
# setcap (libcap2-bin) so the agent can apply file capabilities. Everything else
# (system packages, built-in probes, and upstream NextTrace) is handled by hlg-agent init
# (via its deps management) after the binary is downloaded.
ensure_base_tools() {
  if command -v curl >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    log "installing base tools (curl, libcap2-bin) via apt"
    as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y ca-certificates curl libcap2-bin
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y ca-certificates curl libcap
  elif command -v yum >/dev/null 2>&1; then
    as_root yum install -y ca-certificates curl libcap
  elif command -v apk >/dev/null 2>&1; then
    as_root apk add --no-cache ca-certificates curl libcap
  else
    echo "warning: unknown package manager; install curl and setcap manually" >&2
  fi
}

# Capabilities are applied by hlg-agent init/deps; the installer only places the
# binary and hands off.
apply_binary_caps() {
  local binary_path="\${1:-}"
  if [ -z "$binary_path" ] || [ ! -e "$binary_path" ]; then
    echo "warning: capability target not found: $binary_path" >&2
    return 0
  fi
  if command -v setcap >/dev/null 2>&1; then
    as_root setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$binary_path"
    log "set capabilities on $binary_path"
  else
    echo "warning: setcap not available; skipping capabilities for $binary_path" >&2
  fi
}

log "starting agent install"
log "controller: $CONTROLLER_ORIGIN"
log "install dir: $INSTALL_DIR"
log "data dir: $DATA_DIR"
log "binary name: $BINARY_NAME"
log "service name: $SERVICE_NAME"

ensure_base_tools

as_root install -d -m 0755 "$INSTALL_DIR"
as_root install -d -m 0700 "$DATA_DIR"
log "created install directories"

tmp_binary="$(mktemp)"
cleanup() { rm -f "$tmp_binary"; }
trap cleanup EXIT
log "downloading agent binary"
curl -fsSL "$AGENT_BINARY_URL" -o "$tmp_binary"
echo "$AGENT_BINARY_SHA256  $tmp_binary" | sha256sum -c -

# Detect an existing install: a node token means this node is already
# enrolled. Re-running the installer on it is an UPGRADE — replace the binary
# and restart the service, but do NOT run --install again. --install rewrites
# agent.json and bootstrap-input.json and would drive a fresh registration with
# this run's one-time init key, which is not what "upgrade the agent" means.
existing_install=0
if [ -s "$DATA_DIR/node-token" ] && [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
  existing_install=1
fi

retry_service_restart() {
  local svc="$1"
  local attempt
  for attempt in 1 2 3; do
    case "$SERVICE_MODE" in
      systemd) as_root systemctl restart "$svc" && return 0 ;;
      init.d) as_root rc-service "$svc" restart && return 0 ;;
    esac
    sleep 2
  done
  return 1
}

if [ "$existing_install" -eq 1 ]; then
  log "existing installation detected at $INSTALL_DIR (node token present): upgrading in place"
  # Preserve config + identity: only the binary is replaced. The agent derives
  # its own install dir/binary name from the running file and recovers the
  # service name from the unit that launches it, so no config rewrite is needed
  # here (a full reinstall would rewrite agent.json and could drop files).
  as_root install -m 0755 "$tmp_binary" "$INSTALL_DIR/$BINARY_NAME"
  apply_binary_caps "$INSTALL_DIR/$BINARY_NAME"
  log "installed agent binary to $INSTALL_DIR/$BINARY_NAME"
  if [ "$SERVICE_MODE" = "systemd" ] || [ "$SERVICE_MODE" = "init.d" ]; then
    retry_service_restart "$SERVICE_NAME" || { echo "failed to restart $SERVICE_NAME after upgrade" >&2; exit 1; }
    log "restarted $SERVICE_NAME on the upgraded binary"
  else
    log "service mode is none; restart the agent manually to use the new binary"
  fi
  log "upgrade finished"
  exit 0
fi

# Fresh install: write config/bootstrap and register with the controller.
as_root install -m 0755 "$tmp_binary" "$INSTALL_DIR/$BINARY_NAME"
log "installed agent binary to $INSTALL_DIR/$BINARY_NAME"
apply_binary_caps "$INSTALL_DIR/$BINARY_NAME"

INIT_ARGS=(
  "$INSTALL_DIR/$BINARY_NAME" init \
  --key "$CONTROLLER_ORIGIN/$DOWNLOAD_KEY" \
  --node-id "$NODE_ID_HINT" \
  --service "$SERVICE_MODE" \
  --path "$INSTALL_DIR" \
  --data-dir "$DATA_DIR" \
  --name "$BINARY_NAME" \
  --service-name "$SERVICE_NAME" \
  --user "$RUN_USER" \
  --frontend-origin "$CONTROLLER_ORIGIN" \
)
if [ -n "$BIND_ADDR" ]; then
  INIT_ARGS+=(--bind "$BIND_ADDR")
fi
if { : </dev/tty; } 2>/dev/null; then
  as_root "\${INIT_ARGS[@]}" --install-deps-yes </dev/tty
else
  as_root "\${INIT_ARGS[@]}" --install-deps-yes --yes
fi
log "install finished"
# doctor reads the layout agent.json init just wrote.
as_root "$INSTALL_DIR/$BINARY_NAME" doctor
log "doctor passed"
`;
}

function artifactName(pathname: string): string | null {
  const binaryPrefix = "/_agent/binary/";
  const directPrefix = "/_agent/";
  const name = pathname.startsWith(binaryPrefix)
    ? pathname.slice(binaryPrefix.length)
    : pathname.startsWith(directPrefix)
      ? pathname.slice(directPrefix.length)
      : "";
  if (!AGENT_ARTIFACTS.has(name)) return null;
  return name;
}

function shSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function shDoubleQuote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("$", "\\$").replaceAll("`", "\\`")}"`;
}

function shCommandArg(value: string): string {
  return value.replaceAll("'", "'\\''");
}
