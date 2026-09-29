#!/usr/bin/env bash
set -euo pipefail

# Smoke checks against the local Node runtime stack (scripts/dev-local.sh).
# Verifies the worker boots, serves the public config, and reports its schema
# as ready. It does NOT exercise a node/agent because those require an init
# token issued from the admin panel.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/.env.local" ]]; then
	set -a
	# shellcheck disable=SC1091
	source "$ROOT/.env.local"
	set +a
fi

WORKER_PORT="${WORKER_PORT:-${LG_PORT:-8787}}"
WORKER_ORIGIN="${WORKER_ORIGIN:-http://localhost:$WORKER_PORT}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

expect_status() {
	local want="$1"
	local url="$2"
	shift 2
	local status
	status="$(curl -sS -o "$TMP/smoke-body" -w '%{http_code}' "$@" "$url")"
	if [[ "$status" != "$want" ]]; then
		echo "Expected HTTP $want from $url, got $status" >&2
		cat "$TMP/smoke-body" >&2 || true
		exit 1
	fi
}

# Public config renders with the built-in defaults.
expect_status 200 "$WORKER_ORIGIN/api/public-config" -X GET
grep -q '"site_name"' "$TMP/smoke-body"

# The schema is initialized automatically by the local runtime on first start.
curl -fsS "$WORKER_ORIGIN/api/nodes" >"$TMP/nodes.json"
# /api/nodes returns a JSON array of public nodes.
grep -q '^\[' "$TMP/nodes.json"

# The SPA shell is served from disk and boot config is injected.
expect_status 200 "$WORKER_ORIGIN/" -X GET
grep -q '__LG_BOOT__' "$TMP/smoke-body"

# Frontend routes fall back to the SPA shell (Cloudflare's
# not_found_handling: single-page-application, mirrored by the local runtime).
for path in /admin /admin/; do
	expect_status 200 "$WORKER_ORIGIN$path" -X GET
	grep -q '__LG_BOOT__' "$TMP/smoke-body"
done

echo "Local smoke checks passed."
