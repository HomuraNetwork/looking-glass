#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT/.local/run"
LOG_DIR="$ROOT/.local/log"

if [[ -f "$ROOT/.env.local" ]]; then
	set -a
	# shellcheck disable=SC1091
	source "$ROOT/.env.local"
	set +a
fi

WORKER_PORT="${WORKER_PORT:-${LG_PORT:-8787}}"
LG_DB_PATH="${LG_DB_PATH:-$ROOT/.local/looking-glass.sqlite}"
LG_ASSETS_DIR="${LG_ASSETS_DIR:-$ROOT/controller/frontend/dist}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

pid_file() {
	printf '%s/%s.pid\n' "$RUN_DIR" "$1"
}

stop_one() {
	local name="$1"
	local file
	file="$(pid_file "$name")"
	if [[ -f "$file" ]]; then
		local pid
		pid="$(cat "$file")"
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			for _ in {1..40}; do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.1
			done
			kill -9 "$pid" 2>/dev/null || true
		fi
		rm -f "$file"
	fi
}

stop_stack() {
	stop_one controller
	stop_one agent
}

wait_for() {
	local url="$1"
	local curl_args=("${@:2}")
	for _ in {1..120}; do
		if curl -fsS "${curl_args[@]}" "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

case "${1:-start}" in
	stop)
		stop_stack
		echo "Stopped local HLG stack."
		exit 0
		;;
	status)
		for name in controller agent; do
			file="$(pid_file "$name")"
			if [[ -f "$file" ]] && kill -0 "$(cat "$file")" 2>/dev/null; then
				echo "$name running pid=$(cat "$file")"
			else
				echo "$name stopped"
			fi
		done
		exit 0
		;;
	start)
		# Keep successfully started services alive; clean up only if startup fails.
		cleanup_on_exit() {
			local status=$?
			if (( status != 0 )); then stop_stack; fi
		}
		trap cleanup_on_exit EXIT
		;;
	*)
		echo "usage: $0 [start|stop|status]" >&2
		exit 2
		;;
esac

stop_stack

# The local stack runs the Node runtime (local/), which shares the core with the
# Cloudflare Worker and needs neither wrangler nor a D1 emulator. It initializes
# the schema on first start.

if [[ ! -d "$ROOT/controller/frontend/node_modules" ]]; then
	(cd "$ROOT/controller/frontend" && pnpm install --frozen-lockfile)
fi

(cd "$ROOT/controller/frontend" && pnpm build)
(cd "$ROOT/controller" && pnpm agent:artifacts)
(cd "$ROOT/controller" && pnpm build:local)

(
	cd "$ROOT/controller"
	nohup env \
		LG_PORT="$WORKER_PORT" \
		LG_DB_PATH="$LG_DB_PATH" \
		LG_ASSETS_DIR="$LG_ASSETS_DIR" \
		node local/dist/server.cjs \
		>"$LOG_DIR/controller.log" 2>&1 </dev/null &
	echo $! >"$(pid_file controller)"
)

if ! wait_for "http://localhost:$WORKER_PORT/api/public-config"; then
	echo "Controller did not become ready. See $LOG_DIR/controller.log" >&2
	exit 1
fi

# Build the agent so an operator can run a node's pull command immediately.
(cd "$ROOT/agent" && go generate ./internal/licenses && go build -o "$RUN_DIR/hlg-agent" ./cmd/hlg-agent)

cat <<EOF
Local HLG controller is running.
Controller/frontend: http://localhost:$WORKER_PORT
SQLite database: $LG_DB_PATH
Controller log:  $LOG_DIR/controller.log

The agent is not started automatically: it needs a per-node init token issued
from the admin panel. To bring up a node:

  1. Open http://localhost:$WORKER_PORT/admin and complete first-run setup
     (the schema is initialized automatically on startup).
  2. Create a node and copy its one-time agent pull command.
  3. Run that command (it sets LG_CONTROLLER/LG_INIT_TOKEN, then pulls the
     signed config and certificate).

The built agent binary is at $RUN_DIR/hlg-agent.

Stop the stack with: scripts/dev-local.sh stop
EOF
