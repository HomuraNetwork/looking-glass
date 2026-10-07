# syntax=docker/dockerfile:1

# Build stage for the Go agent. The admin one-click install flow serves the
# agent binaries from the controller's asset directory (/_agent/*), so the
# image must ship them.
FROM golang:1.27-bookworm AS agent-build


# Build identity embedded in the binaries (and recorded in the manifest). Pass
# the commit that last touched agent/:
#   docker build --build-arg LG_BUILD_ID=$(git log -1 --format=%h -- agent)
# It must change only when the agent's Go source changes (NOT the repo HEAD, or
# every frontend/worker commit would flag all nodes as outdated). Defaults to
# "unknown" so an un-parameterized build still works; update detection then
# treats the build id as unknown rather than mis-flagging nodes.
ARG LG_BUILD_ID=unknown

WORKDIR /src/agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent ./
COPY LICENSE /src/LICENSE
RUN go generate ./internal/licenses
# One build id for both binaries so a reporting node can be compared against
# the build the controller distributes. GOARCH is explicit on both: without it
# the "amd64" artifact would silently be a host-arch (e.g. arm64) binary when
# the image is built on a non-amd64 machine.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X hlg/internal/runtime.BuildID=${LG_BUILD_ID}" -o /out/hlg-agent-linux-amd64 ./cmd/hlg-agent \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X hlg/internal/runtime.BuildID=${LG_BUILD_ID}" -o /out/hlg-agent-linux-arm64 ./cmd/hlg-agent \
 && printf '%s\n' "${LG_BUILD_ID}" > /out/.build_id

# One native build stage cross-compiles both static iperf3 binaries.
FROM --platform=$BUILDPLATFORM debian:bookworm AS iperf3-build
ARG BUILDARCH
RUN case "${BUILDARCH}" in \
        arm64) cross=gcc-x86-64-linux-gnu; sysroot=libc6-dev-amd64-cross ;; \
        amd64) cross=gcc-aarch64-linux-gnu; sysroot=libc6-dev-arm64-cross ;; \
        *) echo "unsupported BUILDARCH: ${BUILDARCH}" >&2; exit 1 ;; \
    esac \
    && apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl "${cross}" "${sysroot}" \
    && rm -rf /var/lib/apt/lists/*
COPY controller/deps/build-iperf3.sh /usr/local/bin/build-iperf3
COPY controller/deps/write-libc-notices.sh /usr/local/bin/write-libc-notices.sh
RUN IPERF3_TARGET=amd64 sh /usr/local/bin/build-iperf3 \
    && cp /out/iperf3 /out/hlg-iperf3-linux-amd64 \
    && IPERF3_TARGET=arm64 sh /usr/local/bin/build-iperf3 \
    && cp /out/iperf3 /out/hlg-iperf3-linux-arm64

# Build stage: bundle the frontend assets and the local runtime server.
FROM node:26.10.0-bookworm-slim AS build

WORKDIR /src

# Node 26 does not bundle Corepack. Keep the image's package manager aligned
# with package.json#packageManager explicitly.
RUN npm install --global pnpm@12.7.0

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY controller/package.json controller/package.json
COPY controller/frontend/package.json controller/frontend/package.json
RUN pnpm install --frozen-lockfile

COPY controller controller
COPY LICENSE THIRD_PARTY_NOTICES.md ./
# Build the frontend (static assets). vite clears the output directory, so
# the agent artifacts are copied in afterwards.
RUN pnpm --dir controller/frontend build
COPY --from=agent-build /out /src/controller/frontend/dist/_agent
COPY --from=iperf3-build /out/hlg-iperf3-linux-amd64 /src/controller/frontend/dist/_deps/hlg-iperf3-linux-amd64
COPY --from=iperf3-build /out/hlg-iperf3-linux-arm64 /src/controller/frontend/dist/_deps/hlg-iperf3-linux-arm64
COPY --from=iperf3-build /out/iperf3-LICENSE-amd64.txt /src/controller/build/iperf3-LICENSE-amd64.txt
COPY --from=iperf3-build /out/iperf3-LICENSE-arm64.txt /src/controller/build/iperf3-LICENSE-arm64.txt
RUN node controller/scripts/write-release-manifests.mjs \
  && node controller/scripts/verify-release-artifacts.mjs controller/frontend/dist \
  && pnpm --dir controller build:local

# Runtime stage: just Node + the built artifacts. node:sqlite is built into
# Node (>=22.13 without the experimental flag), so there is no database
# dependency to install.
FROM node:26.10.0-bookworm-slim AS runtime

# Run unprivileged. The base image already provides a `node` user with
# uid/gid 1000 — do not create another one (useradd with the same uid fails).
RUN mkdir -p /var/lib/hlg && chown node:node /var/lib/hlg

WORKDIR /app
LABEL org.opencontainers.image.description="Looking Glass controller"
COPY --from=build /src/controller/local/dist/server.cjs /app/server.cjs
COPY --from=build /src/controller/frontend/dist /app/assets

ENV LG_PORT=8787 \
    LG_DB_PATH=/var/lib/hlg/looking-glass.sqlite \
    LG_ASSETS_DIR=/app/assets \
    LG_SCHEDULE_CRON="*/30 * * * *"

USER node

EXPOSE 8787

# /api/public-config is unauthenticated and returns 200 once the server is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD node -e "fetch('http://localhost:'+process.env.LG_PORT+'/api/public-config').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "/app/server.cjs"]
