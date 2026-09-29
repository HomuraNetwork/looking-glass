# syntax=docker/dockerfile:1
# Native-architecture build for CI. Build once on amd64 and once on arm64.
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY controller/deps/build-iperf3.sh /usr/local/bin/build-iperf3
RUN sh /usr/local/bin/build-iperf3

FROM scratch AS artifact
COPY --from=build /out/iperf3 /iperf3
