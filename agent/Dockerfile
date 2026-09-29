# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hlg-agent ./cmd/hlg-agent

# Runtime on Alpine: packaged tools are present in the image; optional managed
# tools are downloaded at first init using release metadata from the controller.
FROM alpine:3.24

RUN apk add --no-cache \
		ca-certificates \
		curl \
		iperf3 \
		iputils \
		libcap \
		mtr \
		traceroute

# Keep the data directory writable when a host-owned bind mount is attached.
RUN mkdir -p /var/lib/hlg

COPY --from=build /out/hlg-agent /usr/local/bin/hlg-agent

# Preserve capabilities when the image is run with an explicit non-root user.
RUN setcap cap_net_raw+eip /bin/ping \
	&& setcap cap_net_raw+eip /usr/sbin/mtr \
	&& setcap cap_net_raw+eip /usr/sbin/mtr-packet \
	&& setcap cap_net_raw+eip /usr/bin/traceroute \
	&& setcap cap_net_raw,cap_net_bind_service+eip /usr/local/bin/hlg-agent

ENV LG_BIND=:443 \
	LG_DATA_DIR=/var/lib/hlg

EXPOSE 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
	CMD curl -kf https://localhost:443/info || exit 1

ENTRYPOINT ["/usr/local/bin/hlg-agent", "run", "-i", "-c", "/var/lib/hlg/agent.json"]
