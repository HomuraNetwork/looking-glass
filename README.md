# Homura Looking Glass (HLG)

**English** | [简体中文](README.zh-CN.md)

- **Live demo:** [lg.homura.network](https://lg.homura.network)
- **Source:** [GitHub](https://github.com/HomuraNetwork/looking-glass)

Homura Looking Glass (HLG) is a distributed Looking Glass developed by Homura Network. Visitors can select a node and run Ping, Traceroute, MTR, NextTrace, iPerf3, and download speed tests from the web interface without logging in to the node.

HLG consists of a Controller and Agents deployed on network nodes. The Controller provides the web interface, admin panel, and control plane; Agents execute the network tests on each node.

---

## Features

### Ping

Runs IPv4 and IPv6 Ping tests with live latency and packet-loss output.

### Traceroute

Traces IPv4 and IPv6 network paths.

### MTR

Continuously measures latency and loss at every hop. The Controller uses **Team Cymru Bulk Whois** to look up the ASN, prefix, registry, country, and AS/BGP organization for path addresses and adds that network ownership data to the results.

### NextTrace

Integrates [NextTrace](https://github.com/nxtrace/NTrace-core) for route traces with IP geolocation, ASN, and AS-path information.

### iPerf3

Starts upload, download, and parallel-stream tests directly from the web interface.

### Download speed tests

The Agent generates test data as it is requested, so large test files do not need to be stored on the node.

### Node RTT

The web interface measures RTT from the visitor's browser to each node, making node latency easy to compare.

### IPv4 / IPv6

Supports IPv4, IPv6, and custom Agent HTTPS listening ports.

### Admin panel

The Controller provides an `/admin` panel for:

- Managing nodes and generating Agent installation commands
- Viewing node availability, heartbeats, and versions
- Configuring the site name, logo, theme, navigation, and footer
- Managing Agent TLS certificates
- Configuring Cloudflare Turnstile and private-address probe protection
- Enabling TOTP two-factor authentication for administrators

---

## Agent

The HLG Agent is written in Go and is available for Linux `amd64` and `arm64`.

The Agent prefers installed copies of `ping`, `traceroute`, `mtr`, `nexttrace`, and `iperf3`. When a system tool is unavailable:

- Ping, Traceroute, and MTR can use the Agent's built-in Go implementations
- NextTrace can be downloaded from its official GitHub releases and verified with SHA-256
- iPerf3 can use a static build supplied by the Controller

The Agent also handles download tests, heartbeats, configuration synchronization, TLS, and self-updates. A node enrolls with a one-time Init Token and then receives its own Node Token. The Agent verifies signed configurations and update packages from the Controller.

Common maintenance commands:

```bash
hlg-agent doctor
hlg-agent deps check
hlg-agent upgrade --check
hlg-agent upgrade
```

For installation, Docker deployment, dependency management, service operation, and update details, see:

- **[Agent English documentation](agent/README.md)**
- [Agent 中文文档](agent/README.zh-CN.md)

---

## Quick start

The recommended setup runs the Controller on **Cloudflare Workers** and uses the included GitHub Actions workflow to build and deploy it:

1. Create a Cloudflare D1 database
2. Configure the GitHub Environment
3. Run the `Deploy Worker` workflow
4. Open `/admin` and complete first-run setup
5. Create a node and run its generated Agent installation command on the target server

---

## Deploying the Controller

### GitHub Actions + Cloudflare Workers

The [`.github/workflows/deploy-worker.yml`](.github/workflows/deploy-worker.yml) workflow runs the tests, builds the Controller and frontend, generates Agent release artifacts, builds static iPerf3 binaries, and deploys the Worker.

#### 1. Create a D1 database

Create one in the Cloudflare dashboard or with Wrangler:

```bash
npx wrangler d1 create looking-glass-db
```

Save the D1 Database ID returned by the command.

#### 2. Configure the GitHub Environment

In **Settings → Environments**, create an environment named `cloudflare-env`.

Add these **Secrets**:

| Name | Purpose |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID |
| `CLOUDFLARE_API_TOKEN` | API token with Workers and D1 edit permissions |
| `D1_DATABASE_ID` | D1 Database ID |
| `WORKER_NAME` | Worker name |
| `D1_NAME` | D1 database name |

Add these **Variables**:

| Name | Purpose |
| --- | --- |
| `WORKER_CRONS` | Optional five-field cron expression for background work; defaults to every 30 minutes |

Setting `WORKER_CRONS` to `none` disables background work. Certificate renewal, certificate sync nudges, retention cleanup, and node availability sweeps will also stop.

#### 3. Deploy

Go to **Actions → Deploy Worker → Run workflow**. When the workflow finishes, open the Worker's `/admin` page to continue setup.

---

## Building iPerf3

The full Controller build produces static iPerf3 binaries for Linux `amd64` and `arm64`. Agents use them when no suitable system `iperf3` is available.

The build script uses the official ESnet iPerf3 3.21 source archive and pins its SHA-256 digest. Its main build options are:

```text
--enable-static-bin
--disable-shared
--enable-static
--disable-dependency-tracking
--without-openssl
--without-sctp
```

After compilation, the script checks that the binary has no dynamic interpreter and runs an actual client/server test.

```bash
# Build all iPerf3 artifacts
pnpm build:iperf3

# Full Cloudflare build, including Agents and both iPerf3 architectures
pnpm build:cf
```

---

## Deploying to Cloudflare Workers locally

You can also build and deploy from your local machine without GitHub Actions.

### Requirements

- Node.js 26.9 or later
- pnpm 12.7
- Go 1.26 or later
- Docker with Docker Buildx
- A Cloudflare account, D1 database, and API token with Workers and D1 edit permissions

Docker Buildx is used to produce the iPerf3 artifacts for both architectures.

### 1. Install dependencies and create D1

```bash
pnpm install --frozen-lockfile
pnpm -C controller exec wrangler d1 create looking-glass-db
```

### 2. Create the deployment configuration

```bash
cp .env.cloudflare.example .env.cloudflare
```

Fill in:

```text
WORKER_NAME
D1_NAME
D1_DATABASE_ID
WORKER_CRONS
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
```

`WORKER_CRONS` may be omitted to use the default 30-minute schedule, or set to `none` to disable scheduled work.

### 3. Build and deploy

```bash
pnpm build:cf
pnpm deploy:cf
```

`pnpm deploy:cf` renders the Wrangler configuration from `.env.cloudflare` and deploys the Worker.

---

## Certificates on Cloudflare Workers

The Controller can centrally manage Agent TLS certificates using:

- Agent self-signed certificates
- Manually imported certificates
- Automated ACME issuance and renewal with DNS-01

> [!NOTE]
> Requests from Cloudflare Workers to the Let's Encrypt ACME service encounter connection errors, preventing automated issuance. Use ZeroSSL (including email-based EAB registration), Google Trust Services, or a custom ACME service instead. You can also keep the Agent's self-signed certificate or import a certificate in `/admin`.

---

## Self-hosting with Docker

The Controller can be self-hosted with Docker and store its data in SQLite.

> [!NOTE]
> The Docker Controller is maintained as a compatible deployment option but has not yet received full production validation.

### 1. Create the configuration

```bash
cp .env.local.example .env.local
```

Set the public origin whenever possible:

```text
LG_PUBLIC_ORIGIN=https://lg.example.com
```

If the Controller is behind a reverse proxy that you control, enable:

```text
LG_TRUST_PROXY=1
```

See [`.env.local.example`](.env.local.example) for proxy-hop, client-IP header, and trusted-proxy CIDR settings. The reverse proxy must overwrite client-supplied forwarding headers, and direct external access to the origin port must be restricted.

### 2. Start the Controller

```bash
LG_BUILD_ID="$(git log -1 --format=%h -- agent 2>/dev/null || echo latest)" \
  docker compose --env-file .env.local up -d --build
```

By default, Compose binds the Controller to `127.0.0.1:8787` and stores SQLite data in the `lg-data` named volume.

### 3. Configure the reverse proxy

Forward HTTPS traffic from Nginx, Caddy, or another reverse proxy to `127.0.0.1:8787`, with WebSocket forwarding enabled.

---

## Initial setup

After deploying the Controller, open:

```text
https://your-looking-glass.example/admin
```

Then:

1. Initialize the database and create the first administrator
2. Configure site information and signing keys
3. Configure node domains, Turnstile, certificates, and security options as needed
4. Create an Agent node under node management
5. Run the generated one-time installation command on the target server

After enrollment, the node appears in the admin panel and on the Looking Glass page. See the [Agent documentation](agent/README.md) for installation options and operational guidance.

---

## Updating

### GitHub Actions

Run **Actions → Deploy Worker → Run workflow** again.

### Local Cloudflare Workers deployment

```bash
git pull
pnpm install --frozen-lockfile
pnpm build:cf
pnpm deploy:cf
```

After deployment, open `/admin` and apply any pending database migrations when prompted.

### Docker

```bash
git pull
LG_BUILD_ID="$(git log -1 --format=%h -- agent 2>/dev/null || echo latest)" \
  docker compose --env-file .env.local up -d --build
```

---

## Technology

| Component | Technology |
| --- | --- |
| Controller | TypeScript |
| Agent | Go |
| Cloud deployment | Cloudflare Workers |
| Cloud database | Cloudflare D1 |
| Self-hosted deployment | Docker |
| Self-hosted database | SQLite (`node:sqlite`) |
| Agent communication | HTTPS / TLS |
| Configuration / update signing | Ed25519 |
| Certificate management | ACME / DNS-01 |
| MTR ASN lookup | Team Cymru Bulk Whois |
| Route testing | Ping / Traceroute / MTR / NextTrace |
| Throughput testing | iPerf3 |

---

## Architecture

```text
                         ┌──────────────────┐
                         │     Browser      │
                         │  Looking Glass   │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    Controller    │
                         │ Cloudflare Worker│
                         │        or        │
                         │ Docker + SQLite  │
                         └────────┬─────────┘
                                  │
                 ┌────────────────┼────────────────┐
                 │                │                │
                 ▼                ▼                ▼
            ┌─────────┐      ┌─────────┐      ┌─────────┐
            │ Agent A │      │ Agent B │      │ Agent C │
            │  HK  │      │SG│      │   US   │
            └─────────┘      └─────────┘      └─────────┘
```

### Controller

The Controller is the HLG control plane. It:

- Serves the web frontend and API
- Manages Agent enrollment, authentication, heartbeats, and versions
- Authorizes and proxies network test jobs
- Distributes signed configurations and release artifacts
- Manages TLS certificates and scheduled background work

The Controller can run on Cloudflare Workers with D1 or in Docker with SQLite.

### Agent

The Agent runs on the network node. It executes Ping, Traceroute, MTR, NextTrace, iPerf3, and download tests, and handles TLS, configuration synchronization, heartbeats, and updates.

One Controller can manage Agents across multiple locations, networks, and providers. See the [Agent documentation](agent/README.md) for implementation and operational details.

## License

HLG's original code is licensed under the [MIT License](LICENSE).
Third-party code retains its upstream licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Builds generate `frontend/dist/THIRD_PARTY_LICENSES.txt` under the Controller,
served at `/THIRD_PARTY_LICENSES.txt`. It contains the frontend/Controller
runtime dependency notices and, when distributed, the complete upstream iPerf3
LICENSE from its pinned source build. The iPerf3 download manifest and response
headers link to these notices.

The Agent embeds HLG's MIT license and its linked Go dependency/runtime notices;
run `hlg-agent licenses` to read them. Generated license files are build outputs
and are not committed.
