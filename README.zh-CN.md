# Homura Looking Glass (HLG)

[English](README.md) | **简体中文**

- **在线演示：** [lg.homura.network](https://lg.homura.network)
- **源代码：** [GitHub](https://github.com/HomuraNetwork/looking-glass)

Homura Looking Glass（HLG）是 Homura Network 开发的分布式 Looking Glass。访客可以直接在网页中选择节点并执行 Ping、Traceroute、MTR、NextTrace、iPerf3 和下载测速，无需登录节点服务器。

HLG 由 Controller 和部署在各节点上的 Agent 组成。Controller 提供 Web 界面、管理后台和控制面；Agent 在节点上实际执行网络测试。

---

## 功能

### Ping

支持 IPv4 和 IPv6 Ping，实时输出延迟与丢包结果。

### Traceroute

支持 IPv4 和 IPv6 路由追踪。

### MTR

持续检测每一跳的延迟和丢包。Controller 通过 **Team Cymru Bulk Whois** 批量查询路径 IP 对应的 ASN、Prefix、Registry、Country 和 AS/BGP Organization，并将网络归属信息附加到结果中。

### NextTrace

集成 [NextTrace](https://github.com/nxtrace/NTrace-core)，提供包含 IP 地理位置、ASN 和 AS 路径信息的路由追踪结果。

### iPerf3

可以直接从网页发起上传、下载和多并发流测试。

### 下载测速

Agent 在请求时动态生成测试数据，无需在节点磁盘中预先保存大型测速文件。

### 节点 RTT

网页会测量访客浏览器到各节点的 RTT，便于快速比较节点延迟。

### IPv4 / IPv6

支持 IPv4、IPv6 和自定义 Agent HTTPS 监听端口。

### 管理后台

Controller 提供 `/admin` 管理后台，可用于：

- 管理节点并生成 Agent 安装命令
- 查看节点在线状态、心跳和版本
- 配置站点名称、Logo、主题、导航和页脚
- 管理 Agent TLS 证书
- 配置 Cloudflare Turnstile 和私有地址探测保护
- 启用管理员 TOTP 两步验证

---

## Agent

HLG Agent 使用 Go 开发，目前提供 Linux `amd64` 和 `arm64` 二进制。

Agent 会优先使用系统中已有的 `ping`、`traceroute`、`mtr`、`nexttrace` 和 `iperf3`。当系统工具不可用时：

- Ping、Traceroute 和 MTR 可使用 Agent 内置的 Go 实现
- NextTrace 可从官方 GitHub Release 下载，并校验 SHA-256
- iPerf3 可使用 Controller 提供的静态构建版本

Agent 还负责下载测速、节点心跳、配置同步、TLS 服务和自身更新。节点使用一次性 Init Token 注册，注册成功后换取独立的节点 Token。Agent 会验证 Controller 下发的签名配置和更新包。

常用维护命令：

```bash
hlg-agent doctor
hlg-agent deps check
hlg-agent upgrade --check
hlg-agent upgrade
```

完整的安装、Docker 部署、依赖管理、服务管理和更新说明请参阅：

- **[Agent 中文文档](agent/README.zh-CN.md)**
- [Agent English Documentation](agent/README.md)

---

## 快速开始

推荐将 Controller 部署到 **Cloudflare Workers**，并使用仓库自带的 GitHub Actions 工作流完成构建和发布：

1. 创建 Cloudflare D1 数据库
2. 配置 GitHub Environment
3. 运行 `Deploy Worker` 工作流
4. 打开 `/admin` 完成首次初始化
5. 创建节点，并在目标服务器上运行生成的 Agent 安装命令

---

## 部署 Controller

### GitHub Actions + Cloudflare Workers

仓库中的 [`.github/workflows/deploy-worker.yml`](.github/workflows/deploy-worker.yml) 会运行测试、构建 Controller 和前端、生成 Agent 发布资源、构建静态 iPerf3，并部署到 Cloudflare Workers。

#### 1. 创建 D1 数据库

可以在 Cloudflare 控制台中创建，也可以使用 Wrangler：

```bash
npx wrangler d1 create looking-glass-db
```

保存命令返回的 D1 Database ID。

#### 2. 配置 GitHub Environment

在仓库的 **Settings → Environments** 中创建名为 `cloudflare-env` 的 Environment。

添加以下 **Secrets**：

| 名称 | 用途 |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID |
| `CLOUDFLARE_API_TOKEN` | 具有 Workers 和 D1 编辑权限的 API Token |
| `D1_DATABASE_ID` | D1 Database ID |
| `WORKER_NAME` | Worker 名称 |
| `D1_NAME` | D1 数据库名称 |

添加以下 **Variables**：

| 名称 | 用途 |
| --- | --- |
| `WORKER_CRONS` | 可选；后台任务的五字段 Cron 表达式，默认每 30 分钟运行一次 |

将 `WORKER_CRONS` 设为 `none` 可以禁用后台任务，但证书续期、证书同步提醒、数据清理和节点可用性巡检也会同时停止。

#### 3. 部署

进入 **Actions → Deploy Worker → Run workflow**。工作流完成后，打开 Worker 的 `/admin` 页面继续初始化。

---

## iPerf3 构建

Controller 的完整构建会生成 Linux `amd64` 和 `arm64` 静态 iPerf3，供缺少可用 `iperf3` 的 Agent 使用。

构建脚本使用 ESnet 官方 iPerf3 3.21 源码，并固定 SHA-256。主要编译选项为：

```text
--enable-static-bin
--disable-shared
--enable-static
--disable-dependency-tracking
--without-openssl
--without-sctp
```

构建完成后，脚本还会检查二进制是否包含动态链接解释器，并实际运行客户端与服务端测试。

```bash
# 构建全部 iPerf3 资源
pnpm build:iperf3

# 完整 Cloudflare 构建（包含 Agent 和两个架构的 iPerf3）
pnpm build:cf
```

---

## 本地部署到 Cloudflare Workers

如果不使用 GitHub Actions，也可以从本地构建并部署。

### 环境要求

- Node.js 26.9 或更高版本
- pnpm 12.7
- Go 1.26 或更高版本
- Docker 和 Docker Buildx
- Cloudflare Account、D1 数据库，以及具有 Workers 和 D1 编辑权限的 API Token

Docker Buildx 用于生成不同架构的 iPerf3 资源。

### 1. 安装依赖并创建 D1

```bash
pnpm install --frozen-lockfile
pnpm -C controller exec wrangler d1 create looking-glass-db
```

### 2. 创建部署配置

```bash
cp .env.cloudflare.example .env.cloudflare
```

填写：

```text
WORKER_NAME
D1_NAME
D1_DATABASE_ID
WORKER_CRONS
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
```

`WORKER_CRONS` 可以省略，此时默认每 30 分钟运行一次；也可以设为 `none`。

### 3. 构建并部署

```bash
pnpm build:cf
pnpm deploy:cf
```

`pnpm deploy:cf` 会根据 `.env.cloudflare` 生成 Wrangler 配置并发布 Worker。

---

## Cloudflare Workers 证书说明

Controller 支持集中管理 Agent TLS 证书，包括：

- Agent 自签名证书
- 手动导入证书
- 使用 DNS-01 的 ACME 自动签发和续期

> [!NOTE]
> Cloudflare Workers 环境下访问 Let's Encrypt ACME 服务会发生连接错误，无法完成自动签发。可以改用 ZeroSSL（支持通过邮箱申请 EAB 凭据）、Google Trust Services 或自定义 ACME 服务。也可以继续使用 Agent 自签名证书，或在 `/admin` 中手动导入证书。

---

## Docker 自托管

Controller 也可以通过 Docker 自托管，并使用 SQLite 保存数据。

> [!NOTE]
> Docker Controller 目前作为兼容部署方式维护，尚未经过完整的生产环境验证。

### 1. 创建配置

```bash
cp .env.local.example .env.local
```

建议设置对外访问地址：

```text
LG_PUBLIC_ORIGIN=https://lg.example.com
```

如果 Controller 位于你控制的反向代理之后，再启用：

```text
LG_TRUST_PROXY=1
```

有关代理跳数、客户端 IP 请求头和可信代理网段的配置，请查看 [`.env.local.example`](.env.local.example)。反向代理必须覆盖客户端传入的转发请求头，并限制外部直接访问源站端口。

### 2. 启动

```bash
LG_BUILD_ID="$(git log -1 --format=%h -- agent 2>/dev/null || echo latest)" \
  docker compose --env-file .env.local up -d --build
```

Compose 默认将 Controller 绑定到 `127.0.0.1:8787`，并把 SQLite 数据保存在 `lg-data` 命名卷中。

### 3. 配置反向代理

使用 Nginx、Caddy 或其他 HTTPS 反向代理将流量转发到 `127.0.0.1:8787`，并启用 WebSocket 转发。

---

## 初始配置

Controller 部署完成后，打开：

```text
https://your-looking-glass.example/admin
```

然后：

1. 初始化数据库并创建第一个管理员
2. 配置站点信息和签名密钥
3. 按需配置节点域名、Turnstile、证书和安全选项
4. 在节点管理中创建 Agent 节点
5. 将生成的一次性安装命令复制到目标服务器执行

Agent 注册成功后，节点会出现在管理后台和 Looking Glass 页面中。Agent 的安装参数与运维说明请参阅 [Agent 中文文档](agent/README.zh-CN.md)。

---

## 更新

### GitHub Actions

重新运行 **Actions → Deploy Worker → Run workflow**。

### Cloudflare Workers 本地部署

```bash
git pull
pnpm install --frozen-lockfile
pnpm build:cf
pnpm deploy:cf
```

更新后打开 `/admin`，按提示应用数据库迁移。

### Docker

```bash
git pull
LG_BUILD_ID="$(git log -1 --format=%h -- agent 2>/dev/null || echo latest)" \
  docker compose --env-file .env.local up -d --build
```

---

## 技术

| 组件 | 技术 |
| --- | --- |
| Controller | TypeScript |
| Agent | Go |
| Cloud Deployment | Cloudflare Workers |
| Cloud Database | Cloudflare D1 |
| Self-hosted Deployment | Docker |
| Self-hosted Database | SQLite（`node:sqlite`） |
| Agent Communication | HTTPS / TLS |
| Configuration / Update Signing | Ed25519 |
| Certificate Management | ACME / DNS-01 |
| MTR ASN Lookup | Team Cymru Bulk Whois |
| Route Testing | Ping / Traceroute / MTR / NextTrace |
| Throughput Testing | iPerf3 |

---

## 项目架构

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

Controller 是 HLG 的控制面，负责：

- 提供 Web 前端和 API
- 管理 Agent 注册、鉴权、心跳和版本
- 授权并转发网络测试任务
- 下发签名配置与发布资源
- 管理 TLS 证书和后台定时任务

Controller 可以运行在 Cloudflare Workers + D1，或 Docker + SQLite 上。

### Agent

Agent 部署在实际网络节点上，负责执行 Ping、Traceroute、MTR、NextTrace、iPerf3 和下载测速，并处理 TLS、配置同步、心跳和更新。

一个 Controller 可以统一管理多个地区、网络和运营商下的 Agent 节点。更多实现和运维说明请参阅 [Agent 中文文档](agent/README.zh-CN.md)。
