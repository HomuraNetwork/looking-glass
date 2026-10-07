# Homura Looking Glass Agent

[English](README.md) | **简体中文**

`hlg-agent` 是 Homura Looking Glass 的节点端程序。它运行在 Linux 节点上，执行 Ping、Traceroute、MTR、NextTrace、iPerf3 和下载测速，并负责节点注册、配置同步、TLS、心跳及自身更新。

支持 Linux `amd64`（`x86_64`）和 `arm64`（`aarch64`）。项目整体部署与 Controller 配置请参阅[主项目文档](../README.zh-CN.md)。

## 快速安装

推荐在 Controller 管理后台进入 **节点管理 → 添加节点**，复制该节点生成的安装命令。命令格式如下：

```bash
curl -fsSL 'https://lg.example.com/_agent/download?init-key=lginit_xxx' \
  | bash -s -- -k 'lg.example.com/lginit_xxx'
```

请在目标节点上以 `root` 身份运行。Init Token 仅供首次注册使用，不要重复使用或公开。

安装脚本会识别 CPU 架构、下载并校验 Agent，然后调用初始化程序。Agent 随后会注册节点、保存独立的 Node Token、选择探测工具、创建初始 TLS 证书、安装系统服务并启动。

默认路径与监听地址：

| 项目 | 默认值 |
| --- | --- |
| 安装目录 | `/opt/looking-glass` |
| 数据目录 | `/opt/looking-glass/data` |
| HTTPS 监听 | `:443` |
| 服务名称 | `hlg-agent` |

后台同时提供按架构手动下载、SHA-256 校验和初始化步骤，可用于无法执行管道安装脚本的环境。

## 环境要求

- Linux `amd64` 或 `arm64`，推荐使用 systemd 或 OpenRC。
- 默认以 `root` 运行。非 root 运行至少需要 Raw Socket 和低端口绑定权限：

  ```bash
  sudo setcap cap_net_raw,cap_net_bind_service+eip /path/to/hlg-agent
  ```

- Controller 必须能够访问 Agent 的 HTTPS 端口；访客浏览器执行延迟探测时也需要访问该端口。请检查主机防火墙、安全组、上游 ACL 和 NAT 映射。
- 安装 Agent 前应先部署 Controller 并在后台创建节点。

系统版 `ping`、`mtr`、`traceroute` 也必须具有各自所需的权限。

## 初始化

使用 Controller 生成的 Init String 初始化：

```bash
sudo ./hlg-agent init -k 'lg.example.com/lginit_xxxxxx'
```

也可以指定端口：

```bash
sudo ./hlg-agent init -k 'lg.example.com:8443/lginit_xxxxxx'
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--path` | 安装目录，默认 `/opt/looking-glass` |
| `--data-dir` | 数据目录 |
| `--port`, `-p` | HTTPS 端口，是 `--bind :PORT` 的简写 |
| `--bind` | 完整监听地址 |
| `--service` | `auto`、`systemd`、`init.d` 或 `none` |
| `--service-name` | 系统服务名称 |
| `--name`, `--binary-name` | 安装后的二进制名称 |
| `--user` | 已存在的服务用户；初始化程序不会创建用户 |
| `--yes` | 对未指定的选项使用默认值，不交互询问 |
| `--install-deps-yes` | 自动安装所有缺失的运行依赖 |

无人值守安装示例：

```bash
sudo ./hlg-agent init \
  -k 'lg.example.com/lginit_xxxxxx' \
  --path /opt/looking-glass \
  --port 443 \
  --service auto \
  --yes
```

非交互初始化会自动选择可用的工具来源。

## 探测工具

Agent 支持以下工具：

| 工具 | 可用来源 |
| --- | --- |
| Ping | 系统命令、内置 Go 实现 |
| Traceroute | 系统命令、内置 Go 实现 |
| MTR | 系统命令、内置 Go 实现 |
| NextTrace | 系统命令、Agent 管理的下载版本 |
| iPerf3 | 系统软件包、Controller 提供的静态版本 |

自动模式优先使用系统 `PATH` 中的命令；不存在时再使用 Agent 管理的版本或内置实现。实际选择会记录到 `agent.json`，避免每次任务都重新搜索。

### Ping、MTR、MPLS 与 ECMP 能力

| 探测 | IPv4 / IPv6 | 延迟与丢包 | ECMP | MPLS |
| --- | --- | --- | --- | --- |
| Ping | 支持 | 单次 RTT、TTL / Hop Limit、丢包率以及 min/avg/max/mdev | 不适用 | 不适用 |
| 内置 Traceroute | 支持 | 每个响应地址的 RTT | 每跳采样 3 条稳定 UDP 流；多个响应地址标记为 `[ECMP]` | 解析 ICMP 扩展中的 Label、Traffic Class 和 MPLS TTL |
| 系统 Traceroute | 支持 | 每个探针的 RTT | 展示同一跳返回的多个响应地址 | 使用 `-e` 请求显示 ICMP 扩展；Controller 会解析 MPLS 字段 |
| 内置 MTR | 支持 | 持续统计 Loss、Snt、Last、Avg、Best、Wrst | 当前只跟踪一条稳定流，不单独识别 ECMP | 当前不输出 MPLS 栈 |
| 系统 MTR | 支持 | 持续输出 `--split` 统计 | 当前输出管线不标记 ECMP 分支 | 当前命令未启用 MPLS 输出 |

内置 Traceroute 为每条采样流固定源端口和目标端口，使同一条流在不同 TTL 上保持稳定的流哈希；如果同一跳的 3 条流获得多个响应地址，结果会显示 `[ECMP]`。收到 RFC 4884 / RFC 4950 ICMP 扩展时，还会显示类似下面的 MPLS 信息：

```text
[MPLS 404160/TC0/TTL1]
```

这些能力依赖路径中的路由器返回对应 ICMP 响应和扩展。未显示 `[ECMP]` 或 `[MPLS ...]`，只表示本次有限采样没有观察到，不能证明路径中不存在 ECMP 或 MPLS。

### 系统 MTR 的实际命令

任务配置为使用系统 MTR 时，Agent 实际执行：

```bash
# IPv4
TERM=dumb mtr -4 --split -n <target>

# IPv6
TERM=dumb mtr -6 --split -n <target>
```

- `-4` / `-6` 固定地址族。
- `--split` 让结果持续输出，供 Controller 实时转发。
- `-n` 禁止反向 DNS，避免名称查询拖慢或打乱输出。
- `TERM=dumb` 使输出适合非交互终端。

当前系统与内置 MTR 输出都不提供前端所需的 ASN 信息。Agent 只上报 Hop IP 和丢包、延迟等统计值；Controller 随后通过 Team Cymru Bulk Whois 批量查询 ASN、Prefix、Registry、Country 和 AS/BGP Organization，再将补充后的结构化结果发送给前端。

启用私网目标保护时，Agent 会先解析并校验目标，再将选定的 IP 传给探测命令，以避免执行阶段再次解析域名。

如果 MTR 来源配置为 `builtin`，Agent 不会启动外部 `mtr` 进程，而是持续运行内置 Go 探测器。

### 其他系统命令

供排障参考，系统工具模式下的主要调用参数为：

```bash
ping -4 -O -c 5 -W 2 <target>       # IPv6 使用 -6；任务也可请求 10 次
traceroute -4 -n -w 2 -e <target>  # IPv6 使用 -6
nexttrace --ipv4 --map -g en <target> # IPv6 使用 --ipv6
```

### NextTrace

Agent 支持 [NextTrace / NTrace-core](https://github.com/nxtrace/NTrace-core)。下载模式会从 Controller 获取 Release 元数据，下载与当前架构匹配的官方二进制，校验 SHA-256 后保存到数据目录的 `deps/`。Controller 仅接受匹配 `github.com/nxtrace/NTrace-core/releases/` 的下载地址。

### iPerf3

Agent 优先使用节点现有的 `iperf3`，也可以通过系统包管理器安装。无法安装软件包时，可使用 Controller 为 Linux `amd64` 和 `arm64` 提供的静态版本；Agent 会根据依赖 Manifest 校验 SHA-256。

## 工具管理

查看所有工具的有效来源和状态：

```bash
hlg-agent deps check
```

交互配置工具来源：

```bash
sudo hlg-agent deps config
```

也可以非交互指定：

```bash
sudo hlg-agent deps config mtr --source builtin
sudo hlg-agent deps config nexttrace --source download
sudo hlg-agent deps config iperf3 --source system
sudo hlg-agent deps config traceroute --source path --tool-path /usr/local/bin/traceroute
```

`--source` 支持 `auto`、`system`、`builtin`、`download`、`path`、`install` 和 `nothing`；并非每个工具都支持所有来源。修改来源后需重启 Agent，交互模式会询问是否立即重启。

其他命令：

```bash
sudo hlg-agent deps install nexttrace iperf3
sudo hlg-agent deps upgrade
sudo hlg-agent deps builtin ping traceroute mtr
```

## Docker

仓库提供 [Dockerfile](Dockerfile) 和 [compose.yaml](compose.yaml)。在 `agent/` 目录运行：

```bash
mkdir -p /srv/hlg-agent/data

LG_INIT_STRING='lg.example.com/lginit_xxxxxx' \
LG_AGENT_DATA_DIR=/srv/hlg-agent/data \
LG_AGENT_PORT=443 \
docker compose up -d --build
```

Compose 会构建本地镜像 `hlg-agent:local`，加入 `NET_RAW`、`NET_ADMIN` 和 `NET_BIND_SERVICE` Capability，并将宿主机 `${LG_AGENT_PORT:-443}` 映射到容器的 `443`。

容器内数据目录固定为 `/var/lib/hlg`，必须持久化。`LG_INIT_STRING` 只在首次启动且尚无节点身份时使用；以后会读取持久化的 Node Token 和配置。

镜像已包含 `curl`、`iperf3`、`iputils`、`mtr` 和 `traceroute`。NextTrace 等可选工具仍由 Agent 管理。

## TLS 证书

Agent 自身提供 HTTPS。首次初始化时会生成自签名 ECDSA 证书，因此无需预先部署 Nginx 或 Caddy。

Controller 可下发 ACME 签发或手动导入的证书。Agent 将当前证书保存为数据目录中的 `tls.crt` 和 `tls.key`，并在新的 TLS 连接上加载更新后的证书，无需重新安装 Agent。

## 注册、配置与安全

首次注册使用一次性 Init Token。注册成功后，Agent 保存独立的 Node ID 和 Node Token；配置同步、心跳和更新检查都使用节点身份完成。

Controller 下发的运行配置使用 Ed25519 签名。Agent 验证签名后才接受配置，配置内容包括允许的测试类型、任务超时、输出上限、下载限制、iPerf3 会话与端口范围等。不要通过手工修改 `config.json` 绕过这些策略。

Agent 执行任务前还会重新检查目标地址。启用私网保护时，私网地址、无法解析的目标以及不符合地址族要求的目标会被拒绝。

## Agent 更新

检查或安装 Controller 发布的版本：

```bash
hlg-agent upgrade --check
sudo hlg-agent upgrade
```

更新描述包含 Build ID、目标架构、文件大小、SHA-256、Node ID、有效期和 Ed25519 签名。Agent 完成全部校验后才会原子替换当前二进制并重启服务；如果重启失败，会恢复备份版本。

重新安装当前 Build：

```bash
sudo hlg-agent upgrade --force
```

## 健康检查与服务管理

出现安装、配置、证书或探测问题时，先运行：

```bash
hlg-agent doctor
hlg-agent deps check
hlg-agent service status
```

服务控制命令：

```bash
sudo hlg-agent service start
sudo hlg-agent service stop
sudo hlg-agent service restart
```

`--service auto` 会选择 systemd 或 OpenRC。使用 `--service none` 时，Agent 不安装系统服务，需要自行管理 `hlg-agent run` 进程。

## 本地 Probe

`probe` 子命令直接运行 Agent 的内置 Go 探测器，适合验证 Raw Socket 权限和内置实现；它不会读取任务所配置的系统工具来源。

```bash
hlg-agent probe ping 1.1.1.1
hlg-agent probe -6 ping 2606:4700:4700::1111
hlg-agent probe traceroute 8.8.8.8
hlg-agent probe mtr 1.1.1.1
hlg-agent probe -6 mtr 2606:4700:4700::1111
```

默认使用 IPv4。`-4` 与 `-6` 不能同时使用，且本地 Probe 同样需要 `CAP_NET_RAW` 或 root 权限。

要验证系统 MTR 本身，请直接执行前文列出的 `TERM=dumb mtr ...` 命令；要查看 Agent 任务会选择哪个实现，请运行 `hlg-agent deps check`。

## 日志与环境变量

日志等级为 `debug`、`info`、`warn` 或 `error`：

```bash
hlg-agent run --log-level debug
hlg-agent run --log-file /var/log/hlg-agent.log
```

常用环境变量：

| 环境变量 | 说明 |
| --- | --- |
| `LG_CONTROLLER` | Controller 地址 |
| `LG_INIT_STRING` | 首次注册的完整 Init String |
| `LG_INIT_TOKEN` | Init Token |
| `LG_NODE_TOKEN` | Node Token |
| `LG_NODE_ID` | Node ID |
| `LG_BIND` | Agent 监听地址 |
| `LG_DATA_DIR` | 数据目录 |
| `LG_PUBLIC_IPV4` / `LG_PUBLIC_IPV6` | 手动指定上报的公网地址 |
| `LG_FRONTEND_ORIGIN` | 允许的前端 Origin |
| `LG_LOG_LEVEL` / `LG_LOG_FILE` | 日志等级与日志文件 |
| `LG_IPERF_DEBUG_OUTPUT` | 是否向控制 WebSocket 暴露原始 iPerf3 调试事件 |

通常使用后台生成的安装命令时无需手动设置这些变量。

## 本地文件

标准安装将运行记录写入 `/opt/looking-glass/agent.json`，持久化数据保存在 `/opt/looking-glass/data`。Docker 将两者都放在持久化挂载的 `/var/lib/hlg` 中。

| 文件或目录 | 用途 |
| --- | --- |
| `/opt/looking-glass/agent.json` | 本地运行参数、安装布局和工具选择 |
| `<data-dir>/node-token` | 节点鉴权 Token |
| `<data-dir>/config.json` | Controller 下发的签名配置 |
| `<data-dir>/tls.crt` / `tls.key` | 当前 TLS 证书与私钥 |
| `<data-dir>/deps/` | Agent 管理的外部工具 |
| `<data-dir>/deps/deps-manifest.json` | 下载工具的本地完整性记录 |

删除数据目录会丢失节点身份，通常需要在 Controller 中重新生成 Init Token 并注册。操作前请备份。

## 从源码构建

```bash
cd agent
go generate ./internal/licenses
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o hlg-agent ./cmd/hlg-agent
```

交叉编译：

先执行上面的生成步骤。它收集两个 Linux 发布目标实际链接的 Go 运行时和依赖的
完整声明；生成的源码已被 Git 忽略，发布脚本和 Docker 构建会自动执行该步骤。
`hlg-agent licenses` 可以直接输出内嵌声明，无需配置文件、联网或 root 权限。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags='-s -w' -o hlg-agent-linux-amd64 ./cmd/hlg-agent

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags='-s -w' -o hlg-agent-linux-arm64 ./cmd/hlg-agent
```

正式发布还会通过以下链接参数写入 Build ID：

```text
-X hlg/internal/runtime.BuildID=<build-id>
```

## 卸载与命令速查

卸载 Agent：

```bash
sudo hlg-agent uninstall
```

卸载会停止并删除服务以及本地安装文件和数据。需要保留节点身份或证书时，请先备份数据目录。

| 命令 | 说明 |
| --- | --- |
| `hlg-agent init` | 注册、初始化并安装 Agent |
| `hlg-agent run` | 前台运行 Agent |
| `hlg-agent doctor` | 检查安装与运行状态 |
| `hlg-agent service` | 管理系统服务 |
| `hlg-agent deps` | 检查、安装或配置探测工具 |
| `hlg-agent probe` | 直接运行内置网络探测 |
| `hlg-agent upgrade` | 检查或安装 Agent 更新 |
| `hlg-agent uninstall` | 卸载 Agent |
| `hlg-agent version` | 显示版本和 Build ID |
| `hlg-agent licenses` | 输出 HLG 的 MIT 和链接的 Go 依赖、运行时声明 |
| `hlg-agent help` | 显示命令帮助 |
