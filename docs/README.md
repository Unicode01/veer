# Veer 使用指南

Veer 是一个面向虚拟机宿主机和二级路由场景的可编程 Linux 网络转发服务。它用 Go 编写，内置 Web UI、管理 API、SQLite 持久化和 Linux 内核 dataplane，可把端口转发、共享建站、端口范围、Egress NAT、托管网络、IPv6 分发和运行时诊断统一收敛到一个进程里管理。

开发者 API 见 [API.md](API.md)，安全边界见[安全建议](#安全建议)。下列源码构建、脚本与测试命令均在仓库根目录执行。

## 一键部署

Linux 服务器推荐直接使用一键引导脚本。请先进入 root shell（例如执行 `sudo -i`），并确认宿主机正在运行 systemd 或 OpenRC；容器或 chroot 中没有可用服务管理器时不能完成整套部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
```

如果 GitHub Raw 不通：

```bash
tmpdir="$(mktemp -d)" && \
curl -fsSL https://codeload.github.com/Unicode01/veer/tar.gz/refs/heads/main | tar -xzf - --strip-components=1 -C "$tmpdir" && \
bash "$tmpdir/bootstrap.sh"
```

Alpine 的默认 shell 是 ash，首次安装请先准备 Bash、curl 和证书，再使用不依赖进程替换的入口：

```sh
apk add --no-cache bash curl ca-certificates
bootstrap_file="$(mktemp)" && \
curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh -o "$bootstrap_file" && \
bash "$bootstrap_file"
rm -f -- "$bootstrap_file"
```

常用部署参数：

```bash
VEER_REF=main bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
WEB_BIND=0.0.0.0 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
WEB_UI_ENABLED=false bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
READY_TIMEOUT_SECONDS=180 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
VEER_INSTALL_PLUGINS=1 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh) -- --no-inherit-stats
```

`WEB_BIND=0.0.0.0` 会让管理面接受远程连接，但 Veer 本身只提供 HTTP。仅应在受信管理网或 VPN 内使用；公网访问应保持 Veer 监听回环地址，并由启用 TLS 与访问控制的反向代理转发。对新建非回环配置、首次从回环地址改为远程监听，或在远程监听下显式更换令牌，`deploy.sh` 要求 `web_token`（以及非空的 `plugin_admin_token`）至少包含 24 个字符，一键部署生成的 32 字符随机令牌已满足要求。Veer 运行时为兼容既有及手工管理的配置，只会对远程监听下的短令牌输出安全警告而不会拒绝启动；应安排轮换，但不要在未同步更新 WHMCS/API 客户端时直接更换。

`bootstrap.sh` 会安装依赖、拉取源码、执行 `release.sh` 构建，再调用 `deploy.sh` 安装或热更新。默认只构建和安装 Veer 核心；设置 `VEER_INSTALL_PLUGINS=1` 才会构建并安装 bundled stable 插件。它支持 `apt`、`dnf/yum`、`apk` 以及 systemd/OpenRC。中国大陆网络环境下会自动优先使用可用的 Go 镜像和 Go module 代理。

从更名前的 `main` 版本升级时，`deploy.sh` 会把默认目录 `/opt/forward` 迁移到 `/opt/veer`，将服务切换为 `veer.service`，并保留 `/opt/forward`、`forward` 二进制名和 `forward.service` 兼容入口。现有 `forward.db`、内核状态目录和配置文件不会改名；旧 `FORWARD_*` 部署变量仍可使用，同时设置时 `VEER_*` 优先。

需要手动部署时：

```bash
./release.sh amd64
scp veer-linux-amd64 deploy.sh config.example.json root@server:/tmp/
ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'
```

需要插件时额外上传 `veer-plugins.tar.gz`，并以 `VEER_INSTALL_PLUGINS=1 ./deploy.sh` 部署。安装插件文件与启用插件相互独立，升级时未请求安装不会删除或覆盖现有插件目录。

部署默认把 `/opt/veer/veer` 链接为 `/usr/local/bin/veer`，之后可直接运行 `veer help`、`veer version`、`veer kfuncs status` 和 `veer plugin ...`。已有同名普通文件时不会覆盖，只给出警告；`VEER_LINK_CLI=0` 不创建链接，并移除此前为本安装创建的链接；`VEER_CLI_LINK_DIR` 可改为其他绝对路径目录。RHEL 系列 sudo 的 `secure_path` 默认不含 `/usr/local/bin`，可在 root shell 中运行或写完整路径。`plugin backup/restore/migrate-vpn` 在当前目录没有 `forward.db` 时，自动使用可执行文件所在安装目录的数据库和配置里的 `plugins_dir`。未知子命令会直接报错退出，不会误启动第二个 daemon。

部署后默认访问：

```text
http://127.0.0.1:8080
```

本机探针：

```text
http://127.0.0.1:8080/healthz
http://127.0.0.1:8080/readyz
```

## 适用场景

Veer 适合把 Linux 宿主机作为 VM/容器的默认转发器或二级路由，统一管理入口、出口和下联网络。

典型场景：

- Proxmox VE、KVM、Linux bridge、veth/tap 等宿主机网络
- 公网端口、端口段转发到 VM 或容器
- 多台 VM 共享宿主机 TCP `80/443`，并可选共享 UDP `443` 的 QUIC/HTTP/3，按域名回源
- 下联 bridge 的 IPv4 DHCP、静态保留、IPv6 分发和 Egress NAT
- `userspace / TC / XDP` 多 dataplane 转发与自动回退

## 功能概览

核心功能：

- 单端口转发：TCP、UDP、TCP+UDP
- 共享站点：HTTP/HTTPS 共享入口，可选 QUIC/HTTP/3，按域名转发到不同后端
- 端口范围：连续端口区间映射到指定后端
- Egress NAT：按父接口、子接口、出接口、源地址管理出向 NAT；单个子接口可按协议覆盖父接口默认出口，其余接口继续继承默认出口
- 托管网络：创建或托管 existing bridge，维护 IPv4 DHCP、保留地址、自动 Egress NAT
- IPv6 分发：向目标接口下发 `/128` 或 `/64`
- 诊断页：Kernel Runtime、Worker 状态、规则/站点/范围/Egress NAT 统计

配套能力：

- Web UI 和 Bearer Token API
- SQLite 配置与状态持久化
- Worker 热重载和 draining
- TC/XDP 内核态热更新、状态观测和异常恢复
- Goja 控制面与 TC eBPF pipeline 插件系统
- WHMCS addon 插件

共享站点的 QUIC 开关默认关闭。启用后，Veer 会监听同一入口 IP 的 UDP `443`，从 QUIC v1/v2 Initial 中解析 TLS SNI，再把原始数据报转发到 `backend_https_port`；Veer 不终止 TLS，也不替后端校验证书。`deploy.sh` 不会为这个可选功能自动开放 UDP `443`；启用前需确认防火墙允许该端口、后端在同一端口提供 QUIC/HTTP/3，且没有普通 UDP 规则或端口范围占用该监听地址。使用 UFW 时可执行：

```bash
ufw allow 443/udp
```

ECH 隐藏实际 SNI、QUIC 连接迁移，以及同一客户端端点复用多条连接时的未知 CID 轮换目前不在支持范围内。

明文 HTTP 的每个 keep-alive 请求都会重新检查 Host 并清除客户端提供的来源转发头，支持流式响应和 Upgrade。HTTPS 支持跨 TLS record 的 ClientHello，但路由缓冲总量限制为 64 KiB，单个 record 限制为 16 KiB。

## 推荐部署

生产建议：

- 运行在 Linux 上
- 默认把管理面绑定到 `127.0.0.1`
- 内核 dataplane 优先使用 `TC`
- 默认 `kernel_engine_order` 为 `["tc"]`
- `XDP` 只在目标拓扑验证通过后显式加入启用

典型 VM 宿主机拓扑：

```text
公网
  |
  | 203.0.113.10
  |
宿主机
  ├─ eth0              上联/公网接口
  └─ vmbr0             下联/VM bridge，198.51.100.1/24
       ├─ VM-A         198.51.100.10
       └─ VM-B         198.51.100.20
```

典型规则：

```text
in_interface  = eth0
in_ip         = 203.0.113.10
in_port       = 2222
out_interface = vmbr0
out_ip        = 198.51.100.10
out_port      = 22
protocol      = tcp
```

典型 Egress NAT：

```text
parent_interface = vmbr0
child_interface  = tap100i0
out_interface    = eth0
out_source_ip    = 203.0.113.10
protocol         = tcp+udp+icmp
nat_type         = symmetric
```

## 本地开发启动

本地运行：

```bash
cp config.example.json config.json
```

PowerShell：

```powershell
Copy-Item config.example.json config.json
```

修改 `config.json`：

- `web_token` 必须填写真实随机值
- 不能继续使用 `change-me-to-a-secure-token`

启动：

```bash
go run .
```

访问：

```text
http://127.0.0.1:8080
```

API 认证：

```text
Authorization: Bearer <web_token>
```

## 配置

完整示例见 [config.example.json](../config.example.json)。使用指南不再复制整份 JSON，避免示例配置和实际默认值漂移。

关键字段：

- `web_bind`：Web UI / API 监听地址，默认 `127.0.0.1`
- `web_ui_enabled`：是否启用静态 Web UI；关闭后仍保留 `/api/*`、`/metrics`、`/debug/pprof/`、`/healthz`、`/readyz`
- `web_port`：监听端口
- `web_token`：Web UI 和 API 共用的 Bearer Token
- `default_engine`：`auto`、`userspace`、`kernel`
- `kernel_engine_order`：Linux 内核引擎尝试顺序；省略时默认 `["tc"]`
- `managed_network_auto_repair`：托管网络链路变化后的自动修复
- `plugins_enabled`：是否扫描并运行外部插件；默认关闭，必须手动设为 `true` 才会启动外部插件控制面；内置 `veer_core` 始终可见
- `plugins_dataplane_enabled`：是否允许外部插件进入 TC 数据面；默认关闭，当前支持按 priority 围绕 `Veer Core` 排序的 forward/reply TC 链
- `plugins_isolation`：是否让每个插件控制 VM 和命名 Worker 运行在独立子进程；默认开启，仅受信任的本地调试才应关闭
- `plugins_min_sandbox_level`：插件 Host 最低隔离等级，允许 `none`、`minimal`、`partial`、`full`；默认 `full`，达不到时在执行插件 JavaScript 前拒绝启动
- `plugins_remote_install_enabled`：是否开放远程插件安装、更新、回滚、卸载、仓库/信任管理和代码重载；默认关闭，WebUI 同步隐藏入口。关闭时可向本地受信任插件授予 `exec` 权限；开启后禁止 exec。只能在本机修改配置并重启生效，插件页面和资源/动作访问不受该开关影响
- `plugins_require_signed_packages`：是否要求插件包带可独立验证的 Ed25519 签名；默认开启。首次出现的发布者可直接在安装审核中确认，无需预先维护信任列表；开发环境可显式关闭后审批未签名包
- `plugin_admin_token`：插件安装、信任、启停和热加载使用的独立高权限令牌；留空时相关写 API 禁用，非空时必须不同于 `web_token`
- `plugins_max_installed` / `plugins_max_staged` / `plugins_storage_limit_mb`：插件安装数、暂存数和插件持久状态总量上限；`plugins_repository_refresh_minutes` 控制同时启用插件和远程安装后 TUF 元数据的后台刷新周期
- `plugins_enabled=true` 时，`lab` / `preview` / `stable` 插件可执行控制脚本；进入外部 TC 数据面仍需同时开启 `plugins_dataplane_enabled`；`deprecated` 插件始终禁用
- `plugins_dir`：运行时插件目录，默认 `plugins`
- `kernel_rules_map_limit`：内核规则 map 容量，`0` 表示自适应
- `kernel_flows_map_limit`：内核 flow map 容量，`0` 表示自适应
- `kernel_tcp_established_idle_timeout_seconds`：内核已建立 TCP flow 的空闲超时；`0` 表示按 IPv4/IPv6 flow map 的最高利用率自动选择，正数表示固定秒数。auto 在利用率达到 50% / 70% / 85% 时依次采用 6 小时 / 1 小时 / 10 分钟，低负载采用 24 小时；回落阈值分别为 45% / 65% / 80%，避免临界点抖动
- `kernel_nat_ports_map_limit`：内核 NAT 端口 map 容量，`0` 表示自适应
- `kernel_nat_port_min` / `kernel_nat_port_max`：内核 Full NAT 临时端口池
- `experimental_features`：实验特性开关，默认都应保持关闭，按需验证后再开

## Dataplane

Veer 有三条主要 dataplane：

- `userspace`：兼容面最广，作为最终回退路径
- `tc`：当前推荐的 Linux 内核主线路径
- `xdp`：路径更短，但对网卡、bridge/veth/tap、attach mode 更敏感

引擎选择：

- `default_engine = userspace`：全部走用户态
- `default_engine = kernel`：优先内核态，失败后按规则回退
- `default_engine = auto`：自动选择可用路径
- Linux 下会按 `kernel_engine_order` 尝试内核引擎

用户态转发有进程级资源保护：Linux 的监听数和同时处理的 TCP 连接数分别限制为 `min(1024, RLIMIT_NOFILE / 8)`，以保留后端连接和控制通道的文件句柄空间。范围的 TCP+UDP 每端口占两个监听名额；超过预算的内核回退会报告错误，不会继续创建大量 socket。内核 flow 容量不受这一用户态限制影响。

进入内核态通常需要：

- Linux 上具备 eBPF/TC/XDP 能力
- 规则的入口接口和出口接口可解析
- 后端地址和出接口可达
- Full NAT / Egress NAT 可得到可用源地址，或显式配置 `out_source_ip`
- 规则类型在当前内核路径支持范围内

TC 与 XDP 选择建议：

- `TC` 更适合 bridge、tap、veth、PVE 等宿主机场景
- `XDP` 可用但应按目标拓扑单独验证
- `xdp_generic` 默认关闭；veth/tap/netns 测试拓扑通常需要显式启用
- `bridge_xdp`、`kernel_tc_*` 系列开关都属于实验路径

## 托管网络

托管网络有两种模式：

- `create`：由 Veer 动态创建 bridge
- `existing`：托管宿主机已有 bridge

当前能力：

- IPv4 DHCP
- IPv4 静态保留
- IPv6 `/128` 或 `/64` 分发
- 自动 Egress NAT
- 链路变更自动修复
- PVE `qemu-server` / `lxc` 配置识别
- PVE guest 链路识别与修复，覆盖 `fwpr*`、`tap*`、`veth*`

PVE 建议：

- 更推荐托管已有 bridge
- 动态创建的 bridge 不一定会被 PVE UI 当作可配置网络
- `create` 模式可以持久化到 `/etc/network/interfaces`，写入前会创建备份
- bridge 持久化面向 ifupdown/PVE 环境，不是通用网络管理器

## IPv6 分发

IPv6 分发用于给指定接口下发 `/128` 或 `/64`：

- `/128` 更适合精确分配给单个 VM 或接口
- `/64` 更适合让下游继续分发，但需要明确下游是否可信
- DHCPv6/RA 负责地址下发，不等于强制防伪造
- 如需强约束地址使用，应在链路层、bridge、hypervisor、nftables/TC 或上游路由策略上配合

## 运行时诊断

Web UI 的诊断页和 `GET /api/kernel/runtime` 可查看：

- 当前默认引擎与配置顺序
- TC/XDP active entries
- attach 状态和 attach mode
- map 占用、容量、自适应配置
- degraded / pressure / retry / self-heal 状态
- Worker 状态和 runtime error
- 规则、站点、范围、Egress NAT 统计

主进程 CPU、内存或 goroutine 异常时，可用 `/debug/pprof/` 采样（需要 Bearer Token，用法见 [API](API.md) 中的 `GET /debug/pprof/`）。

热更新与异常退出：

- `deploy.sh` 热更新时会尝试交接活动的 userspace rule/range/shared-proxy worker；无法交接的 worker 会由新进程重建
- shared-proxy 二进制更新会关闭旧 QUIC/UDP 监听和中继会话，QUIC 客户端可能需要重连；TCP 已建立连接可以排空，不能据此推断 QUIC 同样无损交接
- TC/XDP 路径会尽量继承内核 flow / NAT / stats 状态；使用 `--no-inherit-stats` 时 stats 会重新累计
- 交接期间旧进程的 tail-call 链会被 pin 住，Full NAT、Egress NAT 和插件阶段在新进程接管前继续生效；XDP 插件 Dispatcher 在 Linux 5.7+ 上由新进程原子替换
- 新版本启动、重启或 `/readyz` 检查失败时，已有安装会自动回滚二进制、配置、服务定义和本次部署替换的 bundled plugins
- 自动回滚不恢复 SQLite 数据库，也不恢复任意外部插件产生的状态；部署前服务原本未运行时只回滚文件，不会自动启动旧版本
- 上述机制以尽量不断流为目标，不是绝对零中断承诺
- 如果进程被 `kill -9`、OOM kill 或异常崩溃，内核附加点可能短时间继续存在
- 下次启动会尝试识别并清理 orphan 附加点

## 插件层

`release.sh` 会把 `wan_core`、`lan_core`、`vtolocal` 和 `pppoe_client` 四个 stable 插件打成可选包；部署默认不安装插件，设置 `VEER_INSTALL_PLUGINS=1` 才会安装。安装后仍需手动设置 `plugins_enabled=true` 才会运行插件控制面，进入 TC 数据面还需设置 `plugins_dataplane_enabled=true`。`packet_observer`、`router_wizard` 与 [vpn_core](plugins/vpn_core/README.md) 仍是源码内的 lab 插件，不进入默认发布包。VPN 示例支持内核 WireGuard、Mihomo、sing-box 和外部 TUN，通过 WAN Core 边界和双向 TC 适配器接入核心：支持 ingress 交接的 helper 使用单接口边界，其余环境使用 veth 兼容路径，内部 peer 对普通界面隐藏。现有 LAN/出向 NAT 可选择隧道出口，无需关闭快速 NAT。插件架构、开发接口和边界说明见 [PLUGIN.md](PLUGIN.md)。

## 平台与依赖

PPPoE/WireGuard 可选择编译 [内核扩展](KERNEL.md)，为 TC 提供 GSO 分段和 skb 头部处理能力。默认构建与部署不加载该模块；增强构建需要匹配目标内核的 `.ko`，能力探测失败时使用基础路径。构建、生命周期和实测数据见该指南。

推荐运行环境：

- Debian 11+
- Ubuntu 22.04+
- RHEL-compatible 9+
- Fedora 38+
- Alpine 3.19+
- Proxmox VE 7+，更推荐 PVE 8+

最终以宿主机实际内核版本和 eBPF 能力为准，不只看发行版版本号。旧内核可能只能运行用户态路径，或无法稳定使用内核 dataplane。默认 full 插件沙箱还要求 cgroup v2 提供 `cpu`、`memory`、`pids` controller；不满足时核心仍可运行，但外部插件会被拒绝启动。

引导脚本同时安装 nftables 和 iptables：透明用户态转发目前仍需要 iptables 的 socket match 与 mangle MARK 支持，不能只安装 nftables。systemd 与 OpenRC 部署均设置 65535 的文件句柄上限。systemd 保留 `ProtectSystem=strict`，插件 namespace 的创建和删除由父进程进入宿主挂载空间执行，以保留跨服务重启的命名 namespace；打开该句柄需要父进程具有 `CAP_SYS_PTRACE`，插件子进程不继承此权限。

OpenRC 部署会在 cgroup 尚未挂载时启动并启用系统的 `cgroups` 服务；每次启动将 Veer 与 supervisor 分配到不同子组，供插件启用 cpu/memory/pids 资源隔离。热更新保留的 worker 不会被移动或清理；停止服务时只移除空 cgroup。已有的 cgroup 挂载与 controller 配置不会被重新挂载或替换。

两种服务管理器每次启动都会准备 `/run/netns`、bpffs 与状态目录，确保重启系统后仍可启动。systemd 用前置服务准备宿主目录与挂载，Veer 主进程继续使用上述文件系统保护。

托管网络的运行时桥使用 netlink，跨上述发行版可用；“持久化桥”目前只写 `/etc/network/interfaces`。RHEL/Fedora 默认使用 NetworkManager 时，应由 `nmcli` 或发行版网络配置管理宿主桥。

构建要求：

- Go 1.26.10+
- `clang`
- Debian/Ubuntu 通常需要 `linux-libc-dev`
- RHEL-compatible/Fedora 通常需要 `kernel-headers`

运行内核 dataplane、透明转发或低位端口可能需要：

- `CAP_NET_BIND_SERVICE`
- `CAP_NET_RAW`
- `CAP_NET_ADMIN`
- `CAP_BPF`
- `CAP_PERFMON`

## 构建与测试

本地构建：

```bash
go build -o veer .
```

交叉构建 Linux 二进制：

```bash
./release.sh
```

只构建指定架构：

```bash
./release.sh amd64
./release.sh arm64
```

`release.sh` 会先编译并嵌入 core eBPF 对象，同时生成可选的 `veer-plugins.tar.gz` 和独立开发者产物 `veer-plugin-sdk.tar.gz`：

- `internal/app/ebpf/forward-tc-bpf.o`
- `internal/app/ebpf/forward-tc-bpf-stats.o`
- `internal/app/ebpf/forward-xdp-bpf.o`
- `internal/app/ebpf/forward-xdp-bpf-stats.o`
- `internal/app/ebpf/plugin-xdp-dispatcher-bpf.o`

TC 与 XDP 源码完全相同的辅助函数放在 `internal/app/ebpf/include/forward_common.h`，两个 dataplane 都在各自的 map 与前置声明之后包含它；修改其中任一函数会同时影响两个对象。只在一侧需要或两侧实现不同的函数仍留在各自的 `.c` 文件中。

只重建 eBPF object 时可使用：

```bash
sh scripts/build-ebpf.sh
sh scripts/build-plugin-ebpf.sh
sh scripts/build-all-ebpf.sh
sh scripts/verify-plugin-manifests.sh
sh scripts/package-plugins.sh
```

发布构建优先使用 `release.sh`。上面的脚本仅用于开发时单独重建 eBPF、校验插件或生成插件运行时包。

常规测试：

```bash
sh scripts/build-all-ebpf.sh  # fresh clone 或清理过 .o 后先执行一次
go test ./...
```

插件发布使用 `sh scripts/verify-plugin-release.sh portable`；root Linux 的完整验收与性能门槛见 [PLUGIN.md](PLUGIN.md#验收边界)。

兼容性门槛包括：Debian 11、Ubuntu 22.04、Rocky Linux 9、Alpine 3.19 和当前 Fedora 容器中的真实依赖安装与 release 构建；Ubuntu amd64/arm64 原生 Linux 测试和 core dataplane；实际部署 unit 下命名 namespace 的创建、跨服务退出保留、重启复用和删除。容器只验证发行版用户环境与编译器。

CI 另外启动官方 Alpine 3.19.8 和 Rocky Linux 9.8 云镜像的 QEMU VM，使用各自默认内核验证实际安装、热更新、崩溃恢复、开机启动、插件沙箱与 TC/XDP 的 IPv4/IPv6 转发和 egress NAT；Alpine 验证 OpenRC 及保留 worker 时的 cgroup 隔离，Rocky 全程保持 SELinux enforcing。镜像固定版本并校验摘要，关键测试被跳过会使验收失败，串口与测试日志保留为 CI artifact。这些结果只覆盖所列镜像与默认策略，自定义内核或 SELinux 策略仍需单独验收。

在装有 QEMU、genisoimage 和 OpenSSH 的 Linux 主机上可复现 VM 验收（可用时使用 KVM，否则使用 TCG）：

```bash
sh scripts/build-all-ebpf.sh
CGO_ENABLED=0 go build -o /tmp/veer-vm-binary .
CGO_ENABLED=0 go test -c -o /tmp/veer-vm.test ./internal/app
python3 scripts/verify-qemu-platform.py alpine --binary /tmp/veer-vm-binary --test-binary /tmp/veer-vm.test
python3 scripts/verify-qemu-platform.py rocky --binary /tmp/veer-vm-binary --test-binary /tmp/veer-vm.test
```

最低兼容版本不代表发行版仍受上游安全维护，生产环境应选择仍在维护的版本。[Debian 11 的官方 LTS 已于 2026-08-31 结束](https://www.debian.org/releases/bullseye/)；其 CI 容器仅使用 archive.debian.org 上 LTS 结束后冻结的归档源验证旧版用户环境，安装脚本不会替用户修改 apt 源。RHEL-compatible 系统会保留已安装的 `curl-minimal` / `coreutils-single`，避免与完整版软件包冲突。

## WHMCS 插件

WHMCS addon 插件源码位于：

```text
whmcs/forward/
```

部署到 WHMCS：

```text
modules/addons/forward/
```

最少配置：

- `默认 Veer API 地址`
- `默认 Veer Bearer Token`，对应 `config.json` 的 `web_token`
- `默认入口 IP`，或按宿主机配置 `server_ip_server_map`

多宿主机场景建议配置：

- `server_ip_server_map`
- `api_server_map`
- `allowed_product_ids`
- 按产品配置端口规则和共享站点上限

客户同步、暂停、恢复和终止操作只同步已有客户/服务归属记录，不再按后端 IP 自动认领远端资源。管理员全量同步导入的未绑定资源保持无归属，后续需显式分配；历史重复绑定不会自动选择一个客户。暂停、恢复使用 `/api/rules/enabled` 和 `/api/sites/enabled` 的明确状态接口，请先升级 Veer 服务端再升级 addon；旧服务端不支持该接口时会报错，不回退到可能因重试而反转状态的 `toggle`。

## 安全建议

- 不要提交真实 `config.json`
- 不要泄露 `web_token`
- 管理面默认绑定 `127.0.0.1`，不要无保护暴露到公网
- 如需远程管理，建议放在 VPN、堡垒机、反向代理鉴权或受限管理网后面
- 部署脚本仅在首次交互安装时显示新生成的管理令牌；升级或非交互执行会隐藏令牌，避免写入自动化日志
- WHMCS 插件里的 Veer Bearer Token 与 `web_token` 是同一个认证语义

本文记录 Veer 的信任模型、默认门禁和仍需由部署者承担的边界。

### 信任模型

Veer 是宿主机网络控制面，核心进程需要修改接口、路由、TC/XDP、nftables 与网络命名空间。获得 `web_token` 的主体等同于网络管理员；获得 `web_token` 和 `plugin_admin_token` 的主体还可以安装、信任、启停和更新插件。宿主机 root 始终在信任边界内，Veer 不试图防御 root。

管理 API 不内置 TLS。默认回环监听是安全基线；远程管理必须置于受信管理网、VPN、堡垒机或启用 TLS 和访问控制的反向代理之后。`/healthz` 与 `/readyz` 故意匿名开放，只返回最小存活状态；其余 `/api/*`、`/metrics` 与 `/debug/pprof/` 均需要 Bearer Token。

### 已有门禁

| 边界 | 门禁 | 使用影响 |
| --- | --- | --- |
| 管理面 | 默认 `127.0.0.1`、常量时间令牌比较、失败尝试限速；`deploy.sh` 对新建远程配置、首次从回环地址改为远程监听或在远程监听下显式轮换令牌时要求至少 24 个字符；既有远程配置的短令牌为兼容升级仅告警、不会阻断；无 Cookie/CORS、请求体和 HTTP 超时上限 | 正常请求无感；连续输错令牌会短暂返回 `429`；既有短令牌应安排轮换 |
| 浏览器 | CSP、禁止嵌套、无引用来源、能力策略；插件 UI 在无同源权限的 sandbox iframe 中运行 | 主令牌为保持日常体验保存在 `localStorage`；插件高权令牌仅保存在当前标签页 `sessionStorage` |
| 本地文件 | 配置、SQLite/WAL/SHM、插件密钥与 IPC 默认 `0600/0700`；拒绝敏感路径符号链接 | 权限不安全时启动阶段自动收紧或拒绝 |
| 插件供应链 | 插件默认关闭；包签名、发布者审核、TUF 仓库元数据、摘要复核、原子安装/回滚与配额 | 首次发布者或权限扩张需要一次明确审核 |
| 插件运行时 | 默认独立进程、full sandbox、seccomp/cgroup/资源上限、显式权限与网络 CIDR、Host broker | 宿主机不满足 full sandbox 时拒绝外部插件，不静默降级 |
| 共享站点 | QUIC 默认关闭；UDP 443 与普通规则统一做冲突校验；只解密协议公开的 Initial 以读取 SNI，握手分片、数据报和会话均有数量/字节/空闲上限 | QUIC 仍是 TLS 透传，Veer 不持有站点私钥、不验证后端证书，也不隐藏 SNI |
| WHMCS | 登录会话、CSRF、资源归属、产品/IP/端口/协议/配额校验、输出转义；同一客户创建操作由数据库行锁串行化 | 正常操作无感，并发超额创建会按既定配额拒绝 |

共享 HTTP 按每个请求选择路由并重建来源转发头，不能通过第二个 keep-alive 请求沿用首次检查绕过校验。WHMCS 客户及服务生命周期同步只使用已有归属，后端 IP 匹配不是资源所有权证明；管理员导入的未绑定资源不会自动授予客户。自动暂停、恢复使用幂等的明确状态接口。

### 部署要求

- 使用部署脚本生成的随机令牌，分别保存 `web_token` 与 `plugin_admin_token`，不要复用。
- 不要把 `config.json`、`forward.db*`、`*.veer-secrets.key` 或部署输出上传到工单、日志平台和制品仓库。
- 非回环管理监听不得直接暴露在公网明文链路上。反向代理应自行限制来源并校验证书。
- 只安装来源可信的插件。签名证明发布来源与完整性，不等同于代码安全审计；外部 dataplane 插件会执行受信 eBPF 对象。
- 远程插件安装默认关闭（`plugins_remote_install_enabled=false`）。本地受信任插件可显式声明 `exec`，命令通过父进程以服务权限运行，不受 JS 沙箱、`net_access` 和单插件 cgroup 限制；须保护本地代码和可执行文件并校验远程动作参数。开启远程安装会禁止 exec，并拒绝声明该权限的网络插件包。
- 共享站点启用 QUIC 前，应确认 UDP `443` 已放行且后端同一 HTTPS 端口确实提供 QUIC。ECH 隐藏实际 SNI、连接迁移、复用客户端端点时的未知 CID 轮换和后端 TLS 身份校验不由当前共享代理处理。
- WHMCS 的共享站点功能目前校验客户后端 IP 归属，但不证明客户拥有所填写的域名。多租户环境应在开放该功能前增加业务侧域名验证，或仅向可信客户开放。

### 保留风险与后续门禁

1. Web 主令牌保存在 `localStorage` 以避免每次打开面板都重新输入。当前通过无第三方脚本、DOM 文本构造、CSP 和插件 iframe 隔离降低 XSS 风险；未来若引入任何第三方前端代码，必须先改为短期会话凭据或受保护的认证代理。
2. 核心服务仍是高权限网络守护进程。systemd 已限制可写路径和 capability 集，但 `CAP_SYS_ADMIN` 等能力由插件命名空间与网络编排路径需要；应继续拆分可由低权限 broker 承担的操作。
3. WHMCS 域名所有权和跨进程配额分别属于业务授权与并发边界。本次已修复配额竞态；域名验证需要结合实际域名资产来源设计，不能用 DNS 解析结果冒充所有权证明。
4. 稳定性和性能测试需要 root Linux、真实内核能力和可重复的硬件基线，发布前应在专用测试机按发布风险运行 `sh scripts/verify-plugin-release.sh stability` 与 `performance`。`privileged`（插件特权集成与 PPPoE 黑盒）已在 GitHub CI 中以 root 运行，专用测试机上仍可手动复跑。

### 发布门禁

GitHub CI 执行 module 完整性、Go 测试与 race、vet、staticcheck、govulncheck、fuzz、Node 单元测试、Playwright E2E、npm audit、PHP 语法、shellcheck、插件 SDK 合约与确定性打包，并以 root 运行插件特权集成测试与 PPPoE 黑盒（任何测试被跳过即失败）。任何安全门禁变更必须带回归测试，且不能通过静默降级换取通过。

## License

[MIT License](../LICENSE)
