# Veer

Veer 是一个面向虚拟机宿主机和二级路由场景的可编程 Linux 网络转发服务。它用 Go 编写，内置 Web UI、管理 API、SQLite 持久化和 Linux 内核 dataplane，可把端口转发、共享建站、端口范围、Egress NAT、托管网络、IPv6 分发和运行时诊断统一收敛到一个进程里管理。

开发者 API 见 [API.md](./API.md)。

## 一键部署

Linux 服务器推荐直接使用一键引导脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
```

如果 GitHub Raw 不通：

```bash
tmpdir="$(mktemp -d)" && \
curl -fsSL https://codeload.github.com/Unicode01/veer/tar.gz/refs/heads/main | tar -xzf - --strip-components=1 -C "$tmpdir" && \
bash "$tmpdir/bootstrap.sh"
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

`bootstrap.sh` 会安装依赖、拉取源码、执行 `release.sh` 构建，再调用 `deploy.sh` 安装或热更新。默认只安装 Veer 核心；设置 `VEER_INSTALL_PLUGINS=1` 才会安装 bundled stable 插件。它支持 Debian/Ubuntu 的 `apt`，也支持 RHEL-compatible/Fedora 的 `dnf/yum`。中国大陆网络环境下会自动优先使用可用的 Go 镜像和 Go module 代理。

从更名前的 `main` 版本升级时，`deploy.sh` 会把默认目录 `/opt/forward` 迁移到 `/opt/veer`，将服务切换为 `veer.service`，并保留 `/opt/forward`、`forward` 二进制名和 `forward.service` 兼容入口。现有 `forward.db`、内核状态目录和配置文件不会改名；旧 `FORWARD_*` 部署变量仍可使用，同时设置时 `VEER_*` 优先。

需要手动部署时：

```bash
./release.sh amd64
scp veer-linux-amd64 deploy.sh root@server:/tmp/
ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'
```

需要插件时额外上传 `veer-plugins.tar.gz`，并以 `VEER_INSTALL_PLUGINS=1 ./deploy.sh` 部署。安装插件文件与启用插件相互独立，升级时未请求安装不会删除或覆盖现有插件目录。

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
- 多台 VM 共享宿主机 `80/443`，按域名回源
- 下联 bridge 的 IPv4 DHCP、静态保留、IPv6 分发和 Egress NAT
- `userspace / TC / XDP` 多 dataplane 转发与自动回退

## 功能概览

核心功能：

- 单端口转发：TCP、UDP、TCP+UDP
- 共享站点：HTTP/HTTPS 共享入口，按域名转发到不同后端
- 端口范围：连续端口区间映射到指定后端
- Egress NAT：按父接口、子接口、出接口、源地址管理出向 NAT
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

完整示例见 [config.example.json](./config.example.json)。根 README 不再复制整份 JSON，避免示例配置和实际默认值漂移。

关键字段：

- `web_bind`：Web UI / API 监听地址，默认 `127.0.0.1`
- `web_ui_enabled`：是否启用静态 Web UI；关闭后仍保留 `/api/*`、`/healthz`、`/readyz`
- `web_port`：监听端口
- `web_token`：Web UI 和 API 共用的 Bearer Token
- `default_engine`：`auto`、`userspace`、`kernel`
- `kernel_engine_order`：Linux 内核引擎尝试顺序；省略时默认 `["tc"]`
- `managed_network_auto_repair`：托管网络链路变化后的自动修复
- `plugins_enabled`：是否扫描并运行外部插件；默认关闭，必须手动设为 `true` 才会启动外部插件控制面；内置 `veer_core` 始终可见
- `plugins_dataplane_enabled`：是否允许外部插件进入 TC 数据面；默认关闭，当前支持按 priority 围绕 `Veer Core` 排序的 forward/reply TC 链
- `plugins_enabled=true` 时，`lab` / `preview` / `stable` 插件可执行控制脚本；进入外部 TC 数据面仍需同时开启 `plugins_dataplane_enabled`；`deprecated` 插件始终禁用
- `plugins_dir`：运行时插件目录，默认 `plugins`
- `kernel_rules_map_limit`：内核规则 map 容量，`0` 表示自适应
- `kernel_flows_map_limit`：内核 flow map 容量，`0` 表示自适应
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

热更新与异常退出：

- `deploy.sh` 更新时会尽量继承内核 flow / NAT / stats 状态
- 这是尽量不断流，不是绝对零中断承诺
- 如果进程被 `kill -9`、OOM kill 或异常崩溃，内核附加点可能短时间继续存在
- 下次启动会尝试识别并清理 orphan 附加点

## 插件层

`release.sh` 会把 `wan_core`、`lan_core`、`vtolocal` 和 `pppoe_client` 四个 stable 插件打成可选包；部署默认不安装插件，设置 `VEER_INSTALL_PLUGINS=1` 才会安装。安装后仍需手动设置 `plugins_enabled=true` 才会运行插件控制面，进入 TC 数据面还需设置 `plugins_dataplane_enabled=true`。`packet_observer` 与 `router_wizard` 仍是源码内的 lab 插件，不进入默认发布包。插件架构、开发接口和边界说明见 [PLUGIN.md](PLUGIN.md)。

## 平台与依赖

推荐运行环境：

- Debian 11+
- Ubuntu 22.04+
- RHEL-compatible 9+
- Fedora 38+
- Proxmox VE 7+，更推荐 PVE 8+

最终以宿主机实际内核版本和 eBPF 能力为准，不只看发行版版本号。旧内核可能只能运行用户态路径，或无法稳定使用内核 dataplane。

构建要求：

- Go 1.25.12+
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

`release.sh` 会先编译并嵌入 core eBPF 对象，同时生成 `veer-plugins.tar.gz` 作为 bundled stable 插件包：

- `internal/app/ebpf/forward-tc-bpf.o`
- `internal/app/ebpf/forward-tc-bpf-stats.o`
- `internal/app/ebpf/forward-xdp-bpf.o`
- `internal/app/ebpf/forward-xdp-bpf-stats.o`

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

## 安全建议

- 不要提交真实 `config.json`
- 不要泄露 `web_token`
- 管理面默认绑定 `127.0.0.1`，不要无保护暴露到公网
- 如需远程管理，建议放在 VPN、堡垒机、反向代理鉴权或受限管理网后面
- WHMCS 插件里的 Veer Bearer Token 与 `web_token` 是同一个认证语义

## License

[MIT License](./LICENSE)
