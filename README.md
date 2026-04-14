# forward

`forward` 是一个面向虚拟机宿主机场景的 NAT Forward 管理服务。

它用 Go 编写，内置 Web UI 和管理 API，使用 SQLite 持久化配置与状态，目标是把宿主机上的端口转发、共享代理、端口范围、Egress NAT、托管网络和 IPv6 分发统一收敛到一个进程里管理。

开发者接口见 [API.md](./API.md)。

## 项目定位

这个项目主要解决下面这些宿主机场景：

- 把宿主机公网端口转发到内网虚拟机
- 把 80/443 收口到宿主机，再按域名转发到不同 VM
- 把一段连续端口映射给某台 VM
- 给托管桥分配 IPv4 DHCP、静态保留和 IPv6 下发
- 让 VM 通过宿主机做 Egress NAT
- 在 Linux 上用 `userspace / tc / xdp` 多条 dataplane 路径做转发和回退

如果你的环境是 Proxmox、KVM、自建 Linux bridge，或者其他“宿主机负责给 VM 提供网络入口/出口”的部署方式，这个项目是对口的。

## 当前能力

当前可以统一管理下面几类对象：

- 规则转发：单端口 TCP / UDP 转发
- 共享站点：80/443 共享代理，按域名分发
- 端口范围：连续端口区间映射
- Egress NAT：按父接口 / 子接口 / 出接口管理出向 NAT
- 托管网络：创建或托管现有 bridge，维护 IPv4 DHCP、保留地址、自动 Egress NAT
- IPv6 分发：向目标接口下发 `/128` 或 `/64`

配套能力包括：

- Web UI
- Bearer Token 鉴权的管理 API
- SQLite 持久化
- Worker 热重载与 draining
- Linux 内核 dataplane 运行时视图
- 仓库内附带 WHMCS 插件

## 当前建议

先说结论：

- 生产上优先按 Linux 使用
- 想进内核 dataplane，优先把 `TC` 当主线
- `XDP` 仍然属于实验路径，建议按拓扑单独验证
- 透明转发仍然更适合按 IPv4 理解和部署
- 如果是 `veth / netns / VM tap` 这类实验拓扑，要跑 XDP 基本应显式开启 `xdp_generic`

更具体一点：

- 用户态转发已经覆盖最广，适合作为最终回退路径
- `TC` 是当前更通用、更稳妥的 Linux 内核转发路径
- `XDP` 已经能通过完整集成测试，但它对网卡类型、attach mode、bridge/veth 组合更敏感
- 在一台 Debian 调试机上，这轮已经确认：`veth` 上的 XDP NAT redirect 在 `driver/native` 模式下可能直接返回 `EOPNOTSUPP`；同一拓扑切到 `generic/SKB` 后可恢复正常
- 如果你当前不准备试验 XDP，最直接的做法就是把 `kernel_engine_order` 固定成 `["tc"]`
- 因此，README 里的 XDP 结论都应该理解为“可用但需按环境验证”，而不是“默认可替代 TC”

## 2026-04-10 测试状态

下面这些套件已经在远程 Debian 调试机上重新跑过：

- `go test ./...`
- `FORWARD_RUN_EGRESS_NAT_TEST=1`
- `FORWARD_RUN_EGRESS_NAT_XDP_TEST=1`
- `FORWARD_RUN_MANAGED_NETWORK_TEST=1`
- `FORWARD_RUN_IPV6_ASSIGNMENT_TEST=1 -run TestIPv6AssignmentManagedAddressIntegration`
- `FORWARD_RUN_TC_IPV6_TEST=1`
- `FORWARD_RUN_XDP_FULLNAT_TEST=1`
- `FORWARD_RUN_XDP_IPV6_TEST=1`

这轮补充确认的关键点：

- XDP Egress NAT、XDP IPv4 full-NAT、XDP IPv6 integration 现在都能通过
- veth 型 XDP 集成拓扑需要 `xdp_generic`
- 这不是规则命中问题，而是部分内核/拓扑下 `driver/native` redirect 自身不可用

## 典型拓扑

最常见的 VM 宿主机场景大致如下：

```text
公网
  |
  | 203.0.113.10
  |
宿主机
  ├─ eth0              公网接口
  └─ vmbr0             VM 网桥，198.51.100.1/24
       ├─ VM-A         198.51.100.10
       └─ VM-B         198.51.100.20
```

典型做法：

- 用 `eth0` 作为入口接口
- 用 `vmbr0` 作为出口接口或托管 bridge
- 让 VM 默认网关指向宿主机桥地址，例如 `198.51.100.1`

### 单端口转发

把宿主机公网 `203.0.113.10:2222` 转发到 VM-A 的 `22`：

```text
in_interface  = eth0
in_ip         = 203.0.113.10
in_port       = 2222
out_interface = vmbr0
out_ip        = 198.51.100.10
out_port      = 22
protocol      = tcp
```

### 共享站点

把 `app.example.com` 转发到 VM-A：

```text
domain             = app.example.com
listen_interface   = eth0
listen_ip          = 203.0.113.10
backend_ip         = 198.51.100.10
backend_http_port  = 80
backend_https_port = 443
```

### 端口范围

把 `30000-30100` 映射到 VM-B：

```text
in_interface   = eth0
in_ip          = 203.0.113.10
start_port     = 30000
end_port       = 30100
out_interface  = vmbr0
out_ip         = 198.51.100.20
out_start_port = 30000
protocol       = tcp+udp
```

### Egress NAT

如果 VM 的默认路由走宿主机桥，出向 NAT 一般会长这样：

```text
parent_interface = vmbr0
child_interface  = tap100i0
out_interface    = eth0
out_source_ip    = 203.0.113.10
protocol         = tcp+udp+icmp
nat_type         = symmetric
```

## 快速开始

1. 复制配置文件：

```bash
cp config.example.json config.json
```

Windows PowerShell：

```powershell
Copy-Item config.example.json config.json
```

2. 修改 `config.json`，至少设置一个真实的 `web_token`

注意：

- `web_token` 不能为空
- 程序会拒绝使用示例占位值 `change-me-to-a-secure-token`

3. 直接运行：

```bash
go run .
```

4. 打开管理面板：

```text
http://127.0.0.1:8080
```

## 配置概览

示例配置见 [config.example.json](./config.example.json)：

```json
{
  "web_bind": "127.0.0.1",
  "web_ui_enabled": true,
  "web_port": 8080,
  "web_token": "change-me-to-a-secure-token",
  "max_workers": 0,
  "drain_timeout_hours": 24,
  "managed_network_auto_repair": true,
  "default_engine": "auto",
  "kernel_engine_order": ["tc", "xdp"],
  "kernel_rules_map_limit": 0,
  "kernel_flows_map_limit": 0,
  "kernel_nat_ports_map_limit": 0,
  "kernel_nat_port_min": 20000,
  "kernel_nat_port_max": 65535,
  "experimental_features": {
    "bridge_xdp": false,
    "xdp_generic": false,
    "kernel_traffic_stats": false,
    "kernel_tc_diag": false,
    "kernel_tc_diag_verbose": false
  },
  "tags": []
}
```

最关键的字段：

- `web_bind`：Web UI / API 监听地址。默认 `127.0.0.1`，更适合生产；如果你明确要直接对外暴露管理面，再显式改成 `0.0.0.0` 或具体管理 IP
- `web_ui_enabled`：是否提供静态 Web UI。默认开启；设为 `false` 后只保留 `/api/*`、`/healthz`、`/readyz`
- `web_port`：Web UI / API 监听端口
- `web_token`：管理面板和 API 的 Bearer Token
- `default_engine`：`auto`、`userspace`、`kernel`
- `kernel_engine_order`：内核引擎顺序。代码默认在省略时只走 `tc`；示例配置里显式写成 `["tc", "xdp"]`，只是为了把 XDP 保留在候选链里，想走更保守的生产配置时可直接改回 `["tc"]`
- `managed_network_auto_repair`：托管网络链路变更后的自动修复
- `kernel_rules_map_limit` / `kernel_flows_map_limit` / `kernel_nat_ports_map_limit`：内核 map 容量上限，`0` 表示自适应
- `kernel_nat_port_min` / `kernel_nat_port_max`：内核 Full NAT 端口池范围，默认 `20000-65535`
- `experimental_features`：实验特性开关

实验特性里目前最重要的几个键：

- `bridge_xdp`
- `xdp_generic`
- `kernel_traffic_stats`
- `kernel_tc_diag`
- `kernel_tc_diag_verbose`

关于 `xdp_generic`：

- 默认关闭
- 不打开时，XDP 只接受 `driver/native`
- 打开后，XDP 才允许 `generic/SKB` 或 mixed attach
- 对 `veth / tap / netns` 型实验拓扑，通常应该显式打开

## 内核 dataplane

### 引擎选择

当前引擎选择逻辑：

- `default_engine = userspace`：全部走用户态
- `default_engine = kernel`：尽量走内核态，失败再安全回退
- `default_engine = auto`：优先尝试内核态，再回退到用户态
- Linux 下会按 `kernel_engine_order` 依次尝试

### 当前推荐

- `TC`：当前更通用、更稳妥的主线内核引擎
- `XDP`：路径更短，但更依赖接口和 attach 条件，建议单独验证

### 当前边界

想进入内核态，通常至少需要满足：

- 普通转发规则通常要求明确的单协议匹配；Egress NAT 有自己单独的约束
- 明确指定 `in_interface` 和 `out_interface`
- 后端地址和出接口可解析
- full-NAT / egress NAT 场景下，出接口上能得到可用源地址，或显式给出 `out_source_ip`

当前更保守的理解方式是：

- `TC` 负责更广的兼容面
- `XDP` 负责更激进的实验路径
- 透明转发仍主要按 IPv4 工作流理解
- IPv6 的非透明内核路径已经有 TC / XDP 集成测试覆盖

### 运行时观测

当前提供：

- Web UI 里的 `Kernel Runtime` 面板
- `GET /api/kernel/runtime`

能看到的内容包括：

- 当前默认引擎与配置顺序
- 每个内核引擎的 active entries
- attach 状态和 attach mode
- map 占用
- retry / self-heal / degraded / pressure 信息
- TC / XDP 诊断字段

### 热更新与异常退出

- 正常停止或 `deploy.sh` 更新时，会尽量让内核态状态由新进程接力
- 这条路径是“尽量不断流”，不是绝对零中断承诺
- 如果进程被 `kill -9`、OOM kill 或异常崩溃，内核附加点可能会暂时继续生效
- 下次启动会尝试识别并清理 orphan 附加点

## 托管网络与 PVE

`Managed Network` 现在有两种工作方式：

- `create`：由 `forward` 动态创建 bridge
- `existing`：托管一个宿主机上已经存在的 bridge

当前托管网络能力包括：

- IPv4 DHCP
- IPv4 静态保留
- IPv6 `/128` 或 `/64` 下发
- 自动生成 Egress NAT
- 链路变更后的自动修复
- PVE `qemu-server` 与 `lxc` 配置识别
- PVE guest 链路自动识别与修复，覆盖 `fwpr*`、`tap*`、`veth*`

### PVE 最低版本

如果是面向 Proxmox VE 部署，建议按下面这条边界理解：

- 最低可运行版本按 `PVE 7.0` 起算；从 `7.0` 开始默认进入 `5.11` 内核线，满足当前 `TC` 主线路径的最低内核要求，也覆盖了 `veth` 场景下 XDP NAT redirect 已知要求的 `5.11+` 边界
- 不建议再把 `PVE 6.x` 视为受支持目标；它默认是 `5.4` 内核线，不在当前内核 dataplane 支持范围内
- 对外文档如果要写得更稳，建议直接写 `PVE 8.x+`
- 最终仍以宿主机实际内核版本为准；如果宿主机手动 pin 到旧内核，只看 PVE 大版本并不能保证内核 dataplane 可用

### PVE 相关建议

如果你是在 Proxmox 上用：

- PVE 界面更偏向识别写入 `/etc/network/interfaces` 的 bridge
- 动态创建的 bridge 不一定会被 PVE 视为“可配置网络”
- 这时更推荐两种方式之一：
  - 直接托管现有 bridge
  - 先用 `create` 动态创建，再执行“持久化 bridge”

### 托管 bridge 持久化

Linux 现在支持把 `create` 模式下的 bridge 写入宿主机 `interfaces` 配置：

- 目标文件：`/etc/network/interfaces`
- 会创建备份
- 会写入一个带 `BEGIN/END forward managed bridge` 标记的静态 block
- 写入成功后，该托管网络会转成 `existing` 模式

这条路径是为 `ifupdown` / PVE 一类环境准备的，不是通用网络配置管理器。
如果你的系统会由其他工具重写 `interfaces`，应把 `forward` 视为辅助写入工具，而不是唯一的 source of truth。

## 平台与依赖

推荐运行环境：

- Linux

### Debian / Ubuntu 最低版本

如果是直接部署在 Debian 或 Ubuntu 上，建议按下面这条边界理解：

- Debian 的最低可运行版本按 `Debian 11 (bullseye)` 起算；它自带 `5.10` 内核线，满足当前 `TC` 主线路径的最低内核要求
- 如果你希望在发行版默认内核上同时覆盖 `TC` 和 `veth` 场景下的 XDP NAT redirect，Debian 侧更推荐直接使用 `Debian 12 (bookworm)+`
- Ubuntu 的最低支持版本按 `Ubuntu 22.04 LTS` 起算；服务端默认使用 `5.15` GA 内核，满足当前内核 dataplane 边界
- 不建议把 `Ubuntu 20.04 LTS` 视为默认受支持目标；它的服务端默认 GA 内核是 `5.4`，版本号本身不能保证内核 dataplane 可用
- 最终仍以宿主机实际内核版本为准；如果系统切到了 HWE、OEM 或自定义内核，应直接以 `uname -r` 判断，而不是只看发行版版本号

构建要求：

- Go 1.25.1 或更高
- `release.sh` 需要 `clang`
- Debian / Ubuntu 上通常还需要 `linux-libc-dev`

如果要使用低位端口、网卡绑定、透明转发或内核 dataplane，还需要相应权限：

- `CAP_NET_BIND_SERVICE`
- `CAP_NET_RAW`
- `CAP_NET_ADMIN`
- `CAP_BPF`
- `CAP_PERFMON`

非 Linux 平台可以编译，但很多高级能力会降级或不可用。

## 性能说明

先给结论：

- 当前 README 的性能数字只代表 `netns + veth` 调试拓扑
- 它们适合比较 dataplane 路径差异
- 它们不等价于真实物理网卡线速

这轮保留的样本来自 `2026-04-10` 的重新复跑。

### 普通 dataplane 小包 PPS

口径：

- UDP steady
- `64B` payload
- `8192` 总连接
- `16` 活跃连接
- `FORWARD_PERF_DISABLE_OFFLOADS=1`

| Engine | Payload PPS | Mean Payload Throughput |
| --- | ---: | ---: |
| iptables | `~84.3-90.0k pps` | `~5.29 MiB/s` |
| nftables | `~84.1-86.3k pps` | `~5.20 MiB/s` |
| userspace | `~28.2-28.5k pps` | `~1.73 MiB/s` |
| TC | `~90.8-96.0k pps` | `~5.69 MiB/s` |

### 普通 dataplane 大流吞吐

口径：

- TCP upload
- `16` 连接 / `16` 并发
- `512 MiB` per connection
- `128 KiB` chunk
- `FORWARD_PERF_DISABLE_OFFLOADS=0`

| Engine | Payload Throughput |
| --- | ---: |
| iptables | `~1027-1121 MiB/s` |
| nftables | `~965-1085 MiB/s` |
| userspace | `~841-875 MiB/s` |
| TC | `~1352-1509 MiB/s` |

### Egress NAT 小包 PPS

口径：

- bridge + uplink `veth`
- UDP steady
- `64B` payload
- `8192` 总连接
- `16` 活跃连接
- `FORWARD_PERF_DISABLE_OFFLOADS=1`

| Engine | Payload PPS | Mean Payload Throughput |
| --- | ---: | ---: |
| iptables | `~74.7k pps` | `~4.56 MiB/s` |
| nftables | `~71.7k pps` | `~4.38 MiB/s` |
| TC | `~83.4k pps` | `~5.09 MiB/s` |

### Egress NAT 大流吞吐

口径：

- bridge + uplink `veth`
- TCP 单向流
- `64` 连接 / `8` 并发
- `1 MiB` per connection
- `16 KiB` chunk
- `FORWARD_PERF_DISABLE_OFFLOADS=0`

| Engine | Upload | Download |
| --- | ---: | ---: |
| iptables | `~1255 MiB/s` | `~1525 MiB/s` |
| nftables | `~1331 MiB/s` | `~1787 MiB/s` |
| TC | `~1936 MiB/s` | `~1828 MiB/s` |

### XDP 性能状态

这轮不再给 XDP 统一性能表，原因很简单：

- XDP 对 attach mode 和拓扑非常敏感
- 同一套规则在 `driver/native` 和 `generic/SKB` 下的表现与可用性都可能不同
- 在 `veth / netns` 压测里，很多瓶颈其实来自本机队列、GRO、softirq 和发送侧背压，而不是规则命中本身

如果你要评估 XDP：

- 按目标网卡、bridge 结构和 offload 组合单独复测
- 同时看 `GET /api/kernel/runtime`
- 同时看 `ip -s link`
- 对 `veth` 型环境，优先确认是否需要 `xdp_generic`

## 构建

本地构建：

```bash
go build -o forward .
```

交叉编译 Linux 版本：

```bash
./release.sh
```

`release.sh` 会先编译：

- `internal/app/ebpf/forward-tc-bpf.o`
- `internal/app/ebpf/forward-xdp-bpf.o`

然后把它们 embed 进最终二进制。

只构建指定架构：

```bash
./release.sh amd64
./release.sh arm64
```

## 部署

仓库自带 Debian 部署脚本 [deploy.sh](./deploy.sh)。
如果你希望目标机自己安装依赖、拉源码、构建并部署，也可以直接使用一键引导脚本 [bootstrap.sh](./bootstrap.sh)。

一键引导部署（Debian 11+ / Ubuntu 22.04+）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
```

常见变体：

```bash
FORWARD_REF=main bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
WEB_BIND=0.0.0.0 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
WEB_UI_ENABLED=false bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
READY_TIMEOUT_SECONDS=180 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh) -- --no-inherit-stats
```

说明：

- 当前默认入口就是 GitHub Raw 上的 `bootstrap.sh`
- 一键脚本会在目标机安装依赖、拉取指定 `Git ref`、执行 `release.sh`，最后再调用 `deploy.sh`
- `bootstrap.sh` 会自动检测是否位于中国大陆；如果命中，会优先从国内 Go 镜像拉取工具链，并为构建阶段设置适合的 `GOPROXY/GOSUMDB`。也可用 `FORWARD_GO_REGION=cn|global|auto`、`FORWARD_GO_BASE_URL=...`、`FORWARD_GO_CN_BASE_URL=...`、`FORWARD_GOPROXY=...`、`FORWARD_GOSUMDB=...` 显式覆盖
- `deploy.sh` 现在默认把管理面限制在 `127.0.0.1`；如果你确实要直接远程打开管理面，请显式设置 `WEB_BIND=0.0.0.0` 或在 `config.json` 里写入具体监听地址
- 如果你只想暴露 API / 探针、不想提供浏览器前端，可设置 `WEB_UI_ENABLED=false`，或在 `config.json` 里写入 `"web_ui_enabled": false`
- `deploy.sh` 生成的新 `config.json` 会直接写入完整默认配置；升级旧配置时也会补齐缺失字段，不需要再翻文档手抄默认项
- 如果旧 `config.json` 里还保留示例占位值 `change-me-to-a-secure-token`，`deploy.sh` 会拒绝继续部署；先改成真实 token，或在部署时显式传入 `WEB_TOKEN=...`
- 更新部署会先备份旧二进制与 systemd unit，再用本机 `/readyz` 探针确认新版本可用；默认等待 120 秒，也可用 `READY_TIMEOUT_SECONDS` 覆盖；如果热更新失败或超时未就绪，会自动回滚到上一版本
- 如果目标机原本没有满足版本要求的 Go，一键脚本会把 Go 临时解压到 `FORWARD_WORKDIR` 下，仅供当前引导流程使用；脚本退出后会连同源码一起清理，不会写入 `/usr/local/go`
- 如果引导流程失败，脚本会输出失败步骤、命令和行号；默认还会保留 `FORWARD_WORKDIR` 便于排查，设置 `FORWARD_KEEP_WORKDIR_ON_ERROR=0` 可改回失败即清理
- 如果你更偏向可复现部署，建议把 `FORWARD_REF` 固定到 tag 或 commit，而不是长期直接跟 `main`

本机探针：

```text
http://127.0.0.1:8080/healthz
http://127.0.0.1:8080/readyz
```

常见流程：

```bash
./release.sh amd64
scp forward-linux-amd64 deploy.sh root@server:/tmp/
ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'
```

部署脚本会处理：

- 安装二进制到 `/opt/forward`
- 生成 `config.json`
- 创建并启用 systemd 服务
- 放行常用端口
- 打开 `net.ipv4.ip_forward`

## WHMCS 插件

仓库内附带 WHMCS addon 插件，源码位于：

```text
plugins/whmcs/forward/
```

部署到 WHMCS 时，应放到：

```text
modules/addons/forward/
```

它主要面向多宿主机、多入口 IP、多 API endpoint 的 NAT/站点管理场景。

最少配置项：

- `API 地址` 与 `API Token`
- `默认入口 IP`，或按宿主机配置 `server_ip_server_map`

多宿主机场景建议同时配置：

- `server_ip_server_map`
- `api_server_map`

使用客户区时建议额外确认：

- WHMCS 服务已正确绑定到对应 `Server`
- `allowed_product_ids` 已限制到允许使用 Forward 的产品
- 如需限制客户可选后端 IP，再配置 `allowed_client_ips`

## 项目结构

```text
.
├─ main.go
├─ bootstrap.sh
├─ internal/
│  └─ app/
│     ├─ run.go
│     ├─ api.go
│     ├─ db.go
│     ├─ worker.go
│     ├─ range_worker.go
│     ├─ shared_proxy.go
│     ├─ dataplane.go
│     ├─ kernel_runtime*.go
│     ├─ managed_network*.go
│     ├─ ipv6_assignment*.go
│     ├─ ebpf/
│     └─ web/
├─ release.sh
├─ deploy.sh
├─ API.md
└─ plugins/
```

## 安全建议

- 不要把真实 `config.json` 提交到公开仓库
- 不要泄露 `web_token`
- 如果 Web 管理面板暴露到公网，建议再放在反向代理或受限网络之后

## License

[MIT License](./LICENSE)
