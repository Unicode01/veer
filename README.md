# forward

`forward` 是一个面向虚拟机宿主机和二级路由场景的 NAT Forward 管理服务。它用 Go 编写，内置 Web UI、管理 API、SQLite 持久化和 Linux 内核 dataplane，可把端口转发、共享建站、端口范围、Egress NAT、托管网络、IPv6 分发和运行时诊断统一收敛到一个进程里管理。

开发者 API 见 [API.md](./API.md)。

## 一键部署

Linux 服务器推荐直接使用一键引导脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
```

如果 GitHub Raw 不通：

```bash
tmpdir="$(mktemp -d)" && \
curl -fsSL https://codeload.github.com/Unicode01/forward/tar.gz/refs/heads/main | tar -xzf - --strip-components=1 -C "$tmpdir" && \
bash "$tmpdir/bootstrap.sh"
```

常用部署参数：

```bash
FORWARD_REF=main bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
WEB_BIND=0.0.0.0 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
WEB_UI_ENABLED=false bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
READY_TIMEOUT_SECONDS=180 bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/forward/refs/heads/main/bootstrap.sh) -- --no-inherit-stats
```

`bootstrap.sh` 会安装依赖、拉取源码、执行 `release.sh` 构建，再调用 `deploy.sh` 安装或热更新。它支持 Debian/Ubuntu 的 `apt`，也支持 RHEL-compatible/Fedora 的 `dnf/yum`。中国大陆网络环境下会自动优先使用可用的 Go 镜像和 Go module 代理。

需要手动部署时：

```bash
./release.sh amd64
scp forward-linux-amd64 deploy.sh root@server:/tmp/
ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'
```

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

`forward` 适合把 Linux 宿主机作为 VM/容器的默认转发器或二级路由，统一管理入口、出口和下联网络。

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
- WHMCS addon 插件

## 推荐部署

生产建议：

- 运行在 Linux 上
- 默认把管理面绑定到 `127.0.0.1`
- 内核 dataplane 优先使用 `TC`
- `XDP` 只在目标拓扑验证通过后启用
- 如果不需要 XDP，建议把 `kernel_engine_order` 设置为 `["tc"]`

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

示例配置见 [config.example.json](./config.example.json)。

```json
{
  "web_bind": "127.0.0.1",
  "web_ui_enabled": true,
  "web_port": 8080,
  "web_token": "change-me-to-a-secure-token",
  "max_workers": 0,
  "drain_timeout_hours": 24,
  "managed_network_auto_repair": true,
  "plugins_enabled": true,
  "plugins_dataplane_enabled": false,
  "plugins_dir": "plugins/runtime",
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
    "kernel_tc_diag_verbose": false,
    "kernel_tc_redirect_neigh_fast": false,
    "kernel_tc_prepared_l2": false,
    "kernel_tc_reply_l2_cache": false
  },
  "tags": []
}
```

关键字段：

- `web_bind`：Web UI / API 监听地址，默认 `127.0.0.1`
- `web_ui_enabled`：是否启用静态 Web UI；关闭后仍保留 `/api/*`、`/healthz`、`/readyz`
- `web_port`：监听端口
- `web_token`：Web UI 和 API 共用的 Bearer Token
- `default_engine`：`auto`、`userspace`、`kernel`
- `kernel_engine_order`：Linux 内核引擎尝试顺序；省略时默认 `["tc"]`
- `managed_network_auto_repair`：托管网络链路变化后的自动修复
- `plugins_enabled`：是否扫描外部运行时插件 manifest；内置 `fvtap` 始终可见
- `plugins_dataplane_enabled`：是否允许外部插件进入 TC 数据面；默认关闭，当前支持按 priority 围绕 `fvtap core` 排序的 forward/reply TC 链
- `plugins_dir`：外部运行时插件目录，默认 `plugins/runtime`
- `kernel_rules_map_limit`：内核规则 map 容量，`0` 表示自适应
- `kernel_flows_map_limit`：内核 flow map 容量，`0` 表示自适应
- `kernel_nat_ports_map_limit`：内核 NAT 端口 map 容量，`0` 表示自适应
- `kernel_nat_port_min` / `kernel_nat_port_max`：内核 Full NAT 临时端口池
- `experimental_features`：实验特性开关，默认都应保持关闭，按需验证后再开

## Dataplane

`forward` 有三条主要 dataplane：

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

- `create`：由 `forward` 动态创建 bridge
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

运行时插件目录默认为 `plugins/runtime`。每个插件使用独立子目录和 `plugin.json` 声明元数据、能力、虚拟接口、可校验对象、受限 dataplane hook 和可选静态 UI 资源：

```json
{
  "api_version": "v1",
  "id": "packet_observer",
  "name": "Packet Observer",
  "version": "0.1.0",
  "kind": "pipeline",
  "capabilities": ["observe"],
  "virtual_interfaces": [{"id": "vtap0", "type": "logical"}],
  "objects": [{
    "id": "observer",
    "path": "observer.o",
    "sha256": "64-character-lowercase-hex-digest",
    "programs": [{"id": "tc_pre_forward", "section": "tc/fvtap/pre_forward", "type": "tc"}]
  }],
  "hooks": [{
    "id": "observe-ingress",
    "engine": "tc",
    "attach": "ingress",
    "stage": "forward",
    "priority": 10,
    "program": "observer:tc_pre_forward",
    "mode": "observe",
    "interfaces": ["eth0"]
  }],
  "resources": [{
    "id": "bindings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual",
    "max_records": 64,
    "max_record_bytes": 4096
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "plugin_reconcile"
  }],
  "ui": {
    "static_dir": "ui",
    "entry": "index.html"
  },
  "metadata": {
    "ui.page": "observe",
    "ui.page_title": "Observe"
  }
}
```

当前插件层包含三部分：控制面发现、Goja 控制脚本和可选的 `fvtap` TC pipeline 数据面。`GET /api/plugins` 会返回外部插件和内置 `fvtap` 描述，并通过 `runtime.external_dataplane_attach` 标记外部数据面是否启用。默认 `plugins_dataplane_enabled=false`，外部插件的 `runtime.mode` 为 `manifest_only`，只表示 manifest、object 和 UI 资源已被发现/校验；内置 `fvtap` 的 `runtime.mode` 为 `builtin` 且 `attached=true`。

启用 `plugins_dataplane_enabled=true` 后，只有当前目录里存在可链入的 `engine=tc`、`stage=forward` 或 `stage=reply` hook 时，TC 入口才会从 legacy/dispatch 切到 `pipeline_v4`。没有实际插件链时不会给热路径增加额外 lookup。内置 `fvtap core` 的 priority 固定为 `1000`；外部 TC 插件使用 manifest `priority` 和 core 对比，低于 `1000` 会装入 core 前 slots，高于 `1000` 会装入 core 后 slots，等于 `1000` 会被拒绝以避免和 core 抢同一排序点。旧 manifest 的 `stage=pre_forward/post_lookup/pre_reply/post_reply` 仍作为兼容别名保留；`GET /api/plugins` 里的 `chain_slot` 表示实际 prog-array slot。插件执行后必须 tail-call 到对应 stage 的 continue slot，除非它明确要返回最终 TC action。当前 forward 和 reply 方向各自有 core 前/后两个物理执行区，单个执行区最多 8 个外部 hook，总 hook 数最多 14 个，以避免触发内核 tail-call 深度上限。XDP 和非 `fvtap` TC hook 仍是 manifest 声明，不会进入数据面。

`hooks[].interfaces` 是可选的插件自驱动 attachment 声明。留空或省略时，插件只会在已有 forward/egress 规则把 `fvtap` 挂到接口后进入链；填写真实接口名时，即使当前没有任何转发规则，TC runtime 也会把 `pipeline_v4` 挂到这些接口上，让 pre-core 插件可以作为广义 core 实现防火墙、观测、协议适配等功能。无规则模式只加载显式接口上的 `pre_forward/pre_reply` hook；core 后 hook 仍需要规则或 flow 上下文。不会自动挂载所有接口；接口不存在会让该插件本轮进入 error 状态。当前链是全局链，不是 per-interface 链；插件如果只想处理某些接口，应在自己的 eBPF 程序里检查 `skb->ifindex` 后再决定 drop/pass/redirect/tail-call。

插件 eBPF object 如需进入 `fvtap` pipeline，必须声明同名共享 map `tc_prog_chain_v4`，类型为 `BPF_MAP_TYPE_PROG_ARRAY`，`max_entries` 至少为 45。服务加载插件对象时会用内置 map 替换该 map，让插件能 tail-call 回对应 stage 的 `fvtap` continue slot。core 后插件如需读取已解析/匹配的稳定上下文，还必须声明共享 map `tc_plugin_ctx_v4`，服务会替换为内置 per-CPU ctx map；其中 IPv4 地址和端口字段按 host byte order 填充，`have_rule=1` 表示本包已匹配规则或回包流。`observe` 仍是对已安装插件对象的信任契约：服务会限制 manifest、路径、大小、sha256 和 program type，但不能证明第三方 TC 程序绝不改包或丢包；生产环境应只加载可信对象。声明了 `objects` 的插件必须保证对象文件在插件目录内、单个对象不超过 16 MiB 且 sha256 匹配；服务会解析 eBPF ELF object，校验 program section/type 并返回 `status`、`program_count`、`map_count`、`resolved_sha256`。

插件控制脚本通过 `control.main` 声明，运行在 Goja 控制面，不进入 TC/XDP 热路径。控制脚本可导出 `onReconcile(ctx)`、`onResourceApply(ctx)`、`onAction(ctx)` 和 `onTimer(ctx)`；可用能力必须在 `control.permissions` 中显式声明。当前 host API 包括：`kv.*` 插件私有 KV，`resources.*` 访问 manifest 资源，`plugins.resources.set()` 在声明 `plugin.resource` 权限后写入其他插件 manifest 已声明的资源，`secret.*` 存储敏感控制面值，`crypto.md5/randomBytes` 支持 CHAP 等协议控制面，`timer.setTimeout/setInterval/clear/list` 支持重试和保活，`net.l2.send/recv/recvMany/exchange/exchangeMany` 支持 Linux raw L2 控制包收发，`ebpf.mapPut/mapDelete/mapClear` 用于把控制面状态写入已加载插件对象的 map。跨插件资源写入会遵守目标资源的 `methods/max_records/max_record_bytes/runtime_update`，未声明 `plugin.resource` 的插件不能写其他插件资源。`net.l2.exchange()` 和 `net.l2.exchangeMany()` 会先准备收包再发包，适合 PPPoE discovery/LCP/IPCP/IPv6CP 这类短窗口交互；它只是控制面 primitive，不代表项目已经内置完整 PPPoE WAN。

插件 UI 资源使用 Bearer Token 鉴权。前端打开插件 UI 时由宿主拉取入口文件，再注入宿主组件和 `ForwardPluginHost` RPC bridge 后放入 sandbox iframe；Web Token 不会暴露给插件页面。插件页面如需读写自己的持久化数据，应通过 `ForwardPluginHost.data.*` 调用 manifest 声明的 `resources`，如需触发显式控制面动作则调用 `ForwardPluginHost.action()`。`runtime_update=manual` 只落库并标记 pending，`plugin_reconcile` 会触发插件运行时重算，`runtime_apply` 会调用 Goja 控制脚本或实现了运行时数据更新接口的宿主数据面。数据更新发生在控制面，不会让 TC/XDP 热路径额外查询 SQLite 或 Web API。

如果插件 manifest 的 `metadata` 声明了 `ui.page`，Web UI 会自动在主分页栏创建对应插件页，例如 `"ui.page": "observe"` 会生成 `Observe` 页并内嵌加载 `ui.entry`。兼容键包括 `ui.page`、`ui_page`、`forward.page`、`forward_ui_page`；标题可用 `ui.page_title`、`forward.page_title` 或 `tab_title` 指定。宿主会给插件入口注入 `fwd-page`、`fwd-card`、`fwd-button`、`fwd-badge`、`fwd-table` 等基础组件样式，并暴露 `window.ForwardPluginHost` helper，方便插件用普通 HTML/CSS/JS 构建接近宿主风格的页面。

示例插件位于 `examples/plugins/packet_observer/`、`examples/plugins/wan_core/`、`examples/plugins/vtolocal/` 和 `examples/plugins/pppoe_client/`。`packet_observer` 需要先执行 `./build.sh` 生成 `packet_observer.o`，再复制到 `plugins/runtime/packet_observer/`；如果开启 `plugins_dataplane_enabled=true`，它会通过 `stage=forward, priority=10` 进入 `fvtap` core 前链，统计包数后 tail-call 回内置转发核心。`wan_core` 是协议中立 WAN adapter，消费标准化 `sessions` 资源并创建 `host veth -> vtap` handoff，状态中会输出 `forward_core.parent_interface`，供 Forward/Egress NAT 规则选择。`pppoe_client` 是 PPPoE 控制面示例，可用 Goja + raw L2 完成 PADI/PADO、PADS、LCP、PAP/CHAP、IPCP、IPv6CP 和 DHCPv6-PD，并可把标准 WAN session 同步到 `wan_core` 创建 handoff；它仍不是生产级 PPPoE WAN 接管实现，真实数据面接管需要启用并验证对应 TC tunnel/forward_core 规则。

把现有转发程序做成 `fvtap` 的可行性：

- 当前实现已经把现有 TC 转发能力暴露为内置 `fvtap` pipeline 节点，并允许外部 TC 插件按 priority 进入 core 前或 core 后链。
- 不建议现在把核心 TC/XDP 拆成外部插件对象。现有热路径依赖固定 tail-call slots、共享 maps、hot restart pinning、fallback/retry 语义和统计结构，直接拆分会增加 verifier、升级兼容和性能退化风险。
- 后续如果要继续扩展，建议先增加 post-forward/reply hook，再逐步开放 rewrite/redirect/drop。`fvtap` 应继续作为内置核心节点，而不是普通第三方插件。

## 平台与依赖

推荐运行环境：

- Debian 11+
- Ubuntu 22.04+
- RHEL-compatible 9+
- Fedora 38+
- Proxmox VE 7+，更推荐 PVE 8+

最终以宿主机实际内核版本和 eBPF 能力为准，不只看发行版版本号。旧内核可能只能运行用户态路径，或无法稳定使用内核 dataplane。

构建要求：

- Go 1.25.1+
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
go build -o forward .
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

`release.sh` 会先编译并嵌入：

- `internal/app/ebpf/forward-tc-bpf.o`
- `internal/app/ebpf/forward-tc-bpf-stats.o`
- `internal/app/ebpf/forward-xdp-bpf.o`
- `internal/app/ebpf/forward-xdp-bpf-stats.o`

常规测试：

```bash
go test ./...
```

内核集成和性能测试需要 Linux、root、netns/veth/TC/XDP 能力，按测试文件中的环境变量单独开启。

## WHMCS 插件

WHMCS addon 插件源码位于：

```text
plugins/whmcs/forward/
```

部署到 WHMCS：

```text
modules/addons/forward/
```

最少配置：

- `默认 Forward API 地址`
- `默认 Forward Bearer Token`，对应 `config.json` 的 `web_token`
- `默认入口 IP`，或按宿主机配置 `server_ip_server_map`

多宿主机场景建议配置：

- `server_ip_server_map`
- `api_server_map`
- `allowed_product_ids`
- 按产品配置端口规则和共享站点上限

## 项目结构

```text
.
├─ main.go
├─ config.example.json
├─ bootstrap.sh
├─ deploy.sh
├─ release.sh
├─ API.md
├─ internal/
│  ├─ app/
│  │  ├─ api.go
│  │  ├─ db.go
│  │  ├─ procmgr.go
│  │  ├─ worker.go
│  │  ├─ range_worker.go
│  │  ├─ shared_proxy.go
│  │  ├─ kernel_runtime*.go
│  │  ├─ managed_network*.go
│  │  ├─ ipv6_assignment*.go
│  │  ├─ ebpf/
│  │  └─ web/
│  ├─ kernelcap/
│  ├─ managednet/
│  ├─ netinfo/
│  └─ netutil/
└─ plugins/
   └─ whmcs/
```

## 安全建议

- 不要提交真实 `config.json`
- 不要泄露 `web_token`
- 管理面默认绑定 `127.0.0.1`，不要无保护暴露到公网
- 如需远程管理，建议放在 VPN、堡垒机、反向代理鉴权或受限管理网后面
- WHMCS 插件里的 Forward Bearer Token 与 `web_token` 是同一个认证语义

## License

[MIT License](./LICENSE)
