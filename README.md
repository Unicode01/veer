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
- `lab` / `preview` / `stable` 插件默认可执行控制脚本；进入外部 TC 数据面仍受 `plugins_dataplane_enabled` 控制；`deprecated` 插件始终禁用
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

插件层的使用说明和示例放在 `examples/plugins/README.md`。README 只保留入口信息：运行时插件目录默认为 `plugins/runtime`，`plugin.json` 只声明身份、稳定级别、权限和 `control.main`，资源、动作、UI、eBPF object、hook 等运行时 surface 由 `control.js` 顶层注册。

当前插件层由 slim manifest、Goja 控制面和可选的 `fvtap` TC pipeline 组成。外部数据面默认关闭，开启前应确认插件可信、对象 hash 和目标内核 eBPF 能力；控制面数据更新只影响 SQLite/Goja/eBPF map，不会让 TC/XDP 热路径查询 Web API。显式接口插件可在没有 Forward/Egress NAT 规则时独立启动 TC pipeline，此时内置 forward/reply core 关闭，pipeline 作为纯插件高速链运行。

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

只重建 eBPF object 时可使用：

```bash
sh scripts/build-ebpf.sh
sh scripts/build-plugin-ebpf.sh
sh scripts/build-all-ebpf.sh
sh scripts/verify-example-plugin-manifests.sh
sh scripts/package-example-plugins.sh
```

`scripts/build-ebpf.sh` 负责核心 TC/XDP object，`scripts/build-plugin-ebpf.sh` 会执行示例插件目录里的 `build.sh`。`scripts/verify-example-plugin-manifests.sh` 只校验示例插件 slim manifest 的身份字段、稳定级别、控制入口、权限、`resource_access` 和 `net_access`；`capabilities/objects/hooks/resources/actions/ui/metadata` 这类 runtime-owned 字段出现在 manifest 中会直接报错。`stable/preview` 插件必须声明并匹配 `control.sha256`；UI 入口、eBPF object、资源、动作和 hook 都由 `control.js` 在 registration-only 阶段注册。`scripts/package-example-plugins.sh` 会生成 runtime-ready 示例插件目录，默认只打包 `stable` 示例，输出到 `dist/plugins-runtime`，并在打包副本的 `plugin.json` 中注入控制脚本 `sha256`；覆盖输出目录前会先校验临时产物，源码目录里的 manifest 不会被改写。可用 `FORWARD_PLUGIN_PACKAGE_DIR=/path/to/plugins/runtime` 指定输出目录；需要受控预览或实验插件时显式设置 `FORWARD_PLUGIN_PACKAGE_STABILITY=stable,preview`、`FORWARD_PLUGIN_PACKAGE_STABILITY=all` 或 `FORWARD_PLUGIN_PACKAGE_STABILITY=lab`。仓库默认忽略生成的 `.o` 文件和 `dist/`，发布构建应使用 `release.sh`，开发调试才需要单独运行这些脚本。

常规测试：

```bash
go test ./...
```

插件示例的真实 Linux 验收测试：

```bash
sudo sh scripts/test-plugin-examples-linux.sh
sudo sh scripts/test-plugin-pppoe-linux.sh
sudo sh scripts/test-plugin-production-linux.sh
```

`test-plugin-production-linux.sh` 是完整生产验收入口，默认设置 `FORWARD_PLUGIN_EXAMPLE_REPEAT=20` 和 `FORWARD_PLUGIN_PIPELINE_REPEAT=20`，先跑脚本语法、manifest verifier、默认 stable package、lab 排除和低内存 helper 自检，再跑示例插件 Linux 行为、外部 TC 插件 attach/cleanup 和插件生成 Egress NAT 的端到端流量测试，之后跑 TC 插件 pipeline 长流/新流稳定性门禁，最后跑插件 pipeline perf smoke。PPPoE gate 依赖 `pppd`、`pppoe-server`、`ethtool` 和 `/dev/net/tun`，默认不并入通用生产入口；需要 PPPoE gate 时单独运行 `test-plugin-pppoe-linux.sh`，或给生产入口设置 `FORWARD_RUN_PLUGIN_PPPOE_TEST=1`。`test-plugin-examples-linux.sh` 会先在宿主 network namespace 内创建并删除临时 veth/bridge，用于验证 `wan_core`、`lan_core`、`vtolocal` 的真实 `net.admin` 行为、repair timer 和 teardown 语义；随后运行 `packet_observer` 类外部 TC 插件 attach/cleanup 测试，再构建 eBPF object，并运行插件生成 Egress NAT plan 的 TC 端到端流量测试，覆盖 `lan_core -> egress_nat_plans -> core` 和 `lan_core -> wan_core status -> egress_nat_plans -> core` 两条路径。`test-plugin-pppoe-linux.sh` 会在可用 Node 时先执行 `examples/plugins/pppoe_client/test-control-node.js` 插件自有控制面测试，覆盖 discovery、PAP/CHAP、IPv6CP、DHCPv6-PD、keepalive/redial、disconnect 和 tunnel map 写入；随后运行插件目录自带黑盒验收：启动真实 `forward` 进程，通过 HTTP 插件 API 触发 `pppoe_client`，再用 netns/veth、rp-pppoe server/pppd AC、ping 和 iperf3 验证 TC 隧道真实流量；测试会关闭临时 veth offload，并让插件执行接口 MTU/offload 准备，避免 TCP partial checksum 在 PPPoE 隧道里被 `ppp0` 丢弃。`test-plugin-stability-linux.sh` 会在 TC+插件 pipeline 下同时保持长连接持续 echo 和周期性创建新短连接，用于捕获断流、新流无法创建、插件链状态卡死这类问题。它们默认不会随 `go test ./...` 执行；如果只想跑 net.admin 行为，可设置 `FORWARD_SKIP_PLUGIN_EGRESS_NAT_TEST=1`：

```bash
sudo FORWARD_RUN_PLUGIN_EXAMPLE_TEST=1 go test ./internal/app -run TestPluginExample -count=1 -v
sudo FORWARD_SKIP_PLUGIN_EGRESS_NAT_TEST=1 sh scripts/test-plugin-examples-linux.sh
sudo FORWARD_PLUGIN_EXAMPLE_REPEAT=20 sh scripts/test-plugin-examples-linux.sh
sudo FORWARD_PLUGIN_PPPOE_REPEAT=3 sh scripts/test-plugin-pppoe-linux.sh
sudo sh scripts/test-plugin-stability-linux.sh
sudo sh scripts/test-plugin-perf-linux.sh
sudo FORWARD_RUN_PLUGIN_PPPOE_TEST=1 sh scripts/test-plugin-production-linux.sh
sudo FORWARD_SKIP_PLUGIN_PERF_TEST=1 sh scripts/test-plugin-production-linux.sh
sh scripts/test-plugin-scripts.sh
```

低内存测试机默认会自动启用 `FORWARD_PLUGIN_TEST_LOW_MEMORY=auto`：当 `/proc/meminfo` 显示内存小于 2 GiB 时，脚本会设置 `GOMAXPROCS=2` 并给 `GOFLAGS` 追加 `-p=1`，降低 `go test`/`go build` 的峰值内存。可用 `FORWARD_PLUGIN_TEST_LOW_MEMORY=0` 关闭，也可用 `FORWARD_PLUGIN_TEST_LOW_MEMORY=1` 在更大机器上强制使用低并发模式。1 GiB 级测试机仍建议在构建机交叉编译测试二进制，避免目标机在 `go test` 编译阶段 OOM：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o forward-internal-app-linux-amd64.test ./internal/app
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o forward-linux-amd64 .
sudo FORWARD_APP_TEST_BINARY=/path/forward-internal-app-linux-amd64.test \
  FORWARD_PERF_BINARY=/path/forward-linux-amd64 \
  sh scripts/test-plugin-production-linux.sh
```

`scripts/test-plugin-stability-linux.sh` 默认跑 20 秒稳定性门禁，可通过 `FORWARD_PLUGIN_STABILITY_SECONDS`、`FORWARD_PLUGIN_STABILITY_LONG_CONNECTIONS`、`FORWARD_PLUGIN_STABILITY_NEW_CONNECTIONS` 和 `FORWARD_PLUGIN_STABILITY_NEW_INTERVAL_MS` 调整时长、长连接数和新流创建频率。`scripts/test-plugin-perf-linux.sh` 默认用轻量负载跑 TC baseline、1 个插件、4 个插件三组 perf smoke；可通过 `FORWARD_PLUGIN_PERF_COUNTS`、`FORWARD_PERF_CONNECTIONS`、`FORWARD_PERF_CONCURRENCY`、`FORWARD_PERF_BYTES_PER_CONN` 等环境变量扩展成完整曲线。`scripts/test-plugin-pppoe-linux.sh` 可通过 `FORWARD_PPPOE_BLACKBOX_SECONDS` 和 `FORWARD_PPPOE_BLACKBOX_PARALLEL` 调整 PPPoE 黑盒 TCP 流量。内核集成和性能测试需要 Linux、root、netns/veth/TC/XDP 能力，按测试文件中的环境变量单独开启。`wan_core`、`lan_core`、`vtolocal` 和 `pppoe_client` 的稳定性标记依赖上述真实 Linux 验收、端到端转发、长稳和性能曲线；`pppoe_client` 已覆盖插件自有控制面协议自测和黑盒 rp-pppoe server/pppd AC 下的真实 session/TCP 流量；生产部署仍应在目标运营商/AC 上额外覆盖断线重拨、真实 IPv4/IPv6/PD、接口 offload/MTU 准备和目标拓扑吞吐验收。`packet_observer` 仍是 `lab` 示例，不能作为生产级功能承诺。

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
