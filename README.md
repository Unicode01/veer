# forward

`forward` 是一个面向虚拟机场景的 NAT Forward 管理服务。

## 典型适用场景

- NAT forward for virtual machine
- 宿主机将公网端口转发到内网虚拟机
- 一台宿主机同时管理多台虚拟机的端口暴露
- 多个域名共享宿主机 80/443，再按域名转发到不同虚拟机
- 将一整段端口范围映射到某台虚拟机
- 在多网卡、VLAN 子接口环境里按接口做入口和出口绑定

它使用 Go 编写，内置 Web 管理面板，使用 SQLite 持久化规则和状态，重点解决“宿主机为虚拟机做 NAT 转发”这类场景下的统一管理问题。

如果你的机器同时承担下面这些职责，这个项目会比较合适：

- 把宿主机的 TCP / UDP 端口暴露给虚拟机
- 把 80/443 收口到宿主机，再按域名分发到不同虚拟机
- 管理游戏服、业务服务或测试环境的一段连续端口
- 观察 worker 状态、draining 过程和基础流量统计

当前支持统一管理以下几类转发任务：

- 单端口转发
- 80/443 共享建站转发
- 端口范围映射
- Worker 进程状态与流量统计

当前 Web 面板已支持深色模式、中英文切换、搜索过滤、分页和基础状态提示。

开发者对接文档见 [API.md](./API.md)。

## 主要特性

- 内置 Web UI，无需额外前端构建步骤
- SQLite 持久化，默认生成 `forward.db`
- 支持规则、站点、范围映射三类转发模型
- Linux 下支持 XDP / TC eBPF 内核转发，并按配置自动回退到用户态
- 支持 Worker 自动分配、重分布和 draining 退出
- 支持规则 / 站点 / 范围映射流量统计
- 支持按需刷新当前连接数，避免每轮刷新都遍历连接表
- 支持标签、排序、搜索、分页
- 通过 Bearer Token 保护管理 API
- 仓库内附带 WHMCS 插件，支持多宿主机入口映射、规则管理、80/443 共享建站和 HAProxy 规则导入脚本

## 平台说明

- 推荐运行环境：Linux
- `SO_BINDTODEVICE` 仅在 Linux 下生效
- 透明源地址转发依赖 Linux 的 `IP_TRANSPARENT`、`ip rule`、`ip route` 和 `iptables`
- 非 Linux 平台可以编译，但透明转发和按接口绑定会降级或不可用
- 多网卡场景支持按入接口 / 出接口绑定
- VLAN 子接口会按普通 Linux 网卡名处理，例如 `eth0.100`
- 同一网卡上的多个 IPv4 地址会在前端作为可选监听地址列出

## 典型虚拟机场景示例

下面是一种很常见的宿主机 + `vmbr0` 拓扑，适合放在 Proxmox / KVM / 自建 Linux bridge 环境里：

```text
公网
  |
  | 203.0.113.10
  |
宿主机
  ├─ eth0              公网接口
  └─ vmbr0             虚拟机网桥，198.51.100.1/24
       ├─ VM-A         198.51.100.10   Web / SSH
       └─ VM-B         198.51.100.20   Game / UDP
```

在这个场景下，`forward` 的典型用法通常是：

- 用 `eth0` 作为入口接口，接公网访问
- 用 `vmbr0` 作为出口接口，把流量转给虚拟机
- 让虚拟机默认网关指向宿主机桥地址，例如 `198.51.100.1`

对应到本项目里，可以这样配置：

### 1. SSH 或单端口服务转发到 VM

把宿主机公网 `203.0.113.10:2222` 转发到 `VM-A` 的 `22` 端口：

```text
in_interface  = eth0
in_ip         = 203.0.113.10
in_port       = 2222
out_interface = vmbr0
out_ip        = 198.51.100.10
out_port      = 22
protocol      = tcp
```

### 2. 80/443 建站转发到 VM

把 `app.example.com` 交给 `VM-A`：

```text
domain            = app.example.com
listen_interface  = eth0
listen_ip         = 203.0.113.10
backend_ip        = 198.51.100.10
backend_http_port = 80
backend_https_port= 443
```

这里 `listen_interface = eth0` 表示 80/443 共享代理只在公网入口侧监听；这轮代码也已经确保该字段会真实参与监听绑定，不再只是界面字段。

### 3. 一段游戏端口映射到 VM

把 `30000-30100` 映射到 `VM-B`：

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

### 4. 透传源地址时的注意事项

如果你在 `eth0 -> vmbr0 -> VM` 的路径上启用了“透传源 IP”：

- VM 必须能把回包重新发回宿主机
- 最常见做法是让 VM 默认网关指向 `vmbr0` 的宿主机地址
- 如果 VM 默认网关绕过宿主机，透传通常会失败

也就是说，在上面的例子里，`VM-A` / `VM-B` 的默认网关通常应该是：

```text
198.51.100.1
```

如果你只是做普通 DNAT/端口映射，不要求后端虚拟机看到真实客户端源地址，那么可以不启用透传，配置会更宽松。

## 运行要求

- Go 1.25.1 或更高版本
- 生产环境建议使用 Linux
- 若需要低位端口监听、透明转发或网卡绑定，进程需要相应权限
  - `CAP_NET_BIND_SERVICE`
  - `CAP_NET_RAW`
  - `CAP_NET_ADMIN`
- 若需要 tc eBPF 内核转发，还需要
  - `CAP_BPF`
  - `CAP_PERFMON`（较新的内核上通常需要；缺失时 verifier 可能把程序按 `!root` 路径拒绝）

项目自带的 [deploy.sh](./deploy.sh) 已处理 Debian 系统上的常见权限与 systemd 配置。

## 快速开始

1. 复制示例配置：

```bash
cp config.example.json config.json
```

Windows PowerShell:

```powershell
Copy-Item config.example.json config.json
```

2. 修改 `config.json`，至少把 `web_token` 改成一个真实的随机值。

注意：

- `web_token` 不能为空
- 程序会拒绝使用示例占位值 `change-me-to-a-secure-token` 启动

3. 直接运行：

```bash
go run .
```

4. 打开管理面板：

```text
http://127.0.0.1:8080
```

5. 在登录弹窗里输入 `config.json` 中配置的 `web_token`。

## 配置说明

示例配置见 [config.example.json](./config.example.json)：

```json
{
  "web_port": 8080,
  "web_token": "change-me-to-a-secure-token",
  "max_workers": 0,
  "drain_timeout_hours": 24,
  "default_engine": "auto",
  "kernel_engine_order": ["tc"],
  "kernel_rules_map_limit": 0,
  "kernel_flows_map_limit": 0,
  "kernel_nat_ports_map_limit": 0,
  "experimental_features": {
    "bridge_xdp": false,
    "kernel_traffic_stats": false
  },
  "tags": []
}
```

字段说明：

- `web_port`：Web 管理面板监听端口，默认 `8080`
- `web_token`：管理 API 和前端登录使用的 Bearer Token
- `max_workers`：最大 Worker 数量；小于等于 `0` 时按 CPU 核数自动计算，内部最少保留 3 个 Worker 槽位
- `drain_timeout_hours`：旧 Worker 进入 draining 状态后的最长保留时长，默认 `24`
- `default_engine`：默认转发引擎，可选 `auto`、`userspace`、`kernel`
- `kernel_engine_order`：Linux 内核态引擎尝试顺序，默认 `["tc"]`；当前会自动跳过不可用引擎并回退。如果想显式试验 XDP，再配置成 `["xdp", "tc"]`
- `kernel_rules_map_limit`：内核 `rules_v4/stats_v4` map 容量；`0` 或省略时按当前 kernel entries 自适应扩容，默认从 `16384` 起按 2 倍增长到 `262144`；设置为正数时使用固定上限
- `kernel_flows_map_limit`：内核 `flows_v4` 连接跟踪表容量；`0` 时按内核 entries 的 4 倍目标自适应扩容，默认基线 `131072`，上限 `1048576`
- `kernel_nat_ports_map_limit`：内核 `nat_ports_v4` 端口保留表容量；`0` 时按内核 entries 的 4 倍目标自适应扩容，默认基线 `131072`，上限 `1048576`
- `experimental_features`：实验性功能开关表，默认关闭；像 `bridge_xdp`、`kernel_traffic_stats` 这类高风险、兼容性或性能权衡仍在收敛中的能力会通过这里单独放开
- `tags`：可选标签列表，会在前端表单中作为下拉项出现

示例：

```json
"experimental_features": {
  "bridge_xdp": true,
  "kernel_traffic_stats": true
}
```

说明：

- 键名会按小写、`-` 转 `_` 归一化，例如 `bridge-xdp` 会被视为 `bridge_xdp`
- 只有代码中显式接入检查的实验项才会生效；未接入的键会被保留但不会影响当前行为
- `bridge_xdp` 已接入第一版实验实现，默认仍为关闭；当前主要面向透明 XDP 场景，依赖 bridge 邻居/FDB 解析，解析失败或接口不兼容时会自动回退
- `kernel_traffic_stats` 用于给内核态规则补充 `bytes/speed` 统计；它会在 TC/XDP 转发路径上增加按包计数，默认关闭，只建议在确实需要观察内核态流量时启用

## 内核引擎与回退链

`forward` 当前的引擎选择逻辑是：

- `default_engine = userspace`：全部走用户态 Worker
- `default_engine = kernel`：优先要求进入内核态；不满足条件时仍会安全回退到用户态
- `default_engine = auto`：先尝试内核态，再自动回退到用户态
- Linux 下内核态会按 `kernel_engine_order` 依次尝试；默认只走 `tc`，如果显式配置 `["xdp", "tc"]` 才会优先尝试 XDP

当前想进入内核态，通常至少需要满足：

- 规则协议必须是单协议 `tcp` 或 `udp`，不能是同一条规则里的 `tcp+udp`
- 必须显式指定 `in_interface` 和 `out_interface`
- 必须有明确的后端 IPv4 地址
- `in_ip` 需要是有效 IPv4；`0.0.0.0` 可以接受，但仍要求显式入接口
- 非透传的 full-NAT 场景下，出接口上需要有可用 IPv4，或者显式指定 `out_source_ip`
- `transparent=true` 和固定 `out_source_ip` 互斥

当前两条内核链路的定位大致是：

- `XDP`：优先级更高，路径更短，但当前主要覆盖透明、单协议、接口条件较理想的规则；桥接出口相关能力仍主要通过 `bridge_xdp` 实验开关控制
- `TC`：覆盖面更广，是当前更通用、更稳妥的内核转发后备路径；很多 XDP 无法接入的规则最终会回落到 TC

补充说明：

- 端口范围映射进入内核态时，会展开成逐端口的 kernel entries，因此大范围映射需要关注 `kernel_rules_map_limit`
- 默认不会强行抖动现有内核会话；运行时更倾向保留活跃映射并在条件允许时原地更新
- `kernel_traffic_stats` 默认关闭，不打开时不会额外在内核路径上维护速率/流量统计

### 内核态生命周期与异常退出预期

- 正常停止服务时，例如 `systemctl stop forward`、`systemctl restart forward` 或给主进程发送 `SIGTERM`，当前 TC/XDP 附加点会按正常退出流程清理或进入热更新接力
- 使用 [deploy.sh](./deploy.sh) 更新时，程序会尝试保留内核态会话表并由新进程接力；这是“尽量不断流”的热更新路径，不等于强一致零中断承诺
- 如果主进程被 `kill -9`、OOM kill 或异常崩溃，userspace 清理逻辑不会执行；已经附加到内核的 TC/XDP 转发可能继续生效一段时间
- 当前版本会在下次启动时检查并清理这类 orphan 的内核态附加点，但它不能让 `kill -9` 当下立刻停止转发
- 如果你的目标是“进程退出后立刻停转发”，应使用正常停止路径，而不要把 `kill -9` 视为内核态的即时停机手段

### 内核态运行时观测

- 统计页新增 `Kernel Runtime` 面板，会展示当前内核态总状态、内核承载规则/范围数量、回退计数、待重试状态，以及每个内核引擎的 map 占用、附加点和最近一次 reconcile 方式
- 同时提供 `GET /api/kernel/runtime` 调试接口，便于脚本或外部面板直接读取这些运行时信息
- 这套观测主要面向调试和联调，不打算作为当前版本的生产告警接口

## 性能测试说明

仓库内附带 Linux-only dataplane benchmark，主要用于做两类评估：

- `pps` 评估：更关注小包包速率、连接规模和 `userspace / tc / xdp` 的相对差异
- `throughput` 评估：更关注大流量 TCP 吞吐，更接近日常 `iperf3` 使用方式

需要注意：

- 基准测试默认使用 `netns + veth` 拓扑，不等于真实物理网卡线速
- 关闭 offload 的结果更适合看软件路径和小包 `pps`
- 保留 offload 的结果更适合看大流 TCP 吞吐
- `XDP` 在部分 offload / 设备组合下仍可能无法加载，因此当前吞吐结论主要基于 `userspace` 与 `tc`
- 当前 benchmark 主要用于调试环境下比较 dataplane 路径差异，不作为生产容量承诺

### 小包 PPS 参考

测试口径：

- UDP steady
- `64B` payload
- `8192` 总连接
- `16` 活跃连接
- `FORWARD_PERF_DISABLE_OFFLOADS=1`
- `FORWARD_PERF_BACKEND_WORKERS=8`

参考结果：

| Engine | Payload PPS | Payload Throughput |
| --- | ---: | ---: |
| TC | `~119.5k pps` | `~7.30 MiB/s` |
| XDP | `~122.1k pps` | `~7.45 MiB/s` |

这一组更适合说明：在当前软件拓扑下，小包场景里 `XDP` 相对 `TC` 仍有小幅优势，但绝对值会明显受到 benchmark 拓扑、helper 与 offload 策略影响。

### 大流吞吐参考

测试口径：

- TCP 单向上传流
- `FORWARD_PERF_TCP_MODE=upload`
- `16` 连接 / `16` 并发
- `512 MiB` per connection
- `128 KiB` chunk
- `FORWARD_PERF_DISABLE_OFFLOADS=0`
- `go test -count=3`

参考结果：

| Engine | Scenario | Payload Throughput |
| --- | --- | ---: |
| Userspace | `16 streams` | `~3076-3444 MiB/s` |
| TC | `16 streams` | `~4947-4969 MiB/s` |

说明：

- 这一组已经更接近常规 `iperf3` 风格的大流 TCP 单向吞吐测试
- `Userspace` 在该实验模型下大致处于 `~25.8-28.9 Gbps` 区间，3 次复测均值约 `3248 MiB/s`
- `TC` 在该实验模型下大致处于 `~41.5-41.7 Gbps` 区间，3 次复测均值约 `4956 MiB/s`
- 同口径下 `TC` 相比 `Userspace` 提升约 `52%`
- `TC` 在 `veth` / 内存路径下可以高于真实 `10G NIC` 线速，这更像软件路径上限，不应直接等价为真实物理网卡吞吐
- 在同机 `netns + veth` 基准里，`32 streams` 及以上的 TCP upload 结果会开始明显受到本机 socket / softirq / veth 竞争影响；这类结果更像测试拓扑的极限，不建议直接作为真实部署下的 `TC` 聚合吞吐结论
- 因此更推荐把 `4-16 streams` 视为较有参考价值的聚合吞吐区间
- 如果目标是接近线上网卡表现，建议重点参考 `payload_mib_per_sec`，不要把实验环境下的 `wire` 估算值直接当作物理链路线速

## 构建

本地构建：

```bash
go build -o forward .
```

交叉编译 Linux 版本：

```bash
./release.sh
```

`release.sh` 会先用 `clang` 编译 `internal/app/ebpf/forward-tc-bpf.o` 和 `internal/app/ebpf/forward-xdp-bpf.o`，再把它们 embed 进最终二进制，因此构建机需要可用的 `clang` 和 Linux 内核头文件。
在 Debian / Ubuntu 上，通常至少需要安装 `clang` 和 `linux-libc-dev`。

只构建指定架构：

```bash
./release.sh amd64
./release.sh arm64
```

## 部署

项目自带 Debian 部署脚本 [deploy.sh](./deploy.sh)。

常见流程：

```bash
./release.sh amd64
scp forward-linux-amd64 deploy.sh root@server:/tmp/
ssh root@server 'cd /tmp && chmod +x deploy.sh && ./deploy.sh'
```

部署脚本会自动完成：

- 安装二进制到 `/opt/forward`
- 生成 `config.json`
- 创建并启用 systemd 服务
- 放行 Web / HTTP / HTTPS 端口
- 打开 `net.ipv4.ip_forward`

## 运行时文件

下面这些文件默认不建议提交到 Git：

- `config.json`
- `forward.db`
- `forward.db-wal`
- `forward.db-shm`
- 本地编译产物，如 `forward`、`forward-linux-amd64`

这轮已经通过 [.gitignore](./.gitignore) 预设好了。

## WHMCS 插件

仓库内附带一个可单独部署的 WHMCS addon 插件，源码位于：

```text
plugins/whmcs/forward/
```

插件目录包含以下内容：

- `forward.php`：WHMCS addon 主入口
- `templates/`：客户区模板
- `assets/`：客户区样式资源
- `lang/`：语言文件
- `import_haproxy.py`：HAProxy 规则导入脚本

这个目录是仓库内的源码位置，不是 WHMCS 最终运行路径。部署到 WHMCS 时，应把整个目录放到：

```text
modules/addons/forward/
```

也就是说，最终目录名仍然必须是 `forward`，因为插件运行时模块名、客户区路由和资源路径都按 `forward` 解析。

当前这套 WHMCS 插件已经按“多宿主机、多 forward 端点”场景做了收敛，重点能力包括：

- 支持按 `serverID` 映射入口 IP 池：`server_ip_server_map`
- 支持按 `serverID` 映射不同的 forward API / Token：`api_server_map`
- 客户区可按产品与服务 IP 自动收敛可用入口 IP，避免跨宿主机误配
- 管理员可以限制客户区允许的产品、客户端目标 IP、协议和端口范围
- 管理员可以单独控制客户区是否允许编辑以下字段：
  - 规则：`listen_ip`、`protocol`、`description`
  - 站点：`listen_ip`、`backend_http_port` / `backend_https_port`、`description`
- `transparent`、`out_source_ip`、`backend_source_ip`、接口字段和默认标签属于管理员侧控制项，客户区不会直接放开

如果你是在多母鸡环境下给 VM 做 NAT / 端口转发，推荐至少配置：

- `server_ip_server_map`
- `api_server_map`
- `client_min_port` / `client_max_port`
- 需要的话再收紧 `client_rule_edit_*` 与 `client_site_edit_*`

## 项目结构

```text
.
├─ main.go                  精简入口
├─ internal/
│  └─ app/
│     ├─ run.go             主程序启动流程
│     ├─ api.go             Web UI 与管理 API
│     ├─ procmgr.go         Worker 调度与 draining 管理
│     ├─ worker.go          端口转发 Worker
│     ├─ range_worker.go    范围映射 Worker
│     ├─ shared_proxy.go    共享建站代理
│     ├─ db.go              SQLite 初始化与迁移
│     ├─ config.go          配置加载
│     ├─ dataplane.go       用户态 / 内核态引擎规划
│     ├─ kernel_runtime*.go 内核态运行时
│     ├─ ebpf/              eBPF 源码与编译产物
│     └─ web/               内置前端资源
├─ release.sh               交叉编译脚本
├─ deploy.sh                Debian 部署脚本
├─ plugins/
│  └─ whmcs/
│     └─ forward/           WHMCS addon 插件源码
```

## 安全建议

- 不要把真实的 `config.json` 提交到公开仓库
- 不要在 README、Issue 或截图中暴露 `web_token`
- 如果服务暴露到公网，建议额外放在反向代理或受限网络环境之后

## License

本仓库当前使用 [MIT License](./LICENSE)。
