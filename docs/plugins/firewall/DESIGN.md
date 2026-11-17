# Firewall 插件设计（草案）

状态：P0 已实现（`plugins/firewall/`，lab）；P1、P2 未实现。适用宿主：Veer dev（e011ecb 之后，`xdp_generic` 默认开启），插件 ABI `control_api_abi=1`、`dataplane.xdp_pipeline.v1`。

## 1. 背景与目标

Veer 的端口转发目前不能按来源限制访问：知道入口端口的任何人都能发起连接。在一台生产宿主机上实测，转发到 Windows 远程桌面的公网端口在白天每小时收到 3–6 万个 SYN，绝大部分来自扫描器；同机还有多条转发到 SSH 的规则，同样暴露在公网。

目标：

- 按目标端口（和可选的目标地址）配置来源 CIDR 的放行/拒绝，IPv4 与 IPv6 都支持。
- 对 TCP 新建连接（SYN）按来源限速，超限后临时封禁。
- 在包进入协议栈和 Veer 核心之前丢弃，丢弃路径尽量便宜；不影响已建立连接的转发性能，尤其不能让 TC 连接缓存失效。
- 不用的人零开销；与随仓库维护的插件、Veer 的各个数据面引擎、常见网卡和内核版本兼容，冲突时明确报错而不是静默失效。
- 规则修改不能把管理员锁在外面。

非目标（第一版）：

- 有状态防火墙（"默认拒绝入站、只放行回包"）。XDP 拿不到核心的连接表，这类策略交给 nftables。
- 出站过滤、LAN 内部过滤、VPN 入口过滤。
- 七层识别、GeoIP、按 VLAN 区分策略。

## 2. 结论：XDP 数据面插件

### 2.1 为什么不放进核心

- 核心程序的指令预算已经很紧：最大的 `forward_ingress_v4_plugin_continue` 用 clang 14 编译后是 25751 条静态指令，6.x 内核的 16 位跳转修补上限约 27k；5.15.0-25 的 verifier 对单个程序最多处理到 507k，上限是 100 万。
- 插件只在启用时加载；没有 XDP Hook 时 Dispatcher 会从接口完全卸载，热路径不增加任何 lookup（见 [PLUGIN.md](../../PLUGIN.md) "XDP 数据面插件"）。
- 插件按目标地址/端口匹配，保护范围不限于 Veer 的规则：宿主机自己的 SSH、管理端口、桥接了公网地址的 VM 都能覆盖。
- 插件有独立的签名、发布、原子安装与回滚，以及 `state_maps` 的状态保留。

### 2.2 为什么是 XDP 而不是 TC Hook

TC 插件 Hook 和连接缓存互斥：只要某个接口上有 TC 插件 Hook，进入该接口的包就不再写连接缓存记录（[forward-tc-bpf.c](../../../internal/app/ebpf/forward-tc-bpf.c) 的 `tc_flow_cache_writable()` → `tc_flow_cache_plugin_hooked()`），因为缓存命中的包会绕过插件链。把防火墙挂在 WAN 口的 TC `pre_forward` 上，会让该口所有入站转发失去连接缓存，并给每个包加两次 tail call。

XDP Hook 不计入这个判断（它只读 TC 的插件配置），在 TC 之前运行，丢弃发生在分配 skb 之前，开销比 TC 更低。

Netfilter Hook 也不合适：TC 核心在 ingress 就 redirect 了转发流量，这些包根本不经过 netfilter。

### 2.3 原生与 generic 两种模式都是正式路径

先区分三个概念：硬件 offload（程序跑在网卡上，几乎没有网卡支持，防火墙也不需要）、原生 XDP（驱动模式，在驱动分配 skb 之前执行）、generic XDP（skb 模式，在 `__netif_receive_skb_core` 开头执行，仍早于 TC ingress 和 Veer 核心）。

原生 XDP 在不少常见环境里没有：

- 软路由和小主机常见的 Realtek 网卡（主线 `r8169` 驱动，包括 RTL8125 2.5G）、Intel `e1000`/`e1000e`、USB 网卡；
- 虚拟和 L3 设备：bridge、VLAN、macvlan、PPP、WireGuard、tun。

所以 generic 模式是正式支持的路径，不是不推荐的退路。按接口自动选择：能原生就原生，否则 generic。

两种模式的差别：

| | 原生 | generic |
|---|---|---|
| 执行时机 | 驱动收包、分配 skb 之前 | skb 已分配，GRO 之后、TC 之前 |
| 丢包能省掉 | skb 分配、GRO、协议栈、Veer 核心 | 协议栈、Veer 核心 |
| 额外开销 | 无 | 每个 skb 转成 xdp_buff；非线性或被 clone 的 skb 要先复制成线性缓冲区（GRO 聚合包基本都是非线性的），大流量 TCP 每个聚合包多一次最多约 64 KB 的复制，小包不受影响 |
| 可用接口 | 驱动支持的网卡 | 任何接口，包括 L3 设备 |

在软路由常见的 1–2.5 Gbps 下，generic 的复制开销大约是一个核心的几个百分点，需要实测（第 8 节）。

和 TC 比：TC 没有复制，但目前宿主只允许 `observe` 模式的 TC Hook 直接挂在接口上（`buildDesiredPluginDataplane` 拒绝其他模式），能丢包的 TC Hook 只能进有序 pipeline，而那会关闭该接口的连接缓存并给每个包加两次 tail call。所以在没有原生 XDP 的接口上，generic XDP 是当前最合适的选择；宿主补上"直接挂载、排在核心之前、能丢包"的 TC 模式之后，再评估是否改用 TC（第 9 节）。

其他代价：

- 只能做无状态过滤（见第 1 节非目标）。
- generic 模式由顶层设置 `xdp_generic` 控制，默认开启（原先是默认关闭的实验功能）；Dispatcher 在所有接口上先试原生模式（`xdpPluginAttachOrder`），驱动不支持时再用 generic。
- 只要有 XDP 插件 Hook 处于运行状态，核心转发就固定走 TC（[kernel_runtime_chain_linux.go](../../../internal/app/kernel_runtime_chain_linux.go) `entriesForCatalogLocked`）。选择了 XDP 转发引擎的用户启用防火墙后会退回 TC，界面和文档必须提示。

## 3. 功能范围与分期

| 阶段 | 内容 |
|---|---|
| P0 | 策略：协议 + 目标端口范围 + 可选目标 CIDR；来源 CIDR 列表按最长前缀给出放行/拒绝，未命中走策略默认动作；全局信任来源；原生 XDP 挂载到用户选定接口；802.1Q/802.1ad 与 PPPoE 会话解析；按策略计数；应用后限时确认、超时回滚 |
| P1 | TCP SYN 按来源限速与临时封禁；封禁列表查看与手动解封；抽样丢包日志 |
| P2 | UDP 按来源限包速；ICMP/任意协议的仅来源策略；从 Veer 规则导入（需要宿主能力，见第 9 节）；正式支持 VPN/L3 入口 |

## 4. 数据面设计

### 4.1 挂载与 Hook 声明

```js
ebpf.loadObject({
  id: 'firewall', path: OBJECT_PATH, sha256: crypto.sha256File(OBJECT_PATH),
  programs: [{id: 'filter', section: 'xdp/veer/firewall', type: 'xdp'}],
  state_maps: [
    {name: 'fw_rate', policy: 'preserve', schema_version: 1},
    {name: 'fw_ban', policy: 'preserve', schema_version: 1},
    {name: 'fw_stats', policy: 'preserve', schema_version: 1}
  ]
});
hooks.attach({
  id: 'wan-filter', engine: 'xdp', stage: 'pre_forward', priority: 10,
  program: 'firewall:filter', mode: 'drop', binding_required: true
});
```

- `binding_required: true` 配合 `hook_bindings` 资源（与 pppoe_client、vpn_core 相同的模式）：接口完全由用户选择，记录缺失时不挂载，不会退化成全局 Hook。
- priority 10，排在未来其他 XDP 插件之前；需要先解封装（例如 VXLAN）再过滤的插件用 `before/after` 明确顺序。
- 每个接口占用 1 个 XDP Hook，接口上限是 14 个，整机上限 32 个。
- 所有规则表、限速、封禁与计数 map 都声明 `preserve`（ring buffer 不能声明）。插件对象更新时复用旧 map；Veer 热重启时，宿主把这些 map pin 下来交给新进程（`plugin_map_handoff_linux.go`），新的 Dispatcher 接管时规则已经在 map 里，计数和封禁继续累计。宿主不能接管时（旧版本宿主、map 布局变化），map 从空开始，控制面按快照重写，见第 6.2 节。

### 4.2 包解析

按顺序解析，任何一步不认识就 `PASS`（fail-open）：

1. 以太网头；最多两层 802.1Q/802.1ad 标签（`VEER_MAX_VLAN_DEPTH`）。开启硬件 VLAN 剥离的网卡上 XDP 看不到标签，策略不依赖 VLAN。PPP、WireGuard、tun 这类 L3 设备在 generic 模式下没有以太网头，包直接从 IP 头开始：控制面在 `fw_ifaces`（ifindex → 链路类型）里标出这些接口，程序据此跳过 L2 解析，IP 版本从首字节判断。
2. PPPoE 会话（ethertype `0x8864`）：6 字节 PPPoE 头加 2 字节 PPP 协议号，`0x0021` 视为 IPv4，`0x0057` 视为 IPv6。发现阶段（`0x8863`）和 PPP 控制协议（LCP/IPCP/IPV6CP/PAP/CHAP）一律 `PASS`，否则会断开拨号。
3. IPv4：校验 IHL；分片偏移非 0（非首片）时没有端口，直接 `PASS`。
4. IPv6：自己遍历扩展头（最多 6 个，L4 偏移不超过 2047 字节）；遇到偏移非 0 的分片头时 `PASS`。没有用 helper 的 `veer_ipv6_l4`：它用包指针推进，每条路径的偏移范围都不同，verifier 无法合并，这个程序会被展开到约 28 万条指令；这里改用整数偏移，每步检查上界后再经 asm 屏障掩码成 0–2047，处理量降到约 1.6 万条。
5. 只处理 TCP 与 UDP（P0/P1），其他协议 `PASS`。只读 L4 头的前 4 字节（端口），不要求完整的 TCP 头。
6. **规避解析的包**：IPv6 扩展头超过 6 个或 L4 起点超过 2047 字节，以及首片里读不到端口的 IPv4/IPv6 分片。Linux 会照常接收并重组这些包，放行就等于绕过过滤，所以只要当前规则集里有策略就丢弃，并计入全局计数；没有策略时照常放行。

### 4.3 匹配模型

一条策略（policy）包含：

- `protocol`：`tcp` / `udp` / `tcp+udp`
- `ports`：若干目标端口区间
- `destinations`：可选目标 CIDR 列表，空表示任意目标
- `default_action`：`allow` 或 `drop`
- `sources`：CIDR → `allow` / `drop` 列表，按最长前缀匹配；未命中时用 `default_action`。纯白名单就是 `default_action=drop` 加一组 `allow`；纯黑名单反过来。
- `syn_limit`（P1）：`{max_new, window_seconds, ban_seconds}`

另有全局 `trusted_sources`：命中即放行，跳过所有策略和封禁，用于管理网段，防止锁死。

同一协议、端口和目标上的策略不允许重叠，由控制面校验时拒绝。

### 4.4 Map 布局

| Map | 类型 | Key → Value | 说明 |
|---|---|---|---|
| `fw_cfg` | ARRAY[1] | 0 → {当前代, 标志} | 原子切换的 selector；标志：有 L3 接口、有策略、控制面已写入（区分重启后的空 map） |
| `fw_ifaces` | HASH 64 | ifindex → 链路类型（以太网 / 无 L2） | 由控制面按绑定接口写入；未登记的接口按以太网处理 |
| `fw_port_bits` | ARRAY[2×2×1024] u64 | (代, 协议, 端口/64) → 位图 | 快速路径：位为 0 的端口直接放行；32 KiB |
| `fw_ports` | LPM_TRIE 16384 | (代, 协议, 端口前缀) → 端口类 | 端口区间按对齐的 2 的幂块拆分，一个区间最多约 30 个前缀；单个端口数组的写法要为 1–65535 这样的区间写 65535 次，超出事务上限 |
| `fw_class` | ARRAY[2×1024] | (代, 端口类) → {任意目标策略, 有带目标的策略} | 端口类由控制面对端口区间做划分得到，256 条策略最多 513 类 |
| `fw_dst4` / `fw_dst6` | LPM_TRIE | (代, 端口类, 目标地址) → 策略槽位 | 只在端口类声明了带目标的策略时查 |
| `fw_policy` | ARRAY[2×256] | (代, 策略槽位) → {默认动作, 限速参数, 标志} | |
| `fw_src4` / `fw_src6` | LPM_TRIE | (代, 策略槽位, 来源地址) → allow/drop | 策略槽位 0 保留给全局信任来源 |
| `fw_ban` | LRU_HASH 65536 | (地址族, 来源前缀, 策略槽位) → 封禁截止时间 ns | P1 |
| `fw_rate` | LRU_HASH 65536 | (地址族, 来源前缀, 策略槽位) → {窗口起点, 计数} | P1 |
| `fw_stats` | PERCPU_ARRAY | 策略槽位 × 计数项 → u64 | 槽位与策略记录的映射存 KV，跨编辑保持稳定 |
| `fw_events` | RINGBUF 256 KiB | 抽样丢包事件 | P1，BPF 侧每 CPU 令牌桶限流 |

来源前缀：IPv4 取 /32，IPv6 默认取 /64（可配），防止攻击者在一个 /64 里换地址绕过限速和封禁。

内存估算（4 CPU）：端口位图 32 KiB，两个 LRU（P1）合计约十几 MiB，LPM 视条目数而定。远低于宿主默认预算（单 map 64 MiB、单插件 256 MiB，见 `plugin_resource_limits.go`）。

### 4.5 每包流程

```text
规避解析且当前代有策略 ................................... DROP(evasive)
解析失败 / 非 TCP、UDP / 非首片 ................................ PASS
g = fw_cfg.generation; 位图 fw_port_bits[g][proto][dport] 为 0 ... PASS   ← 未保护端口：2 次数组查找
cls = fw_ports LPM; policy = 带目标策略 ? fw_dst LPM : fw_class.any
信任来源 LPM 命中 ............................................. PASS
封禁命中且未过期 ...................................... DROP(ban)
来源 LPM（未命中用默认动作） → drop .................... DROP(acl)
TCP SYN 且无 ACK 且策略有限速：窗口计数 +1，超限写封禁 ... DROP(rate)
...................................................... PASS → veer_xdp_continue
```

未保护端口的流量（绝大多数已建立连接和出站连接的回包）只多两次数组查找加上解析。只有被保护端口上的包才会走 LPM。

### 4.6 SYN 限速与封禁（P1）

- 固定窗口计数：`fw_rate` 的值是 `{window_start_ns, count}`。窗口过期就重置；用 `__sync_fetch_and_add` 计数，在 `-mcpu=v1` 下编译成 XADD，5.10 可用。v1 的 XADD 不返回旧值，代码不能使用它的返回值，加完后再读一次计数判断是否超限。多 CPU 并发时允许有少量误差。
- 超限时向 `fw_ban` 写入 `now + ban_seconds`；过期条目在下次查到时视为不存在，LRU 负责回收空间。
- 手动解封：控制面 `ebpf.mapDelete`。LRU 不能放进 `mapTransaction`（宿主会拒绝），逐条操作即可。
- 只对 SYN 计数，所以已建立连接的包不会触发限速。

### 4.7 原子更新

使用 `ebpf.mapTransaction` 的 commit 模式（[PLUGIN.md](../../PLUGIN.md) "ebpf.map_transactions.v1"）：

1. 控制面先扫描 LPM map，删掉非活动代的旧条目，再写入新条目；数组 map 按 KV 里记录的上次写入位置清零后写入（没有记录时整代清零）。
2. 最后一步单独 `mapPut fw_cfg`，切到新代。包路径只读 selector 指向的那一代，不会看到一半新一半旧的规则。
3. 单个事务最多 256 个操作、1 MiB，所以写非活动代时分多个事务；任何一步失败都不切换，旧代继续生效，状态标为 dirty 并定时重试。

### 4.8 计数与日志

- 每策略计数：匹配、放行、ACL 丢弃、封禁丢弃、限速丢弃，外加全局的解析放行和非首片放行。控制面用 `ebpf.mapGetPerCPU` 汇总。
- XDP 丢弃的包对 tcpdump 和 TC 观察插件都不可见（AF_PACKET 和 TC 都在 XDP 之后）。排障只能依赖本插件的计数和日志，界面上要写明。
- 抽样丢包日志（P1）：`ebpf.ringSubscribe` 投递给 worker，在内存里保留最近 N 条，不落库。BPF 侧限流，防止被攻击时把 ring 打满。

### 4.9 指令与 verifier 预算

- 单个程序，无 tail call（Dispatcher 的 continue 除外）；所有循环有界（VLAN ≤ 2、IPv6 扩展头 ≤ 6）。
- 实测（P0）：静态指令 790–850 条；verifier 处理量 6.12 约 1.6 万、5.10.0-32 约 1.7–1.8 万、5.15.0-25 约 3.0–3.2 万（clang 14/18/21）。
- 与核心一样用 `-mcpu=v1` 构建（5.10 会拒绝 v3 的原子指令），并用 clang 14、18、21 在 5.10.0-32、5.15.0-25、6.12 上验证；条件选出的指针在判空前同样要隐藏在 asm 屏障后。

## 5. 控制面设计

### 5.1 Manifest

```json
{
  "id": "firewall", "kind": "pipeline", "stability": "lab",
  "compatibility": {
    "runtime": ">=1.0.0 <2.0.0", "control_api_abi": 1,
    "os": ["linux"], "architectures": ["amd64", "arm64"], "kernel": ">=5.10.0",
    "features": ["dataplane.xdp_pipeline.v1", "dataplane.hook_bindings.v1",
                 "ebpf.map_state.v1", "ebpf.map_transactions.v1", "ui.capabilities.v1"]
  },
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "resource", "kv", "timer", "ui",
                    "ebpf.load", "ebpf.map_read", "ebpf.map_write", "hook.attach", "worker"]
  }
}
```

P1 的抽样日志需要额外声明 `ebpf.ring_push.v1`。

### 5.2 资源与动作

| 名称 | 类型 | 说明 |
|---|---|---|
| `policies` | 资源，带 JSON Schema | 第 4.3 节的策略；上限 256 条，每条来源最多 1024 个 CIDR |
| `settings` | 资源 | 记录 `default`：`interfaces`、`trusted_sources`、`confirm_timeout_seconds`（30–600，默认 120） |
| `snapshots` | 资源，界面只读 | 记录 `applied` 和 `confirmed`：各是一份完整规则集（策略记录加设置），单条最大 1 MiB，一次写入即原子替换；Veer 重启后按它重建 map |
| `hook_bindings` | 资源，界面只读 | 挂载接口，记录对应 Hook `wan-filter`；只由 apply 和回滚写入 |
| `apply` | 动作，`runtime_apply` | 校验草稿、绑定接口、写入非活动代并切换，启动确认计时器 |
| `confirm` | 动作，`runtime_apply` | 取消计时器，把这次规则集记为已确认 |
| `rollback` | 动作，`runtime_apply` | 回到上一次已确认的规则集 |
| `status` | 动作，`runtime_query` | 当前代、确认截止时间、每策略计数、规避丢包数、草稿是否与已应用的一致 |
| `interfaces` | 动作，`runtime_query` | 可绑定的接口及其类型、上级网桥、是否 L3 |
| `bans` / `unban` | 动作（P1） | 分页读取封禁列表（`mapScan` 每页 ≤ 256 条）/ 手动解封 |

`apply` 等改动状态的动作用 `runtime_apply`，宿主把处理函数的错误返回给界面；`runtime_query` 动作的结果才会出现在 HTTP 响应里，所以界面应用后再调用 `status` 读取结果。

### 5.3 防止锁死

宿主不把调用者地址传给动作处理函数，插件无法判断"这次修改会不会挡住自己"。因此采用两层保护：

1. **应用后限时确认**：`apply` 之后用 `timer.setTimeout` 计时（默认 120 秒）。界面在应用成功后自动调用 `confirm`；如果新规则挡住了管理员，浏览器就发不出 `confirm`，计时器到期后回滚到上一次已确认的规则集。等待确认时 Veer 重启（新进程的 map 是空的），恢复的是上一次已确认的规则集，不是未确认的那份；截止时间在 Veer 停机期间过去的，下次 reconcile 时回滚。
2. **校验与提示**（未实现）：策略覆盖 Veer 管理端口（`web_port`）或 22 端口、且没有配置 `trusted_sources` 时，要求显式确认。

### 5.4 校验规则

- CIDR 规范化，去掉主机位；IPv4 映射的 IPv6 地址按 IPv4 处理。
- 同一协议、端口和目标上的策略不能重叠。
- 端口区间与常见回包端口重叠时警告（未实现）：Veer 的内核 NAT 端口池默认 20000–65535，扣除宿主临时端口后实际窗口是 20000–32767；宿主出站连接的回包落在 `ip_local_port_range`。无状态的 `default_action=drop` 覆盖这些端口会打断出站连接的回包。插件目前读不到实际的 NAT 窗口（见第 9 节），先按默认值警告。
- 端口类和 LPM 条目超出容量时拒绝，不截断。

## 6. 兼容性

### 6.1 与随仓库维护的插件

| 插件 | 数据面位置 | 关系与处理 |
|---|---|---|
| pppoe_client | TC `pre_forward`，priority 20，挂在 PPPoE 物理口和本地边界的 ingress；有 kfuncs 时另挂本地边界 egress | 防火墙在同一物理口的 XDP 上先执行，看到的是 PPPoE 会话帧，必须解析 PPPoE（第 4.2 节），发现阶段和 PPP 控制帧一律放行。不经过 TC，不影响 PPPoE 的 TC 链 |
| wan_core（direct / segmented_veth / direct_gro） | 解封装在物理口的 TC 上；direct_gro 经 kfunc 把回包送入 `veerwan` | 同上：XDP 在物理口看到的是解封装之前的帧。防火墙不挂在 `veerwan`、`local0` 或 pipeline veth 这类内部边界上 |
| vpn_core | TC `pre_forward` priority 20，挂在隧道接口 | VPN 入口是 tun 或 WireGuard 这类 L3 设备，只能用 generic 模式加无 L2 解析。VPN 多用作出口，主动入站很少，第一版不把它作为目标；绑定后也能工作，XDP 在它的 TC Hook 之前执行 |
| lan_core / vtolocal / 托管网络 | 内部 bridge、tap、dummy | 不是防火墙的目标接口；绑定 bridge 只能用 generic 模式，界面提示改选物理口 |
| packet_observer 及其他 TC 观察插件 | TC | 看不到被 XDP 丢弃的包，这是预期行为 |
| router_wizard | 只做编排 | 第一版不集成；以后可以通过 typed service 提供"保护管理端口"之类的一键操作 |
| 未来的 XDP 插件 | 同一 Dispatcher | 按 priority 和 `before/after` 排序；Hook 数量受每接口 14 个、整机 32 个的上限约束，超限时只拒绝放不下的那个插件 |

### 6.2 与 Veer 核心

| 方面 | 影响 |
|---|---|
| TC 引擎与连接缓存 | 不受影响：XDP Hook 不计入 `tc_flow_cache_plugin_hooked()`，放行的包照常进入 TC 核心和连接缓存 |
| XDP 转发引擎 | 有任何运行中的 XDP 插件 Hook，核心就固定走 TC，启用防火墙前需提示 |
| 用户态引擎、共享站点（80/443） | 覆盖：XDP 在协议栈之前 |
| Egress NAT | 回包落在 NAT 端口窗口，不要用拒绝默认动作覆盖这些端口（第 5.4 节） |
| 透明转发与 Full NAT | XDP 看到的是原始包：来源是真实客户端，目标是入口地址和端口，与规则类型无关 |
| Veer 热重启 | 旧进程不卸载 Dispatcher，旧链一直运行到新进程用 `XDP_FLAGS_REPLACE` 原子替换（需要 Linux 5.7+，Veer 最低 5.10）。新链用的是旧进程交来的同一份 map，所以没有不过滤的窗口，计数和封禁也不清零。集成测试在热重启期间从被拒来源持续发起连接：宿主不交接 map 时漏过 13 个，交接后为 0。等待确认中的规则集照常等待，控制面按剩余时间重新设置截止定时器（插件定时器不跨进程）。宿主不能接管 map 时，控制面按快照重写，等待确认的规则集回滚到上一次已确认的 |
| `veer hot-restart check` | 只检查核心的 TC map；插件 map 的保留由插件 `state_maps` 契约负责 |
| 管理面 | 防火墙可以挡住管理端口，靠第 5.3 节防锁死 |

### 6.3 网卡与驱动

| 情况 | 说明 |
|---|---|
| 原生 XDP | igb、igc、ixgbe、i40e、ice、mlx5、bnxt、virtio_net、ena、hv_netvsc、veth 等支持；vmxnet3 需要 6.6+ |
| 没有原生 XDP | Realtek `r8169`（含 RTL8125）、`e1000`/`e1000e`、USB 网卡、无线网卡，以及 bridge、VLAN、macvlan、PPP、WireGuard、tun。用 generic 模式，代价见 2.3 |
| 首次挂载 / 最后卸载 | 不少驱动在"无程序 ↔ 有程序"切换时会重建收包队列（例如 igb 会 close/open 设备），造成短暂断流；替换程序不会。启用和停用防火墙应安排在维护窗口；启用期间即使没有策略也保持 Hook 挂载，避免反复切换 |
| 巨帧 MTU | Dispatcher 和插件都不支持 XDP 多缓冲区（`xdp.frags`），MTU 超过驱动单缓冲区上限（很多驱动约 3.5 KB）时原生挂载会失败，需要宿主侧支持（第 9 节） |
| bridge | 挂在成员物理口能看到所有入站包（包括直接桥接给 VM 的）；挂在 bridge 本身（generic）只看到上送宿主的包，也就是 Veer 核心要处理的那部分 |
| VLAN 子接口 / PPP / WireGuard / tun | generic 模式可用；L3 设备按 4.2 的无 L2 方式解析。能挂到下层物理口时优先挂物理口 |
| bond | 挂在 bond 主设备上（较新内核对常见模式支持原生 XDP），不要挂在成员口 |
| 接口上已有其他 XDP 程序 | Veer 不替换，该接口报冲突，其余接口照常挂载 |
| 硬件 VLAN 剥离 | XDP 可能看不到标签；策略本来就不按 VLAN 区分 |
| 多队列 / RSS | 计数用 per-CPU；限速计数用原子加，并发下允许少量误差 |

### 6.4 内核与发行版

- 最低 5.10（与 Veer 一致）。用到的能力：XDP、LPM_TRIE、LRU_HASH、PERCPU_ARRAY、`bpf_ktime_get_ns`、XADD；RINGBUF 需要 5.8+。
- 验证矩阵：clang 14 / 18 / 21 × 5.10.0-32 / 5.15.0-25 / 6.12，外加一个 7.x 内核（例如当前的 PVE 内核）。
- 架构 amd64 / arm64，按插件包规范为每个架构分别声明 sha256。

### 6.5 部署形态

| 形态 | 建议 |
|---|---|
| PVE / KVM 宿主，公网口接在 vmbr0 | 挂在 vmbr0 下面的物理口（例如 `enp*`），不是 vmbr0；桥接在 vmbr0 上的公网 VM 也一起受保护 |
| 云主机 | virtio_net、ENA、hv_netvsc 有原生 XDP；ENA 对 MTU 有上限；Azure 加速网络的流量走 VF，需挂在 netvsc 设备上，由内核转发给 VF |
| PPPoE 家用路由 / 软路由 | 挂在 PPPoE 物理口，依赖第 4.2 节的 PPPoE 解析；Realtek 网卡上走 generic 模式 |
| 多 WAN | 每个 WAN 物理口各绑定一次 |
| LXC / 无特权容器 | 不能加载 BPF，插件包预检会拒绝，不会半装 |

### 6.6 与系统防火墙

XDP 在 nftables、iptables 和 pve-firewall 之前执行，只会丢弃、不会放行它们本来要拒绝的包，两者是叠加关系。被 XDP 丢弃的包不会出现在 nftables 的计数里。

## 7. 失败与降级

一律 fail-open：防火墙出问题时流量照常通过，不会把服务挡掉。

| 失败 | 结果 |
|---|---|
| object 加载或 verifier 拒绝 | 插件进入 error，不挂载，流量不受影响 |
| 某个接口挂载失败 | 只有该接口没有保护，`status` 显示原因；其余接口照常 |
| 规则事务失败 | 不提交 selector，旧代继续生效 |
| 应用后未确认 | 计时器到期后回滚到上一次已确认的规则集 |
| 插件停用或卸载 | Dispatcher 卸载（可能引发驱动重建队列，见 6.3） |
| Veer 热重启 | Dispatcher 交接期间旧链生效，新链沿用同一份 map；宿主不能接管 map 时，新链接管到规则写完之间可能短暂不过滤（见 6.2） |
| ring 满 / worker 慢 | 只丢日志，不影响过滤 |

## 8. 测试计划

- **BPF 单元测试**（`BPF_PROG_TEST_RUN`，XDP 支持）：IPv4/IPv6；单层和两层 VLAN；PPPoE 会话里的 IPv4/IPv6、PPPoE 发现帧、LCP；IPv4 首片和非首片；IPv6 扩展头和分片；SYN、SYN-ACK、ACK；最长前缀优先级；信任来源优先于封禁；两代规则切换；未保护端口快速放行；截断包。
- **verifier 矩阵**：沿用测试机的 `verifytool2` 和 QEMU 来宾，覆盖第 6.4 节的组合，并记录静态指令数和验证处理量。
- **集成测试**（测试机，veth 原生 XDP）：
  - 端口转发只放行白名单来源；
  - SYN 洪泛触发封禁，封禁到期自动解除；
  - 防火墙与 Veer TC 转发同时运行时，连接缓存命中率不变；
  - 应用后不确认会自动回滚；
  - 已启用 XDP 转发引擎时，防火墙启用后核心切换到 TC，界面给出提示；
  - Veer 热重启期间，被拒来源持续发包，统计有多少个包漏过、漏过的时间窗口多长，以及封禁能否从 KV 快照恢复（扩展现有的 `kernel_plugin_xdp_handoff_linux_test.go`）。
- **多插件共存**：在 pppoe_client 黑盒测试（`plugins/pppoe_client/test-blackbox-linux.sh`）的拓扑上，在 PPPoE 物理口启用防火墙，验证拨号、保活和转发都正常；与 vpn_core 同时启用。
- **性能**：
  - 未保护流量：沿用 `TestDataplanePerfMatrix`，分别在原生和 generic 模式下（veth 两种模式都支持）对比启用前后的大流量 TCP 和 64 字节 UDP 包速。原生目标损失 < 3%；generic 重点看大流量 TCP，量化 GRO 聚合包复制的开销；
  - 攻击场景：SYN 洪泛下的丢包速率，与 nftables 在 ingress 的 drop 规则对比。
- **CI**：插件对象加入 `scripts/verify-plugin-release.sh` 的构建和 kernel-load-matrix，单元测试加入 core_tests 列表。

## 9. 需要宿主补充的能力

第 1、6 项已完成；其余不阻塞：

1. ~~插件 map 跨 Veer 热重启保留~~：已实现。声明 `preserve` 的 TC pipeline、XDP、Netfilter 插件 map 由旧进程 pin 到热重启目录，新进程按 `state_maps` 契约接管，启动 reconcile 后释放。vpn_core 的 `tunnel_links` 没有声明 `state_maps`，仍由控制面重写。
2. **只读获取核心转发规则**：插件目前只能写 `forward_rule_plans`，读不到用户在核心里配的规则。P2 的"从 Veer 规则导入"需要一个只读资源或宿主 API。
3. **获取 NAT 端口窗口和 `ip_local_port_range`**：用于第 5.4 节的精确校验，替代按默认值警告。
4. **动作处理函数拿到调用者地址**：可以在应用前就判断新规则会不会挡住当前管理员。
5. **Dispatcher 支持 `xdp.frags`**：解除巨帧 MTU 限制。
6. ~~插件 Hook 单独允许 generic 模式~~：已改为 `xdp_generic` 顶层设置默认开启，插件 Dispatcher 先试原生、再用 generic。如果以后需要按 Hook 指定模式，再加 `xdp_mode: auto | native | generic`。
7. **直接挂载、能丢包的 TC Hook**：目前只有 `observe` 模式能直接挂在接口上，能丢包的必须进 pipeline 并因此关闭连接缓存。增加一种排在核心之前、可以返回丢弃、不计入 `tc_flow_cache_plugin_hooked()` 的直接挂载模式后，没有原生 XDP 的接口可以改用 TC，省掉 generic 的复制开销。
8. **XDP 转发引擎接入 Dispatcher 链末端**：避免启用 XDP 插件就让核心退回 TC。

## 10. 待定问题

1. 插件 ID 用 `firewall` 还是带前缀的名字（例如 `veer_firewall`）。
2. P0 是否就包含 SYN 限速（P1），还是先只发 ACL。
3. 封禁按策略还是全局：按策略更精确，全局更省内存，也能挡住对多个端口扫描的来源。
4. 是否需要按接口区分策略（例如不同 WAN 用不同策略），还是统一一套。
5. 抽样日志保留多少条、是否允许导出。
