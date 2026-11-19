# Firewall 插件设计（草案）

状态：P0、P1 已实现，以 stable 1.0.0 随默认插件包发布（`plugins/firewall/`，当前 1.0.1：TCP 首片读不到标志位时按规避解析丢弃）；P2 未实现。适用宿主：Veer dev（e011ecb 之后，`xdp_generic` 默认开启），插件 ABI `control_api_abi=1`、`dataplane.xdp_pipeline.v1`、`dataplane.xdp_tc_fallback.v1`。

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

没有原生 XDP 的接口上，同一个 Hook 改跑它的 `tc_fallback`：同一 object 里的 tc 程序 `tc_firewall`，直接挂在 TC ingress 最前面，排在 Veer 核心之前（见 2.3）。它不是 TC 插件 Hook，同样不计入 `tc_flow_cache_plugin_hooked()`，也不经过 tail call。

Netfilter Hook 也不合适：TC 核心在 ingress 就 redirect 了转发流量，这些包根本不经过 netfilter。

### 2.3 原生 XDP 与 TC 兜底

先区分几个概念：硬件 offload（程序跑在网卡上，几乎没有网卡支持，防火墙也不需要）、原生 XDP（驱动模式，在驱动分配 skb 之前执行）、generic XDP（skb 模式，在 `__netif_receive_skb_core` 开头执行，仍早于 TC ingress 和 Veer 核心），以及 TC 兜底（同一过滤逻辑编成的 tc 程序，直接挂在 TC ingress 最前面）。

原生 XDP 在不少常见环境里没有：

- 软路由和小主机常见的 Realtek 网卡（主线 `r8169` 驱动，包括 RTL8125 2.5G）、Intel `e1000`/`e1000e`、USB 网卡；
- 虚拟和 L3 设备：bridge、VLAN、macvlan、PPP、WireGuard、tun；
- MTU 超过驱动单缓冲区上限的接口（Dispatcher 不支持 XDP 多缓冲区）。

这些接口上运行 TC 兜底，它和原生 XDP 都是正式路径。按接口自动选择：宿主先试原生模式，失败就把 Hook 的 `tc_fallback` 挂到 TC ingress。同一接口上还有其他插件不带 `tc_fallback` 的 XDP Hook 时，XDP 和 TC 同时挂：排在防火墙前面的那些 Hook 由 generic 模式的 Dispatcher 执行，防火墙仍在 TC 执行，Dispatcher 在该接口上跳过它，只判一次。只有排在防火墙后面的 Hook 没有兜底（generic 一定先于 TC，防火墙不能挪到它后面），或开启了实验项 `xdp_plugin_no_tc_fallback` 时，防火墙才在 generic XDP 里运行。

| | 原生 XDP | TC 兜底 | generic XDP |
|---|---|---|---|
| 执行时机 | 驱动收包、分配 skb 之前 | GRO 之后，TC ingress 最前面（tcx 列表头，或优先级 1–8 的 cls_bpf，跟随核心的挂载方式） | GRO 之后、TC 之前 |
| 丢包能省掉 | skb 分配、GRO、协议栈、Veer 核心 | 协议栈、Veer 核心 | 协议栈、Veer 核心 |
| 额外开销 | 无 | 不复制；一个 GRO 聚合包只判断一次；头部不在线性区时才 `bpf_skb_pull_data` | 每个 skb 转成 xdp_buff，非线性或被 clone 的 skb 先复制成线性缓冲区：GRO 聚合包每个最多复制约 64 KB |
| 可用接口 | 驱动支持的网卡 | 任何接口，包括 L3 设备 | 任何接口 |
| tcpdump | 看不到被丢的包 | 能看到（抓包点在 TC 之前），看不出被丢 | 看不到 |

generic XDP 的复制与程序无关：veth 上一个只返回 XDP_PASS 的空程序同样让大流量 TCP 少约 40%（第 8 节）。TC 兜底读的是原地的 skb，大流量 TCP 的结果见第 8 节。

其他代价：

- 只能做无状态过滤（见第 1 节非目标）。
- 宿主在所有接口上先试原生模式（`xdpPluginAttachOrder`）。原生失败时用 TC 兜底；退回 generic 时还受顶层设置 `xdp_generic` 控制（默认开启）。
- TC 兜底的计数按 skb 计：一个 GRO 聚合包算一个包，字节数照实。
- 只要有 XDP 插件 Hook 处于运行状态，核心转发就固定走 TC（[kernel_runtime_chain_linux.go](../../../internal/app/kernel_runtime_chain_linux.go) `entriesForCatalogLocked`）。选择了 XDP 转发引擎的用户启用防火墙后会退回 TC，界面和文档必须提示。

## 3. 功能范围与分期

| 阶段 | 内容 |
|---|---|
| P0 | 策略：协议 + 目标端口范围 + 可选目标 CIDR；来源 CIDR 列表按最长前缀给出放行/拒绝，未命中走策略默认动作；全局信任来源；原生 XDP 挂载到用户选定接口；802.1Q/802.1ad 与 PPPoE 会话解析；按策略计数；应用后限时确认、超时回滚 |
| P1（已实现） | TCP SYN 按来源限速与临时封禁；封禁列表查看与手动解封；抽样丢包日志 |
| P2 | UDP 按来源限包速；ICMP/任意协议的仅来源策略；从 Veer 规则导入（需要宿主能力，见第 9 节）；正式支持 VPN/L3 入口 |

## 4. 数据面设计

### 4.1 挂载与 Hook 声明

```js
ebpf.loadObject({
  id: 'firewall', path: OBJECT_PATH, sha256: crypto.sha256File(OBJECT_PATH),
  programs: [
    {id: 'filter', section: 'xdp/veer/firewall', type: 'xdp'},
    {id: 'filter_tc', section: 'tc/veer/firewall', type: 'tc'}
  ],
  state_maps: [
    {name: 'fw_rate', policy: 'preserve', schema_version: 1},
    {name: 'fw_ban', policy: 'preserve', schema_version: 1},
    {name: 'fw_stats', policy: 'preserve', schema_version: 1}
  ]
});
hooks.attach({
  id: 'wan-filter', engine: 'xdp', stage: 'pre_forward', priority: 10,
  program: 'firewall:filter', tc_fallback: 'firewall:filter_tc',
  mode: 'drop', binding_required: true
});
```

- 两个程序共用同一份解析和判定代码（`fw_parse`、`fw_judge`），也共用 object 里的全部 map，控制面只维护一份状态。`tc_firewall` 放行返回 `TC_ACT_UNSPEC`（继续交给核心），丢弃返回 `TC_ACT_SHOT`。

- `binding_required: true` 配合 `hook_bindings` 资源（与 pppoe_client、vpn_core 相同的模式）：接口完全由用户选择，记录缺失时不挂载，不会退化成全局 Hook。
- priority 10，排在未来其他 XDP 插件之前；需要先解封装（例如 VXLAN）再过滤的插件用 `before/after` 明确顺序。
- 每个接口占用 1 个 XDP Hook，接口上限是 14 个，整机上限 32 个。
- 所有规则表、限速、封禁与计数 map 都声明 `preserve`（ring buffer 不能声明）。插件对象更新时复用旧 map；Veer 热重启时，宿主把这些 map pin 下来交给新进程（`plugin_map_handoff_linux.go`），新的 Dispatcher 接管时规则已经在 map 里，计数和封禁继续累计。宿主不能接管时（旧版本宿主、map 布局变化），map 从空开始，控制面按快照重写，见第 6.2 节。

### 4.2 包解析

按顺序解析，任何一步不认识就 `PASS`（fail-open）：

1. 以太网头；最多两层 802.1Q/802.1ad 标签（`VEER_MAX_VLAN_DEPTH`）。开启硬件 VLAN 剥离的网卡上 XDP 看不到标签，策略不依赖 VLAN。PPP、WireGuard、tun 这类 L3 设备在 TC 兜底和 generic 模式下没有以太网头，包直接从 IP 头开始：控制面在 `fw_ifaces`（ifindex → 链路类型）里标出这些接口，程序据此跳过 L2 解析，IP 版本从首字节判断。
2. PPPoE 会话（ethertype `0x8864`）：6 字节 PPPoE 头加 2 字节 PPP 协议号，`0x0021` 视为 IPv4，`0x0057` 视为 IPv6。发现阶段（`0x8863`）和 PPP 控制协议（LCP/IPCP/IPV6CP/PAP/CHAP）一律 `PASS`，否则会断开拨号。
3. IPv4：校验 IHL；分片偏移非 0（非首片）时没有端口，直接 `PASS`。
4. IPv6：自己遍历扩展头（最多 6 个，L4 偏移不超过 2047 字节）；遇到偏移非 0 的分片头时 `PASS`。没有用 helper 的 `veer_ipv6_l4`：它用包指针推进，每条路径的偏移范围都不同，verifier 无法合并，这个程序会被展开到约 28 万条指令；这里改用整数偏移，每步检查上界后再经 asm 屏障掩码成 0–2047，处理量降到约 1.6 万条。
5. 只处理 TCP 与 UDP（P0/P1），其他协议 `PASS`。只读 L4 头的前 4 字节（端口），不要求完整的 TCP 头；分片的首片除外，TCP 首片还要带上第 14 字节的标志位，SYN 限速靠它认出新连接。
6. **规避解析的包**：IPv6 扩展头超过 6 个或 L4 起点超过 2047 字节，以及首片里读不到端口（TCP 首片还有标志位）的 IPv4/IPv6 分片。Linux 会照常接收并重组这些包，放行就等于绕过过滤，所以只要当前规则集里有策略就丢弃，并计入全局计数；没有策略时照常放行。

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
| `fw_policy` | ARRAY[2×256] | (代, 策略槽位) → {标志, 默认动作} | 标志：有效、有 SYN 限速 |
| `fw_limit` | ARRAY[2×256] | (代, 策略槽位) → {每窗口新连接数, 窗口秒, 封禁秒, IPv6 前缀, IPv6 掩码 16 字节} | 与规则同代切换；掩码由控制面算好，见 4.6 |
| `fw_src4` / `fw_src6` | LPM_TRIE | (代, 策略槽位, 来源地址) → allow/drop | 策略槽位 0 保留给全局信任来源 |
| `fw_ban` | LRU_HASH 65536 | {地址族, 前缀长度, 策略槽位, 来源地址（掩码后）} → 封禁截止时间（ktime ns） | 过期条目查到时忽略，由 LRU 回收 |
| `fw_rate` | LRU_HASH 65536 | 同 `fw_ban` → {窗口起点 ns, 计数} | |
| `fw_stats` | PERCPU_ARRAY | 策略槽位 × 4 → u64：放行、丢弃（所有原因）、信任；槽位 0 的第 4 项是规避解析丢弃 | 槽位与策略记录的映射存 KV，跨编辑保持稳定 |
| `fw_lstats` | PERCPU_ARRAY | 策略槽位 × 4 → u64：封禁丢弃、限速丢弃；槽位 0 另记日志写入数和 ring 满丢失数 | 新加的 map，不改 `fw_stats` 布局，从 0.1.0 升级时状态 map 照常接管 |
| `fw_log_cfg` / `fw_log_tat` | ARRAY[1] / PERCPU_ARRAY[1] | 日志速率（GCRA 的间隔和容差）/ 每 CPU 下一事件的理论到达时间 | |
| `fw_events` | RINGBUF 256 KiB | 抽样丢包事件（56 字节：时间、接口、策略槽位、原因、协议、端口、来源和目标地址） | 不能声明 state_maps；BPF 侧每 CPU 限流 |

来源前缀：IPv4 取 /32，IPv6 默认取 /64（可配），防止攻击者在一个 /64 里换地址绕过限速和封禁。

内存估算（4 CPU）：端口位图 32 KiB，两个 LRU 合计约十几 MiB，ring 256 KiB，LPM 视条目数而定。远低于宿主默认预算（单 map 64 MiB、单插件 256 MiB，见 `plugin_resource_limits.go`）。

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

### 4.6 SYN 限速与封禁（P1，已实现）

- 固定窗口计数：`fw_rate` 的值是 `{window_start_ns, count}`。窗口过期就重置；用 `__sync_fetch_and_add` 计数，在 `-mcpu=v1` 下编译成 XADD，5.10 可用。v1 的 XADD 不返回旧值，代码不能使用它的返回值，加完后再读一次计数判断是否超限。多 CPU 并发时允许有少量误差。
- 超限时向 `fw_ban` 写入 `now + ban_seconds`；过期条目在下次查到时视为不存在，LRU 负责回收空间。
- 手动解封：控制面 `ebpf.mapDelete`。LRU 不能放进 `mapTransaction`（宿主会拒绝），逐条操作即可。
- 只对 SYN 计数，所以已建立连接的包不会触发限速。
- 策略写法：`syn_limit: {max_new, window_seconds, ban_seconds, ipv6_prefix}`，只允许含 TCP 的策略。`ban_seconds` 为 0 时只丢超限的 SYN、不封禁；`ipv6_prefix` 默认 64（32–128）。封禁按策略：同一来源在别的策略上不受影响。
- 判定顺序：信任来源 → 封禁 → 来源规则 → SYN 限速。被来源规则丢弃的包不计入限速；封禁也作用于来源规则放行的地址。
- IPv6 掩码由控制面按前缀算好写进 `fw_limit`，程序只做按字节与。逐字节按前缀算掩码时，clang 14 把每个字节编译成分支，栈上掩码各不相同让 verifier 无法合并路径：5.10/5.15 上超过 100 万条被拒。改成查表后为 3.9 万 / 5.7 万。
- 槽位被新策略接管时，控制面先删掉这个槽位在 `fw_ban`、`fw_rate` 里的旧条目；`unban` 同时删掉对应的 `fw_rate` 计数，否则下一个 SYN 又会立刻封禁。

### 4.7 原子更新

使用 `ebpf.mapTransaction` 的 commit 模式（[PLUGIN.md](../../PLUGIN.md) "ebpf.map_transactions.v1"）：

1. 控制面先扫描 LPM map，删掉非活动代的旧条目，再写入新条目；数组 map 按 KV 里记录的上次写入位置清零后写入（没有记录时整代清零）。
2. 最后一步单独 `mapPut fw_cfg`，切到新代。包路径只读 selector 指向的那一代，不会看到一半新一半旧的规则。
3. 单个事务最多 256 个操作、1 MiB，所以写非活动代时分多个事务；任何一步失败都不切换，旧代继续生效，状态标为 dirty 并定时重试。

### 4.8 计数与日志

- 每策略计数：匹配、放行、ACL 丢弃、封禁丢弃、限速丢弃，外加全局的解析放行和非首片放行。控制面用 `ebpf.mapGetPerCPU` 汇总。
- XDP 丢弃的包对 tcpdump 和 TC 观察插件都不可见（AF_PACKET 和 TC 都在 XDP 之后）。排障只能依赖本插件的计数和日志，界面上要写明。
- 抽样丢包日志（P1，已实现）：所有丢包原因（规则、封禁、限速、规避解析）都可能写日志。BPF 侧每个 CPU 一个 GCRA 限流，速率由设置 `log_per_second` 决定（默认 10，0 关闭），突发上限等于每秒条数。`ebpf.ringSubscribe` 把批次投递给 `drop_log` worker，worker 在内存里保留最近 500 条，`events` 动作经 `worker.call` 读取，不落库，Veer 重启后清空。时间戳是 ktime，宿主提供单调时钟时换算成墙钟时间。

### 4.9 指令与 verifier 预算

- 每个入口一个程序，无 tail call（Dispatcher 的 continue 除外）；所有循环有界（VLAN ≤ 2、IPv6 扩展头 ≤ 6）。
- 实测（P0）：静态指令 790–850 条；verifier 处理量 6.12 约 1.6 万、5.10.0-32 约 1.7–1.8 万、5.15.0-25 约 3.0–3.2 万（clang 14/18/21）。
- 实测（P1）：静态指令 1505–1694 条；verifier 处理量 6.12 约 3.0–3.8 万、5.10.0-32 约 3.0–3.9 万、5.15.0-25 约 5.2–5.7 万（clang 14/18/21）。所有丢包路径汇到程序入口的同一个出口，日志代码只内联一份。
- 加入 TC 兜底后（拆出 `fw_parse`/`fw_judge`）：`xdp_firewall` 静态指令 1359–1731 条，verifier 处理量 2.3–3.8 万；`tc_firewall` 静态 2083–2646 条，处理量 4.0–6.0 万（clang 14/18/21 × 5.10.0-32、5.15.0-25、6.12，18 种组合全部通过）。
- 与核心一样用 `-mcpu=v1` 构建（5.10 会拒绝 v3 的原子指令），并用 clang 14、18、21 在 5.10.0-32、5.15.0-25、6.12 上验证；条件选出的指针在判空前同样要隐藏在 asm 屏障后。

## 5. 控制面设计

### 5.1 Manifest

```json
{
  "id": "firewall", "version": "1.0.1", "kind": "pipeline", "stability": "stable",
  "compatibility": {
    "runtime": ">=1.0.0 <2.0.0", "control_api_abi": 1, "tc_pipeline_abi": 2,
    "os": ["linux"], "architectures": ["amd64", "arm64"], "kernel": ">=5.10.0",
    "features": ["dataplane.xdp_pipeline.v1", "dataplane.hook_bindings.v1",
                 "ebpf.map_state.v1", "ebpf.map_transactions.v1", "ui.capabilities.v1"]
  },
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "resource", "kv", "timer", "ui", "crypto", "net.admin",
                    "ebpf.load", "ebpf.map_read", "ebpf.map_write", "hook.attach", "worker"]
  }
}
```

抽样丢包日志需要 `worker` 权限和 `ebpf.ring_push.v1` feature。

### 5.2 资源与动作

| 名称 | 类型 | 说明 |
|---|---|---|
| `policies` | 资源，带 JSON Schema | 第 4.3 节的策略；上限 256 条，每条来源最多 1024 个 CIDR |
| `settings` | 资源 | 记录 `default`：`interfaces`、`trusted_sources`、`confirm_timeout_seconds`（30–600，默认 120）、`log_per_second`（0–1000，默认 10） |
| `snapshots` | 资源，界面只读 | 记录 `applied` 和 `confirmed`：各是一份完整规则集（策略记录加设置），单条最大 1 MiB，一次写入即原子替换；Veer 重启后按它重建 map |
| `hook_bindings` | 资源，界面只读 | 挂载接口，记录对应 Hook `wan-filter`；只由 apply 和回滚写入 |
| `check` | 动作，`runtime_query` | 校验草稿，不写任何东西：返回阻止应用的错误、需要确认的提示（第 5.3、5.4 节）和这组提示的 token |
| `apply` | 动作，`runtime_apply` | 校验草稿（有提示时 `accept_warnings` 必须等于 `check` 返回的 token）、绑定接口、写入非活动代并切换，启动确认计时器 |
| `confirm` | 动作，`runtime_apply` | 取消计时器，把这次规则集记为已确认 |
| `rollback` | 动作，`runtime_apply` | 回到上一次已确认的规则集 |
| `status` | 动作，`runtime_query` | 当前代、确认截止时间、每策略计数、规避丢包数、草稿是否与已应用的一致 |
| `interfaces` | 动作，`runtime_query` | 可绑定的接口及其类型、上级网桥、是否 L3 |
| `bans` | 动作，`runtime_query` | 分页读取封禁（`mapScan` 每页 ≤ 256 条）：来源前缀、策略、剩余秒数；宿主提供单调时钟时跳过已过期的 |
| `unban` | 动作，`runtime_apply` | `{key}` 解除一条、`{policy}` 解除一条策略的全部、`{all: true}` 全部解除；同时清掉该来源的 SYN 计数 |
| `events` | 动作，`runtime_query` | 最近的抽样丢包，新的在前，附策略名和接口名 |

`apply` 等改动状态的动作用 `runtime_apply`，宿主把处理函数的错误返回给界面；`runtime_query` 动作的结果才会出现在 HTTP 响应里，所以界面应用后再调用 `status` 读取结果。

### 5.3 防止锁死

宿主不把调用者地址传给动作处理函数，插件无法判断"这次修改会不会挡住自己"。因此采用两层保护：

1. **应用后限时确认**：`apply` 之后用 `timer.setTimeout` 计时（默认 120 秒）。界面在应用成功后自动调用 `confirm`；如果新规则挡住了管理员，浏览器就发不出 `confirm`，计时器到期后回滚到上一次已确认的规则集。等待确认时 Veer 重启（新进程的 map 是空的），恢复的是上一次已确认的规则集，不是未确认的那份；截止时间在 Veer 停机期间过去的，下次 reconcile 时回滚。
2. **应用前提示**：默认丢弃的 TCP 策略覆盖 22（SSH）、8006（Proxmox VE）或 8080（Veer 默认 `web_port`），且没有配置 `trusted_sources` 时，`check` 给出提示。插件读不到 Veer 实际的 `web_port`，改过端口的只有第 1 层保护。提示连同第 5.4 节的回包提示一起算出 token；`apply` 只在 `accept_warnings` 等于当前 token 时执行，所以直接调用 API 也绕不过去；`check` 之后草稿又变了，token 就对不上，要重新 `check`。界面把提示列在页面上方，应用时确认框写明提示条数。

### 5.4 校验规则

- CIDR 规范化，去掉主机位；IPv4 映射的 IPv6 地址按 IPv4 处理。
- 同一协议、端口和目标上的策略不能重叠。
- 端口与回包端口重叠时提示（需要确认，见第 5.3 节）：Veer 的内核 NAT 端口池默认 20000–65535，扣除宿主临时端口后实际窗口是 20000–32767；宿主出站连接的回包落在 `ip_local_port_range`（Linux 默认 32768–60999）。无状态的 `default_action=drop` 覆盖这些端口会丢掉出站连接的回包。默认丢弃的策略覆盖 NAT 窗口里的任何端口，或者用端口区间覆盖临时端口时提示；临时端口里的单个端口不提示，因为本机有程序监听该端口时内核不会把它分给出站连接。插件读不到实际的 NAT 窗口和 `ip_local_port_range`（见第 9 节），按默认值判断。
- 端口类和 LPM 条目超出容量时拒绝，不截断。

## 6. 兼容性

### 6.1 与随仓库维护的插件

| 插件 | 数据面位置 | 关系与处理 |
|---|---|---|
| pppoe_client | TC `pre_forward`，priority 20，挂在 PPPoE 物理口和本地边界的 ingress；有 kfuncs 时另挂本地边界 egress | 防火墙在同一物理口的 XDP 上先执行，看到的是 PPPoE 会话帧，必须解析 PPPoE（第 4.2 节），发现阶段和 PPP 控制帧一律放行。不经过 TC，不影响 PPPoE 的 TC 链 |
| wan_core（direct / segmented_veth / direct_gro） | 解封装在物理口的 TC 上；direct_gro 经 kfunc 把回包送入 `veerwan` | 同上：XDP 在物理口看到的是解封装之前的帧。防火墙不挂在 `veerwan`、`local0` 或 pipeline veth 这类内部边界上 |
| vpn_core | TC `pre_forward` priority 20，挂在隧道接口 | VPN 入口是 tun 或 WireGuard 这类 L3 设备，没有原生 XDP，走 TC 兜底加无 L2 解析。VPN 多用作出口，主动入站很少，第一版不把它作为目标；绑定后也能工作，XDP 在它的 TC Hook 之前执行 |
| lan_core / vtolocal / 托管网络 | 内部 bridge、tap、dummy | 不是防火墙的目标接口；绑定 bridge 走 TC 兜底，只看到上送宿主的包，界面提示改选物理口 |
| packet_observer 及其他 TC 观察插件 | TC | 看不到被 XDP 丢弃的包，这是预期行为 |
| router_wizard | 只做编排 | 第一版不集成；以后可以通过 typed service 提供"保护管理端口"之类的一键操作 |
| 未来的 XDP 插件 | 同一 Dispatcher | 按 priority 和 `before/after` 排序；Hook 数量受每接口 14 个、整机 32 个的上限约束，超限时只拒绝放不下的那个插件 |

### 6.2 与 Veer 核心

| 方面 | 影响 |
|---|---|
| TC 引擎与连接缓存 | 不受影响：XDP Hook 和它的 TC 兜底都不计入 `tc_flow_cache_plugin_hooked()`，放行的包照常进入 TC 核心和连接缓存 |
| XDP 转发引擎 | 有任何运行中的 XDP 插件 Hook，核心就固定走 TC：核心的 XDP 引擎从接口上整体卸载（不只是清空规则），插件 Dispatcher 随后挂载；Hook 全部撤掉时先卸 Dispatcher，核心再回到 XDP。Veer 优先用 XDP 引擎时，界面给出提示（`plugin.host()` 的 `kernel_engine_order` 和 `core_engine_pinned_to_tc`）。`TestFirewallSystemXDPEnginePinning` 覆盖往返 |
| 用户态引擎、共享站点（80/443） | 覆盖：XDP 在协议栈之前 |
| Egress NAT | 回包落在 NAT 端口窗口，不要用拒绝默认动作覆盖这些端口（第 5.4 节） |
| 透明转发与 Full NAT | XDP 看到的是原始包：来源是真实客户端，目标是入口地址和端口，与规则类型无关 |
| Veer 热重启 | 旧进程不卸载 Dispatcher，旧链一直运行到新进程用 `XDP_FLAGS_REPLACE` 原子替换（需要 Linux 5.7+，Veer 最低 5.10）。TC 兜底同样不断档：tcx link 由旧进程 pin 住、cls_bpf filter 留在原位，新进程按相同位置原地换程序。新链用的是旧进程交来的同一份 map，所以没有不过滤的窗口，计数和封禁也不清零。集成测试在热重启期间从被拒来源持续发起连接：宿主不交接 map 时漏过 13 个，交接后为 0。等待确认中的规则集照常等待，控制面按剩余时间重新设置截止定时器（插件定时器不跨进程）。宿主不能接管 map 时，控制面按快照重写，等待确认的规则集回滚到上一次已确认的 |
| `veer hot-restart check` | 只检查核心的 TC map；插件 map 的保留由插件 `state_maps` 契约负责 |
| 管理面 | 防火墙可以挡住管理端口，靠第 5.3 节防锁死 |

### 6.3 网卡与驱动

| 情况 | 说明 |
|---|---|
| 原生 XDP | igb、igc、ixgbe、i40e、ice、mlx5、bnxt、virtio_net、ena、hv_netvsc、veth 等支持；vmxnet3 需要 6.6+ |
| 没有原生 XDP | Realtek `r8169`（含 RTL8125）、`e1000`/`e1000e`、USB 网卡、无线网卡，以及 bridge、VLAN、macvlan、PPP、WireGuard、tun。运行 TC 兜底，见 2.3 |
| 首次挂载 / 最后卸载 | 不少驱动在"无程序 ↔ 有程序"切换时会重建收包队列（例如 igb 会 close/open 设备），造成短暂断流；替换程序不会。启用和停用防火墙应安排在维护窗口；启用期间即使没有策略也保持 Hook 挂载，避免反复切换 |
| 巨帧 MTU | Dispatcher 和插件都不支持 XDP 多缓冲区（`xdp.frags`），MTU 超过驱动单缓冲区上限（很多驱动约 3.5 KB）时原生挂载会失败，改走 TC 兜底 |
| bridge | 挂在成员物理口能看到所有入站包（包括直接桥接给 VM 的）；挂在 bridge 本身（TC 兜底）只看到上送宿主的包，也就是 Veer 核心要处理的那部分 |
| VLAN 子接口 / PPP / WireGuard / tun | TC 兜底可用（TC 看到的外层 VLAN 标签已在 `skb->vlan_tci` 里）；L3 设备按 4.2 的无 L2 方式解析。能挂到下层物理口时优先挂物理口 |
| bond | 挂在 bond 主设备上（较新内核对常见模式支持原生 XDP），不要挂在成员口 |
| 接口上已有其他 XDP 程序 | Veer 不替换，该接口报冲突，其余接口照常挂载 |
| 硬件 VLAN 剥离 | XDP 可能看不到标签；策略本来就不按 VLAN 区分 |
| 多队列 / RSS | 计数用 per-CPU；限速计数用原子加，并发下允许少量误差 |

### 6.4 内核与发行版

- 最低 5.10（与 Veer 一致）。用到的能力：XDP、LPM_TRIE、LRU_HASH、PERCPU_ARRAY、`bpf_ktime_get_ns`、XADD；RINGBUF 需要 5.8+。
- 验证矩阵：clang 14 / 18 / 21 × 5.10.0-32 / 5.15.0-25 / 6.12（测试机，P1 实测见 4.9），外加 CI kernel-load-matrix 覆盖的各个 runner 内核（含 7.x）。
- 架构 amd64 / arm64：BPF 字节码与 CPU 架构无关（两者都是小端），一个 object 两边通用，控制面加载时用 `crypto.sha256File` 校验；`veer plugin test` 对两种架构都通过。

### 6.5 部署形态

| 形态 | 建议 |
|---|---|
| PVE / KVM 宿主，公网口接在 vmbr0 | 挂在 vmbr0 下面的物理口（例如 `enp*`），不是 vmbr0；桥接在 vmbr0 上的公网 VM 也一起受保护 |
| 云主机 | virtio_net、ENA、hv_netvsc 有原生 XDP；ENA 对 MTU 有上限；Azure 加速网络的流量走 VF，需挂在 netvsc 设备上，由内核转发给 VF |
| PPPoE 家用路由 / 软路由 | 挂在 PPPoE 物理口，依赖第 4.2 节的 PPPoE 解析；Realtek 网卡上走 TC 兜底 |
| 多 WAN | 每个 WAN 物理口各绑定一次 |
| LXC / 无特权容器 | 不能加载 BPF，插件包预检会拒绝，不会半装 |

### 6.6 与系统防火墙

XDP 在 nftables、iptables 和 pve-firewall 之前执行，只会丢弃、不会放行它们本来要拒绝的包，两者是叠加关系。被 XDP 丢弃的包不会出现在 nftables 的计数里。

## 7. 失败与降级

一律 fail-open：防火墙出问题时流量照常通过，不会把服务挡掉。

| 失败 | 结果 |
|---|---|
| object 加载或 verifier 拒绝 | 插件运行时报错（`runtime.error`，插件本身仍是启用状态），不挂载，流量不受影响；冷重启后同样（`TestFirewallSystemBrokenObjectFailsOpen`） |
| 某个接口挂载失败 | `status.attachments` 按接口显示挂载状态、模式（driver / generic / tc）和错误；宿主报挂载错误时，`apply` 回滚到上一次确认的规则并报错，页面不会确认一份没生效的规则 |
| 规则事务失败 | 不提交 selector，旧代继续生效 |
| 应用后未确认 | 计时器到期后回滚到上一次已确认的规则集 |
| 插件停用或卸载 | Dispatcher 卸载（可能引发驱动重建队列，见 6.3）；重新启用后约 3–5 秒内恢复过滤（同步重试），`TestFirewallSystemDisableDetaches` 覆盖 |
| Veer 热重启 | Dispatcher 交接期间旧链生效，新链沿用同一份 map；宿主不能接管 map 时，新链接管到规则写完之间可能短暂不过滤（见 6.2） |
| ring 满 / worker 慢 | 只丢日志，不影响过滤 |

## 8. 测试

已实现的测试（Linux 测试都要求 root，并在 `scripts/verify-plugin-release.sh` 里出现 skip 即失败）：

- **控制面单元测试**（node，`plugins/firewall/test-*.test.js`，33 个）：编译与 map 布局、端口区间与冲突、提示规则和 token、SYN 限速校验与掩码、封禁和日志解码；apply / confirm / 截止回滚 / 重启恢复 / 热重启保留、check 与 accept_warnings、限速与日志配置写入、bans / unban / events、槽位复用清理、宿主按 key 排序存储后的草稿比较、挂载状态与核心引擎、挂载失败回滚。
- **BPF 单元测试**（`BPF_PROG_TEST_RUN`）：`TestFirewallProgramVerdicts`（IPv4/IPv6、单层和两层 VLAN、PPPoE 会话、发现帧与 LCP、IPv4/IPv6 首片和非首片、扩展头与过多扩展头、截断包、L3 接口、最长前缀、信任来源、带目标的策略）、`TestFirewallProgramWithoutConfigPasses`、`TestFirewallMapKeysMatchCompiler`（Go 与 compile.js 的 key 字节一致）、`TestFirewallProgramSynLimit`（窗口内放行、超限丢弃并封禁、封禁对已建立连接生效、其他策略不受影响、ACK 与 SYN-ACK 不计数、信任来源不受限、规则丢弃不计入限速、IPv6 按 /64 聚合、过期封禁失效、`ban_seconds` 为 0 只丢不封、日志事件内容、日志限流与关闭）。以上对 clang 14、18、21 编出的 object 都跑过。 每个程序测试都分 `xdp`、`tc` 两个子测试，分别跑 `xdp_firewall` 和 `tc_firewall`（测试机 69 个通过）；TC 下 30 字节截断帧跳过（`BPF_PROG_RUN` 拒收 34 字节以下、IP 头不完整的 TC 帧），线性区之外的头部也测不了（`BPF_PROG_RUN` 只造线性 skb），拉取路径由性能测试里的 GSO 聚合包间接覆盖（受保护端口的包全部按策略放行计数）。
- **宿主 TC 兜底**：`TestKernelXDPPluginTCFallbackRunsAheadOfCore`（tcx 和 cls_bpf 两种挂法：兜底排在一个模拟核心的程序之前，丢弃的包核心收不到；同接口排在后面的 Hook 没有兜底时整体改用 generic；排在前面时 XDP 和 TC 同时挂，前面的 Hook 在 generic Dispatcher 里、防火墙在 TC，各只执行一次；去掉后回到纯 TC，没有残留）、`TestKernelXDPPluginTCFallbackHotRestartHandsOffInPlace`（旧进程退出后兜底继续丢包；新进程接管同一个 tcx link 或 cls_bpf 位置并换上自己的程序，pin 被清理），以及字段校验、同 object 规则和特性要求的单元测试。
- **verifier 矩阵**：clang 14 / 18 / 21 × 6.12（原生）/ 5.10.0-32 / 5.15.0-25（QEMU），数字见 4.9。CI 的 kernel-load-matrix 用 `TestLoadBundledPluginObjectsSmoke` 在各 runner 内核（含 7.x）和来宾内核里加载 `firewall.o`。
- **集成测试**（真实 daemon）：
  - `TestFirewallPluginLinuxIntegration`：veth 原生 XDP 与网桥 TC 兜底两种挂载（网桥上没有 XDP 程序，TC ingress 第一个程序是 `tc_firewall`，状态里模式为 `tc`）；全部丢弃、只放行一个来源；第一次 apply 后丢包日志就能读到（控制面绑定接口后 ring reader 随之启动）；热重启期间被拒来源持续发起连接，漏过 0 个（宿主不交接 map 时 13 个），计数不清零；未确认回滚；SYN 限速：5 个连接放行、第 6 个丢弃并封禁，`bans` 列出来源、`events` 有限速丢包，封禁跨热重启保留，`unban` 后恢复；解绑后 XDP 卸载。
  - `TestFirewallSystemPortForwardAllowlist`：Veer 端口转发（IPv4 透明、IPv4 Full NAT、IPv6 Full NAT）的入口端口按白名单放行，未保护的转发不受影响。
  - `TestFirewallSystemFlowCacheUnaffected`：防火墙未安装 / 安装未绑定 / 绑定三种情况下，TC 连接缓存命中率相同（透明转发约 76–77%，Full NAT 100%）。
  - `TestFirewallSystemXDPEnginePinning`：核心原本用 XDP 引擎服务规则；绑定后规则转到 TC、插件程序挂上、过滤生效；解绑后规则回到 XDP，转发立即恢复。
  - `TestFirewallSystemDisableDetaches`：停用插件后 XDP 卸载、流量恢复；重新启用后重新过滤；删除插件同样。
  - `TestFirewallSystemBrokenObjectFailsOpen`：verifier 拒绝或不是 ELF 的 object，首次启动和冷重启两种情况都报错、不挂载、端口可达。
- **多插件共存**：`TestFirewallCoexistVPNCore`（防火墙在 WAN 上，只放行 WireGuard 对端；vpn_core 的 WireGuard 出口照常工作，LAN 流量经出口出站，其他来源被挡）和 `TestFirewallCoexistPPPoE`（防火墙先绑在 PPPoE 客户端的物理口上再拨号：发现阶段和 LCP 照常，会话起来；PPPoE 会话帧里的 TCP 按策略放行和丢弃，改策略随即生效；LAN 经 PPPoE 出向 NAT 正常；Veer 自己的 LCP 保活一直是 keepalive_ok，会话不变；断开后重拨照常）都已通过。PPPoE 测试需要内核 PPP（测试机的 cloud 内核没有编进，用同版本源码单独编了 ppp_generic、ppp_async、slhc 模块）。PPPoE 服务端的 LCP 回显设置沿用 pppoe_client 黑盒测试：pppoe_client 只在自己收发控制帧时应答服务端的回显，服务端 1 秒一次、3 次不应答就断开的话，不绑防火墙也一样会断（已对照验证）。
- **性能**（测试机：6.12 KVM 来宾，4 vCPU，EPYC 7763；结果是 3 轮相邻配对比值的中位数）：
  - 单包开销（`BenchmarkFirewallProgram`，门禁上限每种情况 1000 ns）：空 XDP 程序 29 ns；未加载或端口不受保护 47–49 ns；信任来源 228 ns；放行 IPv4 363 ns、IPv6 315 ns；丢弃 IPv4 390 ns、IPv6 372 ns；带 SYN 限速的策略上已建立连接的包 327 ns、计数的 SYN 380 ns。受保护端口的开销主要是 LPM 查找（每次约 90–100 ns）；丢包路径比 P0 多约 75 ns，用于丢包日志的时间戳和限流判断。
  - 转发吞吐（`TestFirewallPluginThroughput`，经 Veer 透明转发）：64 字节 UDP 原生模式未保护端口 1.013、受保护端口 0.989，满足"原生损失 < 3%"。大流量 TCP 在 veth 上任何原生 XDP 程序（包括只返回 PASS 的空程序）都会让吞吐降到约 8–9%，这是 veth 的特性（原生 XDP 关闭对端 TSO、逐个复制 skb），与防火墙无关；相对空 XDP 程序，防火墙未保护端口 0.957、受保护端口 0.949，单次配对波动 ±8%，这台机器分辨不了 3% 的目标。按单包开销估算，未保护端口比空程序多约 18 ns/包，10 Gbit/s、1500 字节的流量约占 1.5% 个核。
  - 没有原生 XDP 的接口（veth MTU 9000，原生挂载失败），3 轮中位数：
    | 用例 | TC 兜底 | generic |
    |---|---|---|
    | 大流量 TCP，未保护端口 | 0.989 | 0.644 |
    | 大流量 TCP，受保护端口 | 0.947 | 约 0.61（此前测得） |
    | 64 字节 UDP，未保护端口 | 0.988 | 0.977 |
    | 64 字节 UDP，受保护端口 | 1.03 | — |

    TC 兜底把 generic 的大流量 TCP 损失（约 36–40%）降到 1–5%：它原地读 skb，一个 GRO 聚合包只判断一次，不复制。单轮配对波动仍有 ±8%（受保护端口有一轮 0.69，基线那一轮异常高）。发布门禁要求 `tcp_tc_unprotected` 不低于 0.85、`udp_tc_unprotected` 不低于 0.93。
  - generic 模式（`xdp_plugin_no_tc_fallback`，或同接口排在防火墙之后的 Hook 没有兜底时才会用到）：大流量 TCP 损失约 40%（0.61），**空的 XDP_PASS 程序同样损失 40%（0.60）**，所以这是 generic XDP 本身的代价，不是防火墙的。generic XDP 跑在已经建好的 skb 上，要求 skb 线性、可写并留出 256 字节头部空间；veth 上开着 TSO/GSO 时每个包都是 64 KB 的聚合包，内核要为每个聚合包分配新的线性缓冲区、清零页面再整体复制（`perf`：`clear_page_erms` 从 6% 升到 12.8%，多出 6% 的 `__memcpy`），与程序做什么无关。不经过 Veer 的纯 veth 上同样如此（25–28 → 15.5 Gbit/s，每 Gbit/s 多约 0.03 个核）；固定 1 Gbit/s 时测不出差别。所以千兆级的无原生 XDP 网卡（r8169、e1000e 等）上基本无感，高速虚拟链路（veth、网桥）和 10G 以上会明显占 CPU。关掉 TSO/GSO/GRO（核心 XDP 引擎在 veth 上的做法）能避开复制，但大流量 TCP 本身会掉 79%，得不偿失；关掉之后 generic 下防火墙比空程序多约 7 个百分点。64 字节 UDP 在 generic 下损失 3.8%。这就是加 TC 兜底的原因。
  - SYN 洪泛（`TestFirewallPluginSYNFlood`，单核发包，3 轮中位数，XDP 方式发包）：
    | 目标 | 方式 | 进入主机 | 结果 | 每包软中断 |
    |---|---|---|---|---|
    | 宿主端口 | 防火墙原生 | 1.80 Mpps | 全部丢弃 | 406 ns |
    | 宿主端口 | 防火墙 generic | 1.07 Mpps | 全部丢弃 | 790 ns |
    | 宿主端口 | 防火墙 TC 兜底 | 1.09 Mpps | 全部丢弃 | 765 ns |
    | 宿主端口 | nftables netdev ingress | 0.78 Mpps | 全部丢弃 | 1116 ns |
    | 宿主端口 | 不过滤（syncookies） | 91 kpps | 全部进 TCP | 10.7 µs |
    | Veer 转发的端口 | 防火墙原生 | 1.78 Mpps | 全部丢弃 | 400 ns |
    | Veer 转发的端口 | 防火墙 generic | 1.05 Mpps | 全部丢弃 | 791 ns |
    | Veer 转发的端口 | 防火墙 TC 兜底 | 1.09 Mpps | 全部丢弃 | 758 ns |
    | Veer 转发的端口 | nftables netdev ingress | 86 kpps | **一个都没丢**，全部转发 | 11.5 µs |
    | Veer 转发的端口 | 不过滤 | 86 kpps | 全部转发到后端 | 11.4 µs |

    SYN 是单个小包，没有聚合包可以省复制，所以洪泛下 TC 兜底和 generic 相当，都要先分配 skb；原生 XDP 在分配 skb 之前丢弃，每包约 400 ns。TC ingress 在 netfilter 的 netdev ingress 之前，Veer 的转发先把包送走了，所以 nftables 在 ingress 拦不住 Veer 转发的端口；三种方式里只有防火墙能保护它。AF_PACKET 方式发包时三种过滤都在约 0.36 Mpps（瓶颈在发包端）。丢包比 P0 慢约 70 ns，是丢包日志的时间戳和限流判断。
    早先"不过滤时只有约 146 pps 到达后端"是发包工具的问题：`BPF_PROG_RUN` 的 live frame 模式回收页面时不重新初始化内容，Veer 转发时原地改写的包头（后端的 MAC、地址、端口）跟着页面回到发包程序，再发出去的帧目的 MAC 已经不是主机 veth，被内核按 `OTHERHOST` 丢在 `ip_rcv_core`。发包程序现在每次先写回模板包头。
- **发布门禁**：privileged 层跑上面的集成与共存测试；performance 层跑单包开销、转发吞吐和 SYN 洪泛（阈值可用 `VEER_PLUGIN_RELEASE_FIREWALL_*` / `VEER_PLUGIN_RELEASE_XDP_FIREWALL_MAX_NS` 收紧）。

测试中发现并修复的宿主问题：

- 控制面写 `plugin_reconcile` 资源（例如 Hook 绑定）只重算数据面，不重启 ring reader：第一次绑定接口后丢包日志一直是空的，直到 Veer 重启。现在这条路径也会重新订阅 ring。
- 核心 XDP 引擎和 XDP 插件 Dispatcher 切换：引擎只清空规则、程序留在接口上，Dispatcher 挂不上去；解绑时引擎在 Dispatcher 卸载之前重新挂载，两个接口落到不同模式，转发中断。现在引擎让出时整体卸载，Dispatcher 按方向先后协调。
- 核心 XDP 引擎 generic 模式的 offload 保护找 veth 对端时，把对端在另一个网络命名空间里的 ifindex 拿到当前命名空间里查：命名空间里第一个 veth 和宿主上行口通常都是 ifindex 2，结果关掉了宿主上行口的 TSO/GSO/GRO。现在对端在别的命名空间时只在具名命名空间里找，并核对对端反指回本接口（`TestXDPGenericOffloadTargetsFindPeerInItsNamespace`）。

## 9. 需要宿主补充的能力

第 1、6 项已完成；其余不阻塞：

1. ~~插件 map 跨 Veer 热重启保留~~：已实现。声明 `preserve` 的 TC pipeline、XDP、Netfilter 插件 map 由旧进程 pin 到热重启目录，新进程按 `state_maps` 契约接管，启动 reconcile 后释放。vpn_core 的 `tunnel_links` 没有声明 `state_maps`，仍由控制面重写。
2. **只读获取核心转发规则**：插件目前只能写 `forward_rule_plans`，读不到用户在核心里配的规则。P2 的"从 Veer 规则导入"需要一个只读资源或宿主 API。
3. **获取 NAT 端口窗口和 `ip_local_port_range`**：用于第 5.4 节的精确校验，替代按默认值警告。
4. **动作处理函数拿到调用者地址**：可以在应用前就判断新规则会不会挡住当前管理员。
5. **Dispatcher 支持 `xdp.frags`**：解除巨帧 MTU 限制。
6. ~~插件 Hook 单独允许 generic 模式~~：已改为 `xdp_generic` 顶层设置默认开启，插件 Dispatcher 先试原生、再用 generic。如果以后需要按 Hook 指定模式，再加 `xdp_mode: auto | native | generic`。
7. ~~直接挂载、能丢包的 TC Hook~~：已实现为 XDP Hook 的 `tc_fallback`（`dataplane.xdp_tc_fallback.v1`）。没有原生 XDP 的接口上，宿主把同一 object 里的 tc 程序直接挂在 TC ingress 最前面，排在核心之前，不计入 `tc_flow_cache_plugin_hooked()`；同接口有不带兜底的 Hook 时，排在它之后的 Hook 仍在 TC 执行，与 generic Dispatcher 同时挂载；generic 只在关闭兜底或链尾 Hook 没有兜底时使用。
8. **XDP 转发引擎接入 Dispatcher 链末端**：避免启用 XDP 插件就让核心退回 TC。

## 10. 待定问题

1. ~~插件 ID 用 `firewall` 还是带前缀的名字~~：用 `firewall`，已随 1.0.0 发布。
2. ~~P0 是否就包含 SYN 限速~~：1.0.0 只发 ACL，SYN 限速留在 P1。
3. ~~封禁按策略还是全局~~：按策略。同一来源在别的策略上不受影响；要挡多端口扫描，可以给这些端口建一条带限速的策略。
4. 是否需要按接口区分策略（例如不同 WAN 用不同策略），还是统一一套。
5. ~~抽样日志保留多少条、是否允许导出~~：内存里保留最近 500 条，不落库、不导出。
