# PPPoE 下行 GRO 复测：2026-10-31

同一软件链路三轮中位数中，优化 kfunc 相对原 kfunc 的单流下行变化 +55.8%，四流下行变化 +45.0%；单流/四流上行变化分别为 +1.2% / +0.4%。固定 1 Gbps 下行的四核整机 busy CPU 降低 55.3%。完整结果见 [JSON](pppoe-rx-gro-20261031.json)。

## 修改与验证

解封装后的 TCP 数据和 SYN/FIN/RST 通过同 netns 的双向 veth peer TX 进入已有 local NAPI/GRO。插件自动打开 local GRO、关闭 pipeline TSO，纯 ACK 保留直接接收路径，避免反方向上传受聚合调度影响。UDP、ICMP、IPv4 分片、IPv6 扩展头及不符合 GRO/peer 条件的包保留原路径。继续使用独立 skb clone/COW，接口数量、kfunc ABI 和 NAT/flow 语义不变。

包级测试覆盖 IPv4/IPv6 真实 GRO 聚合、GRO 关闭/peer TSO 开启的回落、纯 ACK 绕过、TCP/UDP/UDP GSO/ICMP、会话/peer/长度异常、线性/非线性 skb，以及 MSS 修改后原始 PPPoE skb 逐字节不变。模块 ABI/生命周期与真实 TC NAT + WireGuard 集成也通过。

## 方法

- Debian 12 / Linux 6.12.74+deb12-cloud-amd64，AMD EPYC 7763，4 vCPU，约 967 MiB RAM。
- 模块和控制脚本基线为 `1df7628c4ea7fb55f51cb9e68e5efc12f91875c7`。二进制复用前轮普通/增强构建，其 build info 标记为 `5128070+dirty`；原增强版和新版使用完全相同的增强二进制，只替换模块与控制脚本。基础 BPF 使用新版脚本的基础分支。代码与产物 SHA-256 随 JSON 保存。
- client netns → LAN bridge → router netns → WAN veth → AC netns → iperf server。pppd 使用 nft SNAT；Veer 使用核心 TC NAT / `prepared_l2`。AC 为原生 Linux PPP/PPPoE + pppd，Python 仅处理 discovery。
- cloud 内核没有 PPP 驱动，使用官方 Linux stable v6.12.74 源码和匹配 headers 临时构建、加载 slhc/ppp_generic/pppox/pppoe，PPPoE hash 使用默认 4 bit；没有安装驱动或重启。
- MTU/MRU 1492，IPv4 TCP，iperf 3.17.1。每项 8 秒，额外预热 2 秒，三轮轮换共 72 项；P1 client/server 分别固定 CPU 0/2，P4 使用四核。固定 1 Gbps 使用内核 socket pacing `--fq-rate` 和发送端 fq。
- 新版接口 offload 由真实插件自动设置，测速脚本只断言结果。预跑、perf profiling 和未完成的测试批次均不计入正式结果。
- CPU 取整机 `/proc/stat` 差值，包含 client、AC、server、router 及预热阶段。四核总 CPU = busy cores / 4 × 100；不是路由器独占 CPU，也不是 Veer 进程 CPU。
- 全部正式项逐一核对原始 iperf JSON 的版本、标签、接收吞吐和每组样本数。

## 结果

三轮中位数，括号为最小值–最大值；上下行以 LAN 客户端为参照。

| 方案 | P1 上行 Gbps | P1 下行 Gbps | P4 上行 Gbps | P4 下行 Gbps |
| --- | ---: | ---: | ---: | ---: |
| pppd + Linux PPP + nft NAT | 3.55 (3.51–3.55) | 2.21 (2.16–2.22) | 4.31 (4.30–4.42) | 2.77 (2.77–2.86) |
| Veer 基础 BPF + TC NAT | 3.46 (3.44–3.46) | 2.36 (2.35–2.38) | 4.85 (4.84–4.86) | 2.97 (2.94–3.02) |
| 原 kfunc + TC NAT | 4.19 (4.18–4.21) | 2.19 (2.18–2.19) | 5.71 (5.52–5.76) | 2.78 (2.78–2.81) |
| 优化 kfunc + TC NAT | 4.24 (4.21–4.26) | 3.41 (3.40–3.42) | 5.74 (5.63–5.77) | 4.04 (4.01–4.06) |

固定 1 Gbps，四核整机总 CPU：

| 方案 | 上行实际 Mbps | 上行 CPU % | 下行实际 Mbps | 下行 CPU % |
| --- | ---: | ---: | ---: | ---: |
| pppd + Linux PPP + nft NAT | 1000.0 (1000.0–1000.1) | 5.77 (4.85–6.12) | 1000.0 (999.9–1000.1) | 4.80 (4.60–5.35) |
| Veer 基础 BPF + TC NAT | 999.8 (999.6–1000.0) | 5.15 (4.95–5.20) | 999.8 (999.7–999.9) | 5.77 (5.47–5.87) |
| 原 kfunc + TC NAT | 999.9 (999.9–1000.1) | 5.22 (4.85–5.50) | 999.8 (999.2–999.8) | 5.42 (4.97–5.67) |
| 优化 kfunc + TC NAT | 999.8 (999.4–999.9) | 4.57 (3.90–4.62) | 999.9 (999.7–1000.1) | 2.42 (2.40–2.60) |

全速四流 TCP 重传次数（每项测量 8 秒）：

| 方案 | 上行重传 | 下行重传 |
| --- | ---: | ---: |
| pppd + Linux PPP + nft NAT | 30582 (29919–31347) | 27434 (27015–28502) |
| Veer 基础 BPF + TC NAT | 36675 (34599–39773) | 26841 (25689–28416) |
| 原 kfunc + TC NAT | 51734 (51468–52996) | 27708 (26771–28145) |
| 优化 kfunc + TC NAT | 51640 (47918–52434) | 19621 (19395–20610) |

正式记录 steal 占四核总量的中位数 0.40%，范围 0.15%–6.49%。

## 解释边界

这是同机软件拓扑，包含 NAT 实现差异、共享 AC 的处理开销、虚拟机调度和多流重传。不能据此推算 N100、物理网卡或真实运营商线路的吞吐，也不能把整机 CPU 降幅解释为单独路由器 CPU 降幅。这里的完整 NAT 对比与 KERNEL.md 中较早的 PPPoE 直接隧道测试拓扑不同。

原始逐项 JSON、接口 offload 快照、日志和核验脚本保存在本次工作区 `test-results/pppoe-opt/`；本报告的 JSON 保存全部 72 项结果、摘要和代码/产物摘要。
