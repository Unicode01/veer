# 可选内核扩展

`veer_kfuncs.ko` 为 TC/eBPF 插件提供版本化包处理能力。默认构建不包含模块支持、不调用 kbuild，也不增加模块加载权限；基础 PPPoE/WG 插件继续使用原 eBPF 路径。

## 数据路径

控制面、Veer NAT/flow/策略和插件编排保持现有分工。JavaScript 选择对象、准备接口和维护配置；逐包操作由 TC 与内核完成。

| 操作 | 模块承担的工作 |
| --- | --- |
| PPPoE 出站 | 接收 GSO skb，在 C 内分段，逐段补 PPPoE 长度和校验和，再发到物理 WAN |
| PPPoE 入站 | 校验会话与长度，去除 padding，调整 skb 头部，复用 veth NAPI/GRO 后交给 local ingress |
| WG 出站 | 去除 Ethernet 头，把 L3 skb 交给内核 WireGuard，保留 GSO |
| WG 入站 | 补 Ethernet 头，经 WAN Core veth 回到核心 reply flow，允许 GRO/GSO |

当前仍保留 WAN Core 的 local/pipeline veth，作为已有 NAT 和接口租约的边界。收益来自延后分段、减少逐段 BPF 调用和包体搬移，不能理解为消除了 veth、分段、checksum 或内存分配。模块使用独立 skb clone，必要时 COW；不是零拷贝承诺。

PPPoE 增强模式为 local 开启 GRO，并关闭 pipeline 的 TSO，使解封装后的 TCP 数据包经同 netns 的双向 veth peer 进入已有 NAPI/GRO。纯 ACK 保留原接收路径，避免拖慢反方向上传；UDP、ICMP、IPv4 分片和带扩展头的 IPv6 也使用原路径。GRO 未开启、peer 不符合条件或仍启用 TSO 时自动回落直接 local ingress，不增加接口、线程或独立 NAPI 生命周期。

## 构建与部署

在目标 Linux 主机或匹配的构建环境准备编译器、clang、kmod、pahole 和**精确匹配目标内核**的 headers/build tree。增强路径要求 Linux 6.1+，以及启用 BPF syscall/JIT、内核 BTF、模块和模块 BTF；最终以实际 kfunc probe 为准。发行版签名策略、Secure Boot/lockdown 也可能阻止加载，需由管理员签名及信任模块。

```sh
# 原构建方式仍默认不带模块。
bash release.sh amd64

# 可选：原生构建匹配当前内核的模块、probe 和带支持的二进制。
VEER_BUILD_KERNEL_MODULE=1 bash release.sh amd64

# 将二进制、部署脚本、配置和 kernel/<release>/veer_kfuncs.ko 一并上传。
VEER_INSTALL_KERNEL_MODULE=1 bash deploy.sh
```

ARM64 主机使用 `arm64`。Go 二进制可以交叉构建；`.ko` 必须匹配目标架构、内核配置、符号版本和 vermagic，不能把一台主机的模块作为通用 Linux 发布物。内核更新后需重新构建并部署对应目录。默认 bootstrap 不自动安装构建模块所需的 headers 和工具。

单独构建及非默认 build tree：

```sh
KDIR=/lib/modules/$(uname -r)/build sh scripts/build-kernel-module.sh
go build -tags veer_kfuncs -o veer .
```

若 headers 包缺少 vmlinux，脚本仅在模块尚无 BTF 时，使用匹配的 base BTF、pahole 和 `resolve_btfids` 补齐，兼容工具原地更新 ELF 和输出独立 BTF 文件的两种方式。原生构建默认读取 `/sys/kernel/btf/vmlinux`；跨内核必须显式提供 `VMLINUX_BTF`。发行版没打包工具时可从对应内核源码构建 `tools/bpf/resolve_btfids`，通过 `RESOLVE_BTFIDS=/absolute/path/resolve_btfids` 指定。不能使用其他内核的 base BTF 冒充匹配版本。

部署把模块放在 `<Veer 可执行文件目录>/kernel/<uname -r>/veer_kfuncs.ko`，要求 root 所有、普通文件、无 group/world 写权限。systemd 单元仅在存在已部署模块时增加 `CAP_SYS_MODULE`，并准备 `/run/veer-kfuncs`；默认部署不增加此权限。模块缺失、加载被拒绝、ABI/probe 不兼容时记录原因，使用基础路径。

显式安装会在修改配置/插件前校验模块产物，原子替换模块文件；更新失败回滚时同时恢复旧模块文件。已经加载的模块遵循下面的引用与卸载规则，不会强制替换运行中的代码。

## 生命周期与插件契约

Veer 在启动插件之前加载并探测模块。宿主只有在 probe 实际调用成功后才发布 `dataplane.kfuncs.handoff.v1`；另行调用接收注入 probe 成功后发布 `dataplane.kfuncs.handoff_ingress.v1`，旧模块不会误报。插件通过 `plugin.host().available_features` 选择对象。VPN 有基础、`-kfuncs.o` 和 `-direct.o` 三份对象；只有新能力与 direct 对象均可用才省去 veth peer。构建插件对象本身不需要模块 headers。

能力是运行中模块实例的结果，不等同于编译标签。模块出现、移除或重新加载后，能力查询按实例重新探测。已经附加的程序不因一次查询切换对象，需正常重载/重启以协调对象和接口设置。

PPPoE 保留 live session 的非秘密准备参数。恢复时若模式变化，会通过 WAN Core 的 `apply_session` 更新其持有的接口 offload 租约；不会重新拨号或把在线 WAN 标为 prepared/down。接口准备失败就清空 tunnel map，保留配置重试。WG 在 apply/repair 时同样根据实际选中的对象协调 GSO/GRO。

共享 daemon lease 避免重叠启动/升级互相卸载。只有最后一个正常退出的 Veer 才尝试卸载自己加载的模块；boot ID 与模块每次加载生成的随机 instance 共同标记所有权。手动加载或替换后的模块不由 Veer 卸载。BPF 引用仍在、权限不足等情况下保留模块并记录日志，不强制卸载。

热更新保留模块和既有 BPF/session 引用，继任进程接管生命周期。替换磁盘 `.ko` 不会热替换运行中的模块代码；需要结束旧引用并完成正常停止/卸载后，新启动才加载新模块。异常退出也不强制拆除活动数据面，继任者可通过所有权记录恢复管理。

## kfunc 开发边界

公共声明在 [plugins/include/veer_kfuncs.h](plugins/include/veer_kfuncs.h)：`veer_kfuncs_abi_v1()`、`veer_skb_handoff_v1()`，以及可选的 `veer_skb_handoff_ingress_v1()`。后者仅接受 `VEER_L3_TO_ETH`，补 Ethernet 后送入目标设备接收路径，执行目标 TC ingress；原函数发送语义与 ABI 保持不变。handoff 配置为 28 字节，仅含标量，当前只注册给 `BPF_PROG_TYPE_SCHED_CLS`。

handoff 不修改或释放调用方的 skb；所有修改都作用于独立 clone。调用后 **BPF 必须始终返回 `TC_ACT_SHOT`**，包括失败路径，避免原包重复发送或回落宿主路由。目标只能是同 netns 的有效、启用、类型匹配且不同于源设备的接口。模块校验参数、PPPoE 会话/长度，限制发送递归，并处理必要的 checksum/MSS。调用权限仍受宿主插件加载和 BPF 特权边界约束；这不是向不可信插件开放任意内核执行。

Veer 自己的 `v1` 约定不代表 Linux 内部 ABI 稳定。增加操作或改变所有权语义需重新审查 verifier、skb/offload 和生命周期，不能把任意 skb 修改函数直接暴露为 kfunc。

## 验证与收益

仅在独立、无已加载 veer_kfuncs 的 root Linux 测试机执行：

```sh
sh scripts/verify-kernel-module.sh
```

该门禁构建模块和两套插件对象，执行实际 ABI probe、生命周期单测、PPPoE IPv4/IPv6/TCP/UDP/UDP GSO/畸形包测试，以及真实 Veer TC NAT + 内核 WG 集成。PPPoE 还检查真实 GRO 聚合、GRO/TSO 不满足条件时的回落、纯 ACK 绕过，以及线性/非线性原始 skb 在 handoff 后逐字节不变（包含 MSS 修改）。WG 测试包含单 socket 长连接跨热更新、异常重启、接口消失、修复和拆除后重新应用。测试结束释放引用和模块；不在业务主机运行。

性能复测使用 `scripts/verify-kfuncs-packets.py --loader <loader> --performance --output <json>`；loader 可用 `go build -o loader ./scripts/kfuncs-test-loader` 构建。WG 使用 `python3 scripts/benchmark-wireguard.py --runtime <directory>`，目录内放 `veer` 和 `plugins/{wan_core,vpn_core}`，增强模式另放匹配 `.ko`。分别用当前源码的普通/带标签二进制执行，保存 results.json；脚本使用独立 netns，WG 实际经过核心 NAT 和加解密。

2026-10-31，Linux 6.12、4 vCPU、约 967 MiB 的独立虚拟机，同机 namespace 单流、每方向 3 轮中位数。下表 PPPoE 为直接隧道测试，未经过 Veer NAT；WG 包含真实核心 NAT 和加解密，不能把两种拓扑的数字直接比较：

| 路径 | 基础 | 增强 | 倍率 |
| --- | --- | --- | --- |
| PPPoE TX，MTU 1492 | 1.26 Gbps | 3.98 Gbps | 3.16× |
| PPPoE RX，MTU 1492 | 1.25 Gbps | 4.05 Gbps | 3.24× |
| WG 上传，MTU 1420 | 0.99 Gbps | 2.20 Gbps | 2.22× |
| WG 下载，MTU 1420 | 1.63 Gbps | 1.63 Gbps | 1.00× |

PPPoE 两侧 WAN veth 均关闭 TX checksum offload，模拟真实线上的 PPPoE 帧。整机忙 CPU 约 1.46–1.52 核降至 1.39–1.49 核。WG 上传忙 CPU 约 2.81 核增至 3.37 核，单位吞吐 CPU 降低；下载 CPU 与吞吐基本持平。最终对照数据和逐轮记录见 [benchmarks/kernel-module-20261031.json](benchmarks/kernel-module-20261031.json)。

随后在同机完整 PPPoE + NAT 拓扑中，对 pppd、基础 BPF、原增强版和本次 GRO 优化版进行了三轮共 72 项轮换复测。原增强版 → 优化版的单流下行中位数为 2.19 → 3.41 Gbps，四流下行为 2.78 → 4.04 Gbps；上行中位数变化为 +1.2% / +0.4%。固定 1 Gbps 下行的四核整机总 CPU 从 5.42% 降至 2.42%，该口径包含 client、AC、server 和 router。拓扑、三轮范围、重传与全部结果见 [完整复测报告](benchmarks/pppoe-rx-gro-20261031.md)。

这些是同机数据面实验，包含虚拟机调度/steal 和 TCP 重传，不是公网带宽或目标物理网卡的性能保证，也不能替代运营商 PPPoE 长时间稳定性验证。当前优化主要覆盖 PPPoE 包处理与 WG 适配，WireGuard 加密本身仍消耗 CPU。

参考：[kfunc 与 verifier 契约](https://docs.kernel.org/bpf/kfuncs.html)、[外部模块构建](https://docs.kernel.org/kbuild/modules.html)、[GSO/GRO 语义](https://docs.kernel.org/networking/segmentation-offloads.html)。
