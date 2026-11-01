# VPN WAN 插件

显式安装的 `lab` 插件，不默认打包。目录和插件 ID 为 `vpn_core`，WebUI 页面为 VPN。核心按管理员操作安装，不在启动时自动下载；已有 WG 的 WAN ID 和接口名保持不变。

WebUI 默认显示出口卡片，新建或编辑时按类型显示表单。支持多 Peer WireGuard 配置、粘贴导入 wg.conf、Mihomo / sing-box 分享链接导入和外部 TUN；密钥与核心配置只写入加密存储，不会回填。代理普通表单只需上联接口、分享内容和节点选择，自动生成完整核心配置；分流、DNS 和原生 JSON 收在可折叠的高级栏。核心安装、默认版本与回滚位于独立的“核心管理”页签。远程订阅下载、共享节点目录和运行时无重启切换仍是后续方案，见 [WebUI 配置流程研究](WEBUI-DESIGN.md)。

| 表单类型 | 普通配置 | 高级配置 |
| --- | --- | --- |
| WireGuard | 配置文件导入，或本机 Address/PrivateKey 与远端 Peer | 监听端口、宿主访问远端内网的路由、MTU、出口位置 |
| Mihomo / sing-box | 实际出站接口、分享链接或 Base64 内容、节点选择 | 直连网段/域名、DNS、原生 JSON；内部 WAN 地址覆盖、MTU、出口位置 |
| 外部 TUN | 已有 TUN 接口名、匹配的接口 alias | 内部 WAN 地址覆盖、MTU、出口位置 |

WireGuard 地址须来自实际连接配置，页面不虚构默认地址。代理和外部 TUN 的内部 WAN 地址不属于节点参数，留空在首次应用时自动分配；核心自己的 TUN 地址由插件管理，外部 TUN 地址则由外部程序管理。

0.8.3 的 sing-box 表单在实际上联旁提供可选“出站 IP”（`upstream_ip`），支持所选接口上的 IPv4 / IPv6，填写时不带前缀；应用前校验地址归属。节点出站、直连出站及直连 DNS 同时写入 `bind_interface` 和对应的 `inet4_bind_address` / `inet6_bind_address`，代理链由最后一跳绑定。只约束所填地址族，另一地址族继续自动选择；留空沿用核心配置。Mihomo 没有原生源 IP 绑定参数，此项不提供给 Mihomo，不额外创建系统路由或 NAT 规则。

“拆除”保留草稿和凭据，供以后重新应用；“删除”通过 `delete_profile` 动作先拆除自有出口，再移除其 VPN / WAN 记录、专用凭据和健康检测设置。清理失败时保留草稿供重试；其他出口引用的凭据、外部 TUN 提供者以及安装的核心版本均保留。删除前应先调整引用该出口的 LAN / 出向 NAT。0.8.4 要求 `wan_core >=1.5.5`，拆除记录在重启后继续保留；兼容旧版误写成“已禁用”的完整撤回状态，核验归属与接口确实不存在后允许重新应用或切换代理核心。

0.8.2 的出口巡检同时核对 TC 双向转接映射；即使接口和核心代际不变，丢失或不匹配的映射也会自动恢复，不重新应用 WAN、不重启核心或清理 flow。WG 每 5 秒巡检，TUN / 代理核心每秒巡检。

0.8.5 修复 WG 清理失败后、隧道已不存在时的重试异常；保留 journal 继续完成清理，不影响其他出口。多出口接口故障隔离还需要配合包含对应 TC 挂载与回滚、源地址恢复重试及 veth 双端所有权清理修复的 Veer 主程序。

## 链路健康检测（0.8.0）

出口卡片提供一个“健康检测”按钮，点击后直接在卡片上显示检测中、结果、请求耗时、检测时间及失败原因，不打开独立面板。默认仅手动检测；内网目标、预期状态、DNS 及可选定时检测通过下方 API 设置，不重新应用出口。

请求绑定已应用的 WAN local veth 及其源 IPv4，经过 WAN 边界、TC 适配器和实际 WG / 代理核心；域名通过同一出口访问指定 DNS。无需额外代理监听端口、curl 或宿主策略路由。后台 worker 只执行请求，主控制面管理有界任务并核验出口代际；重新应用、拆除、接口替换或核心重启后，旧结果不能成为新出口的健康证明。失败只更新检测状态，不触发重启、故障切换、撤销 WAN 或清理 flow。

| 检测设置 | 默认值 / 范围 |
| --- | --- |
| `enabled` | `false`，手动检测始终可用 |
| `url` | `https://www.gstatic.com/generate_204`；HTTP / HTTPS，不含用户凭据或片段 |
| `expected_status` | `204`；100–599，`0` 接受任意 2xx；不跟随重定向 |
| `resolver_ip` | `1.1.1.1`，IPv4 DNS；目标为数值 IP 时不解析 |
| `interval_seconds` | `60`；15–3600 秒 |
| `timeout_ms` | `5000`；500–10000 毫秒，响应体最多 4 KiB |

检测地址可改为 WG 对端内网服务，并配合实际返回状态码。代理请求遵循核心自身的分流规则；要验证代理节点，请选择不命中直连例外的目标。成功只代表当前出口到该目标的 HTTP 请求可用，不覆盖全部目的地、UDP、每个 WG peer 或下游 LAN / NAT 规则。耗时包含连接、TLS、响应及必要的 DNS 解析，不是 ICMP RTT；超过 `max(120 秒, 2 × 检测间隔)` 的结果标为需重新检测。

API：`health_settings` 接收 `{key, settings}`，`health_check` 接收 `{key}` 并立即排队返回，`health_status` 返回 `{items:[{key,settings,state,result}]}`。`state` 为 `unknown` / `checking` / `healthy` / `unhealthy` / `unavailable` / `stale`。同出口并发点击合并，每个出口复用一个持久任务；所有网络等待均在独立 worker 中进行。宿主需支持 `control.http_client.v1`、`control.durable_operations.v1` 和 `control.workers`。

Linux 集成测试通过实际插件 API 验证 WG、Mihomo、sing-box 探测及后端观察到的源地址，覆盖错误 HTTP 状态、超时、错误节点认证、重新应用时的旧任务隔离、定时检测，以及探测期间普通 TC 和选中出口的 TCP / UDP 转发。

## 从 wireguard_mesh 迁移

0.6.0 将旧插件 ID `wireguard_mesh` 改为 `vpn_core`。不能只改目录或直接修改数据库中的 ID：密钥密文的认证信息绑定了原 ID。

1. 备份数据库、对应 `.veer-secrets.key`、插件代码及 `<plugins_dir>.veer-state`。先将引用 VPN 的 LAN / NAT 切换到其他出口，再在旧插件中拆除隧道并停用旧插件。拆除会中断这些隧道的连接，保留草稿与密钥。
2. 把旧 `wireguard_mesh` 代码移到插件扫描目录以外，安装新 `vpn_core` 代码。保持 Veer 停止或旧插件停用，不要在迁移完成前启用新插件。
3. 使用新版本 Veer 执行本地命令：

   ```sh
   /opt/veer/veer plugin migrate-vpn --database /opt/veer/forward.db --plugins-dir /opt/veer/plugins
   ```

4. 重启 Veer 并启用 VPN 插件。确认草稿和核心版本，重新应用所需出口，再恢复 LAN / NAT 的选择。

迁移在 SQLite 事务内改写身份、按新 ID 重新加密 Secret，并迁移受管理核心目录和该目录内的显式 `core_path` 引用。已停用的插件保持停用；旧租约未清理、新 ID 已有状态或两边核心目录同时存在时明确拒绝合并。核心目录改名与数据库提交之间的崩溃可通过原命令重试；迁移失败时保持插件停用。WAN ID、接口名和 LAN/NAT 引用不改名。历史性能报告中的旧路径保留其当时含义。

| driver | 数据处理 | 依赖 |
| --- | --- | --- |
| `wireguard`（旧配置默认值） | 内核 WireGuard | wireguard-tools |
| `mihomo` | Mihomo TUN / gVisor 与代理协议 | 页面安装或本机预装 Mihomo |
| `sing_box` | sing-box TUN / gVisor 与代理协议 | 页面安装或本机预装 sing-box，带 gVisor |
| `tun` | 外部 TUN 提供者 | 提供者自行运行 |

各驱动共用 WAN Core 和双向 TC L2/L3 适配，JavaScript 不逐包转发，无需关闭 Veer 快速 NAT。

TC 适配器要求显式动态接口绑定，只在已应用出口的自有隧道和 pipeline 接口上执行。首次启用且未应用出口时不挂载适配器，不影响普通 TC 出口；自有接口映射缺失时仍丢包，避免断链流量回退到普通上游。插件要求宿主提供 `dataplane.hook_bindings.v1`，旧宿主会拒绝加载。

## Mihomo / sing-box

```text
下游 → Veer TC 分流/NAT → veervpnN ↔ veervpnpN → TC ↔ vtun<标识> ↔ 代理核心 → 原有上游
```

按下方安装步骤安装插件和 `wan_core`，保持远程插件安装关闭。在 VPN 页面的“核心管理”中选择 Mihomo 或 sing-box，点击“安装 / 更新”；版本留空时获取官方最新稳定版，也可指定发布版本。后台下载显示进度，不占用插件控制 VM；从 GitHub 官方 release 元数据读取资产 SHA256，校验压缩包、ELF 架构及版本命令后才原子切换默认版本。旧发布缺少摘要时需在“指定校验值”中填写核实过的 SHA256。amd64 使用兼容指令集构建，ARM 使用保守构建，缺少对应架构资产时明确失败。

核心统一持久保存到 `<plugins_dir>.veer-state/cores/vpn_core/<driver>/<os>-<arch>/<version>/`，与插件代码包和临时运行配置分开。每种核心最多保留 4 个版本，每插件核心文件合计上限 1 GiB；压缩包和解压出的可执行文件各最多 256 MiB。安装失败保留原默认版本并清理临时文件；Veer 崩溃遗留的下载目录在后续启动核心管理时按进程所有者清理。备份包含已安装核心及默认版本，不包含下载临时目录。

“设为默认”选择已安装版本，“回滚上一版本”切回上次默认版本，“删除所选版本”清理不用的版本；默认版本及仍被受管理进程引用的文件禁止删除。安装、更新、选择和回滚均不重启正在运行的出口。确认版本后，重新应用需要切换的出口；其恢复配置固定到应用时的核心路径，不会因后来切换默认版本而自行升级。重新应用会中断该出口的代理连接。版本命令通过只表示核心可运行，不等于节点或出口健康。

未填写 `core_path` 的出口优先使用此处安装的默认核心；没有受管理版本时仍使用 `/usr/local/bin/mihomo` 或 `/usr/local/bin/sing-box`。也可用 `core_path` 指定本机其他绝对路径，文件名必须对应核心；指定的文件不参与插件版本管理。插件不运行 shell。WireGuard 工具和外部 TUN 提供者仍由本机管理员安装维护。

在 VPN 页面新建 Mihomo / sing-box 出口，填写实际上联接口，粘贴分享链接或整体 Base64 编码的分享内容。“识别节点”可预览并选择，直接保存则默认使用第一个节点；一次支持 1–128 个节点，分享内容最多 256 KiB。保存后只返回节点名称、协议、所选序号和高级设置，链接、服务器地址和密码不回填；后续可直接选择其他已导入节点。重新粘贴会替换此出口的整组节点。

| 分享协议 | 支持范围 |
| --- | --- |
| Shadowsocks `ss://` | SIP002 明文/URL-safe Base64 凭据，兼容整体 Base64 的旧 SS 链接；常用 AEAD / 2022 加密方式，不支持 SIP003 插件参数 |
| VMess `vmess://` | Base64 JSON 或 URI；仅 AEAD（alterId=0），TCP / WebSocket / gRPC / HTTP2，可选 TLS |
| VLESS `vless://` | TCP / WebSocket / gRPC / HTTP2，TLS / REALITY、Vision；不支持新式 VLESS encryption |
| Trojan `trojan://` | TLS、TCP / WebSocket / gRPC；sing-box 另支持 HTTP2 |
| Hysteria2 `hysteria2://` / `hy2://` | TLS、单端口、可选 salamander 混淆 |
| AnyTLS `anytls://` | 密码按 URL 编码，端口默认 443，支持 SNI、insecure，以及 ALPN / 指纹参数；兼容显式 `security=tls`、`type=tcp` / `raw`、`headerType=none`，不支持 REALITY 或其他传输封装 |

不支持的协议、传输或参数会在写入 Secret 前报错，不静默丢弃。其他核心功能仍可在“分流与高级配置”中切换为原生 JSON。已有原生 JSON 配置会以原生模式打开，留空继续沿用。这里只导入粘贴内容，不下载订阅 URL，也不接受 YAML；协议映射以 [Mihomo 文档](https://wiki.metacubex.one/en/config/proxies/)、[sing-box 文档](https://sing-box.sagernet.org/configuration/outbound/)、[SIP002](https://shadowsocks.org/doc/sip002.html)、[VMess/VLESS 链接提案](https://github.com/XTLS/Xray-core/discussions/716)、[Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/) 和 [AnyTLS URI](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md) 为依据。

自动配置默认把流量发送到所选节点。高级栏可填写直连 CIDR、直连域名及子域名（依赖 HTTP/TLS/QUIC 嗅探，识别不到时仍走节点）。节点域名解析默认使用经实际上联访问的 `223.5.5.5`，可修改。下游 DNS 默认沿用；可选择接管经过此出口的 TCP/UDP 53 流量，通过节点访问指定 DNS（默认 `1.1.1.1`）。LAN 网关代发的 DNS 不一定经过此出口，DoH/DoT 也不属于 53 端口接管范围。

保存并应用出口配置：

```json
{"driver":"mihomo","slot":1,"mtu":1420,"upstream_interface":"eth0","max_restarts":3}
```

sing-box 使用 `"driver":"sing_box"`。核心配置由 `set_core_config` 加密保存，原生 JSON 最多 768 KiB；API 不指定 `name` 时沿用 `core_<标识>`，指定时写入该 Secret，并通过 profile 的 `config_secret` 引用。页面新建代理配置使用 `core_<driver>_<标识>`，切换核心类型时不会串用另一种核心的配置；已有默认或自定义 Secret 引用继续沿用。链接导入使用 `format:"links"`、`driver`、`value`、从 0 开始的 `selected` 和 `options`；`value` 留空仅调整同类型已导入节点的选择及高级设置。`core_form` 返回不含凭据的编辑摘要。重新应用后生效；恢复使用单独加密保存的已应用配置，不读取后续草稿。

插件生成独占 TUN，强制 gVisor、关闭自动路由和自动重定向，并指定实际上游。Mihomo 额外入站/控制端口及 sing-box 额外入站/experimental 控制项不沿用；不能把 VPN 自身或其他 VPN 边界作为上游。WAN 地址使用 `/32` 或 `/128`，不安装 `remote_routes`。相对文件和资源下载需按核心要求准备，工作目录是受管理的临时目录。

`addresses` 可省略或为空，首次应用会检查本机接口网段、非默认路由、其他出口草稿和已应用租约，从有界候选池选择内部 WAN IPv4 `/32`。优先使用 `10.78.<slot>.1/32`，冲突时尝试其他候选；无可用地址时明确失败，不修改网络或启动核心。已分配地址固定在应用租约中，重新应用和恢复时沿用，避免改变现有 LAN/NAT 选择。高级设置仍可显式填写 `addresses`，保留原 API 行为；已保存的显式地址不会被替换。最终地址发布为 `status.wan_addresses` 和 `status.egress_nat_source_ip`。

宿主按插件控制代际托管进程，提供状态、有限日志、优雅停止、超时强杀、子进程清理和指数退避重启。默认失败重启 3 次，耗尽后需显式重新应用；定时恢复不重置预算；TUN 丢失时通过同一预算执行受控重启，接口 DOWN/MTU 漂移在核验归属后原地修复。插件停用、控制 VM 停止及 Veer 退出会停止进程，Linux 设置父进程死亡信号。完整资源保护下，核心使用独立 cgroup，复用配置中的插件 CPU/内存/PID 和全局上限；核心拥有本地 exec 的服务权限，不属于低权限 JS 沙箱。

核心进程存在且自有 TUN 就绪后才发布可用 WAN；每秒检查状态、ifindex 和 MTU；启动后默认 30 秒仍未创建 TUN 则按同一预算重启，可用 startup_timeout_seconds 调整为 1–300 秒。失败时撤销 TC 映射和 WAN 可用状态，保留所选出口，不回退到直连。ready 只表示本机接入完成，不代表远端节点健康；核心重启会中断它持有的代理连接。WebUI 可按需读取核心日志的尾部，日志可能包含凭据，不会自动加入状态。

健康轮询优先使用宿主原生接口查询，避免每秒为各出口启动多个 `ip` 子进程；旧宿主缺少 alias/TUN 元数据时仍按单接口调用 `ip` 并核验归属。受管理 sing-box 的 TUN 确认启用 vnet header、TX checksum、SG、TSO 和 GSO 后，WAN 边界保留 GSO/GRO，避免提前逐包分段；`inspect.tun_gso` 显示本代际的决定。TUN 刚创建而 offload 尚未协商完成时，间隔 1 秒最多探测 3 次，期间出口保持未就绪。探测失败或不支持时使用逐包边界，健康轮询不重复执行 `ethtool`；核心重启会重新探测。Mihomo 和外部 TUN 保持逐包边界。

slot 1 的出口接口为 `veervpn1`，源 IPv4 使用已发布 WAN 的地址（无冲突时自动分配 `10.78.1.1`），模式为 `prepared_l2`。IPv4 NAT 后核心无法直接区分原下游 IP，设备选择留给 Veer。DNS/fake-IP、UDP/ICMP 支持受核心和代理协议约束，不等同于任意 IP 协议的双向路由 VPN；宿主代发 DNS 不自动继承设备出口。

## 外部 TUN

```json
{"driver":"tun","slot":1,"mtu":1420,"tun_interface":"tun0","tun_alias":"my-vpn-provider"}
```

提供者需创建同一网络命名空间内的 Linux TUN，设置匹配的 alias、MTU 并启用。插件核验身份后只接入 TC/WAN，不启动进程、不接管 FD、不修改或删除提供者接口。纯 SOCKS/HTTP 监听器需另配 TUN 转换。

代理核心测试在独立网络命名空间运行真实加密 Shadowsocks 对端、Veer TC NAT、两种核心的 TCP/UDP 和大包回传，并检查普通 WAN、重启和拆除：

```sh
sudo env "PATH=$PATH" sh scripts/verify-vpn-cores.sh
```

脚本下载固定版本并核验 SHA256，退出后清理；也可通过 `VEER_TEST_MIHOMO` / `VEER_TEST_SING_BOX` 提供本机核心。

同一测试门禁还运行 `TestVPNMultiExitLinuxIntegration`：一个 Veer 同时承载 WG、Mihomo、sing-box 和普通 WAN，各用独立上联。逐出口注入双向 TC 映射丢失/损坏、隧道 DOWN/MTU 漂移、删除/同名外部接口替换、WAN 边界删除、上联 DOWN/重建、核心退出、清理所有权冲突和拆除后重新应用。故障出口恢复后检查实际 TCP/UDP 收发；其余三个出口始终使用原 TCP/UDP socket，逐包核对序号、内容和后端观察到的出口源地址，同时核对核心 PID、边界接口代际及最终资源清理。只在独立测试网络命名空间注入故障。

## WireGuard 驱动


显式安装的 `lab` 插件，不进入默认发布包，也不自动安装 WireGuard。一个 profile 提供一个 WAN，LAN 或下游设备通过现有 Veer 出向 NAT 选择它。

```text
下游设备 → Veer TC 出向 NAT → WAN local veth → pipeline veth
         → WG TC 适配器 → 内核 WireGuard → 主机原有上游 → 对端
回包：内核 WG 解密 → TC 补回 Ethernet → WAN local ingress → Veer reply flow → 下游
```

JavaScript 负责配置和恢复，不参与逐包转发。无需关闭 Veer 快速 NAT；不创建源地址策略规则、不安装全局默认路由，不使用 `wg-quick`。加密后的外层 UDP 使用主机原有路由，因此上游仍可为物理 WAN 或 PPPoE。

## 安装

默认使用基础 TC 适配器。可选 [Veer 内核扩展](../../KERNEL.md) 通过 kfunc 保留 GSO/GRO、减少适配开销；插件自动按宿主实际能力选择 `wg_adapter-kfuncs.o`，不需要额外开关。veth 与核心 NAT 路径仍保留，WireGuard 加密仍由内核 WG 完成。

1. Linux 内核需支持 WireGuard，安装 `wireguard-tools iproute2 ethtool`，确认 `/usr/bin/wg`、`/usr/sbin/ip` 可用。主机原有路由和防火墙需允许对端 UDP。
2. 在 Linux 源码目录运行 `sh plugins/vpn_core/build.sh`，生成 `wg_adapter.o`。将整个插件目录复制到实际 `plugins_dir`，同时安装 `wan_core >=1.5.0 <2.0.0`。
3. 开启 `plugins_enabled=true` 和 `plugins_dataplane_enabled=true`；保持默认 `plugins_remote_install_enabled=false` 以允许插件 exec。插件需要 Veer 的网络管理权限，不执行 shell 或用户提供的脚本。
4. 打开 VPN 页面，保存私钥，再保存并应用 profile。空插件和仅保存的草稿不更改网络。
5. 在 LAN 配置中选择此 WAN，或在出向 NAT 中设置出口接口、源 IPv4 与 `prepared_l2` 重定向模式。不要填写内核 `vwg*` 接口作为核心 NAT 出口。

## 配置示例

```json
{
  "slot": 1,
  "addresses": ["10.77.0.1/32"],
  "listen_port": 51820,
  "mtu": 1420,
  "peers": [{
    "public_key": "替换为对端公钥",
    "endpoint": "192.0.2.2:51820",
    "allowed_ips": ["0.0.0.0/0"],
    "keepalive": 25
  }],
  "remote_routes": []
}
```

标识 `default`、slot `1` 对应：

| 用途 | 值 |
| --- | --- |
| WAN Core ID | `wg_default` |
| 出向 NAT 接口 | `veerwg1` |
| 出向 NAT 源地址 | `10.77.0.1` |
| 出向 NAT 重定向模式 | `prepared_l2` |
| pipeline veth | `veerwgp1` |
| 内核 WG 接口 | `vwgdefault` |

整个 LAN 选择这个 WAN；仅一个设备走 WG 时，为它的下游接口创建更具体的出向 NAT，父接口保持原出口。协议子集覆盖沿用 Veer 的现有编排，不在插件中另建一套设备选择规则。多个出口使用不同 profile 和 slot。

每个 profile 最多 8 个 peer，slot 为 1–8，不可重复；更换 slot 前先拆除。标识限 1–11 位小写字母、数字或下划线，以字母开头。至少提供一个 IPv4 隧道地址；它安装在 WAN local veth，WG 设备自身不重复配置该地址。MTU 默认 1420，范围 1280–9000，应按上游实际 MTU 调整。

endpoint 只接受数值 IP:port，IPv6 使用 `[2001:db8::2]:51820`。AllowedIPs 决定内核 WG 选择的 peer；每个 peer 最多 32 项，相同前缀不能重复分配。keepalive 默认 25 秒，0 关闭。`remote_routes` 可为宿主添加到远端内网的非默认路由，必须由 AllowedIPs 覆盖，且不能覆盖任何 peer endpoint；隧道地址的直连前缀同样不能覆盖 endpoint。下游选路由 Veer 出向 NAT 决定，无需在这里增加默认路由。

远端需把本端隧道源地址加入 AllowedIPs；提供互联网出口时，远端还需配置转发与 NAT。访问远端内网时，将目标 LAN 前缀加入 AllowedIPs。**当前 Veer IPv4 出向 NAT 会转换源地址**，支持下游发起连接及回包；远端主动访问下游需要另外配置端口转发。这不是保留原始 LAN 源地址的双向路由 mesh，也没有自动发现、打洞、中继或密钥分发。IPv6 地址和包可经过适配器，但下游 IPv6 路由仍需单独配置，不宣称支持 IPv6 出向 NAT。

DNS 沿用 LAN 配置。Veer 本机代发的 DNS 属于宿主流量，不会自动继承下游的 WAN 选择。

## 密钥和生命周期

私钥保存到加密 Secret `private_<profile-key>`；`set_key` action 接受 `{"key":"default","value":"实际私钥"}`。PSK 使用同一 action 指定 `name`，再在 peer 中填 `preshared_key_secret`。密钥只通过 stdin 交给 `wg syncconf`，不出现在 argv、状态或日志；inspect 仅查询公钥、endpoint、握手和流量。配置成功不等于对端握手成功。

持久 lease、接口 alias、WAN driver 标记共同约束所有权；遇到外部接口或其他 driver 占用时拒绝接管。应用失败保留 journal 供重试或拆除，TC map 无有效出口时丢包。5 秒检查自有 WG 与 veth 的状态/ifindex，重建时清除旧映射；配置不变时不重复调用 `wg syncconf`。重启恢复上次应用的设置，不自动应用后续编辑的草稿。

拆除前先把引用此 WAN 的 LAN/出向 NAT 切到其他出口。teardown 删除自有 WG、TC 映射和 WAN 边界；不会自动改写其他插件的选择，也不会把使用此 WAN 的连接偷偷迁移到普通 WAN。Secret 和配置草稿保留，可再次应用。

旧 0.1.x 的 `bindings/masquerade/bypass_cidrs` 配置不自动转换。先使用旧 lease 拆除其专用路由/规则/nft 表，再按新 WAN 配置应用；旧资源只按完整所有权与匹配条件删除，不执行全局 flush。

## 验证

```sh
sh scripts/build-all-ebpf.sh
node --test internal/app/web_test/vpn_plugin.test.js
sudo env VEER_RUN_WIREGUARD_TESTS=1 go test ./internal/app -run '^TestWireGuardMeshLinuxIntegration$' -count=1 -v -timeout=5m
```

Linux 测试在独立网络命名空间启动真实 Veer 和 WG peer，验证核心 NAT 与适配器的 TCP/UDP/ICMP 收发、下游接口覆盖、普通 WAN 不受影响、WG 重建及拆除后重新应用。显式启用时缺少权限、工具或内核能力直接失败。
