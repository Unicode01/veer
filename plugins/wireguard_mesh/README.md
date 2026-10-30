# WireGuard Mesh 示例插件

这是一个显式安装的 `lab` 控制面示例，不加入默认 `stable` 插件包，不随部署自动安装，也不自动安装 WireGuard 或修改主机的全局转发开关。数据由 Linux WireGuard 内核接口传输，JavaScript 只管理配置和路由，不参与逐包转发。

支持整个 LAN、单台设备或源网段选择不同隧道出口；支持 IPv4/IPv6、多个 peer、按目标网段分流、可选出口 NAT，以及保留源地址的双向站点互联。每个出口使用一个 profile/独立 WG 接口，WireGuard 再按目的地址的 AllowedIPs 选择 peer。这里没有自动发现、打洞协调、DERP 中继或自动密钥分发；peer 和路由由管理员配置。

## 本机安装

1. 在 Debian/Ubuntu 安装 `wireguard-tools iproute2 nftables procps`，内核需支持 WireGuard。插件使用固定命令路径 `/usr/bin/wg`、`/usr/sbin/ip`、`/usr/sbin/tc`、`/usr/sbin/nft`、`/usr/sbin/sysctl`；其他发行版先确认这些路径。插件不执行 shell 或 `wg-quick` hooks。
2. 按主机需求提前启用 IPv4/IPv6 转发，例如 `net.ipv4.ip_forward=1`、`net.ipv6.conf.all.forwarding=1`。IPv4 的全局 `net.ipv4.conf.all.rp_filter` 应为 `0` 或 `2`，避免严格反向路径检查丢弃隧道回包。插件只将自己 WG 接口的 rp_filter 设为 `2`，不会改动其他接口的设置。
3. **目标 LAN 要走 Linux 路由。** 使用 `lan_core` 时，把目标 profile 的 `auto_egress_nat` 设为 `false` 并应用，关闭相应的手工 Egress NAT，确保 LAN bridge、成员口上没有绕过 Linux 栈的 TC BPF/XDP。插件会检查这些接口，遇到冲突拒绝应用。它不会自动接管已有 Veer 快速 NAT。未选中的设备沿用系统主路由；需要普通 WAN NAT 时，由原有 Linux 防火墙/路由配置提供。
4. 本机将 `plugins/wireguard_mesh` 完整复制至实际 `plugins_dir`，设置 `plugins_enabled=true`，并保留默认 `plugins_remote_install_enabled=false`，然后重启 Veer、启用插件。exec 以 Veer 服务权限执行，需 root/CAP_NET_ADMIN；使用已经约束系统调用的自定义服务沙箱时也要允许这些管理命令。
5. 进入 WireGuard 插件页面，先保存密钥，再保存并应用 profile。仅保存草稿不会更改主机网络。插件默认没有 profile、没有密钥，加载页面或启动空插件不会执行任何命令。

`lab` 表示不纳入默认发布包，手工安装后按现有插件流程启用。远程安装和 exec 的模式约束沿用宿主现有策略。

现有防火墙还需允许 peer 的 UDP 端口、LAN↔WG 转发。插件自己的 nftables guard 不能覆盖其他链中的 drop 策略；不会清空已有防火墙。它不修改 DHCP/DNS，DNS 服务器应由 LAN 配置显式选择：若客户端通过 Veer 的本机 DNS 转发，后续 DNS 请求属于宿主流量，不会自动套用下游设备的选择规则。

## 指定设备使用 WG 出口

本端隧道地址 `10.77.0.1/32`，LAN 为 `192.168.10.0/24`，只让 `192.168.10.20` 从远端上网：

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
  "bindings": [{
    "lan_interface": "br-lan",
    "source": "192.168.10.20/32",
    "destination": "0.0.0.0/0"
  }],
  "masquerade": true,
  "bypass_cidrs": []
}
```

整个 LAN 改用 `source: "192.168.10.0/24"`。`lan_interface` 填实际三层入口（例如 bridge/bond 主接口），不能填 loopback 或被桥接/绑定的成员口。多个设备增加 bindings；选择另一个出口时新增 profile，分配不同 slot 和 peer，避免源/目标选择范围重叠。远端需要允许本端隧道地址的 AllowedIPs，并具备转发、互联网出口及相应 NAT；本插件不能替你配置远端。

接口名为 `vwg<profile-key>`，标识限 1–11 个小写字母、数字或下划线，以字母开头。每个 profile 有一个 `slot`（1–8），对应表 `52000+slot`、规则优先级 `22000+slot*32` 到 `+31`、nft 表 `inet veer_wg_<slot>`，协议标记 `242`。这些空间必须独占。更换 slot 前先拆除。bindings 最多 16 条，peers 最多 8 个，每个 peer 最多 32 个 AllowedIPs；不接受同一 AllowedIPs 重复分配给不同 peer。

`source`/`destination` 可为 IPv4 或 IPv6 地址/CIDR，且每条 binding 的地址族必须一致。IPv6 地址使用原生 IPv6 形式，不接收 IPv4-mapped 写法；有 IPv6 binding 时 MTU 至少 1280。peer endpoint 只接受数值 IP 和端口，IPv6 用 `[2001:db8::2]:51820`，不接受域名。`keepalive` 默认 25 秒，设为 0 可关闭。

规则同时匹配 `iif` 和源/目标地址，宿主自身的 SSH、默认路由、WireGuard 外层 UDP 不会被这些下游规则改道。LAN 接口上已有的全局地址前缀自动绕过 WG，其余需直连网段填入 `bypass_cidrs`；这些绕过项同样明确豁免防直连保护。不要填入 `0.0.0.0/0` 或 `::/0`，否则会绕过整个对应地址族。重叠地址的站点需要先规划地址/NAT，不能直接按相同 LAN 前缀互联。

## 双向内网互联

本端 LAN `192.168.10.0/24`、远端 LAN `192.168.20.0/24`：

- 本端 binding：`source=192.168.10.0/24`、`destination=192.168.20.0/24`，peer AllowedIPs 至少包含远端 LAN；`masquerade=false`。
- 远端做镜像配置：binding 的源/目标互换，peer AllowedIPs 包含本端 LAN。远端也可使用标准 WireGuard 和 Linux 路由，无需 Veer。
- 两端 LAN 设备默认网关应指向各自 WG 路由器，或在其网关上补充到远端 LAN 的静态路由；两端防火墙允许这些网段。

IPv6 同理，例如源 `fd10::/64`、目标 `fd20::/64`。`masquerade=true` 会对选择的 IPv4/IPv6 流量进行 NAT；站点互联及具有正确回程路由的 IPv6 出口应关闭它，以保留源地址。

## 密钥、运行与清理

页面“保存密钥”将私钥写入插件独立的加密 Secret `private_<profile-key>`。也可通过 `set_key` action 写入：`{"key":"default","value":"实际私钥"}`。若启用 PSK，给 action 增加 `name`，然后在 peer 中填写同名 `preshared_key_secret`。私钥不放入 profile，不通过 argv、日志或状态接口返回；WG 配置经 stdin 传给 `wg syncconf`，不落明文临时文件。inspect 仅查询公钥、endpoint、握手时间和字节计数；握手为 0 代表尚未成功握手，配置已应用不等于对端可达。

应用前检查所有参数、密钥、主机转发条件和资源冲突；接口 alias、nft table comment、持久化 lease 共同标记所有权。旧版 nft 的 JSON 未包含 table comment 时，严格检查文本输出中的表头和顶层 comment，不接受链/规则中的同名 comment。使用固定专用路由表和完整 selector 删除规则，不调用系统范围的 flush。对已有未知接口、表或优先级冲突会报错。

选中流量使用独立路由表，包含 unreachable 默认路由；nft guard 阻止它在 WG 接口消失后转向其他出口。应用过程先阻止选中流量再修改路由；中途失败保留已安装 guard 和恢复信息，重试同一配置或拆除，不会假报成功。修改路由的应用操作可能短暂中断选中流量；这是示例管理流程，不保证无损切换。硬退出发生在外部命令之间时需重启/重试完成恢复，不能视作跨进程原子事务。

重启只恢复上次显式应用的配置，不自动应用后续保存的草稿。没有周期性 shell 调用或逐包 JS。接口被外部删除后，流量保持阻断，手动“保存并应用”可恢复。停用插件或执行 teardown 会删除自有规则、路由、接口和 nft 表；**显式拆除后所选设备恢复系统正常路由**。Secret 保留供再次使用。

## 验证

```text
node --test internal/app/web_test/wireguard_plugin.test.js
go run . plugin test --source plugins/wireguard_mesh --os linux --architecture amd64 --kernel 6.6.0
sudo env VEER_RUN_WIREGUARD_TESTS=1 go test ./internal/app -run '^TestWireGuardMeshLinuxIntegration$' -count=1 -v
```

Linux 集成测试在临时网络命名空间中创建路由器、两个下游设备和一个真实 WG peer，验证设备选路、双栈 NAT、未选设备直连、隧道删除后的防泄漏和恢复、整个 LAN 的双向内网互联与精确清理。CI 在 AMD64/ARM64 Linux runner 上执行；缺少工具、权限或 WireGuard 内核支持会使显式启用的测试失败。

参考：[WireGuard 快速开始](https://www.wireguard.com/quickstart/)、[wg(8)](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8)、[WireGuard 网络命名空间](https://www.wireguard.com/netns/)。
