# WireGuard WAN 示例插件

显式安装的 `lab` 插件，不进入默认发布包，也不自动安装 WireGuard。一个 profile 提供一个 WAN，LAN 或下游设备通过现有 Veer 出向 NAT 选择它。

```text
下游设备 → Veer TC 出向 NAT → WAN local veth → pipeline veth
         → WG TC 适配器 → 内核 WireGuard → 主机原有上游 → 对端
回包：内核 WG 解密 → TC 补回 Ethernet → WAN local ingress → Veer reply flow → 下游
```

JavaScript 负责配置和恢复，不参与逐包转发。无需关闭 Veer 快速 NAT；不创建源地址策略规则、不安装全局默认路由，不使用 `wg-quick`。加密后的外层 UDP 使用主机原有路由，因此上游仍可为物理 WAN 或 PPPoE。

## 安装

1. Linux 内核需支持 WireGuard，安装 `wireguard-tools iproute2 ethtool`，确认 `/usr/bin/wg`、`/usr/sbin/ip` 可用。主机原有路由和防火墙需允许对端 UDP。
2. 在 Linux 源码目录运行 `sh plugins/wireguard_mesh/build.sh`，生成 `wg_adapter.o`。将整个插件目录复制到实际 `plugins_dir`，同时安装 `wan_core >=1.5.0 <2.0.0`。
3. 开启 `plugins_enabled=true` 和 `plugins_dataplane_enabled=true`；保持默认 `plugins_remote_install_enabled=false` 以允许插件 exec。插件需要 Veer 的网络管理权限，不执行 shell 或用户提供的脚本。
4. 打开 WireGuard 页面，保存私钥，再保存并应用 profile。空插件和仅保存的草稿不更改网络。
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
node --test internal/app/web_test/wireguard_plugin.test.js
sudo env VEER_RUN_WIREGUARD_TESTS=1 go test ./internal/app -run '^TestWireGuardMeshLinuxIntegration$' -count=1 -v -timeout=5m
```

Linux 测试在独立网络命名空间启动真实 Veer 和 WG peer，验证核心 NAT 与适配器的 TCP/UDP/ICMP 收发、下游接口覆盖、普通 WAN 不受影响、WG 重建及拆除后重新应用。显式启用时缺少权限、工具或内核能力直接失败。
