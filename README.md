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
- 支持 Worker 自动分配、重分布和 draining 退出
- 支持规则 / 站点 / 范围映射流量统计
- 支持标签、排序、搜索、分页
- 通过 Bearer Token 保护管理 API
- 仓库内附带 WHMCS 插件，支持规则管理、80/443 共享建站和 HAProxy 规则导入脚本

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
  "kernel_engine_order": ["xdp", "tc"],
  "kernel_rules_map_limit": 0,
  "experimental_features": {
    "bridge_xdp": false
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
- `kernel_engine_order`：Linux 内核态引擎尝试顺序，默认 `["xdp", "tc"]`；当前会自动跳过不可用引擎并回退
- `kernel_rules_map_limit`：内核 `rules_v4/stats_v4` map 容量；`0` 或省略时按当前 kernel entries 自适应扩容，默认从 `16384` 起按 2 倍增长到 `262144`；设置为正数时使用固定上限
- `experimental_features`：实验性功能开关表，默认关闭；像 `bridge_xdp` 这类高风险、兼容性仍在收敛中的能力会通过这里单独放开
- `tags`：可选标签列表，会在前端表单中作为下拉项出现

示例：

```json
"experimental_features": {
  "bridge_xdp": true
}
```

说明：

- 键名会按小写、`-` 转 `_` 归一化，例如 `bridge-xdp` 会被视为 `bridge_xdp`
- 只有代码中显式接入检查的实验项才会生效；未接入的键会被保留但不会影响当前行为
- `bridge_xdp` 已接入第一版实验实现，默认仍为关闭；当前主要面向透明 XDP 场景，依赖 bridge 邻居/FDB 解析，解析失败或接口不兼容时会自动回退

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
