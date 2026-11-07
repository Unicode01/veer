# Veer

面向虚拟机宿主机和二级路由的可编程 Linux 网络转发服务。内置 WebUI、管理 API 和 SQLite，统一管理端口转发、共享建站、端口段、Egress NAT、托管网络、IPv6 分发与插件；支持 userspace、TC 和 XDP 数据面。

## 安装

在使用 systemd 或 OpenRC 的 Linux 主机中，进入 root shell 后执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Unicode01/veer/refs/heads/main/bootstrap.sh)
```

默认管理地址为 `http://127.0.0.1:8080`。脚本会构建源码并安装或更新 Veer；插件默认不安装。Alpine、GitHub 访问受限和手动部署方式见[使用指南](docs/README.md#一键部署)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [使用指南](docs/README.md) | 部署、配置、功能、系统兼容性与测试 |
| [API](docs/API.md) | 管理接口与集成 |
| [插件开发](docs/PLUGIN.md) | 控制面、数据面、WebUI bridge 与 SDK |
| [可选内核扩展](docs/KERNEL.md) | helper 能力、构建、部署与生命周期 |
| [VPN 插件](docs/plugins/vpn_core/README.md) | WireGuard、Mihomo、sing-box 与出口配置 |
| [安全建议](docs/README.md#安全建议) | 信任模型、部署要求与已知限制 |

配置示例见 [config.example.json](config.example.json)。

[MIT License](LICENSE)
