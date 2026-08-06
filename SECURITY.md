# Veer 安全边界

本文记录 Veer 的信任模型、默认门禁和仍需由部署者承担的边界。安全问题请通过私有渠道报告给维护者，不要在公开 issue 中附带令牌、配置、数据库、插件密钥或主机网络信息。

## 信任模型

Veer 是宿主机网络控制面，核心进程需要修改接口、路由、TC/XDP、nftables 与网络命名空间。获得 `web_token` 的主体等同于网络管理员；获得 `web_token` 和 `plugin_admin_token` 的主体还可以安装、信任、启停和更新插件。宿主机 root 始终在信任边界内，Veer 不试图防御 root。

管理 API 不内置 TLS。默认回环监听是安全基线；远程管理必须置于受信管理网、VPN、堡垒机或启用 TLS 和访问控制的反向代理之后。`/healthz` 与 `/readyz` 故意匿名开放，只返回最小存活状态；其余 `/api/*` 与 `/metrics` 均需要 Bearer Token。

## 已有门禁

| 边界 | 门禁 | 使用影响 |
| --- | --- | --- |
| 管理面 | 默认 `127.0.0.1`、常量时间令牌比较、失败尝试限速、非回环监听最短 24 字符、无 Cookie/CORS、请求体和 HTTP 超时上限 | 正常请求无感；连续输错令牌会短暂返回 `429` |
| 浏览器 | CSP、禁止嵌套、无引用来源、能力策略；插件 UI 在无同源权限的 sandbox iframe 中运行 | 主令牌为保持日常体验保存在 `localStorage`；插件高权令牌仅保存在当前标签页 `sessionStorage` |
| 本地文件 | 配置、SQLite/WAL/SHM、插件密钥与 IPC 默认 `0600/0700`；拒绝敏感路径符号链接 | 权限不安全时启动阶段自动收紧或拒绝 |
| 插件供应链 | 插件默认关闭；包签名、发布者审核、TUF 仓库元数据、摘要复核、原子安装/回滚与配额 | 首次发布者或权限扩张需要一次明确审核 |
| 插件运行时 | 默认独立进程、full sandbox、seccomp/cgroup/资源上限、显式权限与网络 CIDR、Host broker | 宿主机不满足 full sandbox 时拒绝外部插件，不静默降级 |
| 共享站点 | QUIC 默认关闭；UDP 443 与普通规则统一做冲突校验；只解密协议公开的 Initial 以读取 SNI，握手分片、数据报和会话均有数量/字节/空闲上限 | QUIC 仍是 TLS 透传，Veer 不持有站点私钥、不验证后端证书，也不隐藏 SNI |
| WHMCS | 登录会话、CSRF、资源归属、产品/IP/端口/协议/配额校验、输出转义；同一客户创建操作由数据库行锁串行化 | 正常操作无感，并发超额创建会按既定配额拒绝 |

## 部署要求

- 使用部署脚本生成的随机令牌，分别保存 `web_token` 与 `plugin_admin_token`，不要复用。
- 不要把 `config.json`、`forward.db*`、`*.veer-secrets.key` 或部署输出上传到工单、日志平台和制品仓库。
- 非回环管理监听不得直接暴露在公网明文链路上。反向代理应自行限制来源并校验证书。
- 只安装来源可信的插件。签名证明发布来源与完整性，不等同于代码安全审计；外部 dataplane 插件会执行受信 eBPF 对象。
- 共享站点启用 QUIC 前，应确认 UDP `443` 已放行且后端同一 HTTPS 端口确实提供 QUIC。ECH 隐藏实际 SNI、连接迁移、复用客户端端点时的未知 CID 轮换和后端 TLS 身份校验不由当前共享代理处理。
- WHMCS 的共享站点功能目前校验客户后端 IP 归属，但不证明客户拥有所填写的域名。多租户环境应在开放该功能前增加业务侧域名验证，或仅向可信客户开放。

## 保留风险与后续门禁

1. Web 主令牌保存在 `localStorage` 以避免每次打开面板都重新输入。当前通过无第三方脚本、DOM 文本构造、CSP 和插件 iframe 隔离降低 XSS 风险；未来若引入任何第三方前端代码，必须先改为短期会话凭据或受保护的认证代理。
2. 核心服务仍是高权限网络守护进程。systemd 已限制可写路径和 capability 集，但 `CAP_SYS_ADMIN` 等能力由插件命名空间与网络编排路径需要；应继续拆分可由低权限 broker 承担的操作。
3. WHMCS 域名所有权和跨进程配额分别属于业务授权与并发边界。本次已修复配额竞态；域名验证需要结合实际域名资产来源设计，不能用 DNS 解析结果冒充所有权证明。
4. Privileged、稳定性和性能测试需要 root Linux 与真实内核能力，发布前应在专用测试机运行 `sh scripts/verify-plugin-release.sh privileged`，并按发布风险运行 `stability` 与 `performance`。

## 发布门禁

GitHub CI 执行 module 完整性、Go 测试与 race、vet、staticcheck、govulncheck、fuzz、Node 单元测试、Playwright E2E、npm audit、PHP 语法、shellcheck、插件 SDK 合约与确定性打包。任何安全门禁变更必须带回归测试，且不能通过静默降级换取通过。
