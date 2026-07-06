# API 文档

这份文档面向需要把 `forward` 接入其他系统的开发者，例如：

- 自定义运维平台
- CMDB / 资源编排系统
- 虚拟机开通脚本
- 工单系统、自动化脚本、内部控制台
- n8n / Dify / Flowise / 自建 Agent

`forward` 当前不只是规则转发 API，还包含：

- 规则、站点、端口范围
- Egress NAT
- 托管网络
- 托管网络固定 DHCPv4 保留
- IPv6 Assignment
- Worker / Stats / Kernel Runtime 观测

## 基本信息

- Base URL: `http://<host>:<web_port>`
- 默认端口: `8080`
- API 前缀: `/api`
- 认证方式: `Authorization: Bearer <web_token>`
- 写操作默认使用 `application/json`
- 探活端点: `/healthz`、`/readyz` 不使用 `/api` 前缀

`web_token` 来自 `config.json`：

```json
{
  "web_port": 8080,
  "web_token": "replace-with-a-real-token"
}
```

注意：

- `web_token` 不能为空
- 程序会拒绝使用示例占位值 `change-me-to-a-secure-token`

## 认证与错误约定

所有 `/api/*` 端点都需要 Bearer Token。`/healthz` 和 `/readyz` 用于本机或负载均衡探活，不需要 Bearer Token。

请求头示例：

```http
Authorization: Bearer your-token-here
Content-Type: application/json
```

常见状态码：

- `200 OK`: 成功
- `400 Bad Request`: 参数错误或请求体非法
- `401 Unauthorized`: Token 错误或缺失
- `404 Not Found`: 资源不存在
- `405 Method Not Allowed`: 请求方法不支持
- `500 Internal Server Error`: 服务端内部错误

大多数业务错误会返回 JSON，例如：

```json
{
  "error": "invalid id"
}
```

字段校验类错误通常返回：

```json
{
  "error": "create[1] out_source_ip: out_source_ip must be a valid IPv4 address",
  "issues": [
    {
      "scope": "create",
      "index": 1,
      "field": "out_source_ip",
      "message": "out_source_ip must be a valid IPv4 address"
    }
  ]
}
```

`issues` 中常见字段：

- `scope`: `create` / `update` / `toggle` / `delete` / `persist`
- `index`: 批量请求里的条目序号
- `id`: 相关对象 ID
- `field`: 出错字段
- `message`: 原始错误信息

需要注意：

- `401` 和部分 `405` 仍可能是纯文本响应
- `Kernel Runtime` 的调试字段会随版本演进增加，外部解析时应按“已知字段尽量读取，未知字段忽略”处理

## 接口总览

### 健康检查

- `GET /healthz`
- `GET /readyz`

### 基础发现

- `GET /api/interfaces`
- `GET /api/host-network`
- `GET /api/tags`
- `GET /api/plugins`

### 规则

- `GET /api/rules`
- `POST /api/rules`
- `PUT /api/rules`
- `DELETE /api/rules?id=<rule_id>`
- `POST /api/rules/toggle?id=<rule_id>`
- `POST /api/rules/validate`
- `POST /api/rules/batch`

### 站点

- `GET /api/sites`
- `POST /api/sites`
- `PUT /api/sites`
- `DELETE /api/sites?id=<site_id>`
- `POST /api/sites/toggle?id=<site_id>`

### 端口范围

- `GET /api/ranges`
- `POST /api/ranges`
- `PUT /api/ranges`
- `DELETE /api/ranges?id=<range_id>`
- `POST /api/ranges/toggle?id=<range_id>`

### Egress NAT

- `GET /api/egress-nats`
- `POST /api/egress-nats`
- `PUT /api/egress-nats`
- `DELETE /api/egress-nats?id=<egress_nat_id>`
- `POST /api/egress-nats/toggle?id=<egress_nat_id>`

### 托管网络

- `GET /api/managed-networks`
- `POST /api/managed-networks`
- `PUT /api/managed-networks`
- `DELETE /api/managed-networks?id=<managed_network_id>`
- `POST /api/managed-networks/toggle?id=<managed_network_id>`
- `POST /api/managed-networks/persist-bridge?id=<managed_network_id>`
- `POST /api/managed-networks/reload-runtime`
- `POST /api/managed-networks/repair`
- `GET /api/managed-networks/runtime-status`

### 托管网络固定保留

- `GET /api/managed-network-reservations`
- `POST /api/managed-network-reservations`
- `PUT /api/managed-network-reservations`
- `DELETE /api/managed-network-reservations?id=<reservation_id>`
- `GET /api/managed-network-reservation-candidates`

### IPv6 Assignment

- `GET /api/ipv6-assignments`
- `POST /api/ipv6-assignments`
- `PUT /api/ipv6-assignments`
- `DELETE /api/ipv6-assignments?id=<assignment_id>`

### Worker 与运行时

- `GET /api/workers`
- `GET /api/kernel/runtime`
- `POST /api/kernel/runtime/dismiss-note`

### 统计

- `GET /api/rules/stats`
- `GET /api/ranges/stats`
- `GET /api/egress-nats/stats`
- `GET /api/sites/stats`
- `GET /api/stats/current-conns`

## 常用对象

### InterfaceInfo

`GET /api/interfaces` 返回简化接口清单：

```json
[
  {
    "name": "eth0",
    "addrs": ["203.0.113.10", "2001:db8::10"],
    "kind": "device"
  },
  {
    "name": "tap100i0",
    "addrs": [],
    "parent": "vmbr0",
    "kind": "tap"
  }
]
```

### HostNetworkResponse

`GET /api/host-network` 返回更完整的宿主机接口视图：

```json
{
  "interfaces": [
    {
      "name": "vmbr0",
      "kind": "bridge",
      "default_ipv4_route": true,
      "default_ipv6_route": true,
      "addresses": [
        {
          "family": "ipv4",
          "ip": "192.168.4.1",
          "cidr": "192.168.4.1/24",
          "prefix_len": 24
        },
        {
          "family": "ipv6",
          "ip": "2402:db8:1::1",
          "cidr": "2402:db8:1::/64",
          "prefix_len": 64
        }
      ]
    }
  ]
}
```

- `default_ipv4_route`: 该接口当前是否承载主路由表里的 IPv4 默认路由
- `default_ipv6_route`: 该接口当前是否承载主路由表里的 IPv6 默认路由

### PluginCatalog

`GET /api/plugins` 返回运行时插件目录扫描结果和内置 `fvtap` 描述：

```json
{
  "external_plugins_enabled": true,
  "directory": "plugins/runtime",
  "runtime": {
    "builtin_pipeline_id": "fvtap",
    "core_priority": 1000,
    "manifest_discovery": true,
    "object_validation": true,
    "protected_assets": true,
    "external_dataplane_attach": false,
    "supported_engines": ["tc", "xdp", "control"],
    "supported_hook_modes": ["observe", "rewrite", "redirect", "drop", "control"]
  },
  "plugins": [
    {
      "api_version": "v1",
      "id": "fvtap",
      "name": "Forward Virtual Tap",
      "version": "builtin",
      "kind": "pipeline",
      "builtin": true,
      "status": "builtin",
      "runtime": {
        "mode": "builtin",
        "attachable": true,
        "attached": true
      },
      "capabilities": ["egress_nat", "kernel_tc", "kernel_xdp"],
      "objects": [
        {"id": "forward-tc", "path": "builtin:forward-tc"},
        {"id": "forward-xdp", "path": "builtin:forward-xdp"}
      ]
    }
  ]
}
```

字段说明：

- `status`: `builtin` / `active` / `error`
- `runtime`: 插件运行时状态；内置 `fvtap` 为 `mode=builtin` 且已挂载。默认配置下外部插件为 `mode=manifest_only`，启用 `plugins_dataplane_enabled=true` 且存在可链入的 TC `stage=forward/reply` hook 后，会变为 `mode=dataplane` 并返回 `attachments`
- `runtime.core_priority`: 内置 `fvtap core` 的排序锚点，当前固定为 `1000`
- `runtime.external_dataplane_attach`: 是否允许外部数据面插件。默认 `false`；为 `true` 时当前支持 TC `stage=forward/reply` hook 按 priority 进入内置 `fvtap` pipeline。没有实际可链入插件时，TC 热路径仍保持 legacy/dispatch，不额外进入 pipeline wrapper
- `objects`: 插件声明的 eBPF 对象或内置对象；外部对象路径必须留在插件目录内，单个对象最大 16 MiB，声明 `sha256` 时必须匹配文件内容；服务会解析 ELF 并补充 `status`、`resolved_sha256`、`program_count`、`map_count`
- `asset_base_path`: 插件声明 `ui.static_dir` 后生成的静态资源路径，需要 Bearer Token
- `metadata.ui.page`: 可选的 Web UI 顶部分页 ID；声明后前端会自动创建插件页并内嵌加载 `ui.entry`。标题可用 `metadata.ui.page_title` 指定；也兼容 `ui_page`、`forward.page`、`forward_ui_page`、`tab_title` 等键
- `hooks`: 插件声明的 dataplane hook；默认只做控制面展示。开启外部数据面后，只有 `engine=tc`、`stage=forward/reply`、`attach=ingress/both`、非 `control` mode 的 hook 会被加载到 `tc_prog_chain_v4` stage slots。插件程序执行后必须 tail-call 到对应 stage 的内置 continue slot，除非它明确返回最终 TC action。旧 `stage=pre_forward/post_lookup/pre_reply/post_reply` 作为兼容别名保留；XDP 和其他 stage 当前仍是 manifest-only
- `hooks[].interfaces`: 可选的真实 Linux 接口名列表。留空或省略时，插件只随已有 forward/egress 规则触发的 `fvtap` attachment 运行；填写后，即使没有转发规则，TC runtime 也会把 `pipeline_v4` 挂到这些接口上。无规则模式只加载显式接口上的 `pre_forward/pre_reply` hook；core 后 hook 仍需要规则或 flow 上下文。不会自动挂载所有接口；接口不存在会让该插件本轮进入 error。当前 pipeline chain 是全局链，插件如果需要严格按接口生效，应在自己的 eBPF 程序中检查 `skb->ifindex`
- `runtime.attachments[].priority`: 插件 manifest 的排序优先级；低于 `runtime.core_priority` 会运行在 `fvtap core` 前，高于 `runtime.core_priority` 会运行在 core 完成 IPv4/L4 解析和规则匹配后、执行 NAT/redirect 前。等于 core priority 会被拒绝。`runtime.attachments[].chain_slot` 是实际写入 `tc_prog_chain_v4` 的 slot
- `post_lookup` 插件如需读取规则匹配上下文，必须在对象里声明共享 `tc_plugin_ctx_v4` per-CPU array map；服务会替换为内置稳定 ctx map，IPv4 地址和端口字段按 host byte order 填充
- 当前限制：core 前和 core 后两个物理执行区各最多 8 个外部 hook，总 hook 数最多 14 个，以避免触发内核 tail-call 深度上限

插件控制面数据接口：

- `GET /api/plugins/<id>/resources/<resource>`：列出 manifest 允许 `list` 的资源记录，并返回该资源的 `runtime_status`
- `GET /api/plugins/<id>/resources/<resource>/<key>`：读取 manifest 允许 `get` 的单条记录
- `POST /api/plugins/<id>/resources/<resource>`：创建 manifest 允许 `create` 的记录，请求体为 `{"key":"optional","data":{...},"enabled":true}`；未提供 `key` 时由服务生成
- `PUT /api/plugins/<id>/resources/<resource>/<key>`：更新 manifest 允许 `update` 的记录
- `DELETE /api/plugins/<id>/resources/<resource>/<key>`：删除 manifest 允许 `delete` 的记录
- `POST /api/plugins/<id>/actions/<action>`：执行 manifest 声明的动作，请求体为 `{"payload":{...}}`

资源和动作都必须先在 `plugin.json` 中声明。资源数据存储在 SQLite，`secret_fields` 会在 API 返回时脱敏；`runtime_update=manual` 只标记 pending，`plugin_reconcile` 触发插件运行时重算，`runtime_apply` 调用宿主数据面实现的运行时更新接口。运行时更新失败会写入 `runtime_status.status=error` 和 `last_error`，不会让插件 UI 直接拿到 Web Token。

Goja 控制脚本默认只能访问本插件资源。声明 `control.permissions=["plugin.resource"]` 后，可使用 `plugins.resources.set(pluginID, resourceID, key, data, enabled, apply)` 写入其他插件已经声明的资源；该调用仍会校验目标资源的 `methods/max_records/max_record_bytes`。`apply=true` 且目标资源为 `runtime_update=runtime_apply` 时，会立即触发目标插件的 `onResourceApply` 并更新目标资源的 `runtime_status`。未声明该权限时调用会被拒绝。

### RuleStatus

```json
{
  "id": 1,
  "in_interface": "eth0",
  "in_ip": "203.0.113.10",
  "in_port": 2222,
  "out_interface": "vmbr0",
  "out_ip": "198.51.100.10",
  "out_source_ip": "",
  "out_port": 22,
  "protocol": "tcp",
  "remark": "vm-a ssh",
  "tag": "vm",
  "enabled": true,
  "transparent": false,
  "engine_preference": "auto",
  "status": "running",
  "effective_engine": "kernel",
  "effective_kernel_engine": "tc",
  "kernel_eligible": true
}
```

运行时补充字段：

- `status`: `running` / `stopped` / `error`
- `effective_engine`: `userspace` / `kernel`
- `effective_kernel_engine`: `tc` / `xdp` / `mixed`
- `kernel_eligible`: 是否满足内核态接入条件
- `kernel_reason`: 不满足内核态条件时的原因
- `fallback_reason`: 满足条件但最终回退时的原因

### SiteStatus

```json
{
  "id": 1,
  "domain": "app.example.com",
  "listen_ip": "203.0.113.10",
  "listen_interface": "eth0",
  "backend_ip": "198.51.100.10",
  "backend_source_ip": "",
  "backend_http_port": 80,
  "backend_https_port": 443,
  "tag": "vm",
  "enabled": true,
  "transparent": false,
  "status": "running"
}
```

### PortRangeStatus

```json
{
  "id": 1,
  "in_interface": "eth0",
  "in_ip": "203.0.113.10",
  "start_port": 30000,
  "end_port": 30100,
  "out_interface": "vmbr0",
  "out_ip": "198.51.100.20",
  "out_source_ip": "",
  "out_start_port": 30000,
  "protocol": "tcp+udp",
  "remark": "vm-b game",
  "tag": "game",
  "enabled": true,
  "transparent": false,
  "status": "running",
  "effective_engine": "kernel",
  "effective_kernel_engine": "tc",
  "kernel_eligible": true
}
```

### EgressNATStatus

```json
{
  "id": 1,
  "parent_interface": "vmbr0",
  "child_interface": "tap100i0",
  "out_interface": "eth0",
  "out_source_ip": "203.0.113.10",
  "protocol": "tcp+udp+icmp",
  "nat_type": "symmetric",
  "enabled": true,
  "status": "running",
  "effective_engine": "kernel",
  "effective_kernel_engine": "tc",
  "kernel_eligible": true
}
```

### ManagedNetworkStatus

```json
{
  "id": 2,
  "name": "vmbr",
  "bridge_mode": "existing",
  "bridge": "vmbr0",
  "bridge_mtu": 0,
  "bridge_vlan_aware": false,
  "uplink_interface": "eno1",
  "ipv4_enabled": true,
  "ipv4_cidr": "192.168.4.1/24",
  "ipv4_gateway": "",
  "ipv4_pool_start": "192.168.4.2",
  "ipv4_pool_end": "192.168.4.254",
  "ipv4_dns_servers": "8.8.8.8",
  "ipv6_enabled": true,
  "ipv6_parent_interface": "eno1",
  "ipv6_parent_prefix": "2402:db8:1::/64",
  "ipv6_assignment_mode": "single_128",
  "auto_egress_nat": true,
  "remark": "",
  "enabled": true,
  "child_interface_count": 3,
  "generated_ipv6_assignment_count": 3,
  "generated_egress_nat": true,
  "reservation_count": 2,
  "preview_warnings": [],
  "repair_recommended": false,
  "ipv4_runtime_status": "running",
  "ipv4_runtime_detail": "listening for dhcpv4",
  "ipv6_runtime_status": "running"
}
```

补充字段：

- `bridge_mode`: `create` / `existing`
- `generated_ipv6_assignment_count`: 自动生成的 IPv6 Assignment 数量
- `generated_egress_nat`: 是否自动生成 Egress NAT
- `preview_warnings`: 基于当前接口拓扑计算出的提示
- `repair_recommended` / `repair_issues`: 是否建议执行托管网络修复
- `ipv4_*` / `ipv6_*`: 托管网络运行时状态与计数器

### ManagedNetworkReservationStatus

```json
{
  "id": 1,
  "managed_network_id": 2,
  "mac_address": "bc:24:11:84:f5:2c",
  "ipv4_address": "192.168.4.6",
  "remark": "SelfWindows / net0",
  "managed_network_name": "vmbr",
  "managed_network_bridge": "vmbr0"
}
```

### ManagedNetworkReservationCandidate

```json
{
  "managed_network_id": 1,
  "managed_network_name": "vmbr",
  "managed_network_bridge": "vmbr0",
  "pve_vmid": "104",
  "pve_guest_name": "SelfWindows",
  "pve_guest_nic": "net0",
  "child_interface": "tap104i0",
  "mac_address": "bc:24:11:84:f5:2c",
  "suggested_ipv4": "192.168.4.6",
  "ipv4_candidates": [
    "192.168.4.6",
    "192.168.4.7",
    "192.168.4.8"
  ],
  "suggested_remark": "SelfWindows / net0",
  "status": "available"
}
```

如果候选已经和现有固定保留匹配，还会附带：

- `existing_reservation_id`
- `existing_reservation_ipv4`
- `existing_reservation_remark`

### IPv6Assignment

```json
{
  "id": 1,
  "parent_interface": "eno1",
  "target_interface": "tap100i0",
  "parent_prefix": "2402:db8:100::/48",
  "assigned_prefix": "2402:db8:100:1::/64",
  "address": "2402:db8:100:1::",
  "prefix_len": 64,
  "remark": "vm-a ipv6",
  "enabled": true,
  "ra_advertisement_count": 8,
  "dhcpv6_reply_count": 0,
  "runtime_status": "running"
}
```

语义说明：

- `/128` 表示“目标侧使用这个单地址”
- `/64` 常用于目标侧子网和 SLAAC
- 其他前缀长度更适合“下游委派前缀”语义
- 这不是把该地址直接绑定到宿主机 `target_interface`

### WorkerListResponse

```json
{
  "page": 1,
  "page_size": 20,
  "total": 5,
  "binary_hash": "abc123",
  "workers": [
    {
      "kind": "kernel",
      "index": 0,
      "status": "running",
      "binary_hash": "abc123",
      "rule_count": 2,
      "rules": []
    },
    {
      "kind": "egress_nat",
      "index": 0,
      "status": "running",
      "binary_hash": "abc123",
      "egress_nat_count": 1,
      "egress_nats": []
    }
  ]
}
```

`kind` 可能值：

- `kernel`
- `rule`
- `range`
- `egress_nat`
- `shared`

`status` 常见值：

- `running`
- `stopped`
- `draining`
- `error`

### KernelRuntimeResponse

`GET /api/kernel/runtime` 是运行时调试视图，常见关键字段：

```json
{
  "available": true,
  "available_reason": "selected tc kernel engine",
  "kernel_capabilities": {},
  "default_engine": "auto",
  "configured_order": ["tc", "xdp"],
  "traffic_stats": true,
  "tc_diagnostics": false,
  "active_rule_count": 12,
  "active_range_count": 3,
  "retry_pending": false,
  "dismissed_note_keys": [],
  "engines": [
    {
      "name": "tc",
      "available": true,
      "loaded": true,
      "active_entries": 128,
      "attachments": 6,
      "attachment_summary": "eno1(3)/forward, eno1(3)/reply"
    }
  ]
}
```

它还会包含大量调试字段，例如：

- map 容量与占用
- attach mode 与 attachment health
- retry / self-heal / cooldown / backoff
- netlink recover 与 attachment heal 状态
- dismissed note keys
- traffic stats / diagnostics
- 最近一次 reconcile / maintain / prune 信息

## 详细接口

## 1. 基础发现

### 1.0 健康检查

`GET /healthz`

用途：

- 判断 HTTP 服务进程是否存活
- 不需要 Bearer Token

响应示例：

```json
{
  "status": "ok"
}
```

`GET /readyz`

用途：

- 判断服务是否已经完成启动并进入 ready 状态
- 不需要 Bearer Token

启动中返回 `503`：

```json
{
  "status": "starting",
  "ready": false
}
```

就绪后返回 `200`：

```json
{
  "status": "ready",
  "ready": true
}
```

### 1.1 获取简化接口列表

`GET /api/interfaces`

用途：

- 给规则、范围、站点、Egress NAT 表单做接口下拉
- 返回每个接口的 IP 字符串列表

### 1.2 获取宿主机网络拓扑

`GET /api/host-network`

用途：

- 给托管网络和 IPv6 Assignment 表单提供更完整的宿主机网络视图
- 返回按地址族拆开的 `addresses`

### 1.3 获取标签列表

`GET /api/tags`

响应示例：

```json
["vm", "prod", "game"]
```

### 1.4 获取插件目录

`GET /api/plugins`

用途：

- 枚举内置 `fvtap` pipeline 描述
- 枚举 `plugins_dir` 下外部插件 manifest
- 暴露插件 manifest 校验错误，避免启动失败
- 给后续插件管理 UI 或外部控制台做能力发现

说明：

- 默认外部插件目录为 `plugins/runtime`
- 外部插件目录缺失不会报错
- `plugins_enabled = false` 只关闭外部插件扫描，不隐藏内置 `fvtap`
- `plugins_dataplane_enabled = false` 是默认值；设置为 `true` 后允许外部 TC `stage=forward/reply` 插件按 priority 进入内置 `fvtap` pipeline
- 声明 `objects` 的外部插件会校验对象存在性、路径边界、可选 sha256、program section/type 和 hook 引用；校验失败时该插件返回 `status=error`
- 插件静态资源路径为 `/api/plugins/<id>/assets/`，同样需要 Bearer Token
- `runtime.external_dataplane_attach=false` 表示外部插件不会被加载进数据面；`true` 表示允许可信 TC 对象围绕核心 `fvtap` priority 进入 forward/reply 的 core 前/后链。插件对象必须声明共享 `tc_prog_chain_v4` prog-array map，`max_entries` 至少为 45，并在处理后 tail-call 回对应 stage 的 continue slot；core 后插件读取匹配上下文时还需要声明共享 `tc_plugin_ctx_v4` map。`hooks[].interfaces` 可让插件在无转发规则时显式请求接口 attachment，但只有显式接口上的 pre-core hook 会在无规则模式加载，不会自动挂所有接口。生产环境应只对可信对象启用

## 2. 规则接口

### 2.1 获取规则列表

`GET /api/rules`

支持过滤参数：

- `id` / `ids`
- `tag` / `tags`
- `protocol` / `protocols`
- `enabled`
- `transparent`
- `status` / `statuses`
- `in_interface`
- `out_interface`
- `in_ip`
- `out_ip`
- `out_source_ip`
- `in_port`
- `out_port`
- `q`

说明：

- `protocol` 支持 `tcp`、`udp`、`tcp+udp`
- `status` 支持 `running`、`stopped`、`error`
- `q` 会匹配 `id`、备注、标签、接口、IP、端口、协议、状态、引擎字段

### 2.2 新增规则

`POST /api/rules`

请求体示例：

```json
{
  "in_interface": "eth0",
  "in_ip": "203.0.113.10",
  "in_port": 2222,
  "out_interface": "vmbr0",
  "out_ip": "198.51.100.10",
  "out_source_ip": "",
  "out_port": 22,
  "protocol": "tcp",
  "remark": "vm-a ssh",
  "tag": "vm",
  "transparent": false,
  "engine_preference": "auto"
}
```

规则：

- 必填：`in_ip`、`in_port`、`out_ip`、`out_port`
- `protocol` 允许：`tcp`、`udp`、`tcp+udp`
- 省略 `protocol` 时默认 `tcp`
- `engine_preference` 允许：`auto`、`userspace`、`kernel`
- 省略 `engine_preference` 时默认 `auto`
- 创建后默认 `enabled = true`
- `transparent = true` 时必须省略 `out_source_ip`
- IPv6 规则可创建，但当前透明路径和内核接入条件仍主要按 IPv4 约束理解

### 2.3 更新规则

`PUT /api/rules`

请求体与新增类似，但必须包含 `id`。

说明：

- 更新时保留原有 `enabled`
- 更新成功后会触发规则重分布 / 引擎重规划

### 2.4 启用或禁用规则

`POST /api/rules/toggle?id=<rule_id>`

响应示例：

```json
{
  "id": 1,
  "enabled": false
}
```

### 2.5 删除规则

`DELETE /api/rules?id=<rule_id>`

成功响应：

```json
{
  "status": "deleted"
}
```

### 2.6 校验规则批量请求

`POST /api/rules/validate`

用途：

- 在真正写入前做字段校验、接口存在性校验和冲突检查

请求体字段：

- `create`
- `update`
- `delete_ids`
- `set_enabled`

成功时会返回 `valid = true` 和归一化后的内容。失败时返回 `valid = false`、`error`、`issues`。

### 2.7 批量写入规则

`POST /api/rules/batch`

请求体字段：

- `create`
- `update`
- `delete_ids`
- `set_enabled`

说明：

- 整体在一个事务内执行
- 只触发一次规则重分布

## 3. 站点接口

### 3.1 获取站点列表

`GET /api/sites`

返回 `[]SiteStatus`。

### 3.2 新增站点

`POST /api/sites`

请求体示例：

```json
{
  "domain": "app.example.com",
  "listen_ip": "203.0.113.10",
  "listen_interface": "eth0",
  "backend_ip": "198.51.100.10",
  "backend_source_ip": "",
  "backend_http_port": 80,
  "backend_https_port": 443,
  "tag": "vm",
  "transparent": false
}
```

规则：

- 必填：`domain`、`backend_ip`
- `backend_http_port` 和 `backend_https_port` 至少一个非 `0`
- `listen_ip` 为空时默认 `0.0.0.0`
- `transparent = true` 时必须省略 `backend_source_ip`
- 创建后默认 `enabled = true`
- IPv6 站点监听和回源可走普通共享代理路径；透明模式仍限 IPv4

### 3.3 更新站点

`PUT /api/sites`

必须带 `id`。

### 3.4 启用或禁用站点

`POST /api/sites/toggle?id=<site_id>`

### 3.5 删除站点

`DELETE /api/sites?id=<site_id>`

## 4. 端口范围接口

### 4.1 获取范围列表

`GET /api/ranges`

返回 `[]PortRangeStatus`。

### 4.2 新增范围

`POST /api/ranges`

请求体示例：

```json
{
  "in_interface": "eth0",
  "in_ip": "203.0.113.10",
  "start_port": 30000,
  "end_port": 30100,
  "out_interface": "vmbr0",
  "out_ip": "198.51.100.20",
  "out_source_ip": "",
  "out_start_port": 30000,
  "protocol": "tcp+udp",
  "remark": "vm-b game",
  "tag": "game",
  "transparent": false
}
```

规则：

- 必填：`in_ip`、`start_port`、`end_port`、`out_ip`
- `start_port <= end_port`
- `protocol` 允许：`tcp`、`udp`、`tcp+udp`
- 省略 `protocol` 时默认 `tcp`
- `out_start_port = 0` 时自动等于 `start_port`
- `transparent = true` 时必须省略 `out_source_ip`
- 创建后默认 `enabled = true`

### 4.3 更新范围

`PUT /api/ranges`

必须带 `id`。

### 4.4 启用或禁用范围

`POST /api/ranges/toggle?id=<range_id>`

### 4.5 删除范围

`DELETE /api/ranges?id=<range_id>`

## 5. Egress NAT 接口

### 5.1 获取 Egress NAT 列表

`GET /api/egress-nats`

返回 `[]EgressNATStatus`。

### 5.2 新增 Egress NAT

`POST /api/egress-nats`

请求体示例：

```json
{
  "parent_interface": "vmbr0",
  "child_interface": "tap100i0",
  "out_interface": "eno1",
  "out_source_ip": "203.0.113.10",
  "protocol": "tcp+udp+icmp",
  "nat_type": "symmetric"
}
```

规则：

- 必填：`parent_interface`、`out_interface`
- `child_interface` 可选
- `child_interface` 为空表示接管该 `parent_interface` 下所有可接管子接口
- `child_interface = "*"` 会被规范化成空字符串
- `protocol` 必须包含一个或多个：`tcp`、`udp`、`icmp`
- 省略 `protocol` 时默认 `tcp+udp`
- `nat_type` 允许：`symmetric`、`full_cone`
- 省略 `nat_type` 时默认 `symmetric`
- `out_source_ip` 可选，但必须是 `out_interface` 上的本地 IPv4
- `parent_interface` / `child_interface` / `out_interface` 之间不能形成非法重叠
- 同协议集合下，enabled 的 Egress NAT scope 不能互相冲突
- 创建后默认 `enabled = true`

### 5.3 更新 Egress NAT

`PUT /api/egress-nats`

必须带 `id`，更新时保留原有 `enabled`。

### 5.4 启用或禁用 Egress NAT

`POST /api/egress-nats/toggle?id=<egress_nat_id>`

### 5.5 删除 Egress NAT

`DELETE /api/egress-nats?id=<egress_nat_id>`

## 6. 托管网络接口

### 6.1 获取托管网络列表

`GET /api/managed-networks`

返回 `[]ManagedNetworkStatus`。

### 6.2 新增托管网络

`POST /api/managed-networks`

请求体示例：

```json
{
  "name": "vmbr",
  "bridge_mode": "existing",
  "bridge": "vmbr0",
  "bridge_mtu": 0,
  "bridge_vlan_aware": false,
  "uplink_interface": "eno1",
  "ipv4_enabled": true,
  "ipv4_cidr": "192.168.4.1/24",
  "ipv4_gateway": "",
  "ipv4_pool_start": "192.168.4.2",
  "ipv4_pool_end": "192.168.4.254",
  "ipv4_dns_servers": "8.8.8.8",
  "ipv6_enabled": true,
  "ipv6_parent_interface": "eno1",
  "ipv6_parent_prefix": "2402:db8:1::/64",
  "ipv6_assignment_mode": "single_128",
  "auto_egress_nat": true,
  "remark": ""
}
```

规则：

- 必填：`name`、`bridge`
- `bridge_mode` 允许：`create`、`existing`
- 省略 `bridge_mode` 时默认 `create`
- `ipv6_assignment_mode` 允许：`single_128`、`prefix_64`
- `bridge_mtu` 仅在 `create` 模式生效，范围为 `0-65535`
- `existing` 模式下 `bridge_mtu` 和 `bridge_vlan_aware` 会被归零
- `existing` 模式要求目标 bridge 已存在于宿主机
- `create` 模式要求 bridge 名称不与非 bridge 接口冲突
- 创建后默认 `enabled = true`

### 6.3 更新托管网络

`PUT /api/managed-networks`

必须带 `id`，更新时保留原有 `enabled`。

### 6.4 启用或禁用托管网络

`POST /api/managed-networks/toggle?id=<managed_network_id>`

### 6.5 删除托管网络

`DELETE /api/managed-networks?id=<managed_network_id>`

### 6.6 持久化 create 模式 bridge

`POST /api/managed-networks/persist-bridge?id=<managed_network_id>`

用途：

- 把 `create` 模式下的 bridge 写入宿主机 `/etc/network/interfaces`
- 写入成功后，把该托管网络切换成 `existing` 模式

仅支持：

- Linux
- `bridge_mode = create`

成功响应示例：

```json
{
  "status": "persisted",
  "bridge": "vmbr7",
  "interfaces_path": "/etc/network/interfaces",
  "backup_path": "/etc/network/interfaces.forward.bak"
}
```

### 6.7 触发托管网络运行时重载

`POST /api/managed-networks/reload-runtime`

响应示例：

```json
{
  "status": "queued"
}
```

`status` 常见值：

- `queued`
- `success`
- `fallback`

### 6.8 修复托管网络宿主机状态

`POST /api/managed-networks/repair`

响应示例：

```json
{
  "status": "queued",
  "bridges": ["vmbr0"],
  "guest_links": ["tap100i0->vmbr0"]
}
```

如果只做了部分修复，还可能返回：

```json
{
  "status": "partial",
  "bridges": ["vmbr0"],
  "error": "..."
}
```

其中 `guest_links` 可能包含 PVE guest 侧链路名，例如 `fwpr100p0->vmbr0`、`tap100i0->vmbr0`、`veth101i0->vmbr0`。

### 6.9 获取托管网络运行时重载状态

`GET /api/managed-networks/runtime-status`

响应字段包括：

- `pending`
- `due_at`
- `last_requested_at`
- `last_request_source`
- `last_request_summary`
- `last_started_at`
- `last_completed_at`
- `last_result`
- `last_applied_summary`
- `last_error`

## 7. 托管网络固定 DHCPv4 保留

### 7.1 获取固定保留列表

`GET /api/managed-network-reservations`

返回 `[]ManagedNetworkReservationStatus`。

### 7.2 获取保留候选

`GET /api/managed-network-reservation-candidates`

用途：

- 从托管 bridge 当前学习到的 MAC / guest 元信息里给出一键固定保留候选

常见字段：

- `suggested_ipv4`
- `ipv4_candidates`
- `suggested_remark`
- `status`
- `existing_reservation_*`

### 7.3 新增固定保留

`POST /api/managed-network-reservations`

请求体示例：

```json
{
  "managed_network_id": 1,
  "mac_address": "bc:24:11:84:f5:2c",
  "ipv4_address": "192.168.4.6",
  "remark": "SelfWindows / net0"
}
```

规则：

- `managed_network_id` 必须存在，且对应托管网络 `ipv4_enabled = true`
- `mac_address` 必须是有效以太网 MAC，写入时会归一化为小写
- `ipv4_address` 必须落在该托管网络的 `ipv4_cidr` 内
- `ipv4_address` 不能等于托管网络网关地址
- `ipv4_address` 必须是可用 host 地址
- 同一托管网络内，`mac_address` 和 `ipv4_address` 都不能与现有保留冲突

### 7.4 更新固定保留

`PUT /api/managed-network-reservations`

必须带 `id`。

### 7.5 删除固定保留

`DELETE /api/managed-network-reservations?id=<reservation_id>`

成功响应：

```json
{
  "id": 12
}
```

## 8. IPv6 Assignment 接口

### 8.1 获取 IPv6 Assignment 列表

`GET /api/ipv6-assignments`

返回 `[]IPv6Assignment`，并附带运行时计数：

- `ra_advertisement_count`
- `dhcpv6_reply_count`
- `runtime_status`
- `runtime_detail`

### 8.2 新增 IPv6 Assignment

`POST /api/ipv6-assignments`

请求体示例：

```json
{
  "parent_interface": "eno1",
  "target_interface": "tap100i0",
  "parent_prefix": "2402:db8:100::/48",
  "assigned_prefix": "2402:db8:100:1::/64",
  "remark": "vm-a ipv6"
}
```

规则：

- 必填：`parent_interface`、`target_interface`、`parent_prefix`
- `assigned_prefix` 是当前主字段
- 兼容旧字段：也可用 `address` + `prefix_len` 提交，服务端会回填 `assigned_prefix`
- `parent_prefix` 必须是有效 IPv6 CIDR
- `assigned_prefix` 必须是有效 IPv6 CIDR 或可推导出的 IPv6 地址前缀
- `parent_prefix` 必须存在于所选 `parent_interface`
- `assigned_prefix` 必须包含在 `parent_prefix` 中
- `assigned_prefix` 不能和已有 IPv6 Assignment 重叠
- 如果 `address` 已经在宿主机存在，也会被拒绝
- 创建后默认 `enabled = true`

### 8.3 更新 IPv6 Assignment

`PUT /api/ipv6-assignments`

必须带 `id`。

### 8.4 删除 IPv6 Assignment

`DELETE /api/ipv6-assignments?id=<assignment_id>`

## 9. Worker 与运行时接口

### 9.1 获取 Worker 列表

`GET /api/workers`

查询参数：

- `page`
- `page_size`

说明：

- `page_size` 最大 `1000`
- 不传 `page_size` 时返回全部 worker
- 该接口会把规则 worker、范围 worker、共享站点 worker、kernel worker、egress_nat worker 合并返回

### 9.2 获取内核运行时

`GET /api/kernel/runtime`

用途：

- 查看当前内核 dataplane 是否可用
- 查看 `tc` / `xdp` 当前 attach、entries、map 占用、retry、自愈和诊断信息

查询参数：

- `refresh=1`: 跳过共享快照缓存，强制刷新一次运行时视图

也可以通过请求头 `Cache-Control: no-cache` 达到同样的强制刷新效果。

对接建议：

- 适合做排障和可视化
- 不建议把所有字段当成稳定契约硬编码

### 9.3 忽略一条内核运行时提示

`POST /api/kernel/runtime/dismiss-note`

用途：

- 让前端或外部控制台隐藏一条已确认的运行时提示
- 只影响控制面展示，不会修改 dataplane 规则或内核 map

请求体示例：

```json
{
  "key": "attachment_issue|tc(active_entries=3)"
}
```

成功响应：

```json
{
  "dismissed_note_keys": [
    "attachment_issue|tc(active_entries=3)"
  ]
}
```

## 10. 统计接口

### 10.1 规则统计

`GET /api/rules/stats`

查询参数：

- `page`
- `page_size`
- `sort_key`
- `sort_asc`

`sort_key` 允许：

- `rule_id`
- `remark`
- `current_conns`
- `total_conns`
- `rejected_conns`
- `speed_in`
- `speed_out`
- `bytes_in`
- `bytes_out`

### 10.2 范围统计

`GET /api/ranges/stats`

查询参数与 `GET /api/rules/stats` 相同：

- `page`
- `page_size`
- `sort_key`
- `sort_asc`

`sort_key` 允许：

- `range_id`
- `remark`
- `current_conns`
- `total_conns`
- `rejected_conns`
- `speed_in`
- `speed_out`
- `bytes_in`
- `bytes_out`

### 10.3 Egress NAT 统计

`GET /api/egress-nats/stats`

查询参数与 `GET /api/rules/stats` 相同：

- `page`
- `page_size`
- `sort_key`
- `sort_asc`

`sort_key` 允许：

- `egress_nat_id`
- `parent_interface`
- `child_interface`
- `out_interface`
- `out_source_ip`
- `protocol`
- `nat_type`
- `current_conns`
- `total_conns`
- `speed_in`
- `speed_out`
- `bytes_in`
- `bytes_out`

响应项会补充 Egress NAT 元信息，例如：

- `parent_interface`
- `child_interface`
- `out_interface`
- `out_source_ip`
- `protocol`
- `nat_type`

### 10.4 站点统计

`GET /api/sites/stats`

说明：

- 返回数组
- 不分页

### 10.5 当前连接数

`GET /api/stats/current-conns`

响应示例：

```json
{
  "rules": [
    {
      "rule_id": 1,
      "current_conns": 2
    }
  ],
  "ranges": [
    {
      "range_id": 1,
      "current_conns": 3
    }
  ],
  "sites": [
    {
      "site_id": 1,
      "current_conns": 1
    }
  ],
  "egress_nats": [
    {
      "egress_nat_id": 1,
      "current_conns": 4
    }
  ]
}
```

用途：

- 按需拿实时连接数
- 避免每轮都重新拉整张统计表

## 对接建议

- 上层系统应保存本地资源 ID 与 `forward` 对象 `id` 的映射
- 写接口成功后，不要立刻假设 runtime 已完全切换完成，建议再查列表或 `workers`
- 如果依赖真实客户端源地址，启用 `transparent` 前先确认回程路由
- 非透传 full-NAT 且出口接口有多个同族地址时，建议显式传 `out_source_ip` 或 `backend_source_ip`
- 如果要消费 `kernel/runtime`，请按松耦合方式解析 JSON

## curl 示例

### 新增一条规则

```bash
curl -X POST "http://127.0.0.1:8080/api/rules" \
  -H "Authorization: Bearer your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "in_interface": "eth0",
    "in_ip": "203.0.113.10",
    "in_port": 2222,
    "out_interface": "vmbr0",
    "out_ip": "198.51.100.10",
    "out_port": 22,
    "protocol": "tcp",
    "remark": "vm-a ssh"
  }'
```

### 新增一条 Egress NAT

```bash
curl -X POST "http://127.0.0.1:8080/api/egress-nats" \
  -H "Authorization: Bearer your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "parent_interface": "vmbr0",
    "child_interface": "tap100i0",
    "out_interface": "eno1",
    "out_source_ip": "203.0.113.10",
    "protocol": "tcp+udp+icmp",
    "nat_type": "symmetric"
  }'
```

### 新增一个托管网络

```bash
curl -X POST "http://127.0.0.1:8080/api/managed-networks" \
  -H "Authorization: Bearer your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "vmbr",
    "bridge_mode": "existing",
    "bridge": "vmbr0",
    "uplink_interface": "eno1",
    "ipv4_enabled": true,
    "ipv4_cidr": "192.168.4.1/24",
    "ipv4_pool_start": "192.168.4.2",
    "ipv4_pool_end": "192.168.4.254",
    "ipv6_enabled": true,
    "ipv6_parent_interface": "eno1",
    "ipv6_parent_prefix": "2402:db8:1::/64",
    "ipv6_assignment_mode": "single_128",
    "auto_egress_nat": true
  }'
```

### 查询内核运行时

```bash
curl "http://127.0.0.1:8080/api/kernel/runtime" \
  -H "Authorization: Bearer your-token-here"
```
