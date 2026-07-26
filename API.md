# API 文档

这份文档面向需要把 Veer 接入其他系统的开发者，例如：

- 自定义运维平台
- CMDB / 资源编排系统
- 虚拟机开通脚本
- 工单系统、自动化脚本、内部控制台
- n8n / Dify / Flowise / 自建 Agent

Veer 当前不只是规则转发 API，还包含：

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
- 插件高权限操作额外要求: `X-Veer-Plugin-Admin: <plugin_admin_token>`
- 写操作默认使用 `application/json`
- 探活端点: `/healthz`、`/readyz` 不使用 `/api` 前缀

`web_token` 来自 `config.json`：

```json
{
  "web_port": 8080,
  "web_token": "replace-with-a-real-token",
  "plugin_admin_token": "use-a-different-plugin-admin-token"
}
```

注意：

- `web_token` 不能为空
- 程序会拒绝使用示例占位值 `change-me-to-a-secure-token`
- `plugin_admin_token` 可留空以禁用插件高权限 API；非空时必须与 `web_token` 不同

## 认证与错误约定

所有 `/api/*` 端点都需要 Bearer Token。`/healthz` 和 `/readyz` 用于本机或负载均衡探活，不需要 Bearer Token。

请求头示例：

```http
Authorization: Bearer your-token-here
Content-Type: application/json
```

插件包 stage/apply/rollback/uninstall、信任键变更、Secret 轮换、插件启停和代码热加载还需要：

```http
X-Veer-Plugin-Admin: your-separate-plugin-admin-token
```

常见状态码：

- `200 OK`: 成功
- `400 Bad Request`: 参数错误或请求体非法
- `401 Unauthorized`: Token 错误或缺失
- `403 Forbidden`: 插件管理员 Token 缺失、错误或该 API 未配置启用
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
- `GET /api/plugin-sdk-contract`
- `POST /api/plugins/reload`
- `GET /api/plugins/<id>/state`
- `PUT /api/plugins/<id>/state`
- `GET /api/plugins/<id>/assets/<path>`
- `GET /api/plugins/<id>/resources/<resource>`
- `GET /api/plugins/<id>/resources/<resource>/<key>`
- `POST /api/plugins/<id>/resources/<resource>`
- `PUT /api/plugins/<id>/resources/<resource>/<key>`
- `DELETE /api/plugins/<id>/resources/<resource>/<key>`
- `POST /api/plugins/<id>/actions/<action>`
- `GET /api/plugin-packages/provenance`
- `GET|POST|DELETE /api/plugin-repositories`
- `GET /api/plugin-repositories/catalog`
- `POST /api/plugin-repositories/refresh`
- `POST /api/plugin-repositories/stage`
- `POST /api/plugin-repositories/plan`
- `GET|PUT|DELETE /api/plugin-repository-policies`
- `GET /api/plugin-repositories/updates`
- `GET /api/plugin-audit`
- `GET /api/plugin-event-dead-letters`
- `POST /api/plugin-event-dead-letters/retry`
- `POST /api/plugin-event-dead-letters/discard`

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

`GET /api/plugins` 返回运行时插件目录扫描结果和内置 `veer_core` 描述：

```json
{
  "external_plugins_enabled": false,
  "directory": "plugins",
  "runtime": {
    "builtin_pipeline_id": "veer",
    "runtime_version": "1.0.0",
    "tc_pipeline_abi": 2,
    "core_priority": 1000,
    "available_features": ["control.goja.v1", "dataplane.tc_pipeline.v2"],
    "feature_status": {
      "dataplane.tc_pipeline.v2": {"available": true}
    },
    "manifest_discovery": true,
    "object_validation": true,
    "protected_assets": true,
    "minimum_sandbox_level": "full",
    "require_signed_packages": true,
    "stability_levels": ["lab", "preview", "stable", "deprecated"],
    "external_dataplane_attach": false,
    "supported_engines": ["tc", "xdp", "control"],
    "supported_hook_modes": ["observe", "rewrite", "redirect", "drop", "control"],
    "tc_pipeline": {
      "program_array_entries": 111,
      "stage_hook_limit": 8,
      "direction_hook_limit": 14,
      "directions": ["forward", "reply"],
      "phases": ["around_core", "after_apply"],
      "hook_stages": ["forward", "reply", "pre_forward", "post_lookup", "post_apply", "pre_reply", "post_reply", "post_reply_apply"],
      "attaches": ["ingress", "egress", "both"]
    }
  },
  "hot_reload": {
    "enabled": true,
    "check_interval_ms": 2000,
    "update_available": true,
    "last_check_result": "update_available",
    "applied_fingerprint_short_hash": "16f6d9c9ac2a",
    "detected_fingerprint_short_hash": "b5be6406e572"
  },
  "plugins": [
    {
      "api_version": "v1",
      "id": "veer_core",
      "name": "Veer Core",
      "version": "builtin",
      "kind": "pipeline",
      "stability": "stable",
      "builtin": true,
      "status": "builtin",
      "runtime": {
        "mode": "builtin",
        "attachable": true,
        "attached": true
      },
      "capabilities": ["egress_nat", "kernel_tc", "kernel_xdp"],
      "objects": [
        {"id": "veer-tc", "path": "builtin:veer-tc"},
        {"id": "veer-xdp", "path": "builtin:veer-xdp"}
      ]
    }
  ]
}
```

字段说明：

- `enabled`: 插件级开关状态。内置 `veer_core` 固定为 `true`；只有全局 `plugins_enabled=true` 后才会发现外部插件，已发现外部插件的插件级状态默认 `true`
- `status`: `builtin` / `active` / `disabled` / `error`
- `stability`: 插件稳定性等级；`lab` 只适合实验/示例，`preview` 适合受控环境试用，`stable` 表示预期生产可用，`deprecated` 表示不建议新部署。未声明时默认为 `lab`
- `runtime`: 插件运行时状态；内置 `veer_core` 为 `mode=builtin` 且已挂载。全局默认 `plugins_enabled=false`，此时不会扫描外部插件，也不会暴露 resource/action/UI/assets/hook/object surface 或保留 Goja VM、timer、worker。手动启用外部插件但保持 `plugins_dataplane_enabled=false` 时，外部插件为 `mode=registered`；再启用插件数据面且存在可链入的 TC `stage=forward/reply` hook 后，会变为 `mode=dataplane` 并返回 `attachments`
- `runtime.isolation`: 外部控制插件的宿主隔离状态；包含 `enabled`、`platform`、`process_count`、`pids`、`restart_count`、`rss_bytes`、`resource_limit_mode`，以及可选的 `restart_backoff_until`、`last_error`、`resource_limit_degraded`。该对象只描述 Goja 控制面，不表示 TC/XDP 数据面进入用户态
- `runtime.core_priority`: 内置 `Veer Core` 的排序锚点，当前固定为 `1000`
- `runtime.features`: 当前二进制实现的插件 API feature 集合；不代表当前宿主一定具备对应内核能力
- `runtime.available_features` / `runtime.feature_status`: 当前宿主实际可用 feature 及逐项状态。TC/eBPF 由 verifier、map type、clsact/netlink 探测决定，raw L2 会验证 AF_PACKET 权限；不可用项通过 `feature_status.<name>.reason` 返回原因
- `runtime.minimum_sandbox_level`: 控制插件执行前要求的最低 Host 隔离等级；默认 `full`
- `runtime.require_signed_packages`: 包管理器是否拒绝所有未签名候选；默认 `true`
- `runtime.stability_levels`: 当前服务接受的插件稳定性枚举
- `runtime.external_dataplane_attach`: 是否允许外部数据面插件。默认 `false`；为 `true` 时支持 TC `direction=forward/reply` Hook、显式接口 XDP ingress Hook 和宿主编排的原生 Netfilter Hook。没有实际 TC/XDP Hook 时，接口热路径保持原有实现；没有 Netfilter Hook 时不会创建对应 object/link
- `runtime.tc_pipeline`: 当前 TC ABI 的机器可读契约。ABI v2 使用 111-entry prog-array，每个 concrete stage 最多 8 个 Hook，每个方向跨三个 stage 合计最多 14 个 Hook
- `runtime.xdp_pipeline`: XDP 前置链契约。使用 24-entry prog-array，最多 8 个 Hook，仅支持显式接口上的 ingress `pre_forward`/pre-core `forward`
- `actions[].request_schema_version/request_schema/request_schema_digest`：Action 请求的 Draft 2020-12 JSON Schema 契约；HTTP 和插件间调用会在执行 handler 前校验。未声明 Schema 时版本默认为 `1`
- `actions[].response_schema_version/response_schema/response_schema_digest`：`runtime_query` 返回值契约；结果离开 Goja VM 前校验。同一版本下 Schema 摘要变化会在包 stage 时被拒绝
- `services[]`：`control.js` 通过 `plugin.service()` 注册的 typed service；包含独立 SemVer、调用方实际获权后可见的 `actions/resources` 端点及对应完整契约。`plugins.services.list/resolve/call` 不绕过 `action_access/resource_access`，多个提供方匹配时必须显式选择
- `event_subscriptions[].schema_version/schema/schema_digest`：事件 payload 契约。发布版本不匹配或 payload 不符合 Schema 时不会入队，并计入 `runtime.event_bus.rejected`
- `objects`: `control.js` 通过 `ebpf.loadObject()` 注册的 eBPF 对象或内置对象；外部对象路径必须留在插件目录内，单个对象最大 16 MiB。`stable` / `preview` 外部对象的 fallback 和每个 `variants[]` artifact 都必须分别注册正确 `sha256`。服务会逐项检查路径、大小、hash、ELF、program section/type 和 state map，不会只检查当前宿主架构；`lab` 可省略 hash，但仍会计算并校验内容
- `objects[].state_maps`: 私有 map 热升级契约。`preserve` 要求同名、同 `schema_version` 且内核 map spec 兼容并复用原 FD；`reset` 明确确认丢弃旧状态；`migrate` 必须用 `migrate_from` 指向同 object 中较低版本的 `preserve` map。迁移版本必须同时保留旧/新 map，并由新数据面读旧兜底和双写；控制脚本通过 `onEBPFStateMigrate(ctx)` 分批执行 `ebpf.mapScan/mapTransaction`，返回 `{done,cursor,processed}`。任一批次或 reconcile 提交失败会保留 pending 并触发候选更新回滚。对应 feature 为 `ebpf.map_state.v1` 和 `ebpf.map_migration.v1`
- `control.sha256`: Goja 控制脚本完整性声明。`stable` / `preview` 控制脚本必须声明该字段且匹配 `control.main` 文件内容；`lab` 可省略，但服务仍会计算并返回 `control.resolved_sha256` 供审计
- `ui.sha256`: `control.js` 通过 `ui.register()` 注册的 UI 入口完整性值。`stable` / `preview` 插件注册 `ui.entry` 时必须提供该字段且匹配入口文件内容；`lab` 可省略，但服务仍会计算并返回 `ui.resolved_sha256` 供审计
- `asset_base_path`: 插件注册 `ui.static_dir` 后生成的静态资源路径，需要 Bearer Token
- `ui.page` / `ui.page_title`: 可选的 Web UI 顶部分页 ID 和标题，由 `ui.register({page, page_title})` 注册；前端会自动创建插件页并内嵌加载 `ui.entry`
- `hooks`: `control.js` 通过 `hooks.attach()` 注册的 dataplane hook。开启外部数据面后，`engine=tc` 的 `stage=forward/reply` 逻辑 Hook，或显式 concrete stage Hook，会被加载到 `tc_prog_chain_v4`。`priority < runtime.core_priority` 进入 core 前链，`priority > runtime.core_priority` 进入 core 后链，等于 core priority 会被拒绝；`pipeline.attach({phase:"after_apply"})` 映射到 `post_apply/post_reply_apply`。插件程序执行后必须 tail-call 到对应 stage 的内置 continue slot，除非它明确返回最终 TC action。`engine=xdp` 只接受显式接口上的 ingress `pre_forward`/pre-core Hook，最多 8 个，使用独立双 bank Dispatcher 和共享 `xdp_prog_chain`；插件调用 XDP continue slot 后进入下一 Hook，链尾 `XDP_PASS` 继续进入 TC。目标接口已有 XDP 程序时拒绝挂载，不会替换第三方或现有 Veer XDP Core。`engine=netfilter` 使用 `family/hook/phase/namespace` 声明原生 Netfilter placement，宿主自动持有 `bpf_link`；`family=inet` 展开成 IPv4/IPv6 两条 link，接口范围由插件程序和私有 ifindex map 判断，不接受 `interfaces` 或 TC `stage/attach`
- `hooks[].interfaces`: 可选的真实 Linux 接口名列表。留空或省略时，插件只随已有 forward/egress 规则触发的 `veer` attachment 运行；填写后，即使没有转发规则，TC runtime 也会把 pipeline 挂到这些接口上。无规则模式会禁用内置 forward/reply core，把 pipeline 作为纯插件高速链运行；core 后 Hook 仍可运行，但只能拿到按当前地址族清空的 `tc_plugin_ctx_v4/tc_plugin_ctx_v6`，不会有规则或 flow 匹配上下文。不会自动挂载所有接口；接口不存在会让该插件本轮进入 error。程序排序使用全局 chain，但运行时会按 ifindex 和 attach 方向生成阶段掩码；声明 `interfaces` 的 Hook 只会在对应白名单内执行
- `runtime.attachments[].priority`: 插件注册 Hook 的排序优先级。TC attachment 的 `stage` 是 `pre_forward/post_lookup/post_apply/pre_reply/post_reply/post_reply_apply` 之一，`chain_slot` 是实际写入 `tc_prog_chain_v4` 的 slot；Netfilter attachment 通过 `family/netfilter_hook/phase/namespace` 和 `filter_handle=bpf_link:priority=...` 描述原生 link
- `hooks[].before/hooks[].after`：同一 concrete stage 内的全限定 `plugin_id/hook_id` 拓扑约束。运行时在 reconcile 阶段检测缺失目标、跨 stage 引用和循环，并把最终顺序反映到 `runtime.attachments[].order/chain_slot`；该能力不增加每包热路径开销
- `hooks[].packet_metadata[]`：可选 TC packet metadata ABI v1 binding。字段为 `slot`（object 本地 `0..15`）、`namespace`（`owner_plugin/name`）、`schema_version`、`max_bytes`（最多 64）和 `access=read|read_write`。只有 namespace owner 可写；所有读写方必须声明相同 schema/长度。宿主最多编排 32 个 namespace，并用双栈 per-CPU generation 阻止跨包陈旧读取。解析后的 binding 会同步到 `runtime.attachments[].packet_metadata`
- core 后插件如需读取规则匹配上下文，必须在对象里同时声明共享 `tc_plugin_ctx_v4` 和 `tc_plugin_ctx_v6` per-CPU array map；服务会替换为内置稳定 map，并只让插件读取当前包地址族对应的上下文
- 当前限制：每个 concrete stage 最多 8 个外部 Hook；forward 三阶段合计最多 14 个，reply 三阶段也合计最多 14 个，以避免触发内核 tail-call 深度上限
- `forward_rule_plans`: 约定资源名。活跃的 `lab` / `preview` / `stable` 插件声明并写入 enabled plan 后，控制面会按普通 `Rule` 字段编译成 synthetic forward rule，参与 `/api/rules` effective 视图、规则统计元数据、Worker 分发和 TC/XDP 内核候选规划，但不会写入真实 `rules` 表。支持字段为 `in_interface/in_ip/in_port/out_interface/out_ip/out_source_ip/out_port/protocol/remark/tag/enabled/transparent/engine_preference`；校验、端口冲突检测和接口/source IP 检查与手工规则一致。显式核心规则、站点和端口范围优先，listener 冲突的插件 plan 会被跳过。插件 forward rule 使用当前分发周期内的正数 synthetic rule id 以兼容内核 map；该 id 是运行时视图，不应被插件持久引用。
- `egress_nat_plans`: 约定资源名。活跃的 `lab` / `preview` / `stable` 插件声明并写入 enabled plan 后，控制面会编译成负数 ID 的 synthetic Egress NAT runtime item，参与 Worker、统计元数据、内核重试和托管网络局部 reload，但不会写入真实 `egress_nats` 表。显式核心 Egress NAT 和托管网络自动 NAT 优先，scope/protocol 重叠的插件 plan 会被跳过。`deprecated` 插件不会影响核心转发。`redirect_mode=prepared_l2` 是显式高级模式，只适用于 TC veth handoff 且 peer 能在 host namespace 解析的场景；XDP、普通物理出口和 peer 位于 netns 的 veth 会拒绝该模式
- `dhcpv4_plans`: 约定资源名。活跃插件写入 enabled plan 后，控制面会把它编译成负数 ID 的 synthetic managed-network DHCPv4 listener，复用现有 DHCP Discover/Offer/Request/Ack 服务，但只服务已存在的 LAN bridge，不创建 bridge、不管理网关地址，也不自动创建 Egress NAT。支持字段为 `bridge/ipv4_cidr/gateway/pool_start/pool_end/dns_servers/remark/enabled`；`dns_servers` 只接受 IPv4 地址，去重后最多 8 条，并作为 DHCPv4 Option 6 下发。显式托管网络优先，同一 bridge 已被显式托管网络或其他插件 plan 服务时，后续 plan 会被跳过
- `ipv6_assignment_plans`: 约定资源名。活跃插件写入 enabled plan 后，控制面会把它编译成负数 ID 的 synthetic IPv6 assignment，复用现有 IPv6 路由、网关地址、RA 和 DHCPv6 runtime，但不会写入真实 `ipv6_assignments` 表。支持字段为 `parent_interface/target_interface/parent_prefix/assigned_prefix/assigned_prefix_length/subnet_index/upstream_routed/configure_gateway/reject_unassigned/dns_servers/remark/enabled`；可直接指定 `assigned_prefix`，也可由 `parent_prefix`、`assigned_prefix_length` 和 `subnet_index` 选择子网。`dns_servers` 只接受可下发的全局 IPv6 单播地址，去重后最多 8 条，并通过 RA RDNSS 与 DHCPv6 Recursive DNS 下发。显式 IPv6 assignment 优先，前缀与现有 assignment 或先编译的插件 plan 重叠时，后续 plan 会被跳过

插件控制面数据接口：

- `POST /api/plugins/reload`：手动应用插件源目录的当前候选版本。服务每 2 秒检查目录内容指纹，变化只会在 `GET /api/plugins` 的 `hot_reload.update_available` 中标记待更新，不会自动执行候选 control.js 或改动数据面。手动应用会先复制稳定快照并校验 manifest、control、UI 和 eBPF object，再执行 reconcile 和数据面分发；失败返回 `5xx` 并保留上一份已应用快照。`hot_reload.applied_fingerprint*` 和 `detected_fingerprint*` 分别表示运行中版本与源目录候选版本，二者不同即存在待更新。常规文件使用受限 SHA256 内容 hash，超大文件只纳入路径、大小和 mtime 等元数据
- `GET /api/plugins/<id>/state`：读取外部插件的持久启用状态和当前 catalog 中的插件视图。内置 `veer_core` 不支持该接口
- `PUT /api/plugins/<id>/state`：设置外部插件启用状态，请求体为 `{"enabled":true}` 或 `{"enabled":false}`。禁用会热卸载该插件 runtime surface，停止 Goja control VM、timer、worker，移除 TC pipeline hook，并停止该插件贡献的 `forward_rule_plans`、`egress_nat_plans`、`dhcpv4_plans` 和 `ipv6_assignment_plans` synthetic runtime；插件自身资源记录会保留，重新启用后继续使用
- `GET /api/plugins/<id>/resources/<resource>`：列出 `control.js` 注册且允许 `list` 的资源记录，并返回该资源的 `runtime_status`。支持 `limit` 和 `offset` 查询参数，默认 `limit=1000`，最大 `limit=5000`；响应包含 `total/limit/offset/has_more`
- `GET /api/plugins/<id>/resources/<resource>/<key>`：读取 `control.js` 注册且允许 `get` 的单条记录
- `POST /api/plugins/<id>/resources/<resource>`：创建 `control.js` 注册且允许 `create` 的记录，请求体为 `{"key":"optional","data":{...},"enabled":true}`；未提供 `key` 时由服务生成。成功响应包含记录本身和该资源的 `runtime_status`
- `PUT /api/plugins/<id>/resources/<resource>/<key>`：更新 `control.js` 注册且允许 `update` 的记录。成功响应包含记录本身和该资源的 `runtime_status`。资源数据会按 canonical JSON 存储，字段顺序不构成变更；资源注册了 `secret_fields` 时，更新请求中缺省的 secret 字段或值为 `__redacted__` 的 secret 字段会保留旧值，显式传入空字符串才会清空该字段；如果 `data/enabled` 语义不变且当前 runtime status 不是 `error`，该请求是 no-op，不会 bump revision 或重复 runtime apply；如果当前 runtime status 是 `error`，相同 payload 仍会重试 runtime apply
- `DELETE /api/plugins/<id>/resources/<resource>/<key>`：删除 `control.js` 注册且允许 `delete` 的记录。成功响应包含 `status=deleted` 和该资源的 `runtime_status`
- `control_methods`：资源可选字段，只影响本插件 Goja 控制脚本的 `resources.*` 权限校验；HTTP/UI 资源 API 和跨插件 `plugins.resources.*` 都只看目标资源的 `methods`。未声明 `control_methods` 时按 `methods` 处理。生产插件可用它把 `status`、`egress_nat_plans` 等派生资源对外和对其他插件设为只读，同时允许自身控制脚本维护。
- `POST /api/plugins/<id>/actions/<action>`：执行 `control.js` 注册的动作，请求体为 `{"payload":{...}}`。请求会先按 Action 的 `request_schema` 校验；`runtime_update=runtime_query` 的动作会把通过 `response_schema` 校验的 `exports.onAction(ctx)` JSON 返回值放入响应 `result`，且不写 action runtime status、不触发 core 重分发
- `GET /api/plugins/<id>/logs?level=<level>&limit=<n>`：读取该插件持久化的结构化日志，最新记录优先。`level` 可选 `debug/info/warn/error`，`limit` 为 `1..500`；响应中的 `state.entries` 是累计写入量，`state.dropped` 是限流或队列满时的丢弃量。日志字段会递归脱敏，异步批量写入 SQLite，服务重启后仍可查询已提交记录

插件包和运维接口：

- `GET /api/plugin-admin/status`：返回 `configured` 和当前请求的 `authorized`，用于 WebUI 校验当前标签页提供的 `X-Veer-Plugin-Admin`。该接口本身只要求普通 Bearer Token
- 下列写接口均同时要求 Bearer Token 和 `X-Veer-Plugin-Admin`；只读 history/probation/audit/trust/secret 状态接口仍只要求 Bearer Token

- `POST /api/plugin-packages/stage`：上传由 `veer plugin sign` 生成的单文件 `.veerpkg`，或未签名的 `.tar.gz`，并执行有界解包、manifest/control/UI/object、兼容性、依赖、签名和权限差异预检。请求体是原始包字节，不是 JSON；payload 最大 32 MiB，`.veerpkg` 只允许固定的 `package.tar.gz` 与 `signature.json` 成员。服务端从容器内验证 payload SHA256、Ed25519 签名、signer ID 和公钥，外置的 `X-Veer-Plugin-Signer`、`X-Veer-Plugin-Public-Key`、`X-Veer-Plugin-Signature` 会被拒绝。未知、已撤销或超出授权范围的发布者不会阻止预检，但应用时需要明确批准。成功返回一次性 `stage.id`、候选版本、`signed/trusted/publisher_status`、发布者指纹、权限摘要、新增权限、依赖/冲突和运行时表面；stage 24 小时后过期，预检本身不会替换运行中插件。联合升级时传 `?defer_relationships=true`，仍会执行包、签名、权限、Goja surface 和宿主兼容性校验，但把依赖/冲突的最终判断延迟到批量应用
- `POST /api/plugin-packages/apply`：应用已预检候选，请求体为 `{"stage_id":"...","approved_privilege_digest":"...","approve_unsigned":false,"approve_publisher":false,"remember_publisher":false}`。允许未签名包的开发策略下，未签名候选必须设置 `approve_unsigned=true`；有效签名但发布者未知、已撤销或超出授权范围时必须设置 `approve_publisher=true`。`remember_publisher=true` 仅适用于首次出现且签名有效的发布者，会在同一安装操作中按当前插件 ID、权限、执行层级和稳定级别创建最小信任范围；应用失败会移除该新建记录。存在新增权限时必须原样回传本次 stage 的 `privilege_digest`。服务会再次校验源版本、候选指纹、签名和权限表面，避免 stage 后被替换
- `POST /api/plugin-packages/apply-batch`：原子应用 1 至 16 个候选，请求体为 `{"stages":[<apply request>,...]}`。服务拒绝重复插件，统一解析最终 catalog 的版本依赖、冲突、循环和宿主兼容性，再通过持久 batch journal 切换全部目录；整批只执行一次 runtime reconcile 和一次 Worker 分发。运行时、资源 migration 或任一目录切换失败会恢复整批旧版本；重启恢复会依据 journal 阶段整批回滚或完成提交。`defer_relationships` stage 不能通过单包 `/apply` 应用
- `GET /api/plugin-packages/history?plugin_id=<id>`：读取某插件最多 10 项本地包历史，用于审计和回滚
- `GET /api/plugin-packages/provenance?plugin_id=<id>`：读取已安装包的来源、仓库 target、channel、TUF metadata version 和 archive SHA256。`status` 为 `trusted/revoked/target_unavailable/repository_unavailable/metadata_unavailable` 之一；该状态用于阻止后续替换并告警，不会自动卸载运行中插件
- `GET /api/plugin-packages/probations?plugin_id=<id>`：读取候选版本观察状态。`pending=true` 表示插件尚未实际启用；运行后进入 10 分钟观察期。单包候选在隔离宿主重复崩溃或超时/OOM/协议破坏类熔断时回滚到 `previous_history_id`，首次安装没有历史时只自动禁用并保留配置。批量候选包含相同 `group_id`，任一成员触发内部致命故障时，更新成员从受校验 history 整组恢复，新安装成员从 catalog 原子移除；恢复失败会恢复整个候选组并按 1/2/4/8 分钟退避。普通线路、认证和接口错误不会触发自动回滚
- `GET /api/plugin-packages/probation-groups?group_id=<id>&plugin_id=<id>`：读取批量候选观察组、完整成员、组级恢复次数和最近失败。观察组通过或恢复前，组成员不能被单独安装、回滚或卸载，防止覆盖整组恢复依据
- `POST /api/plugin-packages/rollback`：准备历史版本回滚，请求体为 `{"plugin_id":"...","history_id":"..."}`。成功返回新的 stage；调用方仍须通过 `/api/plugin-packages/apply` 完成权限确认和应用
- `POST /api/plugin-packages/uninstall`：卸载插件，请求体为 `{"plugin_id":"...","force":false,"purge_data":false}`。默认保留插件记录和历史；`purge_data=true` 会删除插件资源、状态和 Secret 数据；存在必需依赖者时必须显式 `force=true`
- `GET /api/plugin-trust`：列出 Ed25519 发布者公钥、`active/revoked` 状态及可选 `scope`。信任用于识别后续包并免去重复的陌生发布者确认，不是安装前置条件。`POST /api/plugin-trust` 用 `{"name":"...","public_key":"base64-or-hex","replaces":"optional-old-key-id","scope":{"plugin_ids":["vendor_*"],"permissions":["plugin.register","ui"],"permissions_restricted":true,"execution_tiers":["control"],"stabilities":["stable","preview"]}}` 添加或原子轮换；范围字段为空表示该维度不限制，`permissions_restricted=true` 可把空权限列表明确限制为零权限，整个 `scope` 省略表示全局发布者。轮换省略 `scope` 时继承旧范围，显式范围只能保持或收窄。`DELETE /api/plugin-trust` 用 `{"id":"..."}` 撤销。撤销记录不会物理删除，后续签名显示为 `publisher_status=revoked` 并要求当前安装明确批准，不会自动卸载已有插件
- `GET /api/plugin-audit?plugin_id=<id>&limit=<n>&before_id=<id>`：读取持久化插件审计记录，最新记录优先。`limit` 为 `1..500`，使用当前页最后一项的 `id` 作为 `before_id` 向前翻页
- `GET /api/plugin-event-dead-letters?plugin_id=<optional>&limit=<n>&before_id=<id>`：跨插件读取 durable 事件死信，最新记录优先。`plugin_id` 为空时返回全部插件，`limit` 为 `1..500`，使用当前页最后一项的数字 `id` 作为 `before_id` 向前翻页；返回项包含原始 `delivery_id/topic/payload`、订阅、来源、尝试次数和最近错误
- `POST /api/plugin-event-dead-letters/retry`：把指定死信恢复为 pending，请求体为 `{"plugin_id":"...","delivery_id":"..."}`。该操作要求插件管理员权限，复用原 delivery 和 payload，不重新发布事件，并写入审计日志
- `POST /api/plugin-event-dead-letters/discard`：永久删除指定死信，请求体同 retry。该操作要求插件管理员权限并写入审计日志；只允许删除仍为 dead 的 delivery，不能删除 pending 投递
- `GET /api/plugin-secrets`：读取 Secret AEAD keyring 的可用性、持久化状态、活动 key ID 和 key 数量，不返回密钥材料；`POST /api/plugin-secrets` 在线生成新活动密钥并重新加密所有已声明 Secret 字段。存在未完成资源迁移时轮换会被拒绝
- `GET /api/plugin-repositories`：列出已固定初始 root 的 TUF 仓库；`POST` 用 `{"id":"...","name":"...","metadata_url":"https://.../metadata/","targets_url":"https://.../targets/","channel":"stable","root":{...}}` 添加；`DELETE` 用 `{"id":"..."}` 删除。添加、删除要求插件管理员权限，URL 必须为 HTTPS，`root` 是原始 TUF root JSON 对象
- `GET /api/plugin-repositories/catalog?repository_id=<id>`：读取上次验证并缓存的 catalog；`POST /api/plugin-repositories/refresh` 用 `{"repository_id":"..."}` 执行完整 TUF root/timestamp/snapshot/targets 更新
- `POST /api/plugin-repositories/stage`：用 `{"repository_id":"...","plugin_id":"...","version":"optional","defer_relationships":false}` 从已验证 target 创建单个 stage
- `POST /api/plugin-repositories/plan`：用 `{"repository_id":"...","plugin_id":"...","version":"optional"}` 回溯求解完整必需依赖闭包并创建最多 16 个 stage。满足全部约束的已安装版本会列入 `reused`；最终仍需把返回 stages 的权限摘要交给 `/api/plugin-packages/apply-batch` 原子应用
- `GET /api/plugin-repository-policies`：列出每插件仓库策略；`PUT` 用 `{"plugin_id":"...","repository_id":"...","channel":"stable","pinned_version":"optional-exact-semver","hold":false}` 创建或替换，`DELETE` 用 `{"plugin_id":"..."}` 清除。pin 和 hold 同时约束根插件与依赖求解；写操作要求插件管理员权限。有策略引用时对应仓库不能删除
- `GET /api/plugin-repositories/updates`：基于已验证的缓存 catalog 返回已安装插件的 `current_version/available_version/status/policy/provenance` 和 `execution_tier`。`status` 包括 `current/update_available/held/pinned/revoked/unavailable/metadata_unavailable`；该接口不联网、不下载且不自动应用
- `plugins_enabled=true` 时宿主每 `plugins_repository_refresh_minutes` 分钟在独立后台循环刷新所有 TUF 仓库，默认 360、范围 15 至 10080。刷新只更新 metadata/catalog/撤销状态，不创建 stage；插件系统关闭时不启动该循环
- 包管理全局数量和磁盘配额由 `plugins_max_installed`、`plugins_max_staged`、`plugins_storage_limit_mb` 控制。超限前会清理最旧且未被 probation 引用的历史；仍不足时写接口返回冲突/参数错误，不影响运行中的插件

资源和动作都必须先由 `control.js` 注册。资源数据以 canonical JSON 存储在 SQLite，`max_record_bytes` 按 canonical 后的存储大小计算，`secret_fields` 会在 API 返回时脱敏，并在 HTTP update 时支持“保留脱敏旧值”的表单语义；`runtime_update=manual` 只标记 pending，`plugin_reconcile` 触发插件运行时重算，`runtime_apply` 调用宿主数据面实现的运行时更新接口。动作还可声明 `runtime_query`，用于不落 action runtime status 的瞬时结果，返回 JSON 上限为 64 KiB；它不会额外限制控制脚本原有权限，插件仍应自行保证查询动作无副作用。运行时更新失败会写入 `runtime_status.status=error` 和 `last_error`，不会让插件 UI 直接拿到 Web Token。资源写接口会先提交 SQLite；如果随后的运行时应用失败，响应会使用 `5xx` 并返回已落库记录、`error`、`runtime_error` 和 `runtime_status`，调用方应按“配置已保存但运行时未生效”处理，避免盲目重试创建导致 key 冲突。动作执行失败同样返回 `5xx`、`error`、`runtime_error` 和 `runtime_status`，用于插件 UI 展示具体失败状态。

Goja 控制脚本默认只能访问本插件资源。每个插件默认持有一个持久 Goja VM，`control.js` 顶层只在注册/初始化时执行一次，顶层变量会在 `onReconcile/onResourceApply/onAction/onTimer` 之间保留；同一插件主控制事件仍串行执行，避免并发改写 KV、netlink 或 runtime status。`onEBPFStateMigrate` 也在主 VM 串行执行，但进入独立 `dataplane_migration` phase，仅允许本插件 `ebpf.map_read/map_write`、日志和只读 Host 信息。声明 `control.permissions=["worker"]` 后，可用 `worker.call(name, handler, payload)` 同步调用命名 worker VM，或用 `worker.dispatch(name, handler, payload)` 异步投递长任务；worker VM 同样保留顶层变量，但只在控制面执行，不进入 TC/XDP 包热路径。声明 `control.permissions=["resource"]` 后，可用 `resources.set(resourceID, key, data, enabled, apply)` 和 `resources.delete(resourceID, key, apply)` 写入/删除本插件已注册资源；本插件资源访问会校验 `control_methods`（未声明则按 `methods` 处理），写入/删除会更新该资源的 `runtime_status`，`apply=true` 时会按该资源的 `runtime_update` 立即应用。声明 `control.permissions=["plugin.resource"]` 后，还必须在 `control.resource_access` 中逐项声明允许访问的目标插件、资源和方法，才可使用 `plugins.resources.get(pluginID, resourceID, key)`、`plugins.resources.list(pluginID, resourceID, options)`、`plugins.resources.set(pluginID, resourceID, key, data, enabled, apply)` 和 `plugins.resources.delete(pluginID, resourceID, key, apply)` 读取、写入或删除其他插件已注册资源；跨插件访问仍会校验目标资源的公开 `methods`、`max_records` 和 `max_record_bytes`，不会因为目标资源声明了 `control_methods` 而获得额外写权限。`resources.list(resourceID, options)`、`plugins.resources.list(..., options)` 和 `kv.list(options)` 的 `options` 支持 `{limit, offset}`，默认 `limit=1000`，最大 `limit=5000`；需要全量处理大量记录时应按页循环读取。`get/list` 返回的记录结构和本插件 `resources.get/list` 一致，且跨插件目标资源必须在 `methods` 中允许对应操作；跨插件 `get/list/set` 的返回值会按目标资源 `secret_fields` 脱敏，不会把目标插件密钥原文返回给调用方；`set` 是 upsert，调用方白名单和目标资源 `methods` 都必须同时允许 `create` 与 `update`；`delete` 要求目标资源 `methods` 允许 `delete`。`plugins.services.list/resolve/call` 在这些白名单之上提供带版本的服务发现和动作调用，只返回已授权端点；服务发现本身不会产生新的权限。`apply=true` 时，会按目标资源的 `runtime_update` 使用和 HTTP API 一致的应用流程并更新目标资源的 `runtime_status`；运行时失败会写入目标资源 `runtime_status.status=error` 和 `last_error`。`apply=false` 时，相同 `data/enabled` 的 set 和缺失 key 的 delete 是 no-op，不会重复 bump record revision 或 runtime status。未声明对应权限或白名单时调用会被拒绝。声明 `crypto` 后可使用 `crypto.md5()`、`crypto.randomBytes()` 和 `crypto.sha256File(relativePath)`；`sha256File` 只能读取本插件目录内文件，适合 stable/preview 插件在注册 eBPF object 或 UI 入口时声明当前构建产物 hash。声明 `blob` 后可使用私有、原子、受配额且纳入 backup/restore 的二进制对象存储；它不跨插件共享，也不替代加密 Secret。声明 `net.admin` 后可使用 `net.link.ensureVeth/ensureBridge/setMaster/clearMaster/delete/setUp/setMTU/getOffloads/setOffloads`、`net.addr.replace/delete` 和 `net.route.replace/delete` 管理 Linux veth、bridge、桥成员、地址、路由和可控 offload；声明 `net.namespace/net.tuntap` 后可经父进程 broker 管理命名 namespace 与 TUN/TAP，但不会获得 `setns`、`/dev/net/tun` 或 FD。非 Linux 平台会返回不支持错误。每个插件最多保留 64 个命名 timer 和 16 个命名 worker，超限时本批 timer 更新或 worker 启动会被拒绝。

事件 API 使用 `event` 权限；订阅必须同时有 `worker`。自定义发布 topic 被固定为 `plugin.<本插件 ID>.*`。跨插件订阅还必须声明 `plugin.event` 和 `control.event_access=[{"plugin":"source","topic_prefixes":["plugin.source.topic"]}]`，运行时同时校验来源插件与 topic 前缀。`events.publish()` 返回 `{matched,enqueued,persisted,deferred,dropped,rejected}`；投递异步执行，`enqueued/persisted` 不等于 handler 已完成。订阅默认是进程内 `volatile`；设置 `delivery="durable"` 后会先写 SQLite，失败按 `retry_delay_ms` 指数退避，达到 `max_attempts` 后转为死信。插件只能管理自己的死信且不能丢弃 pending；管理员接口可跨插件查询、重试和确认丢弃并记录审计。系统事件包括 `net.link`、`net.addr`、`net.neigh`、`net.route`、`resource.changed` 和 `plugin.lifecycle`。网络事件复用 `net.admin + net_access(link.read)` 过滤；多路径路由要求所有相关接口均被授权。

`net.admin`、`net.l2`、`net.tcp`、`net.udp`、`net.http`、`net.dns` 和 `net.tuntap` 都是两段式权限。声明后，manifest 必须同时提供 `control.net_access`；每个条目包含 `interfaces` 和 `operations`。`interfaces` 支持精确接口名或 `*` 通配模式，`operations` 只允许 `addr.write`、`dns`、`http`、`l2`、`link.create`、`link.delete`、`link.master`、`link.offload`、`link.read`、`link.state`、`neigh.write`、`route.write`、`rule.write`、`tcp`、`tuntap`、`udp`。`http/dns/l2/tcp/udp/tuntap` 操作分别要求对应总权限，其它操作要求 `net.admin`。`net.namespace` 或 `net.tuntap` 还要求 `control.namespace_access`；空 namespace 规范化为 `host`，命名 namespace 最长 63 字节。运行时传入 host API 的接口名同样会被校验：最长 15 字节，且不能包含 `/`、`\` 或空白字符。`net.link.list()` 会过滤为当前插件拥有 `link.read` 的接口，避免插件借枚举接口绕过白名单。`net.link.getOffloads()` 读取 `rx/tx/sg/tso/ufo/gso/gro/lro` 当前状态并要求 `link.read`；`net.link.setOffloads()` 只允许调整这些特性，并要求目标接口声明 `link.offload`。单路径 `net.route.replace/delete` 必须传入 `dev`；多路径请求改用 1 至 64 个 `nexthops`，每项包含 `dev`、可选 `gateway`、`weight=1..256` 和 `onlink`，且不能再同时传顶层 `dev/gateway`。运行时会对每个下一跳逐项匹配 `route.write` 白名单，并按目标、路由表和 metric 对 FIB 槽位加互斥租约。对应宿主 feature 为 `control.net_multipath.v1`。生产插件应优先授权自己创建的 `veer*`、`wan*`、`br*` 等接口；如果需要操作 `eth*`、`vmbr*` 等物理或宿主接口，必须在 manifest 中显式声明。

`net_access` 条目可选的 `remote_hosts`、`remote_cidrs`、`remote_ports` 分别限制目标域名、解析后的 IP 和端口；字段未填写时不限制对应维度，填写后必须匹配。`remote_hosts` 仅支持精确域名、`*` 或最左侧 `*.example.com`，原始 TCP/UDP API 因只接受 IP 而禁止配置该字段。HTTP 目标、DNS resolver、持久 socket 建连/接收/热更新和 UDP 回包都会执行 endpoint 检查，无法规范化的 endpoint 按拒绝处理。`net.http.request` 支持受限 HTTP/HTTPS、同源重定向、TLS 1.2+、私有 CA 与 mTLS；使用自定义 resolver 时还必须独立声明 `net.dns`、`operations:["dns"]` 及 resolver endpoint 范围。`net.dns.lookup` 支持 `A/AAAA/IP/TXT/MX/SRV/CNAME/PTR` 和 UDP/TCP resolver。对应 feature 为 `control.http_client.v1`、`control.dns_client.v1`。

持久 socket 可用 `net.socket.watch({handle,worker,handler,max_bytes})` 切换到事件驱动读取；宿主向 `ctx.socket` 投递 `data/accept/eof/error`，同一 socket 等前一 handler 返回后再读取下一批。watch 状态随事务式热升级转移，被 watch 的句柄拒绝手工 `read/accept`，调用 `unwatch` 后恢复拉取模式。UDP 未授权来源和 TCP 未授权 accepted child 只被丢弃，不关闭父监听口。该接口要求 `worker` 与对应 `net.tcp/net.udp` 权限，对应 feature 为 `control.socket_events.v1`。

`net.namespace.get/list/ensure/delete/release/owned` 与 `net.tuntap.ensure/close/read/write/list/owned` 仅由 Linux 父进程执行。已有但不属于插件的白名单 namespace 可以读取和使用，不能删除；插件创建的 namespace 和设备会写入 identity-aware ownership。`net.link/addr/route/rule/neigh` 以及 `net.l2/udp/socket/http/dns` 请求可用 `namespace` 指定命名空间，并同时受 `net.namespace`、`namespace_access` 和原有接口权限约束。禁用、卸载或崩溃恢复时先按 namespace identity 恢复内部网络资源，再关闭 TUN/TAP 和删除插件自建 namespace；同名 namespace 被替换时不会误清理新对象。`net.tuntap.read` 单次最多 65535 字节、最长等待 15 秒，`write` 接受单包十六进制数据；两者是控制面接口，不应承担高速逐包转发。对应 feature 为 `control.netns_provider.v1`、`control.netns_scoped.v1` 和 `control.tuntap_provider.v1`。

所有 netlink 写操作都受宿主资源租约保护。创建的 link 由插件持有；已有接口的 master、状态、MTU、ARP、promiscuous、offload、GSO、地址和路由按属性记录首次修改前状态。插件失活时自动恢复，恢复失败保留租约重试，跨 Linux boot 或接口 identity 改变时不会把旧状态写入新设备。`net.lease.list()` 返回本插件的 `{type,key,metadata,created_at,updated_at}`；`net.lease.restore(type,key)` 恢复并释放单个租约。`net.link.delete()` 仅能删除当前插件创建并持有的 link。

控制面内置存储有固定或可配置配额：每个插件最多 1024 条 `kv` 记录，单条 KV canonical JSON 最大 64 KiB；每个插件最多 128 条 `secret` 记录，单条 secret 最大 4 KiB；Blob 默认每对象 64 MiB、每插件 1024 个/256 MiB、全局 2 GiB，单次 IPC 分块最大 1 MiB；插件日志单行会截断到 4 KiB；每个插件最多 64 个命名 timer 和 16 个命名 worker，单个 timer payload 最大 16 KiB，单次 worker payload/result 最大 1 MiB。

`__kv` 和 `__secret` 是 Goja 控制面内部资源名，插件不能通过 `plugin.resource()` 或 `control.resource_access` 声明它们；HTTP 插件资源 API 和插件 UI RPC 只暴露 `control.js` 显式注册的业务资源。

`ebpf.mapPut/mapDelete/mapClear` 只能写插件自己的配置 map。共享运行时 map（包括 `tc_prog_chain_v4`、`tc_plugin_ctx_v4`、`tc_plugin_ctx_v6`、`tc_plugin_metrics`、`xdp_prog_chain`）被保留，即使插件声明了 `ebpf.map_write` 也不能写入、删除或清空。`mapClear` 只允许清空 `max_entries <= 16384` 的 map；array/per-CPU array 会原位清零，其他 map 删除现有 key。更大的配置表应由插件按 key 分批删除。`ebpf.mapGetPerCPU` 返回按 possible CPU 排列且移除对齐 padding 的十六进制 value 数组，供插件聚合 per-CPU 统计。`ebpf.mapScan(object, map, {cursor,limit,max_bytes})` 对普通 key/value map 提供 best-effort 游标读取，单次 `limit <= 256`、原始 key/value 合计不超过 1 MiB；完成时 `done=true` 且 `cursor=""`。

持续消费插件私有 BPF ring buffer 时，在注册阶段使用 `ebpf.ringSubscribe({id,object,map,worker,handler,...})`。该 API 要求 `ebpf.load`、`ebpf.map_read` 和 `worker`，每个 object/map 只允许一个消费者；reader 使用独立有界队列主动投递到持久 worker，队列满或插件 pending payload 达到 16 MiB 时丢弃新批次而不反压数据面。`ebpf.ringStats()` 返回读取、投递、丢弃和 handler 错误统计。按需诊断可继续用 `ebpf.ringRead(object, map, {max_records,max_bytes,timeout_ms})` 拉取最多 256 条、1 MiB、15 秒的批次；存在 push 订阅时不能对同一 map 再执行 pull。两者都不能读取 Veer 保留 map，也不会把 map FD 交给隔离子进程。对应宿主 feature 分别为 `ebpf.ring_push.v1` 和 `ebpf.bounded_reads.v1`。

插件 UI 通过宿主注入的 `VeerPluginHost` RPC bridge 调用上述 API。`VeerPluginHost.data.upsert(resource, key, data, options)` 会先执行 update，只有返回 `404` 时才 fallback 到 create；其他 runtime/API 错误会原样 reject，避免覆盖真实失败原因。RPC 失败时 Promise reject 的 Error 会包含 `payload`、`status`、`runtime_status` 和 `runtime_error` 字段，插件页面应优先展示 `runtime_error` 或 `runtime_status.last_error`，而不是只显示通用错误文本；宿主注入的 `VeerPluginHost.errorText(error)` 和 `VeerPluginHost.toastError(error)` 已封装该优先级。

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

- 枚举内置 `veer_core` 插件及 `veer` pipeline 描述
- 枚举 `plugins_dir` 下外部插件 slim manifest 和 `control.js` 注册 surface
- 暴露插件 manifest / 注册 surface 校验错误，避免启动失败
- 给后续插件管理 UI 或外部控制台做能力发现

说明：

- 默认外部插件目录为 `plugins`
- 外部插件目录缺失不会报错
- `plugins_enabled = false` 是默认值，只关闭外部插件扫描和运行，不隐藏内置 `veer_core`；必须手动设为 `true` 才会启动外部插件控制面
- `plugins_dataplane_enabled = false` 是默认值；同时将 `plugins_enabled` 和该项设为 `true` 后，才允许外部 TC/XDP 插件进入接口 pipeline，或由宿主加载 Netfilter 原生 Hook link
- `plugins_isolation = true` 是默认值；主控制 VM 与每个命名 Worker 使用独立持久子进程。仅受信任的本地调试才应关闭该项
- `plugins_min_sandbox_level = "full"` 是默认值；Host 或硬资源限制达不到要求时会在执行控制脚本前拒绝插件。旧内核/Windows 调试必须显式降低该值
- `plugins_require_signed_packages = true` 是默认值；包管理器不会接受 `approve_unsigned` 覆盖，但任何携带自包含公钥且签名有效的 v2 包都可在审核发布者状态后应用，不要求预先写入 trust store；受校验历史和 TUF target 同样可应用
- 外部插件可通过 `PUT /api/plugins/<id>/state` 热启用/禁用；禁用状态会持久化，重启后仍生效。禁用不会删除插件资源记录，但会停止 Goja VM、timer、worker、UI/assets/API surface、TC/XDP/Netfilter Hook，以及插件生成的 synthetic forward、Egress NAT、DHCPv4 和 IPv6 assignment plan
- 插件源目录每 2 秒扫描一次，变化只标记待更新；`POST /api/plugins/reload` 才会校验并应用候选快照。应用失败时旧 control VM、静态资源和数据面保持运行。常规文件使用受限 SHA256 内容 hash，超大文件只纳入元数据
- 通过 `ebpf.loadObject()` 注册对象的外部插件会校验对象存在性、路径边界、可选 sha256、program section/type 和 hook 引用；校验失败时该插件返回 `status=error`
- 插件静态资源路径为 `/api/plugins/<id>/assets/`，同样需要 Bearer Token
- `runtime.external_dataplane_attach=false` 表示外部插件不会被加载进数据面；`true` 表示允许可信 TC/XDP/Netfilter object 按各自 placement 契约加载。TC ABI v2 对象必须声明共享 `tc_prog_chain_v4`，Netfilter object 则直接挂原生 `bpf_link`，不使用 TC prog-array。不会自动挂载未声明的接口、Hook 或 namespace，生产环境应只对可信对象启用

### 1.5 获取插件 SDK 契约

`GET /api/plugin-sdk-contract`

返回当前二进制生成的版本化控制 API、feature、资源限制、事件总线、持久 operation 以及 TC/XDP/Netfilter pipeline 契约。contract v7 的 `control.capabilities` 逐方法返回 `permissions`、`any_permissions`、`conditional_permissions`、`phases`、`contexts`、`max_request_bytes` 和 `max_response_bytes`；`operations` 返回 operation 状态集合与数量、字段、总存储和重试上限；`control_methods` 是由同一注册表生成的兼容列表。`tc_pipeline` 描述 ABI v2 的方向与 stage，`xdp_pipeline` 描述 24-entry prog-array、8 Hook 上限、仅 ingress 且必须显式接口的约束，`netfilter_pipeline` 描述 family、原生 Hook、语义 phase、namespace scope 和 placement 上限。该接口需要 Bearer Token，只支持 `GET`；第三方安装器可在 stage 前比较 `runtime.control_api_abi`、`runtime.tc_pipeline_abi` 和 `runtime.features`。本地 CI 可用 `veer plugin contract --check sdk/plugin/api-contract.json` 对同一结构做严格校验。

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

- 上层系统应保存本地资源 ID 与 Veer 对象 `id` 的映射
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
