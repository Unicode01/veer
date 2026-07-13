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
  "external_plugins_enabled": true,
  "directory": "plugins",
  "runtime": {
    "builtin_pipeline_id": "veer",
    "core_priority": 1000,
    "manifest_discovery": true,
    "object_validation": true,
    "protected_assets": true,
    "stability_levels": ["lab", "preview", "stable", "deprecated"],
    "external_dataplane_attach": false,
    "supported_engines": ["tc", "xdp", "control"],
    "supported_hook_modes": ["observe", "rewrite", "redirect", "drop", "control"]
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

- `enabled`: 插件级开关状态。内置 `veer_core` 固定为 `true`，外部插件默认 `true`
- `status`: `builtin` / `active` / `disabled` / `error`
- `stability`: 插件稳定性等级；`lab` 只适合实验/示例，`preview` 适合受控环境试用，`stable` 表示预期生产可用，`deprecated` 表示不建议新部署。未声明时默认为 `lab`
- `runtime`: 插件运行时状态；内置 `veer_core` 为 `mode=builtin` 且已挂载。禁用外部插件时为 `mode=disabled`，不会暴露 resource/action/UI/assets/hook/object surface，也不会保留 Goja VM、timer 或 worker。默认配置下外部插件为 `mode=registered`，表示 slim manifest 已发现且 `control.js` runtime surface 已注册/校验，但未进入外部数据面；启用 `plugins_dataplane_enabled=true` 且存在可链入的 TC `stage=forward/reply` hook 后，会变为 `mode=dataplane` 并返回 `attachments`
- `runtime.core_priority`: 内置 `Veer Core` 的排序锚点，当前固定为 `1000`
- `runtime.stability_levels`: 当前服务接受的插件稳定性枚举
- `runtime.external_dataplane_attach`: 是否允许外部数据面插件。默认 `false`；为 `true` 时当前支持 TC `stage=forward/reply` hook 按 priority 进入内置 `veer` pipeline。没有实际可链入插件时，TC 热路径仍保持 legacy/dispatch，不额外进入 pipeline wrapper
- `objects`: `control.js` 通过 `ebpf.loadObject()` 注册的 eBPF 对象或内置对象；外部对象路径必须留在插件目录内，单个对象最大 16 MiB。`stable` / `preview` 外部对象必须注册 `sha256` 且匹配文件内容；`lab` 对象可省略 `sha256`，但服务仍会计算并返回 `resolved_sha256`。服务会解析 ELF 并补充 `status`、`resolved_sha256`、`program_count`、`map_count`
- `control.sha256`: Goja 控制脚本完整性声明。`stable` / `preview` 控制脚本必须声明该字段且匹配 `control.main` 文件内容；`lab` 可省略，但服务仍会计算并返回 `control.resolved_sha256` 供审计
- `ui.sha256`: `control.js` 通过 `ui.register()` 注册的 UI 入口完整性值。`stable` / `preview` 插件注册 `ui.entry` 时必须提供该字段且匹配入口文件内容；`lab` 可省略，但服务仍会计算并返回 `ui.resolved_sha256` 供审计
- `asset_base_path`: 插件注册 `ui.static_dir` 后生成的静态资源路径，需要 Bearer Token
- `ui.page` / `ui.page_title`: 可选的 Web UI 顶部分页 ID 和标题，由 `ui.register({page, page_title})` 注册；前端会自动创建插件页并内嵌加载 `ui.entry`
- `hooks`: `control.js` 通过 `hooks.attach()` 注册的 dataplane hook。开启外部数据面后，只有 `engine=tc`、`stage=forward/reply`、`attach=ingress/both`、非 `control` mode 的 hook 会被加载到 `tc_prog_chain_v4` stage slots。`priority < runtime.core_priority` 进入 core 前链，`priority > runtime.core_priority` 进入 core 后链，等于 core priority 会被拒绝。插件程序执行后必须 tail-call 到对应 stage 的内置 continue slot，除非它明确返回最终 TC action。XDP 和非 `veer` TC hook 当前仍是 registration-only
- `hooks[].interfaces`: 可选的真实 Linux 接口名列表。留空或省略时，插件只随已有 forward/egress 规则触发的 `veer` attachment 运行；填写后，即使没有转发规则，TC runtime 也会把 `pipeline_v4` 挂到这些接口上。无规则模式会禁用内置 forward/reply core，把 pipeline 作为纯插件高速链运行；显式接口的 core 前和 core 后 hook 都可运行，但 core 后 hook 此时只能拿到清空的 `tc_plugin_ctx_v4`，不会有规则或 flow 匹配上下文。不会自动挂载所有接口；接口不存在会让该插件本轮进入 error。程序排序使用全局 chain，但运行时会按 ifindex 和 attach 方向生成阶段掩码；声明 `interfaces` 的 Hook 只会在对应白名单内执行，无需插件自行重复检查 `skb->ifindex`
- `runtime.attachments[].priority`: 插件注册 hook 的排序优先级。`runtime.attachments[].stage` 是内部物理执行区，例如 `pre_forward`、`post_lookup`、`pre_reply`、`post_reply`；`runtime.attachments[].chain_slot` 是实际写入 `tc_prog_chain_v4` 的 slot
- core 后插件如需读取规则匹配上下文，必须在对象里声明共享 `tc_plugin_ctx_v4` per-CPU array map；服务会替换为内置稳定 ctx map，IPv4 地址和端口字段按 host byte order 填充
- 当前限制：`pre_forward`、`post_lookup`、`pre_reply`、`post_reply` 各最多 8 个外部 hook；forward 两阶段合计最多 14 个，reply 两阶段也合计最多 14 个，以避免触发内核 tail-call 深度上限
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
- `POST /api/plugins/<id>/actions/<action>`：执行 `control.js` 注册的动作，请求体为 `{"payload":{...}}`。`runtime_update=runtime_query` 的动作会把 `exports.onAction(ctx)` 返回的 JSON 放入响应 `result`，且不写 action runtime status、不触发 core 重分发

资源和动作都必须先由 `control.js` 注册。资源数据以 canonical JSON 存储在 SQLite，`max_record_bytes` 按 canonical 后的存储大小计算，`secret_fields` 会在 API 返回时脱敏，并在 HTTP update 时支持“保留脱敏旧值”的表单语义；`runtime_update=manual` 只标记 pending，`plugin_reconcile` 触发插件运行时重算，`runtime_apply` 调用宿主数据面实现的运行时更新接口。动作还可声明 `runtime_query`，用于不落 action runtime status 的瞬时结果，返回 JSON 上限为 64 KiB；它不会额外限制控制脚本原有权限，插件仍应自行保证查询动作无副作用。运行时更新失败会写入 `runtime_status.status=error` 和 `last_error`，不会让插件 UI 直接拿到 Web Token。资源写接口会先提交 SQLite；如果随后的运行时应用失败，响应会使用 `5xx` 并返回已落库记录、`error`、`runtime_error` 和 `runtime_status`，调用方应按“配置已保存但运行时未生效”处理，避免盲目重试创建导致 key 冲突。动作执行失败同样返回 `5xx`、`error`、`runtime_error` 和 `runtime_status`，用于插件 UI 展示具体失败状态。

Goja 控制脚本默认只能访问本插件资源。每个插件默认持有一个持久 Goja VM，`control.js` 顶层只在注册/初始化时执行一次，顶层变量会在 `onReconcile/onResourceApply/onAction/onTimer` 之间保留；同一插件主控制事件仍串行执行，避免并发改写 KV、netlink 或 runtime status。声明 `control.permissions=["worker"]` 后，可用 `worker.call(name, handler, payload)` 同步调用命名 worker VM，或用 `worker.dispatch(name, handler, payload)` 异步投递长任务；worker VM 同样保留顶层变量，但只在控制面执行，不进入 TC/XDP 包热路径。声明 `control.permissions=["resource"]` 后，可用 `resources.set(resourceID, key, data, enabled, apply)` 和 `resources.delete(resourceID, key, apply)` 写入/删除本插件已注册资源；本插件资源访问会校验 `control_methods`（未声明则按 `methods` 处理），写入/删除会更新该资源的 `runtime_status`，`apply=true` 时会按该资源的 `runtime_update` 立即应用。声明 `control.permissions=["plugin.resource"]` 后，还必须在 `control.resource_access` 中逐项声明允许访问的目标插件、资源和方法，才可使用 `plugins.resources.get(pluginID, resourceID, key)`、`plugins.resources.list(pluginID, resourceID, options)`、`plugins.resources.set(pluginID, resourceID, key, data, enabled, apply)` 和 `plugins.resources.delete(pluginID, resourceID, key, apply)` 读取、写入或删除其他插件已注册资源；跨插件访问仍会校验目标资源的公开 `methods`、`max_records` 和 `max_record_bytes`，不会因为目标资源声明了 `control_methods` 而获得额外写权限。`resources.list(resourceID, options)`、`plugins.resources.list(..., options)` 和 `kv.list(options)` 的 `options` 支持 `{limit, offset}`，默认 `limit=1000`，最大 `limit=5000`；需要全量处理大量记录时应按页循环读取。`get/list` 返回的记录结构和本插件 `resources.get/list` 一致，且跨插件目标资源必须在 `methods` 中允许对应操作；跨插件 `get/list/set` 的返回值会按目标资源 `secret_fields` 脱敏，不会把目标插件密钥原文返回给调用方；`set` 是 upsert，调用方白名单和目标资源 `methods` 都必须同时允许 `create` 与 `update`；`delete` 要求目标资源 `methods` 允许 `delete`。`apply=true` 时，会按目标资源的 `runtime_update` 使用和 HTTP API 一致的应用流程并更新目标资源的 `runtime_status`；运行时失败会写入目标资源 `runtime_status.status=error` 和 `last_error`。`apply=false` 时，相同 `data/enabled` 的 set 和缺失 key 的 delete 是 no-op，不会重复 bump record revision 或 runtime status。未声明对应权限或白名单时调用会被拒绝。声明 `crypto` 后可使用 `crypto.md5()`、`crypto.randomBytes()` 和 `crypto.sha256File(relativePath)`；`sha256File` 只能读取本插件目录内文件，适合 stable/preview 插件在注册 eBPF object 或 UI 入口时声明当前构建产物 hash。声明 `net.admin` 后可使用 `net.link.ensureVeth/ensureBridge/setMaster/clearMaster/delete/setUp/setMTU/getOffloads/setOffloads`、`net.addr.replace/delete` 和 `net.route.replace/delete` 管理 Linux veth、bridge、桥成员、地址、路由和可控 offload；非 Linux 平台会返回不支持错误。每个插件最多保留 64 个命名 timer 和 16 个命名 worker，超限时本批 timer 更新或 worker 启动会被拒绝。

`net.admin`、`net.l2`、`net.tcp` 和 `net.udp` 都是两段式权限。声明任一权限时，manifest 必须同时提供 `control.net_access`；每个条目包含 `interfaces` 和 `operations`。`interfaces` 支持精确接口名或 `*` 通配模式，`operations` 只允许 `addr.write`、`l2`、`link.create`、`link.delete`、`link.master`、`link.offload`、`link.read`、`link.state`、`route.write`、`tcp`、`udp`。运行时传入 host API 的接口名同样会被校验：最长 15 字节，且不能包含 `/`、`\` 或空白字符。`l2`、`tcp`、`udp` 操作分别要求 `net.l2`、`net.tcp`、`net.udp`，其它操作要求 `net.admin`；调用 host API 时会按目标接口逐次校验。`net.link.list()` 会过滤为当前插件拥有 `link.read` 的接口，避免插件借枚举接口绕过白名单。`net.link.getOffloads()` 读取 `rx/tx/sg/tso/ufo/gso/gro/lro` 当前状态并要求 `link.read`；`net.link.setOffloads()` 只允许调整这些特性，并要求目标接口声明 `link.offload`。`net.route.replace/delete` 必须传入 `dev`，并按该接口匹配 `route.write` 白名单，避免插件写入无法归属到接口授权的系统路由。生产插件应优先授权自己创建的 `veer*`、`wan*`、`br*` 等接口；如果需要操作 `eth*`、`vmbr*` 等物理或宿主接口，必须在 manifest 中显式声明。

控制面内置存储有固定配额：每个插件最多 1024 条 `kv` 记录，单条 KV canonical JSON 最大 64 KiB；每个插件最多 128 条 `secret` 记录，单条 secret 最大 4 KiB；插件日志单行会截断到 4 KiB；每个插件最多 64 个命名 timer 和 16 个命名 worker，单个 timer payload 最大 16 KiB，单次 worker payload/result 最大 1 MiB。

`__kv` 和 `__secret` 是 Goja 控制面内部资源名，插件不能通过 `plugin.resource()` 或 `control.resource_access` 声明它们；HTTP 插件资源 API 和插件 UI RPC 只暴露 `control.js` 显式注册的业务资源。

`ebpf.mapPut/mapDelete/mapClear` 只能写插件自己的配置 map。共享运行时 map 名称 `tc_prog_chain_v4`、`tc_plugin_ctx_v4`、`xdp_prog_chain` 被保留，即使插件声明了 `ebpf.map_write` 也不能写入、删除或清空这些 map。`mapClear` 只允许清空 `max_entries <= 16384` 的 map；array/per-CPU array 会原位清零，其他 map 删除现有 key。更大的配置表应由插件按 key 分批删除。`ebpf.mapGetPerCPU` 返回按 possible CPU 排列且移除对齐 padding 的十六进制 value 数组，供插件聚合 per-CPU 统计。

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
- `plugins_enabled = false` 只关闭外部插件扫描，不隐藏内置 `veer_core`
- `plugins_dataplane_enabled = false` 是默认值；设置为 `true` 后允许外部 TC `stage=forward/reply` 插件按 priority 进入内置 `veer` pipeline
- 外部插件可通过 `PUT /api/plugins/<id>/state` 热启用/禁用；禁用状态会持久化，重启后仍生效。禁用不会删除插件资源记录，但会停止 Goja VM、timer、worker、UI/assets/API surface、TC hook，以及插件生成的 synthetic forward、Egress NAT、DHCPv4 和 IPv6 assignment plan
- 插件源目录每 2 秒扫描一次，变化只标记待更新；`POST /api/plugins/reload` 才会校验并应用候选快照。应用失败时旧 control VM、静态资源和数据面保持运行。常规文件使用受限 SHA256 内容 hash，超大文件只纳入元数据
- 通过 `ebpf.loadObject()` 注册对象的外部插件会校验对象存在性、路径边界、可选 sha256、program section/type 和 hook 引用；校验失败时该插件返回 `status=error`
- 插件静态资源路径为 `/api/plugins/<id>/assets/`，同样需要 Bearer Token
- `runtime.external_dataplane_attach=false` 表示外部插件不会被加载进数据面；`true` 表示允许可信 TC 对象围绕核心 `veer` priority 进入 forward/reply 的 core 前/后链。插件对象必须声明共享 `tc_prog_chain_v4` prog-array map，`max_entries` 至少为 77，并在处理后 tail-call 回对应 stage 的 continue slot；core 后插件读取匹配上下文时还需要声明共享 `tc_plugin_ctx_v4` map。`hooks.attach({interfaces})` 可让插件在无转发规则时显式请求接口 attachment；无规则模式下 core 前和 core 后 hook 都可加载，但 core 后 hook 只能拿到清空的 `tc_plugin_ctx_v4`，不会有规则或 flow 匹配上下文。不会自动挂所有接口，生产环境应只对可信对象启用

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
