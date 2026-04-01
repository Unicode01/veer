# API 文档

这份文档面向需要把 `forward` 接入其他系统的开发者，例如：

- 自定义运维平台
- CMDB / 资源编排系统
- 虚拟机开通脚本
- n8n / Dify / Flowise / 自建 Agent
- 内部控制台、工单系统、自动化脚本

## 基本信息

- Base URL: `http://<host>:<web_port>`
- 默认端口: `8080`
- API 前缀: `/api`
- 认证方式: `Authorization: Bearer <web_token>`
- 写操作默认使用 `application/json`

`web_token` 来自 `config.json`：

```json
{
  "web_port": 8080,
  "web_token": "replace-with-a-real-token"
}
```

注意：

- `web_token` 不能为空
- 程序会拒绝使用示例占位值 `change-me-to-a-secure-token` 启动

## 认证

所有 `/api/*` 端点都需要带 Bearer Token。

请求头示例：

```http
Authorization: Bearer your-token-here
Content-Type: application/json
```

`curl` 示例：

```bash
curl -H "Authorization: Bearer your-token-here" \
  http://127.0.0.1:8080/api/rules
```

## 响应与错误约定

成功时一般返回 JSON。

常见情况：

- `200 OK`: 成功
- `400 Bad Request`: 参数错误或请求体非法
- `401 Unauthorized`: Token 错误或缺失
- `404 Not Found`: 部分场景下资源不存在
- `405 Method Not Allowed`: 请求方法不支持
- `500 Internal Server Error`: 服务端内部错误

需要注意：

- 大多数业务错误返回 JSON，例如 `{"error":"invalid id"}`
- `401` 和部分 `405` 仍可能通过 `http.Error(...)` 返回纯文本，不保证是 JSON

对接方建议：

- 优先按 HTTP 状态码判断成功 / 失败
- 如果响应体是 JSON，再读取 `error` 字段
- 不要假设所有失败返回都能直接按 JSON 解析

## 对象模型

### Rule

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
  "engine_preference": "auto"
}
```

字段补充：

- `out_source_ip`：非透传 full-NAT 时可选，强制指定回源 / SNAT 使用的宿主机 IPv4
- `engine_preference`：规则级引擎偏好，可选 `auto`、`userspace`、`kernel`

### RuleStatus

`GET /api/rules` 和 `GET /api/workers` 中的规则项会带运行时字段：

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

字段补充：

- `effective_engine`：当前实际生效的引擎，通常为 `userspace` 或 `kernel`
- `effective_kernel_engine`：内核态具体引擎，当前可能为 `xdp`、`tc` 或 `mixed`
- `kernel_eligible`：规则是否满足内核态接入条件
- `kernel_reason`：不满足内核态条件时的原因
- `fallback_reason`：满足条件但最终回退用户态时的原因
- `effective_kernel_engine`、`kernel_reason`、`fallback_reason` 为空时会被省略

### Site

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
  "transparent": false
}
```

字段补充：

- `backend_source_ip`：非透传时可选，指定共享站点代理访问后端时使用的本地源 IPv4

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

### PortRange

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
  "transparent": false
}
```

### PortRangeStatus

`GET /api/ranges` 和 `GET /api/workers` 中的范围项会带运行时字段：

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
  "protocol": "tcp",
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

状态值说明：

- 规则 / 站点 / 范围列表接口中的 `status` 常见值为 `running`、`stopped`、`error`
- `GET /api/workers` 内嵌的规则 / 范围项还可能出现 `disabled`
- worker 自身 `status` 还可能是 `draining`

## 接口列表

### 1. 获取接口列表

`GET /api/interfaces`

返回当前主机上存在 IPv4 地址的接口列表。多网卡、VLAN 子接口、同卡多地址都会反映在这里。

响应示例：

```json
[
  {
    "name": "eth0",
    "addrs": ["203.0.113.10"]
  },
  {
    "name": "vmbr0",
    "addrs": ["198.51.100.1"]
  }
]
```

### 2. 获取标签列表

`GET /api/tags`

响应示例：

```json
["vm", "prod", "game"]
```

### 3. 规则接口

#### 3.1 获取规则列表

`GET /api/rules`

支持按查询参数过滤，常用参数：

- `id` / `ids`：按规则 ID 过滤，支持逗号分隔
- `tag` / `tags`：按标签过滤，支持逗号分隔
- `protocol` / `protocols`：按协议过滤，支持 `tcp`、`udp`、`tcp+udp`
- `enabled`：按启用状态过滤，支持 `true` / `false`
- `transparent`：按透传开关过滤，支持 `true` / `false`
- `status` / `statuses`：按运行状态过滤，支持 `running`、`stopped`、`error`
- `in_interface` / `out_interface`：按入/出接口精确过滤
- `in_ip` / `out_ip` / `out_source_ip`：按入/出 IP 精确过滤
- `in_port` / `out_port`：按入/出端口精确过滤
- `q`：按 `id`、备注、标签、接口、IP、端口、协议、状态做模糊匹配

响应示例：

```json
[
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
]
```

#### 3.2 新增规则

`POST /api/rules`

请求体：

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
- `engine_preference` 允许：`auto`、`userspace`、`kernel`
- 省略 `protocol` 时默认 `tcp`
- 省略 `engine_preference` 时默认 `auto`
- 创建后默认 `enabled = true`
- `transparent = true` 时必须省略 `out_source_ip`

#### 3.3 更新规则

`PUT /api/rules`

请求体与新增规则类似，但必须包含 `id`。

说明：

- 更新时会保留原有 `enabled` 状态；如需修改启停，请使用 `POST /api/rules/toggle` 或 `POST /api/rules/batch` 的 `set_enabled`
- 更新成功后会触发一次规则重分布 / 引擎重规划

#### 3.4 启用 / 禁用规则

`POST /api/rules/toggle?id=<rule_id>`

响应示例：

```json
{
  "id": 1,
  "enabled": false
}
```

#### 3.5 删除规则

`DELETE /api/rules?id=<rule_id>`

响应示例：

```json
{
  "status": "deleted"
}
```

#### 3.6 校验规则批量操作

`POST /api/rules/validate`

请求体与批量接口一致，用于在真正写入前做字段校验、接口存在性校验和监听冲突检查。

请求体示例：

```json
{
  "create": [
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
  ],
  "update": [],
  "delete_ids": [],
  "set_enabled": []
}
```

响应示例：

```json
{
  "valid": true,
  "create": [
    {
      "id": 0,
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
      "engine_preference": "auto"
    }
  ]
}
```

校验失败时会返回：

- `valid = false`
- `error`：首条错误摘要，方便脚本直接展示
- `issues`：逐项错误明细，包含 `scope`、`index`、`id`、`field`、`message`

#### 3.7 批量写入规则

`POST /api/rules/batch`

请求体字段：

- `create`：批量创建规则
- `update`：批量更新规则
- `delete_ids`：批量删除规则 ID
- `set_enabled`：批量设置启用状态，元素格式为 `{ "id": 1, "enabled": true }`

批量接口会在一个事务内执行，并只触发一次规则重分布。

请求体示例：

```json
{
  "create": [
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
  ],
  "update": [
    {
      "id": 2,
      "in_interface": "eth0",
      "in_ip": "203.0.113.10",
      "in_port": 8080,
      "out_interface": "vmbr0",
      "out_ip": "198.51.100.20",
      "out_source_ip": "",
      "out_port": 80,
      "protocol": "tcp",
      "remark": "vm-b web",
      "tag": "vm",
      "transparent": false,
      "engine_preference": "kernel"
    }
  ],
  "delete_ids": [3],
  "set_enabled": [
    {
      "id": 4,
      "enabled": false
    }
  ]
}
```

成功响应示例：

```json
{
  "created": [],
  "updated": [],
  "deleted_ids": [3],
  "set_enabled": [
    {
      "id": 4,
      "enabled": false
    }
  ]
}
```

### 4. 站点接口

#### 4.1 获取站点列表

`GET /api/sites`

返回 `[]SiteStatus`，每项包含站点配置和 `status` 字段。

#### 4.2 新增站点

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
- `backend_http_port` 和 `backend_https_port` 至少有一个非 `0`
- `listen_ip` 为空时默认 `0.0.0.0`
- `transparent = true` 时必须省略 `backend_source_ip`
- 创建后默认 `enabled = true`

#### 4.3 更新站点

`PUT /api/sites`

必须带 `id`，其余字段与新增站点一致。

#### 4.4 启用 / 禁用站点

`POST /api/sites/toggle?id=<site_id>`

成功响应：

```json
{
  "id": 1,
  "enabled": true
}
```

失败时如果找不到站点，会返回：

```json
{
  "error": "site not found"
}
```

#### 4.5 删除站点

`DELETE /api/sites?id=<site_id>`

### 5. 范围映射接口

#### 5.1 获取范围映射列表

`GET /api/ranges`

返回 `[]PortRangeStatus`，每项包含范围配置、`status` 和内核引擎相关字段。

#### 5.2 新增范围映射

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
- `start_port` 必须小于等于 `end_port`
- `protocol` 允许：`tcp`、`udp`、`tcp+udp`
- `protocol` 默认为 `tcp`
- `out_start_port = 0` 时自动等于 `start_port`
- `transparent = true` 时必须省略 `out_source_ip`
- 创建后默认 `enabled = true`

#### 5.3 更新范围映射

`PUT /api/ranges`

必须带 `id`，其余校验规则与新增相同。

#### 5.4 启用 / 禁用范围映射

`POST /api/ranges/toggle?id=<range_id>`

#### 5.5 删除范围映射

`DELETE /api/ranges?id=<range_id>`

### 6. Worker 接口

#### 6.1 获取 Worker 列表

`GET /api/workers`

支持查询参数：

- `page`
- `page_size`

说明：

- `page_size` 最大 `1000`
- 不传 `page_size` 时返回全部 worker
- 该接口会把用户态规则 worker、范围 worker、共享站点 worker，以及内核态 worker 统一合并后返回

响应示例：

```json
{
  "page": 1,
  "page_size": 20,
  "total": 4,
  "binary_hash": "abc123...",
  "workers": [
    {
      "kind": "kernel",
      "index": 0,
      "status": "running",
      "binary_hash": "abc123...",
      "rule_count": 2,
      "rules": []
    },
    {
      "kind": "rule",
      "index": 0,
      "status": "running",
      "binary_hash": "abc123...",
      "rule_count": 2,
      "rules": []
    },
    {
      "kind": "shared",
      "index": 0,
      "status": "running",
      "binary_hash": "abc123...",
      "site_count": 1
    }
  ]
}
```

`kind` 可能值：

- `kernel`
- `rule`
- `range`
- `shared`

### 7. 统计接口

#### 7.1 规则统计

`GET /api/rules/stats`

支持查询参数：

- `page`：页码，默认 `1`
- `page_size`：每页数量，默认 `20`，最大 `500`
- `sort_key`：可选 `rule_id`、`remark`、`current_conns`、`total_conns`、`rejected_conns`、`speed_in`、`speed_out`、`bytes_in`、`bytes_out`
- `sort_asc`：是否升序，默认 `true`

响应示例：

```json
{
  "page": 1,
  "page_size": 20,
  "total": 1,
  "sort_key": "bytes_out",
  "sort_asc": false,
  "items": [
    {
      "rule_id": 1,
      "remark": "vm-a ssh",
      "active_conns": 2,
      "total_conns": 120,
      "rejected_conns": 0,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "speed_in": 1024,
      "speed_out": 2048,
      "nat_table_size": 0
    }
  ]
}
```

注意：

- 这个接口支持按 `current_conns` 排序，但返回项本身不包含 `current_conns` 字段
- 如果你要拿实时当前连接数，请调用 `GET /api/stats/current-conns`

#### 7.2 范围映射统计

`GET /api/ranges/stats`

支持查询参数：

- `page`
- `page_size`
- `sort_asc`
- `sort_key`：可选 `range_id`、`remark`、`current_conns`、`total_conns`、`rejected_conns`、`speed_in`、`speed_out`、`bytes_in`、`bytes_out`

响应示例：

```json
{
  "page": 1,
  "page_size": 20,
  "total": 1,
  "sort_key": "range_id",
  "sort_asc": true,
  "items": [
    {
      "range_id": 1,
      "remark": "vm-b game",
      "active_conns": 3,
      "total_conns": 300,
      "rejected_conns": 0,
      "bytes_in": 1048576,
      "bytes_out": 3145728,
      "speed_in": 2048,
      "speed_out": 4096,
      "nat_table_size": 1
    }
  ]
}
```

同样地：

- 支持按 `current_conns` 排序
- 返回项本身不直接包含 `current_conns`

#### 7.3 站点统计

`GET /api/sites/stats`

返回值仍是数组，不分页：

```json
[
  {
    "site_id": 1,
    "domain": "app.example.com",
    "active_conns": 3,
    "total_conns": 300,
    "bytes_in": 1048576,
    "bytes_out": 3145728,
    "speed_in": 2048,
    "speed_out": 4096
  }
]
```

#### 7.4 当前连接数

`GET /api/stats/current-conns`

用于按需获取规则 / 范围 / 站点的实时当前连接数，避免轮询统计列表时每次都遍历连接表。

返回说明：

- 某个对象没有出现在对应数组里时，通常可视为当前连接数为 `0`

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
  ]
}
```

## 常见集成流程

### 场景 1：创建虚拟机后自动开通 SSH 转发

1. 云管平台 / 虚拟化平台创建 VM
2. 获取 VM 内网 IP，例如 `198.51.100.10`
3. 调用 `POST /api/rules`
4. 记录返回的 `id`
5. 后续如需停用，调用 `POST /api/rules/toggle?id=<id>`

### 场景 2：为虚拟机自动开通域名

1. 完成 DNS 解析
2. 调用 `POST /api/sites`
3. 把 `domain -> backend_ip` 关系写入内部系统
4. 轮询 `GET /api/workers` 或 `GET /api/sites` 检查状态

### 场景 3：面板侧做状态展示

建议最少轮询以下接口：

- `GET /api/rules`
- `GET /api/sites`
- `GET /api/ranges`
- `GET /api/workers`
- `GET /api/rules/stats`
- `GET /api/sites/stats`
- `GET /api/ranges/stats`
- `GET /api/stats/current-conns`

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
    "out_source_ip": "",
    "out_port": 22,
    "protocol": "tcp",
    "remark": "vm-a ssh",
    "tag": "vm",
    "transparent": false,
    "engine_preference": "auto"
  }'
```

### 关闭一条规则

```bash
curl -X POST "http://127.0.0.1:8080/api/rules/toggle?id=1" \
  -H "Authorization: Bearer your-token-here"
```

### 查询 workers

```bash
curl "http://127.0.0.1:8080/api/workers?page=1&page_size=20" \
  -H "Authorization: Bearer your-token-here"
```

### 查询当前连接数

```bash
curl "http://127.0.0.1:8080/api/stats/current-conns" \
  -H "Authorization: Bearer your-token-here"
```

## 对接建议

- 你的上层系统最好保存本地资源 ID 和 `forward` 返回对象 `id` 的映射
- 写接口成功后，不要立刻假设 worker 已完全切换完成，建议随后查询状态接口确认
- 如果你依赖真实客户端源地址，启用 `transparent` 前要先保证回程路由正确
- 如果你只是做普通端口映射，优先不要启用 `transparent`
- 非透传 full-NAT 且宿主机出口接口存在多个 IPv4 时，建议显式传 `out_source_ip` / `backend_source_ip`

## 与前端行为的差异

有几个实现细节需要明确：

- `GET /api/workers` 是服务端分页
- `GET /api/rules/stats` 和 `GET /api/ranges/stats` 现在也是服务端分页
- `GET /api/sites/stats`、`GET /api/rules`、`GET /api/sites`、`GET /api/ranges` 仍然返回全量列表
- 前端表格的本地搜索 / 本地分页行为，不代表所有后端接口都支持同样的分页或筛选语义

如果你后续要做大规模自动化对接，建议优先基于对象 `id` 做增量同步，而不是完全复用前端的分页逻辑。
