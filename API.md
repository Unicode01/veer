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
  "web_token": "change-me-to-a-secure-token"
}
```

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
- 但 `401` 和部分 `405` 是通过 `http.Error(...)` 返回的，不保证是 JSON

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
  "out_ip": "192.168.100.10",
  "out_port": 22,
  "protocol": "tcp",
  "remark": "vm-a ssh",
  "tag": "vm",
  "enabled": true,
  "transparent": false
}
```

### Site

```json
{
  "id": 1,
  "domain": "app.example.com",
  "listen_ip": "203.0.113.10",
  "listen_interface": "eth0",
  "backend_ip": "192.168.100.10",
  "backend_http_port": 80,
  "backend_https_port": 443,
  "tag": "vm",
  "enabled": true,
  "transparent": false
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
  "out_ip": "192.168.100.20",
  "out_start_port": 30000,
  "protocol": "tcp+udp",
  "remark": "vm-b game",
  "tag": "game",
  "enabled": true,
  "transparent": false
}
```

### 状态字段

常见状态值：

- `running`
- `stopped`
- `error`
- `draining`
- `disabled`

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
    "addrs": ["192.168.100.1"]
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
- `transparent`：按透明转发开关过滤，支持 `true` / `false`
- `status` / `statuses`：按运行状态过滤，支持 `running`、`stopped`、`error`
- `in_interface` / `out_interface`：按入/出接口精确过滤
- `in_ip` / `out_ip`：按入/出 IP 精确过滤
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
    "out_ip": "192.168.100.10",
    "out_port": 22,
    "protocol": "tcp",
    "remark": "vm-a ssh",
    "tag": "vm",
    "enabled": true,
    "transparent": false,
    "status": "running"
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
  "out_ip": "192.168.100.10",
  "out_port": 22,
  "protocol": "tcp",
  "remark": "vm-a ssh",
  "tag": "vm",
  "transparent": false
}
```

规则：

- 必填：`in_ip`、`in_port`、`out_ip`、`out_port`
- `protocol` 允许：`tcp`、`udp`、`tcp+udp`
- 省略 `protocol` 时默认 `tcp`
- 创建后默认 `enabled = true`

#### 3.3 更新规则

`PUT /api/rules`

请求体与新增规则类似，但必须包含 `id`。

说明：

- 更新时会保留原有 `enabled` 状态
- 更新成功后会触发 worker 重分布

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
      "out_ip": "192.168.100.10",
      "out_port": 22,
      "protocol": "tcp",
      "remark": "vm-a ssh",
      "tag": "vm"
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
      "out_ip": "192.168.100.10",
      "out_port": 22,
      "protocol": "tcp",
      "remark": "vm-a ssh",
      "tag": "vm",
      "enabled": true,
      "transparent": false
    }
  ]
}
```

校验失败时会返回：

- `valid = false`
- `error`：首条错误摘要，方便脚本直接展示
- `issues`：逐项错误明细，包含 `scope`、`index`、`field`、`message`

#### 3.7 批量写入规则

`POST /api/rules/batch`

请求体字段：

- `create`：批量创建规则
- `update`：批量更新规则
- `delete_ids`：批量删除规则 ID
- `set_enabled`：批量设置启用状态，元素格式为 `{ "id": 1, "enabled": true }`

批量接口会在一个事务内执行，并只触发一次 worker 重分布。

请求体示例：

```json
{
  "create": [
    {
      "in_interface": "eth0",
      "in_ip": "203.0.113.10",
      "in_port": 2222,
      "out_interface": "vmbr0",
      "out_ip": "192.168.100.10",
      "out_port": 22,
      "protocol": "tcp",
      "remark": "vm-a ssh",
      "tag": "vm"
    }
  ],
  "update": [
    {
      "id": 2,
      "in_interface": "eth0",
      "in_ip": "203.0.113.10",
      "in_port": 8080,
      "out_interface": "vmbr0",
      "out_ip": "192.168.100.20",
      "out_port": 80,
      "protocol": "tcp",
      "remark": "vm-b web",
      "tag": "vm"
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

返回带 `status` 的站点列表。

#### 4.2 新增站点

`POST /api/sites`

请求体示例：

```json
{
  "domain": "app.example.com",
  "listen_ip": "203.0.113.10",
  "listen_interface": "eth0",
  "backend_ip": "192.168.100.10",
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

返回带 `status` 的范围映射列表。

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
  "out_ip": "192.168.100.20",
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
- `protocol` 默认为 `tcp`
- `out_start_port = 0` 时自动等于 `start_port`
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

- 只有这个接口支持服务端分页
- `page_size` 最大 `1000`
- 不传 `page_size` 时返回全部 worker

响应示例：

```json
{
  "page": 1,
  "page_size": 20,
  "total": 3,
  "binary_hash": "abc123...",
  "workers": [
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

- `rule`
- `range`
- `shared`

### 7. 统计接口

#### 7.1 规则统计

`GET /api/rules/stats`

响应示例：

```json
[
  {
    "rule_id": 1,
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
```

#### 7.2 范围映射统计

`GET /api/ranges/stats`

字段和规则统计类似，只是主键字段为 `range_id`。

#### 7.3 站点统计

`GET /api/sites/stats`

响应示例：

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

## 常见集成流程

### 场景 1：创建虚拟机后自动开通 SSH 转发

1. 云管平台 / 虚拟化平台创建 VM
2. 获取 VM 内网 IP，例如 `192.168.100.10`
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
    "out_ip": "192.168.100.10",
    "out_port": 22,
    "protocol": "tcp",
    "remark": "vm-a ssh",
    "tag": "vm",
    "transparent": false
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

## 对接建议

- 你的上层系统最好保存本地资源 ID 和 `forward` 返回的对象 `id` 映射
- 写接口成功后，不要立刻假设 worker 已完全切换完成，建议随后查询状态接口确认
- 如果你依赖真实客户端源地址，启用 `transparent` 前要先保证回程路由正确
- 如果你只是做普通端口映射，优先不要启用 `transparent`

## 与前端行为的差异

有一个实现细节需要明确：

- Web 前端中的大部分分页是浏览器本地分页
- 服务端 API 当前只有 `/api/workers` 支持原生分页参数
- 规则、站点、范围映射、统计接口当前都是一次性返回全量数据

如果你后续要做大规模自动化对接，建议优先基于对象 `id` 做增量同步，而不是依赖前端的分页行为。
