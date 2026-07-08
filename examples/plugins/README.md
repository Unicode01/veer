# Forward 插件编写指南

本目录放运行时插件示例。插件部署到 `plugins/runtime/<plugin_id>/` 后由 Forward 扫描加载，每个插件使用独立子目录。

## 基本结构

最小插件通常包含：

```text
my_plugin/
  plugin.json
  control.js
  ui/
    index.html
```

`plugin.json` 只放静态信息和授权边界，不放资源、动作、hook 或页面细节：

```json
{
  "api_version": "v1",
  "id": "my_plugin",
  "name": "My Plugin",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "resource", "ui"]
  }
}
```

`control.js` 顶层负责注册运行时 surface：

```js
plugin.capabilities(["config"]);

plugin.resource({
  id: "profiles",
  methods: ["list", "get", "create", "update", "delete"],
  runtime_update: "plugin_reconcile",
  max_records: 64,
  max_record_bytes: 4096
});

plugin.action({
  id: "apply",
  runtime_update: "plugin_reconcile"
});

ui.register({
  static_dir: "ui",
  entry: "index.html",
  page: "my_plugin",
  page_title: "My Plugin"
});

exports.onReconcile = function (ctx) {
  // 根据 resources/KV/secret 更新系统状态或 eBPF map。
};
```

顶层注册阶段只允许声明类 API，例如 `plugin.*`、`ebpf.loadObject`、`hooks.attach`、`ui.register`。`kv`、`resources`、`secret`、`timer`、`net.*` 和 `ebpf.mapPut/mapDelete/mapClear` 这类有副作用的 API 只能在 handler 阶段使用。

## 控制面生命周期

`control.main` 运行在 Goja 控制面，不进入 TC/XDP 热路径。每个插件默认有一个持久 Goja VM，`control.js` 顶层只在初始化或脚本变化后执行一次，顶层变量会在 handler 调用之间保留。

可导出的常用 handler：

```js
exports.onReconcile = function (ctx) {};
exports.onResourceApply = function (ctx) {};
exports.onAction = function (ctx) {};
exports.onTimer = function (ctx) {};
```

声明 `worker` 权限后，可以把慢任务放到命名 worker VM：

```js
let mainCount = 0;

exports.onAction = function () {
  mainCount++;
  return worker.call("dialer", "onDial", { attempt: mainCount });
};

let dialCount = 0;

exports.onDial = function (ctx) {
  dialCount++;
  return { worker: ctx.worker.name, dialCount, payload: ctx.payload };
};
```

worker 不是 `new Worker("file")`。第一次 `worker.call(name, handler, payload)` 或 `worker.dispatch(name, handler, payload)` 会由 Go 侧创建一个 goroutine 和独立 Goja Runtime，加载同一个 `control.main` 一次，然后调用 `exports[handler](ctx)`。每个 worker 的顶层状态独立保留。

## 资源、动作和持久化

插件 UI 和控制脚本都应通过注册资源表达持久化配置。资源数据存 SQLite，按 canonical JSON 比较，字段顺序不构成变更。

资源的 `methods` 控制 HTTP/UI 可访问能力：

```js
plugin.resource({
  id: "sessions",
  methods: ["list", "get", "create", "update", "delete"],
  control_methods: ["list", "get", "create", "update", "delete"],
  runtime_update: "runtime_apply",
  secret_fields: ["password"]
});
```

`control_methods` 只影响本插件 Goja 控制脚本。HTTP/UI 和跨插件访问只看 `methods`，因此派生状态建议对外只读、对控制脚本可写：

```js
plugin.resource({
  id: "status",
  methods: ["list", "get"],
  control_methods: ["list", "get", "create", "update", "delete"],
  runtime_update: "manual"
});
```

`runtime_update` 语义：

- `manual`：只落库或标记 pending，不自动重算。
- `plugin_reconcile`：触发 `exports.onReconcile(ctx)`。
- `runtime_apply`：触发资源级运行时应用，通常进入 `exports.onResourceApply(ctx)` 或宿主 runtime update。

插件之间默认不能互相写数据或触发动作。需要跨插件调用时，在调用方 manifest 里声明最小权限：

```json
{
  "control": {
    "permissions": ["plugin.action"],
    "action_access": [
      {
        "plugin": "wan_core",
        "actions": ["apply_session", "teardown"]
      }
    ]
  }
}
```

控制脚本里使用 `plugins.actions.call(plugin, action, payload)`：

```js
exports.onAction = function () {
  return plugins.actions.call("wan_core", "apply_session", {
    wan_id: "default",
    usable: true
  });
};
```

跨插件 action 调用走目标 action 自己的 `runtime_update` 语义和 `max_payload_bytes` 限制；self-call 会被拒绝，避免同一个 Goja VM 死锁。

## WebUI 和插件通信

插件 UI 通过 `ui.register()` 暴露入口：

```js
ui.register({
  static_dir: "ui",
  entry: "index.html",
  page: "observe",
  page_title: "Observe"
});
```

WebUI 通信链路如下：

1. 主 WebUI 调用 `GET /api/plugins` 获取插件 catalog，其中包含 `ui.entry`、`ui.page`、`ui.page_title` 和 `asset_base_path`。
2. 用户打开插件 UI 或切到插件分页时，宿主 WebUI 用自己的 Bearer Token 拉取 `/api/plugins/<id>/assets/<entry>`。
3. 宿主把插件 HTML 注入基础样式和 `window.ForwardPluginHost` bridge，再通过 sandbox iframe 的 `srcdoc` 加载。
4. 插件页面不能拿到 Web Token；读写数据时调用 `ForwardPluginHost.data.*` 或 `ForwardPluginHost.action()`。
5. `ForwardPluginHost` 在 iframe 内用 `postMessage` 发出 `forward-plugin-rpc`。
6. 父页面校验消息来源必须是已登记的插件 iframe，并校验 `pluginId` 匹配。
7. 父页面用宿主 token 调用真实 API，例如 `/api/plugins/<id>/resources/<resource>` 或 `/api/plugins/<id>/actions/<action>`。
8. API 返回后，父页面再用 `postMessage` 回传 `forward-plugin-rpc-result`。
9. 插件页面的 Promise resolve/reject；失败时 Error 会带 `payload`、`status`、`runtime_status` 和 `runtime_error`。

插件页面常用写法：

```html
<script>
async function saveProfile() {
  const host = window.ForwardPluginHost;
  try {
    await host.data.upsert("profiles", "default", { enabled: true }, { enabled: true });
    host.toast("Saved");
  } catch (error) {
    host.toastError(error);
  }
}
</script>
```

可用 helper：

- `ForwardPluginHost.locale`
- `ForwardPluginHost.t(messages, key, params)`
- `ForwardPluginHost.onLocaleChange(callback)`
- `ForwardPluginHost.data.list(resource, {limit, offset})`
- `ForwardPluginHost.data.get(resource, key)`
- `ForwardPluginHost.data.create(resource, data, {key, enabled})`
- `ForwardPluginHost.data.update(resource, key, data, {enabled})`
- `ForwardPluginHost.data.upsert(resource, key, data, {enabled})`
- `ForwardPluginHost.data.delete(resource, key)`
- `ForwardPluginHost.action(action, payload)`
- `ForwardPluginHost.toast(message)`
- `ForwardPluginHost.toastError(error)`
- `ForwardPluginHost.errorText(error)`
- `ForwardPluginHost.requestResize()`

宿主还注入基础组件和 class 名，例如 `host.card()`、`host.button()`、`host.table()`、`fwd-card`、`fwd-button`、`fwd-table`，方便插件页面保持接近主 WebUI 的交互风格。

插件页面的 i18n 由插件自己维护 messages，不写入 manifest。宿主会把当前主 WebUI 语言注入为 `ForwardPluginHost.locale`，主页面切换语言时会向已加载 iframe 发送 locale 事件：

```html
<script>
const F = window.ForwardPluginHost;
const messages = {
  "zh-CN": { save: "保存配置", saved: "已保存 {{name}}" },
  "en-US": { save: "Save Profile", saved: "Saved {{name}}" }
};

const button = F.button(F.t(messages, "save"), async function () {
  F.toast(F.t(messages, "saved", { name: "default" }));
});

F.onLocaleChange(function () {
  button.textContent = F.t(messages, "save");
  F.requestResize();
});
</script>
```

## TC 数据面插件

启用 `plugins_dataplane_enabled=true` 后，注册了 TC `stage=forward` 或 `stage=reply` hook 的可信插件可以进入内置 `fvtap` pipeline。默认没有实际插件链时，不会给热路径增加额外 lookup。

内置 `fvtap core` priority 固定为 `1000`：

- `priority < 1000`：core 前插件。
- `priority > 1000`：core 后插件。
- `priority == 1000`：拒绝，避免和 core 抢同一排序点。

没有 Forward/Egress NAT 规则时，显式声明了 `interfaces` 的 hook 仍可把 `pipeline_v4` 挂到目标接口上；这时内置 forward/reply core 会被关闭，pipeline 只执行插件链。core 后插件仍可运行，但 `tc_plugin_ctx_v4` 是清空上下文，不包含规则或 flow 匹配结果。

进入 `fvtap` pipeline 的 TC object 必须声明共享 `tc_prog_chain_v4` prog-array map，处理后应 tail-call 回对应 stage 的 continue slot，除非插件明确要返回最终 TC action。core 后插件如果要读取规则匹配上下文，需要声明共享 `tc_plugin_ctx_v4` map；只有内置 core 实际启用并匹配规则或回包 flow 时，该上下文才会带有 `have_rule` 或 `have_flow`。

生产环境只应加载可信 eBPF object。服务会校验路径、大小、sha256、program type 和 section，但不能证明第三方程序一定不会改包或丢包。

stable/preview 插件注册 object 或 UI 入口时必须声明 sha256。跨架构 eBPF object 会因目标架构不同产生不同 hash，推荐在 `control.js` 注册阶段使用 `crypto.sha256File("object.o")` 和 `crypto.sha256File("ui/index.html")` 读取本插件目录内当前产物 hash，再交给加载器复核。

## 网络管理权限

`net.admin` 和 `net.l2` 是两段式授权：既要在 `control.permissions` 声明总权限，也要在 `control.net_access` 声明可操作接口模式和操作。

示例：

```json
{
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "net.admin", "net.l2"],
    "net_access": [
      {
        "interfaces": ["fwd*", "br*", "wan*"],
        "operations": ["link.create", "link.delete", "link.master", "link.offload", "link.state", "addr.write", "route.write", "l2"]
      }
    ]
  }
}
```

接口名运行时仍会校验长度和非法字符。生产插件应尽量只授权自己创建的接口前缀；物理口需要逐项显式授权。

## 示例插件

- `packet_observer`：TC pipeline 观测示例，需要执行 `build.sh` 生成 eBPF object；仍是 `lab`。
- `wan_core`：协议中立 WAN handoff 示例，消费标准化 session，创建 host veth 到 vtap 的接入。
- `lan_core`：LAN bridge 和 synthetic Egress NAT plan 示例。
- `vtolocal`：vtap 和本机接口/路由 handoff 示例。
- `pppoe_client`：Goja + raw L2 PPPoE 控制面和 TC PPPoE 隧道插件；已提供 `test-control-node.js`、`test-blackbox-linux.sh` 和 `scripts/test-plugin-pppoe-linux.sh`。控制面自测覆盖 discovery、PAP/CHAP、IPv6CP、DHCPv6-PD、keepalive/redial、disconnect 和 tunnel map 写入；黑盒测试通过真实 `forward` 进程、HTTP 插件 API、rp-pppoe server/pppd AC、ping 和 iperf3 验证 TC 隧道真实流量。Linux 测试依赖 `ethtool` 并会准备 MTU/offload；生产使用前仍应在目标运营商/AC 上跑真实断线重拨、IPv4/IPv6/PD、长流稳定性和目标拓扑吞吐验收。

## 编写建议

- manifest 保持薄，只声明身份、入口和权限。
- 资源设计先区分用户配置和派生状态，派生状态对 HTTP/UI 只读。
- 需要编排核心转发能力时，优先生成声明式资源：`forward_rule_plans` 对应端口转发规则，`egress_nat_plans` 对应 Egress NAT；不要直接写全局 `rules` / `egress_nats` 表。
- UI 永远通过 `ForwardPluginHost` 访问资源和动作，不假设能拿到 Web Token。
- 慢任务、重试、拨号状态机放 worker 或 timer，不阻塞主控制 VM。
- 热路径能力只放 eBPF object 和 map，配置更新通过控制面批量写 map，避免包路径查询 SQLite 或 HTTP。
- `lab` 插件默认不应影响生产数据面；要进数据面或执行高权限控制面，必须在配置中显式允许。
