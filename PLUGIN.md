# Veer 插件开发指南

仓库的 `plugins/` 目录存放随项目维护的运行时插件。Veer 默认扫描 `plugins/<plugin_id>/`，每个插件使用独立子目录。

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

pipeline.node({
  id: "my_plugin",
  description: "Optional logical node shown in the Veer pipeline."
});

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

顶层注册阶段只允许声明类 API，例如 `plugin.*`、`pipeline.*`、`ebpf.loadObject`、`hooks.attach`、`ui.register`。`kv`、`resources`、`secret`、`timer`、`worker`、`net.*` 和 `ebpf.mapPut/mapDelete/mapClear` 这类有副作用的 API 只能在 handler 阶段使用。

逻辑节点建议使用更明确的入口：

- `pipeline.node({id, description})`：声明纯 veer 逻辑链节点，不创建 Linux 接口。
- `pipeline.handoff({id, type, description})`：声明系统接入适配器，通常对应 bridge、veth、tun 或本机路由管理。
- `pipeline.attach({direction, attach, priority, program, interfaces})`：声明 eBPF 程序应进入哪条 veer 逻辑链和 TC ingress/egress 挂载点；Veer 根据 core priority 自动编排 core 前后和 tail-call slot。
- `plugin.pipelineNode()`、`plugin.handoff()`、`plugin.virtualInterface()` 和 `hooks.attach()` 仍可用，但只作为兼容/低层入口。

## 控制面生命周期

`control.main` 运行在 Goja 控制面，不进入 TC/XDP 热路径。每个插件默认有一个持久 Goja VM，`control.js` 顶层只在初始化或脚本变化后执行一次，顶层变量会在 handler 调用之间保留。

Veer 每 2 秒检查插件源目录内容指纹。插件增删或 `plugin.json`、`control.js`、UI、eBPF object 变化只会设置 `update_available`，不会自动执行候选代码或重建数据面；WebUI 的“应用更新”或 `POST /api/plugins/reload` 会复制一份稳定候选快照，完成 manifest、control、UI 和 object 校验后再 reconcile。校验或运行时切换失败会保留上一份已应用快照。常规文件使用受限 SHA256 内容 hash，超大文件只纳入路径、大小和 mtime 等元数据。

可导出的常用 handler：

```js
exports.onReconcile = function (ctx) {};
exports.onResourceApply = function (ctx) {};
exports.onAction = function (ctx) {};
exports.onTimer = function (ctx) {};
```

需要在代码或静态资源更新时保留 VM 内状态，可以实现事务式升级钩子：

```js
exports.onUpgradeSnapshot = function (ctx) {
  return {sequence: sequence};
};

exports.onUpgradeRestore = function (ctx) {
  sequence = (ctx.upgrade.state || {}).sequence || 0;
};
```

切换时 Veer 会暂停该插件的新调用，排空主 VM 与命名 worker 的在途请求，在旧 VM 调用 `onUpgradeSnapshot`，再在候选 VM 调用 `onUpgradeRestore`；全部成功后才原子替换 VM 所有权。失败会丢弃候选并继续使用旧 VM。旧版本实现 snapshot 而候选缺少 restore 时会拒绝更新；候选首次加入 restore、旧版本没有 snapshot 时收到的 `state` 为 `null`；两端都没有钩子时保持冷替换语义。

`ctx.upgrade` 包含 `protocol_version`、`phase`、`scope`、`worker_name`、`from_version`、`to_version`、`state`、`timers` 和 `sockets`。每个 snapshot 必须是 JSON 可序列化值且不超过 256 KiB。snapshot/restore 阶段只允许普通 JavaScript 状态处理和 `log.*`；KV、resource、timer、worker、network、注册 API 与 eBPF map API 均被禁止，避免候选失败后留下外部副作用。

实现 restore 后，宿主持有的 timer 会保持原 generation 和触发时间，socket 句柄会在候选仍声明相同 `net.tcp`/`net.udp` 权限及 `net_access` 时转移，现有命名 worker 也会按 `scope: "worker"` 独立迁移。宿主 core 重建时，Veer 仅会在插件 ID、object ID 和实际加载字节的 SHA256 都不变时复用规格兼容的插件私有 map；object 内容升级、禁用或删除不会继承这些 map。eBPF map 中需要跨 object 更新保留的协议状态仍应落入 `runtime_apply` resource；Veer 会在新 dataplane 挂载后重放这类资源。VM snapshot 不替代 dataplane map 的兼容设计。

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

每个插件最多同时保留 256 个 worker 请求和 16 MiB worker payload，统计范围同时包含排队与正在执行的请求；超限调用会立即失败。`worker.stats()` 返回当前值、峰值、拒绝次数和上限，`worker.list()` 还会返回每个 worker 的执行状态、队列深度和 payload 占用。

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
- 动作可使用 `runtime_query`：执行 `exports.onAction(ctx)` 并把 JSON 返回值放进 HTTP 响应的 `result`，不写 action runtime status、不触发 core 重分发，适合流量、链路和设备状态快照。返回值最大 64 KiB。

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
3. 宿主把插件 HTML 注入基础样式和 `window.VeerPluginHost` bridge，再通过 sandbox iframe 的 `srcdoc` 加载。
4. 插件页面不能拿到 Web Token；读写本插件数据时调用 `VeerPluginHost.data.*` 或 `VeerPluginHost.action()`。
5. `VeerPluginHost` 在 iframe 内用 `postMessage` 发出 `veer-plugin-rpc`。
6. 父页面校验消息来源必须是已登记的插件 iframe，并校验 `pluginId` 匹配。
7. 父页面用宿主 token 调用真实 API，例如 `/api/plugins/<id>/resources/<resource>` 或 `/api/plugins/<id>/actions/<action>`。
8. API 返回后，父页面再用 `postMessage` 回传 `veer-plugin-rpc-result`。
9. 插件页面的 Promise resolve/reject；失败时 Error 会带 `payload`、`status`、`runtime_status` 和 `runtime_error`。

插件页面常用写法：

```html
<script>
async function saveProfile() {
  const host = window.VeerPluginHost;
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

- `VeerPluginHost.locale`
- `VeerPluginHost.t(messages, key, params)`
- `VeerPluginHost.onLocaleChange(callback)`
- `VeerPluginHost.data.list(resource, {limit, offset})`
- `VeerPluginHost.data.get(resource, key)`
- `VeerPluginHost.data.create(resource, data, {key, enabled})`
- `VeerPluginHost.data.update(resource, key, data, {enabled})`
- `VeerPluginHost.data.upsert(resource, key, data, {enabled})`
- `VeerPluginHost.data.delete(resource, key)`
- `VeerPluginHost.plugins.resources.list(plugin, resource, {limit, offset})`
- `VeerPluginHost.plugins.resources.get(plugin, resource, key)`
- `VeerPluginHost.action(action, payload)`
- `VeerPluginHost.toast(message)`
- `VeerPluginHost.toastError(error)`
- `VeerPluginHost.errorText(error)`
- `VeerPluginHost.requestResize()`

跨插件 UI 读取只开放 `list/get`，并复用调用方 manifest 的 `control.resource_access` 白名单。iframe 不能借此访问未授权插件资源，也不开放跨插件写入；编排写操作仍通过 Goja `plugins.resources` / `plugins.actions` 完成。

宿主还注入基础组件和 class 名，例如 `host.card()`、`host.button()`、`host.table()`、`host.recordPicker()`、`host.collectionEditor()`、`veer-card`、`veer-button`、`veer-table`。`recordPicker` 用于已有记录/新建记录切换，`collectionEditor` 用于路由等结构化数组，避免页面要求用户手写内部 key 或原始 JSON。

插件页面的 i18n 由插件自己维护 messages，不写入 manifest。宿主会把当前主 WebUI 语言注入为 `VeerPluginHost.locale`，主页面切换语言时会向已加载 iframe 发送 locale 事件：

```html
<script>
const F = window.VeerPluginHost;
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

启用 `plugins_dataplane_enabled=true` 后，使用 `pipeline.attach()` 注册 TC `direction=forward` 或 `direction=reply` 的可信插件可以进入内置 `veer` pipeline。默认没有实际插件链时，不会给热路径增加额外 lookup。

`veer` 是逻辑 pipeline，不是 Linux netdev。它的作用是把宿主 TC dispatcher、插件 eBPF 程序和内置 Veer Core 编排成一条 tail-call chain：

- 真实接口只出现在边界：例如 `eth1` 是 TC attach 点，`br-lan` 是 LAN ingress 点。
- `pipeline.node()` / `plugin.virtualInterface()` 只描述逻辑节点或能力，不会创建系统网卡，也没有 ifindex。
- `pipeline.attach({ interfaces: [...] })` 同时定义 dispatcher 挂载目标和该 Hook 的执行白名单；即使其他规则或插件也让 dispatcher 挂在同一组接口上，该 Hook 也不会在声明范围外执行。它不会把 vtap 落成 netdev。
- `vtolocal` 使用单个 dummy 接入 Linux 协议栈；`wan_core` 的 direct 模式使用 dummy，PPPoE 所需的 `segmented_veth` 模式则创建 local/pipeline veth 对。它们都是显式 L3/分段边界，不是逻辑 veer 节点。

因此，PPPoE、firewall、VXLAN 这类数据面插件应优先实现为逻辑 chain。只有需要让 Linux 本机看见 L3 边界或提供明确分段点时才创建 dummy/veth/tun/bridge 等系统接口；插件节点本身始终不占用 netdev。

推荐写法是让 Goja 声明意图，具体 pre/post stage、prog-array slot 和 core 插入点由 Veer runtime 决定：

```js
pipeline.attach({
  id: "firewall-pre",
  direction: "forward",
  priority: 100,
  program: "firewall:tc_filter",
  mode: "drop",
  interfaces: ["br-lan"]
});

pipeline.attach({
  id: "observe-after-core",
  direction: "forward",
  priority: 1100,
  program: "observer:tc_post",
  mode: "observe",
  context: ["tc_plugin_ctx_v4"]
});
```

当前 TC pipeline 已覆盖：

- `pre_forward`：core 查规则前，适合 PPPoE/VXLAN decap、早期 drop、包头预处理。
- `post_lookup`：core 找到规则后、真正执行 forward rewrite 前，适合读取 `tc_plugin_ctx_v4` 做观测或轻量标记。
- `pre_reply`：reply flow lookup 前，适合 reply 方向预处理。
- `post_reply`：reply flow lookup 后、reply rewrite 前，适合 PPPoE/VXLAN 回包封装这类依赖 flow context 的处理。
- `attach=ingress|egress`：同一逻辑 chain 可分别绑定到真实接口的 TC ingress 或 egress，并使用独立接口作用域。

PPPoE 路径出站使用 `local0 -> pipeline peer TC ingress -> PPPoE stage -> physical WAN`，入站使用 `physical WAN TC ingress -> PPPoE stage -> local0 ingress`。`local0` 与内部 pipeline peer 组成由 `wan_core` 管理的 veth 边界；pipeline peer 只承担数据面换向，不应作为用户可选 WAN 接口。

动态 PPPoE 地址、对端地址和路由由 `wan_core` 发布到这个本地边界，并在重拨时替换；`vtolocal` 只用于静态本地边界，不应同时管理同一个 PPPoE 接口的动态地址。

内置 `Veer Core` priority 固定为 `1000`：

- `priority < 1000`：core 前插件。
- `priority > 1000`：core 后插件。
- `priority == 1000`：拒绝，避免和 core 抢同一排序点。

`hooks.attach()` 仍支持显式 `pre_forward/post_lookup/pre_reply/post_reply`，用于兼容旧插件或做底层测试；新插件应优先用 `pipeline.attach()`。

没有 Veer/Egress NAT 规则时，显式声明了 `interfaces` 的 hook 仍可把 `pipeline_v4` 挂到目标接口上；这时 Veer Core 的 forward/reply 路径会被关闭，pipeline 只执行插件链。core 后插件仍可运行，但 `tc_plugin_ctx_v4` 是清空上下文，不包含规则或 flow 匹配结果。

进入 `veer` pipeline 的 TC object 必须声明共享 `tc_prog_chain_v4` prog-array map，处理后应 tail-call 回对应 stage 的 continue slot，除非插件明确要返回最终 TC action。eBPF tail call 是 continuation，不是普通函数调用；tail-call 成功后不会回到插件原来的栈帧。core 后插件如果要读取规则匹配上下文，需要声明共享 `tc_plugin_ctx_v4` map；只有内置 core 实际启用并匹配规则或回包 flow 时，该上下文才会带有 `have_rule` 或 `have_flow`。新插件应 include 当前版本的 `plugins/include/veer_plugin_helpers.h` 并随版本重新编译 object，以保持共享 prog-array 规格一致，同时复用 veer slot、continue helper、skb 写入/校验和/redirect 包装和基础 IPv4/L4 解析 helper。

生产环境只应加载可信 eBPF object。服务会校验路径、大小、sha256、program type 和 section，但不能证明第三方程序一定不会改包或丢包。

stable/preview 插件注册 object 或 UI 入口时必须声明 sha256。跨架构 eBPF object 会因目标架构不同产生不同 hash，推荐在 `control.js` 注册阶段使用 `crypto.sha256File("object.o")` 和 `crypto.sha256File("ui/index.html")` 读取本插件目录内当前产物 hash，再交给加载器复核。

## 网络管理权限

`net.admin`、`net.l2`、`net.tcp` 和 `net.udp` 是两段式授权：既要在 `control.permissions` 声明总权限，也要在 `control.net_access` 声明可操作接口模式和操作。`net.udp` 提供 `send`、`recv`、`exchange`，Linux 下会按声明接口尝试绑定设备，适合控制面探测、协商和轻量 L4 管理流量；`net.tcp` 用于下文的宿主持久 socket。数据面隧道仍应放在 TC/eBPF。

`net.l2` 提供 `send`、`recv`、`recvMany`、`exchange` 和 `exchangeMany`。`exchange`/`exchangeMany` 默认收发相同 EtherType；需要跨协议阶段收包时可设置 `recv_ethertype`，运行时会先打开接收 socket 再发送。例如 PPPoE 断开可发送 discovery `0x8863`，同时等待 session `0x8864`，避免先发后监听导致快速响应丢失。

示例：

```json
{
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "net.admin", "net.l2", "net.udp"],
    "net_access": [
      {
        "interfaces": ["veer*", "br*", "wan*"],
        "operations": ["link.create", "link.delete", "link.master", "link.offload", "link.state", "addr.write", "route.write", "l2", "udp"]
      }
    ]
  }
}
```

接口名运行时仍会校验长度和非法字符。生产插件应尽量只授权自己创建的接口前缀；物理口需要逐项显式授权。

`net.link.get()` 和 `net.link.list()` 在 Linux 下返回的 link 对象包含 `statistics`，其中有 `rx_packets/tx_packets/rx_bytes/tx_bytes/rx_errors/tx_errors/rx_dropped/tx_dropped`。读取由 netlink 完成，不会给数据面增加指令；TC redirect 到 dummy 等路径可能绕过该 netdev 的驱动计数，这类逻辑隧道应改读自己的 eBPF 计数。`net.link.getOffloads(iface)` 通过 `ethtool -k` 返回 `rx/tx/sg/tso/ufo/gso/gro/lro` 当前布尔状态，可在修改前记录并在 teardown 时精确恢复。

声明 `ebpf.map_read` 后，`ebpf.mapGet(object, map, keyHex)` 返回普通 map value 的十六进制字符串；`ebpf.mapGetPerCPU(object, map, keyHex)` 返回按 possible CPU 排列的十六进制 value 数组，已经去掉每 CPU 的 8 字节对齐 padding。插件可按自己的 value ABI 聚合这些值，适合无原子竞争的包数和字节数统计。

需要为同一物理口创建独立二层身份时，可使用 `net.link.ensureMacvlan()`。调用方需要父接口的 `link.read` 和子接口的 `link.create` 权限；返回值包含接口信息和本次是否实际创建。随机 MAC 应由插件首次生成后持久化，重拨时复用，避免每次被上游识别成新终端：

```js
var result = net.link.ensureMacvlan({
  name: "veerppp0",
  parent: "eth1",
  mode: "bridge",
  mac: "02:11:22:33:44:55",
  up: true
});

log.info(result.link.name + " created=" + result.created);
```

`mac` 必须是非零单播地址。清理前应记录并校验 `created=true`，只删除插件自己创建的接口。`net.link.getOffloads()` 和 `net.link.setOffloads()` 依赖系统 `ethtool`；一键部署会安装该依赖，裁剪系统需要自行提供。`net.link.setGSO(iface, {max_size: mtu, max_segs: 1})` 只设置设备 GSO 上限，不能保证 TC egress 在执行前已完成分段；不支持 GSO 的封装器还必须在 ingress 侧限制 GRO/GSO，或使用显式分段边界。

`net.udp.exchange` 适合做一次请求一次响应的控制面探测：

```js
var reply = net.udp.exchange({
  interface: "wan0",
  remote_ip: "198.51.100.10",
  port: 51820,
  payload_hex: "01020304",
  timeout_ms: 1000
});

if (reply === null) {
  throw new Error("udp probe timed out");
}
```

`exchange` 中的 `port` 是远端端口，接收侧默认按发送目标 IP 和端口过滤回包。单独使用 `net.udp.recv` 时，`port` 表示本地监听端口；如果需要避免歧义，可显式使用 `remote_port`、`local_port`。

### 持久 TCP/UDP socket

长期控制连接使用宿主持有的 `net.socket`，句柄可以跨主 VM 和 worker handler 保留。TCP 需要 `net.tcp` 权限与接口级 `tcp` 操作；UDP 沿用 `net.udp` 权限与 `udp` 操作。每个插件最多持有 32 个句柄；插件停用、冷替换或进程退出时会自动关闭，事务式热升级可以继承句柄。

```js
var peer = net.socket.open({
  network: "tcp4",
  interface: "wan0",
  local_ip: "192.0.2.10",
  remote_ip: "198.51.100.1",
  remote_port: 179,
  timeout_ms: 3000,
  no_delay: true
});

net.socket.write({handle: peer.handle, payload_hex: "ffffffff", timeout_ms: 1000});
var chunk = net.socket.read({handle: peer.handle, max_bytes: 65536, timeout_ms: 1000});
net.socket.close({handle: peer.handle});
```

可用方法为 `open`、`listen`、`accept`、`read`、`write`、`status`、`list` 和 `close`。UDP `listen` 返回 datagram 句柄，`read` 会返回 `remote_ip`/`remote_port`，回复时将其传给 `write`。

socket 生命周期不受单次 handler 结束影响，但一次拨号、读、写或 accept 最长 15 秒，单次 Goja handler 仍限制为 20 秒。长期协议应在 worker 中处理一批数据后返回，再用 one-shot timer 触发下一次 worker dispatch；不要使用永久 `while` 循环。

## 随仓库维护的插件

- `wan_core`（stable）：消费标准化 WAN session；direct 模式管理本地 L3 dummy，`segmented_veth` 模式管理 local/pipeline veth 边界。
- `lan_core`（stable）：管理 LAN bridge，并生成 Egress NAT、DHCPv4 和 IPv6 assignment plan。
- `vtolocal`（stable）：创建静态本地 L3 dummy，并管理该接口上的地址与路由。
- `pppoe_client`（stable）：Goja + raw L2 PPPoE 控制面和双向 TC 隧道插件。插件目录内保留控制面自测和 Linux 黑盒脚本，覆盖 discovery、PAP/CHAP、IPv6CP、DHCPv6-PD、keepalive/redial、disconnect 和 tunnel map 写入。生产使用前仍应在目标运营商/AC 上跑真实断线重拨、IPv4/IPv6/PD、长流稳定性和目标拓扑吞吐验收。
- `packet_observer`（lab）：TC pipeline 观测示例，需要执行 `build.sh` 生成 eBPF object。
- `router_wizard`（lab）：组合 PPPoE/WAN/LAN 资源的路由配置向导示例。

`release.sh` 和 `scripts/package-plugins.sh` 默认只把 stable 插件放入 `veer-plugins.tar.gz`。

## 验收边界

仓库保留可重复的代码测试、插件构建、manifest 校验和 PPPoE namespace 黑盒脚本；依赖具体运营商、测试机或测速环境的长稳与性能脚本仍按本地环境维护，不进入默认源码树。

- 常规代码测试使用 `go test ./...` 和 `node --test internal/app/web_test/*.test.js`。
- 插件发布前使用 `scripts/verify-plugin-manifests.sh` 和 `scripts/package-plugins.sh` 校验 slim manifest、control hash、runtime 注册和打包结果。
- 涉及 netns、TC/XDP、PPPoE AC、吞吐和断线重拨的测试必须在目标 Linux/运营商环境单独验收，避免把一次性测试机脚本固化到项目入口。

## 编写建议

- manifest 保持薄，只声明身份、入口和权限。
- 资源设计先区分用户配置和派生状态，派生状态对 HTTP/UI 只读。
- 需要编排核心能力时，优先生成声明式资源：`forward_rule_plans` 对应端口转发规则，`egress_nat_plans` 对应 Egress NAT，`dhcpv4_plans` 对应现有 LAN 接口上的 DHCPv4 服务，`ipv6_assignment_plans` 对应路由、网关地址、RA 与 DHCPv6；不要直接写全局配置表。
- UI 永远通过 `VeerPluginHost` 访问资源和动作，不假设能拿到 Web Token。
- 慢任务、重试、拨号状态机放 worker 或 timer，不阻塞主控制 VM。
- 热路径能力只放 eBPF object 和 map，配置更新通过控制面批量写 map，避免包路径查询 SQLite 或 HTTP。
- 默认发布包不包含 `lab` 插件。手动部署 lab 插件前必须审查 manifest 权限，并用插件启用状态控制其控制面；进入 TC 数据面还必须显式开启 `plugins_dataplane_enabled`。
