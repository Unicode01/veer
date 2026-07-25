# Veer 插件开发指南

仓库的 `plugins/` 目录存放随项目维护的运行时插件。Veer 默认关闭外部插件；手动设置 `plugins_enabled=true` 后扫描 `plugins/<plugin_id>/`，每个插件使用独立子目录。

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
  "compatibility": {
    "runtime": ">=1.0.0 <2.0.0",
    "control_api_abi": 1
  },
  "control": {
    "main": "control.js",
    "permissions": ["plugin.register", "resource", "ui"]
  }
}
```

manifest 只承载静态契约：身份、入口、权限、兼容范围、依赖和冲突。资源、动作、Hook、object、逻辑接口和页面仍由 `control.js` 注册。插件 `version` 必须是完整 SemVer；`compatibility.runtime`、`compatibility.kernel` 和依赖版本使用 SemVer 约束。

需要其他插件时显式声明依赖：

```json
{
  "compatibility": {
    "runtime": ">=1.0.0 <2.0.0",
    "control_api_abi": 1,
    "tc_pipeline_abi": 2,
    "os": ["linux"],
    "architectures": ["amd64", "arm64"],
    "kernel": ">=5.10.0",
    "features": ["dataplane.tc_pipeline.v2"]
  },
  "dependencies": [
    {"id": "wan_core", "version": ">=1.2.0 <2.0.0"},
    {"id": "optional_helper", "version": "^2.0.0", "optional": true}
  ],
  "conflicts": [
    {"id": "legacy_wan", "version": "<1.0.0"}
  ]
}
```

Veer 在执行 Goja 或加载 eBPF 前检查宿主 runtime、控制 API ABI、TC pipeline ABI、操作系统、架构、内核、feature、依赖版本、禁用状态、冲突和循环依赖。必需依赖按拓扑顺序注册和 reconcile，并按反向顺序 deactivate；可选依赖缺失不会阻止插件。运行时可通过 `plugin.host()` 查询 `runtime_version`、`control_api_abi`、`tc_pipeline_abi`、`os`、`arch`、`kernel_release`、`core_priority`、`features`、`available_features` 和 `feature_status`。`features` 是当前 Veer 二进制实现的稳定 API 集合；`available_features` 才表示当前内核、权限和系统能力实际可用，`feature_status[name].reason` 给出不可用原因。manifest 仍必须声明硬依赖，不能用运行时分支替代。隔离、资源 schema、资源事务、宿主网络租约和批量网络事务分别使用 `control.process_isolation.v1`、`control.resource_schema.v1`、`control.resource_transactions.v1`、`control.net_leases.v1`、`control.net_transactions.v1` feature 标识。

`plugin.host().resource_limits` 返回当前宿主实际采用的插件预算。宿主在加载 object 前按 program/map 数、指令数、map 类型、`max_entries` 和 possible CPU 数估算内核内存，并同时限制单 map、单插件与全局 map 占用；不受管理的 pinned map、Arena 和 StructOps map 会被拒绝。动态注册的 capability、resource、action、Hook、object 和逻辑接口也有数量上限。SQLite 写入在同一事务内检查单插件与全局字节预算，schema migration 超额会整体回滚。Linux 隔离进程共享插件级 cgroup，并受父级全局内存/PID 预算约束。配置项集中在 `plugins_resource_limits`，catalog 的 `resource_usage` 会显示已准入的估算 map 内存、数据库实际占用及超限告警。

包 stage 会根据注册后的完整 surface 自动补充宿主要求：TC Hook 要求真实 `dataplane.tc_pipeline.v2`，XDP Hook 要求 `dataplane.xdp_pipeline.v1`，`state_maps` 要求 `ebpf.map_state.v1`，`net.admin/net.l2/net.tcp/net.udp` 权限分别触发 netlink、AF_PACKET 或 socket preflight，`net.namespace/net.tuntap` 还会检查 Linux namespace 与 `/dev/net/tun` provider，`net.*` 事件订阅会检查 link/address/neighbor/route netlink subscription。TC 探测复用 verifier/clsact 检测，XDP 探测检查 program type、prog-array 和接口枚举能力，bounded map read 还会检查 ring-buffer map；不满足时包在目录切换前被拒绝，而不是安装后才报错。

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
  page_title: "My Plugin",
  resources: [{resource: "profiles", methods: ["list", "get", "create", "update"]}],
  actions: ["apply"]
});

exports.onReconcile = function (ctx) {
  // 根据 resources/KV/secret 更新系统状态或 eBPF map。
};
```

顶层注册阶段只允许声明类 API，例如 `plugin.*`、`pipeline.*`、`ebpf.loadObject`、`hooks.attach`、`ui.register`。`kv`、`resources`、`secret`、`blob`、`timer`、`worker`、`net.*` 和 `ebpf.mapPut/mapDelete/mapClear` 这类有副作用的 API 只能在 handler 阶段使用。

控制脚本可用相对 CommonJS `require()` 拆分模块，不需要在 manifest 枚举文件：

```js
const session = require('./lib/session');
const codec = require('./lib/codec.js');
```

只接受相对 `.js` 路径，并支持省略扩展名和目录 `index.js`；bare package、JSON、绝对路径、反斜杠和越出插件根目录的路径都会被拒绝。每个持久主 VM/Worker 独立缓存模块并支持 CommonJS 循环依赖，最多加载 128 个模块、单模块 256 KiB、总计 8 MiB。隔离 Host 不读取文件系统，`require()` 由父进程从当前已应用插件快照按需代理源码；模块变化会进入目录 fingerprint，只有显式应用更新才替换 VM。对应 feature 为 `control.modules.v1`。

逻辑节点建议使用更明确的入口：

- `pipeline.node({id, description})`：声明纯 veer 逻辑链节点，不创建 Linux 接口。
- `pipeline.handoff({id, type, description})`：声明系统接入适配器，通常对应 bridge、veth、tun 或本机路由管理。
- `pipeline.attach({direction, attach, priority, program, interfaces})`：声明 eBPF 程序应进入哪条 veer 逻辑链和 TC ingress/egress 挂载点；Veer 根据 core priority 自动编排 core 前后和 tail-call slot。
- `plugin.pipelineNode()`、`plugin.handoff()`、`plugin.virtualInterface()` 和 `hooks.attach()` 仍可用，但只作为兼容/低层入口。

## 控制面生命周期

`control.main` 运行在 Goja 控制面，不进入 TC/XDP 热路径。每个插件默认有一个持久 Goja VM，`control.js` 顶层只在初始化或脚本变化后执行一次，顶层变量会在 handler 调用之间保留。默认的 `plugins_isolation=true` 会让主 VM 和每个命名 Worker 分别运行在持久子进程中；Veer 主进程只通过有界 IPC 调用它们，并继续作为数据库、Secret、netlink、socket 和 eBPF capability 的唯一 broker。

### 进程隔离与故障边界

外部插件仍由 `plugins_enabled` 总开关显式启用。启用后，隔离宿主不会获得 Web Token、SQLite 句柄、netlink socket、eBPF map FD 或宿主网络 socket；JavaScript 只能调用 manifest 已授权且 SDK contract 中存在的 API。IPC 使用长度前缀 JSON，限制单帧大小、64 层 JSON 深度、单事件 4096 次 host call 和 20 秒执行时间。JSON 数字在隔离边界两侧保持 JavaScript `number` 语义；需要精确表达超过 `Number.MAX_SAFE_INTEGER` 的协议计数或标识时应使用十进制字符串。插件脚本死循环、协议破坏、子进程崩溃或 OOM 只会终止对应 VM，不会自动重放失败事件，后续事件按 250 ms 到 30 s 的指数退避重建 VM。

Linux 子进程设置 `no_new_privs` 及 core/FD rlimit，并在 root 服务下清空补充组后降到 UID/GID 65534。线程/进程数量由每插件 cgroup `pids.max` 隔离；不能使用 `RLIMIT_NPROC`，因为 Linux 按真实 UID 汇总该限制，而所有隔离 Host 共用专用低权限 UID，会让互不相关的插件争抢同一额度。Goja 执行循环固定在完成文件系统限制的 OS 线程上：优先用 Landlock 拒绝插件 Host 直接读取或改写宿主文件系统；内核没有 Landlock 时，父进程会创建 root 所有、只读且为空的私有目录，子进程在降权前 chroot 到该目录。chroot 后不继承宿主目录 FD，降权与 seccomp 又阻止重新 chroot、挂载或切换 namespace，因此两种路径都只允许经父进程 capability broker 访问文件、网络、netlink 和 eBPF。seccomp deny-list 使用 TSYNC 阻止 Host 直接创建网络 socket、执行程序、加载 eBPF 或调用内核管理接口。

每个插件的所有 VM 共享 cgroup v2 上限：512 MiB 内存、64 个进程和 2 个 CPU 配额；另有每进程 224 MiB RSS 兜底监控。Veer 会只增不减地把 `memory/pids/cpu` controller 委派到自己的 cgroup 子树，适配默认未启用 subtree controller 的 OpenWrt；无法获得所需 controller 时仍拒绝 full sandbox。`plugins_min_sandbox_level` 默认是 `full`；缺少 UID/GID 隔离、Landlock/空 chroot 文件系统隔离、seccomp TSYNC 或硬资源限制时，父子进程会在执行插件 JavaScript 前拒绝启动。旧内核或开发环境可显式降为 `partial`、`minimal` 或 `none`，实际降级原因仍显示在 `runtime.isolation.sandbox_level/sandbox_degraded`。Windows 只有 Job Object 和 `partial` 等级，必须显式降低策略后才能运行控制插件。

`plugins_isolation=false` 只用于受信任的本地调试。它会恢复进程内 Goja VM，插件脚本缺陷可直接消耗主进程资源，因此生产环境不应关闭。关闭整个插件系统时不会创建 plugin-host，也不会给 TC/XDP 每包路径增加分支或 IPC。

资源事务、插件包安装和 VM 热升级提供宿主可控制范围内的原子提交与失败回滚。普通 handler 内的 netlink 修改、eBPF map 写入、socket 写入、L2/UDP 发送和跨插件动作不能形成跨内核与外部对端的全局事务；插件必须使用幂等 reconcile、明确的 ownership 和补偿清理。普通 JavaScript 错误允许 `finally` 中提交修复 timer，超时、OOM 或协议退出则丢弃该未完成事件的 timer journal。

Veer 每 2 秒检查插件源目录内容指纹。插件增删或 `plugin.json`、`control.js`、UI、eBPF object 变化只会设置 `update_available`，不会自动执行候选代码或重建数据面；WebUI 的“应用更新”或 `POST /api/plugins/reload` 会复制一份稳定候选快照，完成 manifest、control、UI 和 object 校验后再 reconcile。校验或运行时切换失败会保留上一份已应用快照。常规文件使用受限 SHA256 内容 hash，超大文件只纳入路径、大小和 mtime 等元数据。

启动时同样先创建私有已应用快照；快照失败会保持外部控制面和数据面插件关闭，并在 catalog 中报告错误，绝不退回可变源目录直接执行。Goja 主脚本在 VM 创建前还会复核 catalog 记录的已应用 SHA256，避免初始化与执行之间的文件替换绕过手动更新门禁。

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

`ctx.upgrade` 包含 `protocol_version`、`phase`、`scope`、`worker_name`、`from_version`、`to_version`、`state`、`timers` 和 `sockets`。每个 snapshot 必须是 JSON 可序列化值且不超过 256 KiB。snapshot/restore 阶段只允许普通 JavaScript 状态处理和 `log.*`；KV、resource、blob、timer、worker、network、注册 API 与 eBPF map API 均被禁止，避免候选失败后留下外部副作用。

实现 restore 后，宿主持有的 timer 会保持原 generation 和触发时间，socket 句柄会在候选仍声明相同 `net.tcp`/`net.udp` 权限及 `net_access` 时转移，现有命名 worker 也会按 `scope: "worker"` 独立迁移。普通 reconcile 会继续持有未变化 object 的现有私有 map；object 字节变化时，只有旧、新版本都声明相同 `state_maps policy=preserve`、`schema_version` 相同且 map spec 兼容的 map 才会复用原 FD。禁用、删除、显式 `reset` 或不兼容 schema 不会静默继承状态。VM snapshot 与 dataplane map 状态是两套独立契约，不能互相替代。

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

### 类型和单元测试宿主

编辑 `control.js` 时可以引用 [sdk/plugin/control.d.ts](sdk/plugin/control.d.ts) 获得 Goja 全局 API、context、resource 和 pipeline 类型：

```js
/// <reference path="../../sdk/plugin/control.d.ts" />
```

不依赖运行中的 Veer 即可用 [sdk/plugin/test-host.cjs](sdk/plugin/test-host.cjs) 执行持久主 VM、独立 worker VM、resource/KV/secret/blob、timer 和 event 单元测试：

```js
const { createTestHost } = require('../../sdk/plugin/test-host.cjs');

const host = createTestHost({
  pluginDir: __dirname,
  fixtures: { resources: { profiles: { default: { data: { enabled: true } } } } },
  adapters: {
    'net.link.get': (name) => ({ name, up: true, kind: 'dummy' })
  }
});

host.reconcile();
console.log(host.snapshot());
```

发布前使用运行时自带 conformance 命令。`test` 会执行目标环境兼容检查、两次独立 Goja 注册并比较 surface digest，再完成一次确定性打包/解包回读；stable 控制插件必须显式声明当前 `control_api_abi`，stable 数据面插件还必须声明 `tc_pipeline_abi`。

```text
veer plugin test --source ./plugins/my_plugin --os linux --architecture arm64 --kernel 6.6.0
veer plugin contract --check ./sdk/plugin/api-contract.json
veer plugin contract --output ./api-contract.json
veer plugin contract --types-output ./methods.d.ts
```

`GET /api/plugin-sdk-contract` 返回运行中二进制生成的同一份权威契约。契约摘要按 canonical JSON 计算；控制方法、feature、资源限制或 pipeline ABI 发生漂移时，仓库契约测试和 `contract --check` 都会失败。contract v6 的 `control.capabilities` 为每个 Host 方法声明必需/任一/条件权限、可调用阶段、主 VM/Worker 范围以及隔离 IPC 请求和响应上限；`operations` 公开持久 operation 的状态和配额，`control_methods` 作为简单工具兼容列表保留，并由同一注册表生成。

### 兼容与 ABI 演进

- `api_version` 定义 manifest 格式；`compatibility.runtime` 定义 Veer 插件运行时的 SemVer 范围；`control_api_abi` 和 `tc_pipeline_abi` 分别定义 Goja Host API 语义及 TC map/context/tail-call 契约。它们不是同一个版本号，不能互相替代。
- 当前稳定契约为 runtime `1.0.0`、control API ABI `1`、TC pipeline ABI `2`。stable 控制插件必须声明当前 control ABI；带 object 或 Hook 的 stable 插件还必须声明当前 TC ABI。未声明 ABI 的 lab/preview 插件不获得跨版本兼容保证。
- 同一 ABI 内只允许增加可选方法、feature、字段和提高上限；删除方法、改变参数/返回语义、收紧既有配额，或改变共享 eBPF map、context、返回动作和 tail-call 布局都必须提升对应 ABI。
- 插件必须按 feature 探测可选能力，并忽略返回对象中的未知字段。宿主不会把缺失的内核、权限或系统工具能力伪装成可用。
- ABI 提升前必须保留旧 contract fixture 和 conformance 测试，明确兼容窗口或提升 runtime major；不能只修改 `api-contract.json` 让漂移测试通过。Control ABI 1 和 TC ABI 2 的历史边界固定在 `sdk/plugin/fixtures/`，方法改名/删除或 TC slot/map/context 漂移会直接失败。`sdk/plugin/api-contract.json`、`control.d.ts`、生成的 `methods.d.ts`、`webui.d.ts` 和 `veer_plugin_helpers.h` 必须随同一提交更新；公开 TypeScript 声明不允许使用 `any` 掩盖宿主契约。

特权 API 默认抛错，必须逐项提供 adapter；测试宿主不会把 netlink、raw L2、socket 或 eBPF 操作伪装成成功。它用于控制逻辑单测，不能替代 `veer plugin pack` 的真实 Goja/manifest 校验，也不能替代 Linux netns 和目标运营商环境验收。

## 资源、动作和持久化

插件 UI 和控制脚本都应通过注册资源表达持久化配置。资源数据存 SQLite，按 canonical JSON 比较，字段顺序不构成变更。

不适合 JSON 的证书链、协议缓存或其他二进制大对象使用独立 `blob` 权限。Blob 位于私有 `plugins.veer-state/blobs/<plugin>/`，单文件使用带长度和 SHA-256 的版本化头，提交前写入同文件系统临时区并 `fsync + atomic replace`；正式文件会进入 `veer plugin backup/restore`，未提交 upload 不进入备份。默认每对象 64 MiB、每插件 1024 个/256 MiB、全局 2 GiB，可由 `plugins_resource_limits` 收紧。

小于等于 1 MiB 的数据可直接原子写入：

```js
blob.put({key: "peer-cache", payload_hex: "010203"});
var chunk = blob.read({key: "peer-cache", offset: 0, max_bytes: 65536});
blob.verify({key: "peer-cache"});
```

较大数据使用 `begin -> write -> commit`，每个 write 必须给出连续 offset，单块最大 1 MiB；可在 begin 声明 `expected_bytes` 和 `sha256`，commit 不匹配时不会替换旧对象。另有 `abort/stat/list/delete`。每插件最多 8 个、全局最多 64 个在途 upload，临时字节也受独立配额；禁用、冷替换、进程退出和 generation 切换会中止未提交 upload，已提交 Blob 保留。Blob 以 `0600` 明文存储，不应用来替代会自动加密和脱敏的 `secret` API。该能力对应 `control.blobs.v1`。

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

Action 可以分别声明请求和响应的 Draft 2020-12 JSON Schema：

```js
plugin.action({
  id: "lookup",
  runtime_update: "runtime_query",
  request_schema_version: 1,
  request_schema: {
    type: "object",
    required: ["key"],
    properties: {key: {type: "string"}},
    additionalProperties: false
  },
  response_schema_version: 1,
  response_schema: {
    type: "object",
    required: ["status"],
    properties: {status: {type: "string"}}
  }
});
```

宿主会规范化 Schema 并返回对应 `*_schema_digest`。HTTP、直接 runtime 调用和 `plugins.actions.call()` 都在执行 handler 前校验请求；`runtime_query` 返回后再校验响应。同一 Schema 版本的摘要不可变化，更新契约必须提升对应 `request_schema_version` 或 `response_schema_version`。未声明 Schema 时版本仍默认为 `1`，只执行 JSON 和大小校验。

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

跨插件 action 调用走目标 action 自己的 `runtime_update`、Schema 和 `max_payload_bytes` 限制；self-call 会被拒绝，避免同一个 Goja VM 死锁。

多个实现提供同一种能力时，使用 typed service，避免消费者把端点集合写死在自己的控制逻辑里。提供方在注册阶段把已经声明的 action/resource 组成带 SemVer 的服务：

```js
plugin.service({
  id: "wan.adapter",
  version: "1.0.0",
  actions: ["apply_session", "teardown"],
  resources: ["sessions", "status"]
});
```

消费者使用 `plugins.services.list()` 查看已授权提供方，或用 `resolve()` 要求唯一匹配；存在多个匹配项时必须显式指定 `provider`。调用仍受 manifest 的 `plugin.action`、`action_access`、`plugin.resource` 和 `resource_access` 双重授权，不会因为服务发现扩大权限：

```js
var wan = plugins.services.resolve({
  service: "wan.adapter",
  version: "^1.0.0",
  provider: "wan_core"
});

return plugins.services.call({
  service: wan.service.id,
  version: "^1.0.0",
  provider: wan.plugin_id,
  action: "apply_session",
  payload: {wan_id: "default", usable: true}
});
```

发现结果只包含调用方实际获权的 action/resource 及其 Schema 契约。禁用、错误或未加载的提供方不会参与解析；同步调用复用跨插件循环检测。服务版本不得倒退，同 major 不能删除端点，端点契约变化必须提升服务版本，删除整个服务则必须提升插件 major。对应宿主 feature 为 `control.typed_services.v1`。

### 持久 operation 与崩溃恢复

需要编排多个插件或多次内核操作时，manifest 声明 `operation` 权限和 `control.durable_operations.v1` feature。operation API 只允许主 VM 调用；主 VM 的事件串行执行，`revision` CAS 会拒绝旧状态覆盖新进度。`input/state/result/error` 在 SQLite 中整段使用插件 Secret keyring 做 AEAD 加密，备份、恢复、密钥轮换和卸载 purge 都包含 operation 状态。

```js
function applyRouter(config) {
  var op = operations.begin({
    key: "router_default",
    kind: "router.apply",
    input: {config: config},
    state: {step: 0},
    restart: true
  });
  if (!op.resumable) return op.result;

  op = operations.claim(op.id, op.revision);
  if (op.state.step < 1) {
    plugins.services.call({
      service: "wan.adapter",
      version: "^1.0.0",
      provider: "wan_core",
      action: "apply_session",
      payload: op.input.config.wan
    });
    op = operations.checkpoint(op.id, op.revision, {
      phase: "wan_ready",
      state: {step: 1}
    });
  }
  return operations.complete(op.id, op.revision, {status: "applied"});
}

exports.onReconcile = function () {
  operations.list({resumable: true, limit: 32}).forEach(function (op) {
    if (op.kind === "router.apply") applyRouter(op.input.config);
  });
};
```

状态为 `pending`、`running`，或到达 `next_attempt_unix_ms` 的 `retry_wait` 时，`resumable=true`。`claim()` 增加 attempt 并返回新 revision；`checkpoint()` 持久化阶段和状态；`complete()`、`fail()`、`cancel()` 进入终态；`retry()` 设置下一次重试；`remove()` 只删除终态记录；`stats()` 返回数量和加密存储占用。默认每插件最多 1024 条、每字段 256 KiB、总计 64 MiB。

该契约提供 **at-least-once** 重放，不承诺跨 SQLite、netlink、eBPF map、远端协议对端的 exactly-once。进程可能在外部动作成功、checkpoint 落库前退出，因此每一步必须使用幂等 ensure/replace/action；不能幂等的步骤必须记录可验证 identity，并提供反向补偿。Router Wizard 使用相同机制恢复 `WAN -> PPPoE -> LAN` 编排。

## 事件与插件协作

`events.subscribe()` 在注册阶段声明订阅，事件由独立持久 worker VM 异步处理。每个订阅有独立有界队列；队列满时发布方不会阻塞，容量丢弃进入 `dropped`。`events.publish()` 只能发布 `plugin.<本插件 ID>.*`，返回 `{matched,enqueued,persisted,deferred,dropped,rejected}`，其中 `rejected` 表示版本或 Schema 不兼容且事件未进入队列，`enqueued` 和 `persisted` 都不表示 handler 已执行完成。

订阅其他插件的自定义事件必须同时声明 `event`、`worker`、`plugin.event` 和最小 topic 前缀白名单：

```json
{
  "control": {
    "permissions": ["event", "worker", "plugin.event"],
    "event_access": [
      {
        "plugin": "pppoe_client",
        "topic_prefixes": ["plugin.pppoe_client.session"]
      }
    ]
  }
}
```

```js
events.subscribe({
  id: "pppoe_sessions",
  topic: "plugin.pppoe_client.session",
  match: "prefix",
  worker: "events",
  handler: "onPPPoESession",
  queue_size: 64,
  schema_version: 1,
  schema: {
    type: "object",
    required: ["status"],
    properties: {status: {type: "string"}}
  }
});

exports.onPPPoESession = function (ctx) {
  log.info(ctx.event.source_plugin, ctx.event.topic, ctx.event.payload);
};
```

默认 `delivery="volatile"` 只使用内存队列，适合状态通知和可重新计算的事件。需要进程重启后继续投递时声明 `delivery="durable"`，并可设置 `max_attempts=1..16` 与 `retry_delay_ms=100..60000`；默认最多 8 次、初始退避 500 ms。durable 事件会先原子写入 SQLite，再由订阅 worker 按顺序领取；handler 成功后删除，失败后指数退避，达到上限后转为 dead letter。每插件最多保留 2048 条、全局最多 16384 条 durable delivery，配额满时本次发布计入 `dropped`，不会阻塞发布方或挤掉已有记录。

插件只能通过 `events.deadLetters()` 查看自己的死信，通过 `events.retry(deliveryId)` 把 dead 状态恢复为 pending，或通过 `events.discard(deliveryId)` 明确丢弃；不能删除仍在等待投递的 pending 事件。管理员可在插件管理页统一筛选、重试和确认丢弃所有插件死信，也可使用 `/api/plugin-event-dead-letters` 系列接口。重试复用原 `delivery_id`、payload 和幂等上下文，不会重新发布或生成第二条事件；handler 仍应使用 `ctx.event.delivery_id` 实现下游幂等。所有管理员变更都会写入插件审计日志。

运行时同时校验 topic 命名空间和真实发布来源，不能通过伪造 `plugin.<其他插件>.*` 绕过授权。系统事件包括 `net.link`、`net.addr`、`net.neigh`、`net.route`、`resource.changed` 和 `plugin.lifecycle`。网络事件要求 `net.admin` 以及对应接口的 `net_access: link.read`；多路径路由只有在全部相关接口均获授权且接口解析完整时才会投递。

## WebUI 和插件通信

插件 UI 通过 `ui.register()` 暴露入口：

```js
ui.register({
  static_dir: "ui",
  entry: "index.html",
  page: "observe",
  page_title: "Observe",
  resources: [{resource: "bindings", methods: ["list", "create", "delete"]}],
  actions: ["apply"],
  resource_access: [{plugin: "wan_core", resource: "status", methods: ["list"]}]
});
```

`resources` 和 `actions` 是 iframe 页面可调用的本插件最小权限；省略即拒绝对应 RPC。声明必须是已注册 resource/action 的子集。`resource_access` 只允许跨插件 `list/get`，并且还必须是 manifest `control.resource_access` 的子集。该契约对应 `ui.capabilities.v1`。

发布方用第三个参数携带契约版本：

```js
events.publish("plugin.pppoe_client.session.changed", {status: "up"}, {schema_version: 1});
```

订阅 Schema 会生成 `schema_digest`。同一订阅 ID 在同一 `schema_version` 下不能静默改变 Schema；版本不匹配或 payload 校验失败会在入队前拒绝，Worker 投递前还会防御性复核。未声明 Schema 的订阅默认版本为 `1`。

WebUI 通信链路如下：

1. 主 WebUI 调用 `GET /api/plugins` 获取插件 catalog，其中包含 `ui.entry`、`ui.page`、`ui.page_title` 和 `asset_base_path`。
2. 用户打开插件 UI 或切到插件分页时，宿主 WebUI 用自己的 Bearer Token 拉取 `/api/plugins/<id>/assets/<entry>`。
3. 宿主把插件 HTML 注入基础样式、强制 CSP 和 `window.VeerPluginHost` bridge，再通过只含 `allow-scripts` 的 sandbox iframe `srcdoc` 加载。
4. 插件页面不能拿到 Web Token；读写本插件数据时调用 `VeerPluginHost.data.*` 或 `VeerPluginHost.action()`。
5. `VeerPluginHost` 在 iframe 内用 `postMessage` 发出 `veer-plugin-rpc`。
6. 父页面校验消息来源必须是已登记的插件 iframe，并校验 `pluginId` 匹配。
7. 父页面用宿主 token 调用真实 API，例如 `/api/plugins/<id>/resources/<resource>` 或 `/api/plugins/<id>/actions/<action>`。
8. API 返回后，父页面再用 `postMessage` 回传 `veer-plugin-rpc-result`。

插件 iframe 默认禁止网络连接、远程图片/字体/媒体、子 frame、Worker、表单提交、弹窗、顶层导航和 referrer，并且没有 `allow-same-origin`。页面需要访问网络时应调用插件 action，由隔离 Goja 控制面在 manifest 声明的 `net_access` 范围内完成；不要从浏览器绕过 capability broker。静态资源不能依赖第三方 CDN；多文件页面通过父页面代取同插件目录内的受控资源，iframe 本身仍保持 `connect-src 'none'`。

`VeerPluginHost.assets` 提供 `text/json/style/script/dataURL`。路径必须是同一 `ui.static_dir` 下不含空段或 `..` 的相对路径；父页面携带自己的 Token 请求资源，校验 MIME 和大小后才通过 RPC 返回。文本、JSON、CSS 和 JavaScript 单文件最多 1 MiB，图片 Data URL 最多 4 MiB。`style()` 和 `script()` 会把校验后的内容以内联节点加入当前 sandbox 文档：

```html
<script>
Promise.all([
  VeerPluginHost.assets.style("assets/plugin.css"),
  VeerPluginHost.assets.script("assets/plugin.js")
]).catch(VeerPluginHost.toastError);
</script>
```

每个 iframe 最多同时发出 32 个 RPC，请求 payload 最大 2 MiB、总待处理 payload 最大 4 MiB，并有独立短时速率限制。父页面会再次执行相同准入检查，因此插件不能通过自行构造 `postMessage` 绕过限制。对应 feature 为 `ui.assets.v1`。
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

插件 UI 使用 TypeScript 或 `// @ts-check` 时可引用 `sdk/plugin/webui.d.ts`，其中包含 `window.VeerPluginHost`、RPC 错误、record picker 和 collection editor 类型。

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
- `VeerPluginHost.assets.text/json/style/script/dataURL`
- `VeerPluginHost.action(action, payload)`
- `VeerPluginHost.toast(message)`
- `VeerPluginHost.toastError(error)`
- `VeerPluginHost.errorText(error)`
- `VeerPluginHost.requestResize()`

跨插件 UI 读取只开放 `list/get`，并同时检查 `ui.register().resource_access` 与调用方 manifest 的 `control.resource_access` 白名单。iframe 不能借此访问未授权插件资源，也不开放跨插件写入；编排写操作仍通过 Goja `plugins.resources` / `plugins.actions` 完成。

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

同时启用 `plugins_enabled=true` 和 `plugins_dataplane_enabled=true` 后，使用 `pipeline.attach()` 注册 TC `direction=forward` 或 `direction=reply` 的可信插件可以进入内置 `veer` pipeline。没有实际插件链时，不会给热路径增加额外 lookup。

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
  context: ["tc_plugin_ctx_v4", "tc_plugin_ctx_v6"]
});

pipeline.attach({
  id: "firewall-after-decap",
  direction: "forward",
  priority: 200,
  after: ["pppoe_client/pppoe-ingress"],
  before: ["packet_observer/capture"],
  program: "firewall:tc_filter",
  mode: "drop"
});
```

当前 TC pipeline 已覆盖：

- `pre_forward`：core 查规则前，适合 PPPoE/VXLAN decap、早期 drop、包头预处理。
- `post_lookup`：core 找到规则后、真正执行 forward rewrite 前，适合读取按地址族隔离的 `tc_plugin_ctx_v4/tc_plugin_ctx_v6` 做观测或轻量标记。
- `post_apply`：forward rewrite、校验和更新完成后且最终 redirect 前，适合依赖已改写 L3/L4 的封装或审计；通过 `phase: "after_apply"` 注册。
- `pre_reply`：reply flow lookup 前，适合 reply 方向预处理。
- `post_reply`：reply flow lookup 后、reply rewrite 前，适合读取 flow context 或做回包预处理。
- `post_reply_apply`：reply rewrite、校验和更新完成后且最终 redirect 前，适合 PPPoE/VXLAN 回包封装；通过 `direction: "reply", phase: "after_apply"` 注册。
- `attach=ingress|egress`：同一逻辑 chain 可分别绑定到真实接口的 TC ingress 或 egress，并使用独立接口作用域。

ABI v2 的共享 prog-array 固定为 111 slots。每个具体 stage 最多 8 个 Hook，forward 和 reply 每个方向跨三个 stage 合计最多 14 个 Hook，以保留 eBPF tail-call 深度余量。超限会在注册/reconcile 阶段拒绝，不会截断链。

PPPoE 路径出站使用 `local0 -> pipeline peer TC ingress -> PPPoE stage -> physical WAN`，入站使用 `physical WAN TC ingress -> PPPoE stage -> local0 ingress`。`local0` 与内部 pipeline peer 组成由 `wan_core` 管理的 veth 边界；pipeline peer 只承担数据面换向，不应作为用户可选 WAN 接口。

动态 PPPoE 地址、对端地址和路由由 `wan_core` 发布到这个本地边界，并在重拨时替换；`vtolocal` 只用于静态本地边界，不应同时管理同一个 PPPoE 接口的动态地址。

内置 `Veer Core` priority 固定为 `1000`：

- `priority < 1000`：core 前插件。
- `priority > 1000`：core 后插件。
- `priority == 1000`：拒绝，避免和 core 抢同一排序点。

同一 concrete stage 内可用 `before/after` 声明全限定 `plugin_id/hook_id` 约束。显式约束优先于默认 priority；未参与约束的 Hook 仍按 priority、插件 ID、Hook ID 稳定排序。引用缺失、跨 stage 引用、自引用或环会让相关插件本轮进入 error 并从链中移除，依赖该插件的排序约束随后也会失败；无关插件继续运行。排序只在 reconcile 时拓扑计算，实际每包链仍是相同的 prog-array tail call，不增加热路径 map lookup。对应 feature 为 `dataplane.hook_order.v1`。

### Packet metadata ABI v1

同一包上的 TC Hook 可通过 `packet_metadata` 交换固定上限的小型结构，不必修改包或增加控制面往返：

```js
pipeline.attach({
  id: "classify",
  direction: "forward",
  priority: 100,
  program: "classifier:tc_classify",
  packet_metadata: [{
    slot: 0,
    namespace: "classifier/result",
    schema_version: 1,
    max_bytes: 16,
    access: "read_write"
  }]
});
```

- `namespace` 使用 `owner_plugin/name`。只有 owner 可声明 `read_write`；消费者声明 `read`，并且版本和长度必须与 owner 完全一致。
- `slot` 是 object 内的本地 binding slot，范围 `0..15`；宿主在 reconcile 时把最多 32 个 namespace 映射到隔离的全局 slot。引用缺失、越权写入、schema 冲突或同一 object 的本地 slot 冲突会只剔除相关插件。
- object 调用 `VEER_DECLARE_PACKET_METADATA()` 声明宿主管理的 binding map 和四张共享双栈 map。写入使用 `veer_packet_metadata_write_begin_for_skb()` 后填写 `payload`，最后调用 `veer_packet_metadata_commit()`；读取使用 `veer_packet_metadata_read_for_skb()` 并检查 `payload_len`。
- 每个地址族使用独立 per-CPU generation。未在当前包写入的数据不会从上一个包泄漏；热更新后的 namespace 重排也不会复用旧包内容。
- 只有当前接口实际命中 metadata Hook 时，core 才增加一次 generation map lookup。未声明 metadata 的插件链和插件关闭路径不承担该开销。

packet metadata 的 namespace 防止可信插件之间误用 ABI，不是恶意 eBPF 的安全沙箱；允许进入数据面的 object 本身仍可改包、丢包或直接访问其声明的共享 map。跨插件顺序应同时用 `before/after` 明确声明。对应 feature 为 `dataplane.packet_metadata.v1`。

`hooks.attach()` 仍支持显式 `pre_forward/post_lookup/post_apply/pre_reply/post_reply/post_reply_apply`，用于底层测试或精确指定 concrete stage；新插件应优先用 `pipeline.attach()`。

没有 Veer/Egress NAT 规则时，显式声明了 `interfaces` 的 hook 仍可把 TC pipeline 挂到目标接口上；这时 Veer Core 的 forward/reply 路径会被关闭，pipeline 只执行插件链。core 后插件仍可运行，但 `tc_plugin_ctx_v4/tc_plugin_ctx_v6` 是按当前包地址族清空的上下文，不包含规则或 flow 匹配结果。

进入 `veer` pipeline 的 TC object 必须声明共享 `tc_prog_chain_v4` prog-array map，处理后应 tail-call 回对应 stage 的 continue slot，除非插件明确要返回最终 TC action。eBPF tail call 是 continuation，不是普通函数调用；tail-call 成功后不会回到插件原来的栈帧。core 后插件如果要读取规则匹配上下文，需要同时声明共享 `tc_plugin_ctx_v4` 和 `tc_plugin_ctx_v6` map；只有内置 core 实际启用并匹配规则或回包 flow 时，对应地址族上下文才会带有 `have_rule` 或 `have_flow`。新插件应 include 当前版本的 `plugins/include/veer_plugin_helpers.h` 并随 ABI 版本重新编译 object，以保持共享 prog-array 规格一致，同时复用 slot、continue helper、skb 写入/校验和/redirect 包装以及 IPv4/IPv6/L4 解析 helper。

生产环境只应加载可信 eBPF object。服务会校验路径、大小、sha256、program type 和 section，但不能证明第三方程序一定不会改包或丢包。

stable/preview 插件注册 object 或 UI 入口时必须声明 sha256。包含 `variants` 时，fallback 和每一个架构 artifact 都必须存在并分别声明正确 SHA256；stage/lint 会逐项检查路径、大小、hash、ELF、program section/type 和 state map，而不是只验证当前宿主架构。跨架构 eBPF object 可能产生不同 hash，推荐在 `control.js` 注册阶段使用 `crypto.sha256File()` 对每个产物分别取值，再交给加载器复核。

需要跨 object 版本保留连接表或隧道状态时，必须在 `ebpf.loadObject()` 中声明私有 map 状态契约：

```js
ebpf.loadObject({
  id: "dataplane",
  path: "dataplane.o",
  state_maps: [
    {name: "sessions", policy: "preserve", schema_version: 1}
  ]
});
```

相同 object 定义的普通 reconcile 会继续持有现有 map。object 内容变化时，只有旧、新版本都声明 `preserve`、`schema_version` 相同且内核 map spec 兼容的 Hash/Array、per-CPU、LRU 或 LPM Trie 私有 map 才会复用原 FD；复用在新程序装入和双 bank 切链前完成，不复制条目，也不会产生半迁移状态。已声明保留的 map 被移除、改版本或变得不兼容时，候选更新失败并保留旧链。确实需要丢弃旧状态时，新版本必须显式声明 `{name: "sessions", policy: "reset"}`；该变更会进入包 runtime surface/权限摘要，不能静默发生。prog-array、ring buffer、map-of-maps 和 socket/device 引用类 map 不允许声明 `preserve`。

map schema 变化使用显式、可回滚的双 map 迁移，不能在旧 map 仍被数据面并发写入时做一次不受协调的原地复制：

```js
ebpf.loadObject({
  id: "dataplane",
  path: "dataplane.o",
  state_maps: [
    {name: "sessions_v1", policy: "preserve", schema_version: 1},
    {name: "sessions_v2", policy: "migrate", schema_version: 2, migrate_from: "sessions_v1"}
  ]
});

exports.onEBPFStateMigrate = function (ctx) {
  var migration = ctx.ebpf_migration;
  var page = ebpf.mapScan(migration.object_id, migration.source_map, {
    cursor: migration.cursor,
    limit: migration.max_entries,
    max_bytes: migration.max_bytes
  });
  if (page.entries.length) {
    ebpf.mapTransaction({operations: page.entries.map(function (entry) {
      return {
        op: "put",
        object: migration.object_id,
        map: migration.target_map,
        key: entry.key,
        value: convertSessionV1ToV2(entry.value)
      };
    })});
  }
  return {done: page.done, cursor: page.cursor, processed: page.entries.length};
};
```

新 object 必须在整个候选观察期保留旧 map，读取新 map 未命中时回退旧 map，并对新增、更新和删除同时写入两个 schema。宿主无法从 verifier 证明第三方 object 正确实现了双写，因此该约束仍属于可信数据面插件契约。迁移 handler 每次只处理一批，返回值必须包含 `done/cursor/processed`；未完成批次必须推进非空十六进制 cursor 并报告 `1..256` 条处理记录。宿主最多执行 65536 批、总计 5 分钟，每次调用仍受 20 秒 handler 限制。迁移阶段只开放 `ebpf.map_read`、`ebpf.map_write`、日志和 `plugin.host()`，不能修改 KV、资源、网络或 timer。

任何批次、后置资源 replay 或资源事务提交失败时，迁移保持 pending，候选更新返回失败并允许热更新事务恢复旧 catalog、旧链和仍被双写维护的 source map；目标 `migrate` map 只有在回滚版本继续以相同 schema `preserve` source map 时才允许丢弃。迁移版本稳定后，下一版本把新 map 改为 `preserve`、旧 map 改为 `reset`；再后一个版本才能删除旧 map 定义。对应 feature 为 `ebpf.map_migration.v1`。

## XDP 数据面插件

XDP 插件使用 `engine: "xdp"`，只能注册 `pre_forward` 或 `priority < 1000` 的 `forward` Hook，并且必须声明显式 ingress 接口。XDP 没有 egress Hook，也不能读取 `tc_plugin_ctx_v4/tc_plugin_ctx_v6`；需要 core 查表结果、reply 方向或改写后的包时应使用 TC stage。

XDP 插件 object 必须声明 24-entry 的共享 `xdp_prog_chain`，处理后调用 `veer_xdp_continue(ctx)` 进入下一 Hook。链结束返回 `XDP_PASS`，随后继续进入现有 TC/系统路径。单条 XDP 链最多 8 个 Hook，按 priority、插件 ID、Hook ID 稳定排序；更新使用双 bank 原子切换。

Veer 使用独立最小 Dispatcher，不改写实验性的 Forward XDP NAT object。只要 catalog 中存在可运行的 TC/XDP 插件 Hook，核心转发规则就固定走 TC，避免 XDP Core 绕过插件链；XDP 插件仍可在相同 ingress 上先于 TC 执行。目标接口已有任何 XDP 程序时会报告冲突，Veer 不替换、不接管；driver 模式不可用时，只有显式开启 `xdp_generic` 才尝试 generic 模式。

没有 XDP Hook、插件被禁用或插件系统关闭时，Dispatcher 会从接口完全卸载，不给无插件热路径增加 lookup。接口删除后，同名接口重建会按新 ifindex 重新挂载；崩溃恢复同时核对原进程 start-time 和 XDP program ID，绝不根据旧 ifindex 盲目删除其他程序。对象内容更新可继承兼容的 `state_maps`；Hook、模式、优先级或接口范围变化失败时不会隐形保留旧链。

同一个 eBPF object 不能同时承载 TC 和 XDP Hook。跨引擎插件应拆成两个 object，使私有 map 的 ownership 和 Goja map API 目标保持唯一；需要同步配置时由控制面使用 map transaction 分别更新。

`dataplane.xdp_pipeline.v1` 表示宿主具备 XDP program、prog-array 和接口枚举基础能力。它不保证每块网卡支持 native XDP，最终 attach mode 和冲突仍以运行时 attachment 状态为准。

## 网络管理权限

`net.admin`、`net.l2`、`net.tcp`、`net.udp`、`net.http`、`net.dns` 和 `net.tuntap` 是两段式授权：既要在 `control.permissions` 声明总权限，也要在 `control.net_access` 声明可操作接口模式和操作。命名 namespace 内的操作还必须声明 `net.namespace` 和 `control.namespace_access`；其中 `host` 表示初始 namespace，命名 namespace 支持显式名称或 `*` 通配模式。`net.udp` 提供 `send`、`recv`、`exchange`，Linux 下会按声明接口尝试绑定设备，适合控制面探测、协商和轻量 L4 管理流量；`net.tcp` 用于下文的宿主持久 socket。数据面隧道仍应放在 TC/eBPF。

每条 `net_access` 可用 `remote_hosts`、`remote_cidrs` 和 `remote_ports` 进一步收窄 `http`、`dns`、`tcp` 或 `udp` 的远端。三个字段都省略时保持“不限制远端”的兼容语义；只要填写某一字段，请求就必须同时满足该字段。域名支持精确值、`*` 或仅位于最左侧的 `*.example.com`，CIDR 同时支持 IPv4/IPv6，端口为 `1..65535`。原始 TCP/UDP API 只接受 IP，因此不能用 `remote_hosts` 授权。宿主会在连接前、重定向、UDP 回包、TCP accept 和 socket 热更新时重新检查 endpoint；无法解析的远端地址按拒绝处理。

`net.http.request()` 提供受限 HTTP/HTTPS 客户端，支持绑定接口、namespace、源地址、请求头、有限请求体、同源重定向、TLS 1.2+、私有 CA 和双向 TLS。它不读取系统代理，也不允许覆盖 `Host` 等保留头。自定义 `resolver_ip` 时，插件除 `net.http + operations:["http"]` 外，还必须持有 `net.dns + operations:["dns"]`，resolver endpoint 也必须通过 DNS 的 `remote_cidrs/remote_ports` 范围。目标 URL 与 resolver 是两次独立授权，不能用 HTTP 权限间接访问任意 DNS 服务。

`net.dns.lookup()` 支持 `A/AAAA/IP/TXT/MX/SRV/CNAME/PTR`，可选择 UDP/TCP resolver、接口、namespace、源地址和超时。DNS 返回数量和总大小受宿主限制；HTTP/DNS 都由父进程 broker 建立 socket，隔离 Goja 进程不会获得网络 FD。对应 feature 为 `control.http_client.v1` 和 `control.dns_client.v1`。

```json
{
  "control": {
    "permissions": ["net.http", "net.dns"],
    "net_access": [
      {
        "interfaces": ["wan0"],
        "operations": ["http"],
        "remote_hosts": ["api.example.com"],
        "remote_cidrs": ["192.0.2.0/24"],
        "remote_ports": [443]
      },
      {
        "interfaces": ["wan0"],
        "operations": ["dns"],
        "remote_cidrs": ["192.0.2.53/32"],
        "remote_ports": [53]
      }
    ]
  }
}
```

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

### 受控 network namespace 与 TUN/TAP

插件不能直接调用 `setns`、打开 `/dev/net/tun` 或获得设备 FD。父进程 broker 提供 `net.namespace.get/list/ensure/delete/release/owned` 与 `net.tuntap.ensure/close/read/write/list/owned`；只有插件创建且持有 ownership 的 namespace 可以删除，使用白名单内已有 namespace 不会自动取得所有权。`net.link/addr/route/rule/neigh` 请求以及 `net.l2/udp/socket` 请求都可带 `namespace`；Socket 和 Raw L2 FD 在目标 namespace 内创建，之后由宿主持有。批量路由、规则或邻居事务的所有成员必须位于同一 namespace，避免伪装成跨 namespace 原子提交。

命名 namespace、TUN/TAP 和其中的网络修改按 namespace identity 写入租约。禁用、卸载和崩溃恢复会先恢复命名空间内的邻居、规则、路由、地址和链路，再关闭设备并删除插件自建 namespace；同名 namespace 被替换时只清理 ledger，不会触碰替换后的网络对象。该作用域能力对应 `control.netns_scoped.v1`。

```json
{
  "control": {
    "permissions": ["net.namespace", "net.tuntap"],
    "namespace_access": ["veer-*"],
    "net_access": [
      {"interfaces": ["tun*", "tap*"], "operations": ["tuntap"]}
    ]
  },
  "compatibility": {
    "features": ["control.netns_provider.v1", "control.netns_scoped.v1", "control.tuntap_provider.v1"]
  }
}
```

```js
var ns = net.namespace.ensure({name: "veer-lab", loopback_up: true});
var device = net.tuntap.ensure({name: "tun0", namespace: ns.name, mode: "tun", mtu: 1400, up: true});
var packet = net.tuntap.read({name: "tun0", namespace: ns.name, max_bytes: 65535, timeout_ms: 1000});
if (!packet.timed_out) net.tuntap.write({name: "tun0", namespace: ns.name, data: packet.data});
net.route.replace({namespace: ns.name, dst: "192.0.2.0/24", dev: "tun0", table: 100});
```

`read/write` 每次只处理一个最大 65535 字节的包，读取最长等待 15 秒，适合协议协商、诊断和低频控制流量。它经过 Goja IPC，不应用作 VPN、PPPoE 或隧道的逐包转发路径；生产数据面应由 TC/eBPF object 处理，Goja 只维护状态机和 map。宿主保留 FD，并用内部唤醒通道保证插件禁用不会等待长轮询超时。

插件创建的 bridge/veth/dummy/macvlan，以及对已有接口 master、up/down、MTU、ARP、promiscuous、offload、GSO、地址和路由的修改都会写入宿主资源租约。租约按属性互斥，记录首次修改前的值和 Linux boot ID；插件禁用、卸载或加载失败时按依赖顺序恢复，同名接口 identity 已变化或系统已跨 boot 时只丢弃旧租约，不会修改新设备。插件主动把属性、地址或自己新增的路由恢复到原值时租约自动释放。`net.lease.list()` 可读取本插件当前租约；`net.lease.restore(type, key)` 会恢复并释放指定租约，失败时保留记录供重试。`net.link.delete()` 只允许删除本插件通过 ensure API 创建并持有的 link，不能凭接口白名单删除宿主或其他插件的设备。

需要同时切换多条路由、策略规则或静态邻居时，使用 `net.route.transaction()`、`net.rule.transaction()` 或 `net.neigh.transaction()`。每批最多 128 项；运行时先完成全部参数、权限、接口、租约冲突和内核快照预检，再按顺序应用，任一项失败会逆序恢复已经应用的项及 ownership ledger。事务只发生在控制面，不给 TC 热路径增加指令。示例：

```js
net.route.transaction([
  {op: "replace", request: {namespace: "veer-router", dst: "0.0.0.0/0", gateway: "192.0.2.1", dev: "wan0", table: 100}},
  {op: "delete", request: {namespace: "veer-router", dst: "198.51.100.0/24", dev: "wan0", table: 100}}
]);
```

ECMP/多拨选路使用同一 API 的 `nexthops` 字段；运行时会校验每个出口接口的 `route.write` 权限，并把全部下一跳 ifindex 写入恢复租约：

```js
net.route.replace({
  dst: "0.0.0.0/0",
  table: 100,
  metric: 10,
  nexthops: [
    {dev: "wan0", gateway: "192.0.2.1", weight: 1},
    {dev: "wan1", gateway: "198.51.100.1", weight: 2, onlink: true}
  ]
});
```

每条 route 支持 1 至 64 个下一跳，`weight` 范围是 1 至 256。`nexthops` 不能与顶层 `dev/gateway` 混用；MPLS、任意 encap/via 和原始 flags 不向插件开放。路由事务 journal 会保存并恢复原始 multipath 与内核 flags。需要该能力的插件应声明 `compatibility.features=["control.net_multipath.v1"]`。

声明 `ebpf.map_read` 后，`ebpf.mapGet(object, map, keyHex)` 返回普通 map value 的十六进制字符串；`ebpf.mapGetPerCPU(object, map, keyHex)` 返回按 possible CPU 排列的十六进制 value 数组，已经去掉每 CPU 的 8 字节对齐 padding。`ebpf.mapScan(object, map, options)` 以最后一条 key 的十六进制值作为游标，单次最多读取 256 条、1 MiB；它是并发更新下的 best-effort 快照，per-CPU map 仍应按已知 key 使用 `mapGetPerCPU`。插件可按自己的 value ABI 聚合这些值，适合无原子竞争的包数和字节数统计。

持续消费 ring buffer 时，优先在注册阶段使用 `ebpf.ringSubscribe()` 把有限批次主动投递到持久 worker：

```js
ebpf.ringSubscribe({
  id: "kernel_events",
  object: "dataplane",
  map: "events",
  worker: "event_reader",
  handler: "onKernelEvents",
  queue_size: 16,
  max_records: 64,
  max_bytes: 65536,
  poll_timeout_ms: 500
});

exports.onKernelEvents = function (ctx) {
  for (var i = 0; i < ctx.payload.records.length; i++) {
    handleEventHex(ctx.payload.records[i].data);
  }
};
```

订阅要求同时声明 `ebpf.load`、`ebpf.map_read` 和 `worker`。宿主 reader 与 worker 队列解耦；慢 handler 不会阻塞 eBPF 数据面或 reader，但队列满、插件累计 pending payload 达到 16 MiB 时会丢弃新批次。`ebpf.ringStats()` 返回读取、投递、丢弃、handler 错误和 pending byte 统计。一个 object/map 只能有一个 push 消费者，启用订阅后不能再对同一 map 调用 `ringRead`。dataplane 重算会先停止旧 reader，object 挂载完成后再订阅当前 map FD。该能力对应 `ebpf.ring_push.v1`。

按需诊断仍可使用 pull-based `ebpf.ringRead(object, map, options)`。单次最多读取 256 条、1 MiB，等待最长 15 秒；无数据时返回 `timed_out=true`，达到记录或字节边界时返回 `limit_reached=true`。读取应放在命名 worker 中，每次处理有限批次后返回，再通过 timer 或下一次 dispatch 继续，避免阻塞主控制 VM：

```js
exports.readKernelEvents = function () {
  var batch = ebpf.ringRead("dataplane", "events", {
    max_records: 64,
    max_bytes: 262144,
    timeout_ms: 1000
  });
  for (var i = 0; i < batch.records.length; i++) {
    handleEventHex(batch.records[i].data);
  }
  return {records: batch.records.length, pending: batch.remaining};
};
```

宿主每次 pull 读取都会克隆当前 map FD；数据面热替换时，当前批次最多停留到本次 timeout，下一批会自动读取新 object。pull 接口不创建后台 goroutine，push 和 pull 都不会把 eBPF map FD 暴露给隔离子进程。需要这些接口的插件可在 `compatibility.features` 分别声明 `ebpf.ring_push.v1` 或 `ebpf.bounded_reads.v1`。

控制面需要一次更新多项 eBPF 配置时使用 `ebpf.mapTransaction()`。每次最多 256 个 `put/delete`、总 key/value 不超过 1 MiB；宿主先解析并快照全部槽位，在同一 runtime 锁内应用，失败时逆序恢复。可选的 `commit` 必须是 `put`，始终最后执行：插件应先把配置写入非活动 generation，再用 `commit` 更新 selector，包路径只读取 selector 指向的 generation，才能获得原子可见性。直接批量修改正在读取的活动 map 只有错误回滚，不具备包级原子可见性。

```js
ebpf.mapTransaction({
  operations: [
    {op: "put", object: "dataplane", map: "config", key: "01000000", value: "0100000000000000"},
    {op: "put", object: "dataplane", map: "config", key: "02000000", value: "0100000000000000"}
  ],
  commit: {object: "dataplane", map: "config_generation", key: "00000000", value: "01000000"}
});
```

该能力对应 `ebpf.map_transactions.v1`。事务只支持普通 Hash/Array/LRU/LPM raw-value map，不支持 per-CPU、prog-array、map-in-map、socket/device 引用或 ring buffer；这些类型需要专用 ABI。

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

`mac` 必须是非零单播地址。清理前应记录并校验 `created=true`，只删除插件自己创建的接口。`net.link.getOffloads()` 和 `net.link.setOffloads()` 依赖系统 `ethtool`；一键部署会安装该依赖，裁剪系统需要自行提供。需要这两个 API 的插件应声明 `control.net_offloads.v1`，宿主会在启用前检查工具是否存在。`net.link.setGSO(iface, {max_size: mtu, max_segs: 1})` 只设置设备 GSO 上限，不能保证 TC egress 在执行前已完成分段；不支持 GSO 的封装器还必须在 ingress 侧限制 GRO/GSO，或使用显式分段边界。

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

可用方法为 `open`、`listen`、`accept`、`read`、`write`、`status`、`list`、`close`、`watch`、`unwatch` 和 `watchList`。UDP `listen` 返回 datagram 句柄，`read` 会返回 `remote_ip`/`remote_port`，回复时将其传给 `write`。

需要长期收包或提供 TCP/UDP 服务时，使用事件驱动 watcher，避免 worker 定时轮询：

```js
net.socket.watch({
  handle: peer.handle,
  worker: "bgp",
  handler: "onBGPSocket",
  max_bytes: 65536
});

exports.onBGPSocket = function (ctx) {
  if (ctx.socket.type === "data") {
    consumeBGPBytes(ctx.socket.payload_hex);
  } else if (ctx.socket.type === "accept") {
    net.socket.watch({handle: ctx.socket.accepted.handle, worker: "bgp", handler: "onBGPSocket"});
  }
};
```

watcher 由父进程阻塞读取，并把 `data/accept/eof/error` 事件按单 socket 顺序同步交给指定持久 worker；主控制 VM 不会被占用。handler 返回前不会继续读取同一 socket，因此 TCP 会自然向内核施加背压，不会把无限数据排进 JavaScript 队列；不同 socket 共享同一 worker 时仍按该 worker 串行执行。UDP 无法向发送方施加背压，内核接收缓冲区满时仍可能丢包。来源不满足 `remote_cidrs/remote_ports` 时只丢弃该 datagram 或 accepted child，不会让未授权报文关闭监听口。

被 watch 的句柄不能再手工 `read/accept`，但可继续 `write/status/close`；先调用 `unwatch` 才能恢复拉取模式。事务式热升级会在 upgrade gate 排空在途事件后连同 watcher、worker/handler 名称和 socket 句柄一起转移；候选失去 `worker`、socket 或 endpoint 权限时拒绝切换。该能力对应 `control.socket_events.v1`。

socket 生命周期不受单次 handler 结束影响，但一次拨号、手工读写或 accept 最长 15 秒，单次事件 handler 仍限制为 20 秒。watch handler 应处理一批数据后立即返回，不要使用永久 `while` 循环。

## 随仓库维护的插件

- `wan_core`（stable）：消费标准化 WAN session；direct 模式管理本地 L3 dummy，`segmented_veth` 模式管理 local/pipeline veth 边界。
- `lan_core`（stable）：管理 LAN bridge，并生成 Egress NAT、DHCPv4 和 IPv6 assignment plan。
- `vtolocal`（stable）：创建静态本地 L3 dummy，并管理该接口上的地址与路由。
- `pppoe_client`（stable）：Goja + raw L2 PPPoE 控制面和双向 TC 隧道插件。插件目录内保留控制面自测和 Linux 黑盒脚本，覆盖 discovery、PAP/CHAP、IPv6CP、DHCPv6-PD、keepalive/redial、disconnect 和 tunnel map 写入。生产使用前仍应在目标运营商/AC 上跑真实断线重拨、IPv4/IPv6/PD、长流稳定性和目标拓扑吞吐验收。
- `packet_observer`（lab）：TC pipeline 观测示例，需要执行 `build.sh` 生成 eBPF object。
- `router_wizard`（lab）：组合 PPPoE/WAN/LAN 资源的路由配置向导示例。

`release.sh` 和 `scripts/package-plugins.sh` 默认只把 stable 插件放入 `veer-plugins.tar.gz`。

`bootstrap.sh` 默认只构建和安装 Veer 核心，不执行 bundled 插件构建；`deploy.sh` 默认也不会解压或覆盖插件目录。设置 `VEER_INSTALL_PLUGINS=1` 才会构建并安装 bundled 插件；该开关不启用插件运行时，插件控制面和 TC 数据面仍分别由 `plugins_enabled`、`plugins_dataplane_enabled` 控制。直接运行 `release.sh` 时仍默认生成插件包，可用 `VEER_BUILD_PLUGIN_BUNDLE=0` 只构建核心发布物。

## 插件包发布

正式发布同时提供独立的 `veer-plugin-sdk.tar.gz`。归档保留 `sdk/plugin/`、`plugins/include/veer_plugin_helpers.h`、本指南和许可证，并带逐文件 SHA256 的 `sdk-manifest.json`；第三方插件不需要克隆 Veer 主仓库即可获得 TypeScript 契约、测试宿主、ABI fixture、eBPF helper 和 CI 模板。`scripts/package-plugin-sdk.sh` 使用固定成员顺序、时间戳和权限生成确定性归档，发布门禁会生成两次比较字节，并从归档初始化、构建、验收和打包一个 pipeline 插件。

Veer 可执行文件内置与服务端安装器共用格式和安全边界的打包工具：

```text
veer plugin pack --source ./plugins/my_plugin --output ./dist/my_plugin-1.0.0.tar.gz
veer plugin keygen --private-key ./publisher.key --public-key ./publisher.pub
veer plugin sign --archive ./dist/my_plugin-1.0.0.tar.gz --private-key ./publisher.key
veer plugin verify --package ./dist/my_plugin-1.0.0.veerpkg --public-key ./publisher.pub
veer plugin backup --database ./forward.db --plugins-dir ./plugins --output ./plugin-state.tar.gz
veer plugin restore --archive ./plugin-state.tar.gz --database ./forward.db --plugins-dir ./plugins
```

`pack` 会执行 manifest、control hash、Goja 注册、路径、文件类型、条目数和大小校验，并生成确定性 `tar.gz`。`sign` 使用 Ed25519 对带 Veer v2 domain 的 archive SHA256 签名，默认输出同名 `.veerpkg`；该单文件容器只包含不可变的 `package.tar.gz` 和 `signature.json`，可直接发布或上传，不再生成独立 `.sig`。安装端会限制容器成员、数量、压缩方式和大小，再校验 payload 摘要、签名及发布者密钥指纹；外置签名和旧 sidecar 请求头不再接受。`verify` 要求显式提供预期公钥，用于确认包内公钥就是操作者信任的那一把；签名有效本身不等于已建立长期信任。未签名的本地 `.tar.gz` 仍可预检，但受 `plugins_require_signed_packages` 策略约束。

`plugins_require_signed_packages=true` 是默认包准入策略。此时 `approve_unsigned` 不能覆盖签名要求，但签名有效的首次发布者不需要预先进入 trust store：WebUI 会显示密钥指纹、权限和风险，管理员确认后即可只安装当前候选。需要调试本地未签名包时必须显式关闭该策略；未签名确认和权限扩张摘要仍分别生效。

信任键可以限制 `plugin_ids`（精确 ID 或尾部 `*` 前缀）、`permissions`、`execution_tiers`（`control/dataplane`）和 `stabilities`；`permissions_restricted=true` 允许把空权限列表明确锁定为零权限。有效签名位于范围内时显示为已信任；超出范围时仍可人工批准当前候选，但不会隐式扩大原范围。安装审核中的“记住发布者”会按当前候选自动生成最小范围，同一批次由同一密钥签署的包会合并各自最小范围。密钥轮换默认继承范围，显式新范围只能收窄；需要扩大长期授权时应单独审核，而不是借轮换隐式升级。

私钥由 `keygen` 以 PKCS#8 PEM 和 `0600` 权限创建。生产发布应离线保存私钥，并通过独立渠道公布公钥指纹供用户核对。用户可以在首次安装审核中选择只批准当前包，或记住该发布者对此插件的后续更新；两种路径都会重新执行完整候选校验、依赖检查和权限差异审批。

需要维护可更新插件源时使用内置 TUF 仓库工具：

```text
veer plugin repository init --directory ./private-repository
veer plugin repository add --directory ./private-repository --archive ./dist/my_plugin-1.0.0.tar.gz --channel stable
veer plugin repository publish --directory ./private-repository
veer plugin repository revoke --directory ./private-repository --plugin my_plugin --version 1.0.0 --channel stable --reason "security advisory"
veer plugin repository rotate-key --directory ./private-repository --role root
veer plugin repository status --directory ./private-repository
```

私有仓库的 target 已由 TUF 元数据签名，因此 `repository add` 继续接收 `pack` 生成的原始 `.tar.gz`；`.veerpkg` 用于不经过 TUF 仓库的单文件签名分发。

客户端为每个已安装插件提供独立仓库策略：仓库 ID、`stable/preview` channel、可选精确 SemVer pin 和 hold。pin 会同时约束直接安装和依赖求解；hold 会保留当前已安装版本，即使它只是其他插件的依赖也不能被替换。策略不会自动执行升级，WebUI 只生成经过完整依赖求解和权限复核的候选 stage。`plugins_enabled=true` 时，宿主按 `plugins_repository_refresh_minutes`（默认 360 分钟）在独立后台循环刷新 TUF 元数据和撤销状态；插件关闭时不启动该循环，刷新永远不会下载或运行 target。

workspace 是 `0700` 私有发布目录，包含 Ed25519 私钥、不可变包缓存、版本状态和恢复 journal；只有其中的 `public/` 是静态 TUF 输出。不同用户运行的 nginx 无法穿透该私有父目录，生产部署应在持有 workspace 的发布进程完成 `publish` 后，把完整 `public/` 原子同步到独立 Web 根目录，不能放宽私钥目录权限或逐文件覆盖在线仓库。`add/revoke/publish/rotate-key/status` 使用跨进程独占锁；publish 和 key rotation 在进程中断后会按持久 journal 幂等恢复。

同一插件、版本和 channel 的 archive digest 不可替换，撤销也不可取消。root 轮换由旧、新 root 双签；targets/snapshot/timestamp 轮换通过新 root 授权。客户端必须以 `public/metadata/root.json` 的原始 JSON 作为初始 trust root，并分别配置以 `/metadata/`、`/targets/` 结尾的 HTTPS URL。仓库撤销只阻止后续 stage/apply 并显示来源告警，不会自动卸载正在承担网络功能的插件。

插件包安装、应用、回滚、卸载、信任密钥变更、Secret keyring 轮换、插件启停和代码热加载除了 `Authorization: Bearer <web_token>`，还要求 `X-Veer-Plugin-Admin: <plugin_admin_token>`。两个 token 必须不同；`plugin_admin_token` 为空时这些高权限 API 禁用，读取 catalog、历史、日志和审计不受影响。WebUI 只把插件管理员 token 保存在当前标签页的 `sessionStorage`。

trust store 不物理删除发布者记录。撤销后状态变为 `revoked`，该密钥签署的新包会在审核中显示高风险且不能从安装流程重新建立长期信任，但插件管理员仍可明确批准当前候选；添加新公钥时可设置 `replaces`，持久 rotation journal 会先确保新键存在，再把旧键写成 `revoked/replaced_by`，断电后启动恢复会幂等完成。

`backup` 使用 SQLite `VACUUM INTO` 创建一致性快照，并把数据库、Secret keyring、插件目录和 `plugins.veer-state` 写入带逐文件 SHA256 的有界归档。`restore` 只验证并暂存恢复请求，不在线替换运行中的数据库；服务下次启动会在打开 SQLite 前按 journal 切换四类状态，失败时恢复旧状态。用 `veer plugin restore --status|--retry|--cancel` 管理待处理请求。

包管理默认最多安装 128 个插件、保留 32 个 stage，插件目录与包状态合计上限 2048 MiB；可用 `plugins_max_installed`、`plugins_max_staged`、`plugins_storage_limit_mb` 调整。达到存储上限时先删除最旧的可淘汰历史，每个插件最新历史和 probation/批量恢复引用的历史不会被删除。

成功应用的候选会进入 10 分钟版本观察期。插件运行时关闭或插件本身禁用时观察期保持 pending，实际启用后才开始计时；同一候选的隔离宿主重启达到 3 次，或控制 handler 连续触发超时、OOM、协议破坏等内部致命熔断时，Veer 自动回滚到本次替换留下的历史版本。首次单包安装没有历史版本时只自动禁用插件，不删除插件目录和资源。正常关机会写入 clean marker，只有连续 3 次未写 marker 的服务启动才触发启动安全恢复；PPPoE 认证失败、线路超时、接口消失等外部错误不参与该判断。状态可在插件管理概览或 `GET /api/plugin-packages/probations` 查看。

批量应用会创建持久原子观察组。任一成员触发内部致命故障时，更新成员从受校验 history 恢复，新安装成员从 catalog 移除，所有目录、resource schema migration 和 runtime 只提交一次；中途失败会恢复完整候选组并按 1、2、4、8 分钟退避。组通过或恢复前不能单独替换、回滚或卸载成员，以保证恢复依据不会被覆盖。组成员和恢复状态可通过 `GET /api/plugin-packages/probation-groups` 查看。

需要同时升级依赖者与被依赖者时，在 WebUI 一次选择最多 16 个包，或分别用 `POST /api/plugin-packages/stage?defer_relationships=true` 预检后提交 `/api/plugin-packages/apply-batch`。延迟关系校验不会跳过签名、权限、代码 surface 或宿主能力校验；最终版本图在目录切换前统一解析。批量 journal、候选和备份位于 `plugins.veer-state/batches`，整批只触发一次 runtime reconcile，失败或重启不会保留部分新版本。

## 验收边界

`scripts/verify-plugin-release.sh` 是插件 v1 的权威发布门禁，分层执行，不能用普通 `go test ./...` 的环境性 skip 代替特权验收：

- `portable`：在 Linux CI 重建 core/插件 eBPF，并执行全部 Go、Race、WebUI、SDK、TypeScript contract、manifest/package round-trip、`govulncheck` 和七个短时 fuzz target；非 Linux 本地运行只校验已有插件 object，不能替代 Linux CI。GitHub Actions 对 `main`、`dev` 和 PR 强制执行这一层。
- `privileged`：在 root Linux 上执行真实 netns、TUN/TAP、netlink ownership/crash recovery、隔离进程/cgroup/OOM、WAN/LAN/vtolocal、IPv6 plan、Egress NAT、完整双向 TC chain、XDP dispatcher、XDP-to-TC，以及 PPPoE IPv4/IPv6、手动重拨、自动重拨和 timer fence 黑盒；指定测试出现任何 skip 即失败。
- `stability`：至少 120 秒同时维持 64 条长连接中的 16 条活跃流，并持续创建 32 条一批的新连接；任一旧流中断、新流创建失败、TC runtime 失效或测试被 skip 都失败。目标运营商上的 PPPoE 仍需额外运行 24 至 48 小时，覆盖强制断线、重拨、IPv4、IPv6CP、DHCPv6-PD 和业务长流。
- `performance`：每个 TC profile 都与紧邻执行的独立 disabled baseline 配对，逐轮交替先后顺序并取至少三组配对比值中位数，避免共享宿主的分钟级漂移污染全局 baseline。插件开启但无 Hook 相对关闭插件吞吐不得低于 95%；单个 no-op、observer 或 firewall Hook 不得低于 90%；2/4/8 个 no-op Hook 不得低于 80%。XDP Dispatcher 零 Hook 相对 plain pass 额外成本不得高于 30 ns，每个 no-op Hook 的增量不得高于 75 ns。阈值可为明确记录的目标硬件基线收紧，不能在发布时临时放宽。

发布候选在特权 Linux 上执行 `sh scripts/verify-plugin-release.sh all`。脚本会主动检查 root、工具、关键 PASS 记录和所有 skip，并在结束后清理测试产物；目标运营商 PPPoE 长测结果单独进入发布记录，不伪装成可在 namespace 内证明的项目测试。

## 编写建议

- manifest 保持薄，只声明身份、入口和权限。
- 资源设计先区分用户配置和派生状态，派生状态对 HTTP/UI 只读。
- 需要编排核心能力时，优先生成声明式资源：`forward_rule_plans` 对应端口转发规则，`egress_nat_plans` 对应 Egress NAT，`dhcpv4_plans` 对应现有 LAN 接口上的 DHCPv4 服务，`ipv6_assignment_plans` 对应路由、网关地址、RA 与 DHCPv6；不要直接写全局配置表。
- UI 永远通过 `VeerPluginHost` 访问资源和动作，不假设能拿到 Web Token。
- 慢任务、重试、拨号状态机放 worker 或 timer，不阻塞主控制 VM。
- 热路径能力只放 eBPF object 和 map，配置更新通过控制面批量写 map，避免包路径查询 SQLite 或 HTTP。
- 默认发布包不包含 `lab` 插件。手动部署 lab 插件前必须审查 manifest 权限，并显式开启全局 `plugins_enabled`，再用插件级状态控制其控制面；进入 TC 数据面还必须显式开启 `plugins_dataplane_enabled`。
