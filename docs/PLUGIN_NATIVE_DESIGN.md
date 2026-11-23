# 原生插件系统设计（插件系统 v2）

状态：已实现（第 0–4 阶段，2026-11-22）。随仓库维护的插件全部改为 Rust 原生插件；goja 运行时、隔离插件宿主进程（`--plugin-host`）、模块加载器和 JS SDK 已删除，生产二进制不再链接 goja。宿主 API 绑定改用 `internal/hostvalue` 的值模型，原生插件与宿主测试用的 JS 插件经同一个 `callPluginHostMethod` 分发；JS 插件只在测试里由 goja 驱动（`plugin_control_script_test.go`）。开发者文档见 [PLUGIN.md](PLUGIN.md)。与本文的差异：

- 宿主测试仍用小型 JS 插件覆盖宿主 API（数百个用例），JS 引擎只编进测试二进制。
- SDK 契约文件（`sdk/plugin/api-contract.json`）保留为语言无关的方法目录，契约版本升到 19。
- `veer-plugin-test` 由 Rust SDK 的 `testing` feature（`FakeHost`、`Harness`）实现，不单独成包。
- 只是系统调用的宿主方法（宿主命名空间内的链路读取、`net.l2.*`、`net.udp.*`、`crypto.md5/randomBytes`）由 worker 在插件进程内执行（contract 的 `worker_methods`，与宿主实现逐项对照测试）；定时器、事件、网络变更、eBPF map、托管进程、`net.socket`、`net.http/dns` 仍由宿主执行，理由见 [PLUGIN.md](PLUGIN.md) 的“宿主 API 的调用方式”。

以下为原设计。

## 1. 背景

现在的插件是 JavaScript，跑在 goja 解释器里。每个插件的主 VM 和每个命名 worker 各占一个隔离的插件宿主进程（`veer --plugin-host`），宿主 API 都经 JSON RPC 回到主进程执行。2026-11-21 在 PVE 上实测（wan_core、vpn_core 两个插件）：

| 项目 | 数据 |
|---|---|
| 进程 | 主进程、keeper，加 4 个插件宿主进程（两个插件各一个主 VM、一个事件 worker） |
| 内存（PSS） | 约 129 MB；每个插件宿主进程独占 8–10 MB，另分摊 20 MB 共享的程序文件 |
| 宿主 API | 176 个方法、35 组，64 个能力标志，SDK 契约版本 17 |
| 插件代码 | 8 个插件约 1.3 万行 JS 控制代码、5300 行测试；WebUI 约 8200 行 |
| 宿主代码 | 插件相关 Go 约 6.8 万行，其中 goja、隔离宿主和控制层约 2.7 万行 |

成本集中在三处：解释执行（wan_core 一次完整应用约 10 ms，大部分是 JS 和 RPC）、每个 VM 一个进程、一整套 JS 沙箱契约（注册阶段、SDK 契约、测试宿主与真实宿主对齐、worker VM、热升级 snapshot/restore）。事件只能在 worker VM 里处理，再用定时器转回主 VM，是这套模型带来的复杂度之一。

## 2. 目标与非目标

目标：

1. 插件是 Linux 原生共享库（`.so`），通过一个 C ABI 与宿主交互。C、C++、Rust、Zig 直接实现；Go 经 cgo 实现（限制见 9.3 节）；Python 等经一个转接 `.so` 接入。
2. 进程模型：veer 宿主加插件 worker。稳定插件共用一个 worker，不确定是否可靠的插件放进独立 worker。托管外部程序的 keeper 保留。
3. 完全事件驱动：插件声明订阅的事件表，宿主在源头过滤后投递；插件内不轮询，定时器只用于真正的超时和退避。
4. 降低复杂度：插件的资源、动作、服务、页面、eBPF 对象、hook 和订阅全部在 manifest 里静态声明，去掉"注册阶段"；ABI 只有一个导出符号和一张宿主函数表。
5. WebUI 保留：插件页面、资源与动作的 HTTP API、页面里的宿主方法不变。
6. 插件逐步用 Rust/C++ 重写；ABI 不依赖宿主语言，宿主以后也可以换成 C++。

非目标：

- 不在进程内隔离原生代码。原生插件拥有所在 worker 进程的全部能力，隔离以 worker 为单位。
- 不支持热卸载 `.so`（`dlclose` 不可靠）。重新加载插件就是重启它所在的 worker。
- 插件只支持 Linux。

## 3. 进程模型

```text
veer 宿主 ──┬── unix socket ── veer-plugin-worker "shared"   wan_core lan_core pppoe_client firewall vtolocal ...
           ├── unix socket ── veer-plugin-worker "vpn_core" （独立 worker）
           └── keeper ── sing-box / mihomo / 插件托管的其它程序
```

| 进程 | 职责 |
|---|---|
| veer 宿主 | 配置、数据库（资源、KV、密钥、blob、网络租约和事务日志）、eBPF 对象的加载与挂载、hook 和 pipeline、事件源（netlink、进程、资源、数据面）、WebUI 和 API、权限检查、worker 监管 |
| 插件 worker | 一个小的原生运行时（建议 Rust 实现）：`dlopen` 插件、为每个插件实例提供宿主函数表、按实例串行投递消息、把宿主调用转发给 veer 宿主 |
| keeper | 托管进程在宿主热重启、worker 重启时都不断开。已实现为 worker 程序的另一种运行方式（argv[0] 为 `veer-process-keeper`，`sdk/native/worker/src/keeper.rs`），协议与原来的 Go keeper 相同 |

### 3.1 worker 分组

manifest 声明 `worker`：`shared`（默认组）、`dedicated`（独立进程）或一个组名（几个插件共用一个具名 worker）。宿主配置可以覆盖。默认策略：

- `stability: stable` 且签名有效的插件：`shared`。
- `lab` 或来源未知的插件：`dedicated`。
- Go 插件：强制 `dedicated`（9.3 节）。
- 自动降级：某个插件让共享 worker 崩溃或卡住（6.3 节），宿主重启 worker 时把它移到独立 worker，并在插件状态里标明原因，管理员确认后再放回。

### 3.2 worker 的权限

所有特权操作都经宿主执行（网络配置、eBPF、托管进程、密钥），worker 本身不需要 root 或任何 capability。独立 worker 还可以：单独的 cgroup（内存、CPU、pids 限额）、seccomp 白名单、不需要网络时放进空的网络命名空间。共享 worker 有一个共用的 cgroup。

### 3.3 预期内存

宿主约 47 MB（现在主进程的独占内存），共享 worker 估计 5–15 MB（Rust 运行时加几个插件），每个独立 worker 估计 3–8 MB，keeper 改成单独的小程序后估计 1–3 MB。PVE 现在的组合预计从约 129 MB 降到 60–75 MB。这些是估计值，第一阶段完成后实测。

## 4. 插件包

```text
plugins/wan_core/
  plugin.json             manifest（v2）
  lib/x86_64-linux-gnu/libwan_core.so
  lib/x86_64-linux-musl/libwan_core.so
  lib/aarch64-linux-gnu/libwan_core.so
  lib/aarch64-linux-musl/libwan_core.so
  wan_core.o              可选：eBPF 对象，宿主照旧加载
  ui/                     可选：页面静态文件，宿主照旧提供
```

- `.so` 按目标三元组分目录；worker 只加载和自己相同三元组的库。Veer 同时发布 glibc 和 musl 构建，插件也要两种都提供（或只声明支持其中一种）。
- manifest 记录每个库的 sha256；宿主校验后再让 worker 加载，库文件放在宿主所有、worker 只读的目录里。包签名沿用现有机制。

### 4.1 manifest v2

在现有 manifest 上增加静态声明，替代 `plugin.resource`、`plugin.action`、`plugin.service`、`ui.register`、`pipeline.*`、`hooks.attach`、`ebpf.loadObject`、`events.subscribe` 等注册调用：

```json
{
  "abi": 1,
  "id": "wan_core",
  "version": "2.0.0",
  "stability": "stable",
  "worker": "shared",
  "library": {"x86_64-linux-gnu": {"path": "lib/x86_64-linux-gnu/libwan_core.so", "sha256": "..."}},
  "permissions": ["net.admin", "resource", "timer", "ui"],
  "net_access": [{"interfaces": ["veer*"], "operations": ["link.create", "addr.write", "route.write", "rule.write", "neigh.write", "link.offload"]}],
  "resources": [{"id": "sessions", "methods": ["list", "get", "create", "update", "delete"], "runtime_update": "runtime_apply", "schema": "schemas/session.json"}],
  "actions": [{"id": "apply_session", "schema": "schemas/apply_session.json"}],
  "services": [{"id": "wan.adapter", "version": "1.0.0", "actions": ["apply_session", "prepare_handoff", "teardown"]}],
  "subscriptions": [
    {"topic": "net", "match": "prefix", "interfaces": ["veer*"], "neigh_states": ["permanent", "noarp"]},
    {"topic": "resource.changed", "resources": ["profiles"]}
  ],
  "ui": {"static_dir": "ui", "entry": "index.html", "page": "wan"},
  "objects": [],
  "hooks": []
}
```

eBPF 对象、TC/XDP hook、`tc_fallback`、`tc_egress`、`state_maps` 的字段和现在相同，只是从 JS 注册调用移到 manifest。

## 5. ABI 契约

### 5.1 原则

- 纯 C ABI。C++ 异常、Rust panic 不得越过边界，SDK 在边界上捕获并转成错误码。
- 只有一个导出符号 `veer_plugin_entry`。插件描述表和宿主函数表的第一个字段都是 `struct_size`：新增函数追加在末尾，次版本号加一，旧插件和新宿主互相可用；主版本号变化表示不兼容。
- 跨边界的数据：结构化内容用 UTF-8 JSON（资源记录、配置、动作请求本来就是 JSON，C 用 cJSON、Rust 用 serde、Python 用 json 即可）；二进制内容（eBPF map 键值、ring buffer 记录）放在单独的附件里，不做 hex/base64 转换。控制面调用频率低，JSON 编解码成本可以忽略；以后如果实测有瓶颈，再引入 CBOR 作为可选编码。
- 内存：输入由调用方持有，只在调用期间有效；输出写进调用方给的 `veer_buf`，由宿主函数 `buf_reserve` 分配，各自的分配器不交叉释放。

### 5.2 头文件草案

```c
/* sdk/native/include/veer_plugin.h */
#include <stddef.h>
#include <stdint.h>

#define VEER_PLUGIN_ABI_MAJOR 1
#define VEER_PLUGIN_ABI_MINOR 0

typedef struct veer_slice { const uint8_t *data; size_t len; } veer_slice;
typedef struct veer_buf { uint8_t *data; size_t len; size_t cap; } veer_buf;

typedef enum veer_msg_kind {
  VEER_MSG_RECONCILE = 1,      /* 按持久状态把一切恢复到期望状态 */
  VEER_MSG_DEACTIVATE = 2,     /* 插件被禁用、卸载：清理自己的资源 */
  VEER_MSG_EVENT = 3,          /* 订阅的事件；name 是 topic */
  VEER_MSG_TIMER = 4,          /* 插件设定的定时器；name 是定时器名 */
  VEER_MSG_ACTION = 5,         /* 动作请求；reply 是动作结果 */
  VEER_MSG_QUERY = 6,          /* 只读查询（status、inspect） */
  VEER_MSG_RESOURCE_APPLY = 7, /* runtime_update 资源的记录变化 */
  VEER_MSG_WAKE = 8,           /* 插件自己用 post 投递的消息 */
  VEER_MSG_SNAPSHOT = 9,       /* 可选：升级前导出内存状态 */
  VEER_MSG_RESTORE = 10        /* 可选：升级后导入内存状态 */
} veer_msg_kind;

typedef struct veer_msg {
  uint32_t struct_size;
  uint32_t kind;
  uint64_t sequence;
  veer_slice name;
  veer_slice payload;          /* JSON */
  veer_slice attachment;       /* 原始字节，可为空 */
} veer_msg;

typedef struct veer_host_v1 {
  uint32_t struct_size;
  uint16_t abi_major, abi_minor;
  void *ctx;
  /* 宿主 API：method 如 "net.route.replace"、"resources.set"、"timer.set"，request 是 JSON。 */
  int32_t (*call)(void *ctx, veer_slice method, veer_slice request, veer_slice attachment,
                  veer_buf *reply, veer_buf *reply_attachment);
  void (*log)(void *ctx, int32_t level, veer_slice message);
  /* 线程安全：给本实例投递一条 VEER_MSG_WAKE，插件自己的线程用它回到串行队列。 */
  int32_t (*post)(void *ctx, veer_slice payload);
  int32_t (*buf_reserve)(void *ctx, veer_buf *buf, size_t len);
  uint64_t (*monotonic_ns)(void *ctx);
  /* eBPF map 快路径；map 是 manifest 声明的 map 在 create 配置里给出的句柄。 */
  int32_t (*map_lookup)(void *ctx, uint32_t map, veer_slice key, veer_buf *value);
  int32_t (*map_update)(void *ctx, uint32_t map, veer_slice key, veer_slice value, uint64_t flags);
  int32_t (*map_delete)(void *ctx, uint32_t map, veer_slice key);
} veer_host_v1;

typedef struct veer_plugin_v1 {
  uint32_t struct_size;
  uint16_t abi_major, abi_minor;
  const char *id;              /* 必须等于 manifest 的 id */
  void *(*create)(const veer_host_v1 *host, veer_slice config);   /* config 是 JSON */
  void (*destroy)(void *instance);
  /* 返回 0 表示成功；负数是错误码，详情以 {"error":..., "code":...} 写进 reply。 */
  int32_t (*handle)(void *instance, const veer_msg *msg, veer_buf *reply);
} veer_plugin_v1;

const veer_plugin_v1 *veer_plugin_entry(uint16_t host_abi_major);
```

### 5.3 线程与超时

- worker 给每个插件实例一个投递线程，同一实例的 `handle` 从不并发。共享 worker 里一个插件卡住不影响其它插件。
- `handle` 里调用的宿主函数都是同步的。插件可以自己开线程做阻塞工作，完成后用 `post` 回到自己的串行队列。
- 每次 `handle` 有超时（默认与现在的执行超时相同）。超时后宿主把插件标为卡住；线程无法强杀，所以重启它所在的 worker，并按 3.1 节降级。

### 5.4 宿主 API 目录

`call` 的方法名和语义尽量沿用现有的 176 个方法（`net.*`、`resources.*`、`kv.*`、`secret.*`、`blob.*`、`timer.*`、`process.*`、`plugins.services.call`、`plugins.resources.*`、`events.publish`、`metrics.*`、`operations.*`、`log.*`），宿主侧的实现和校验直接复用。去掉只为 JS 服务的：`worker.*`（改由 worker 分组和插件自己的线程替代）、`crypto.*`（原生代码自带）、注册类方法（移进 manifest）。`net.http`、`net.dns` 保留为可选：经宿主发出的请求受 `net_access` 约束，插件也可以自己发起网络请求，但那不受宿主约束（第 8 节）。

第 0 阶段从 `sdk/plugin/api-contract.json` 生成一份方法目录：每个方法的请求和返回 JSON schema、所需权限、错误码。各语言 SDK 的类型化接口从这份目录生成。

现有插件的实际用量（按调用处计）决定了哪些方法要优先、要走快路径：

| 插件 | 主要用到的宿主 API |
|---|---|
| pppoe_client | `resources` 62、`timer` 44、`net.l2` 17、`crypto` 14、`net.link` 13、`ebpf` 10 |
| vpn_core | `resources` 34、`kv` 24、`process` 23、`secret` 13、`timer` 13、`operations` 9 |
| wan_core | `resources` 21、`net.link` 10、`timer` 8、`net.route/rule/neigh/addr` 各 2 |
| firewall | `ebpf` 22（集合与规则 map）、`kv` 10、`timer` 8、`resources` 8 |
| router_wizard | `operations` 11、`resources` 4、`plugins.services` 2 |
| lan_core、vtolocal | `net.link`、`resources`、`net.addr/route/prefix`、`plugins.services` |

### 5.5 由 worker 本地处理的调用

有些调用不需要往返宿主，worker 运行时自己处理：

- `timer.*`：worker 用 timerfd 实现，到期后向插件投递 `VEER_MSG_TIMER`。定时器只在内存里，插件在 `RECONCILE` 时重新设定（现在的插件已经这样做）。
- `log.*`、`metrics.*`：worker 先缓冲，批量发给宿主。
- `crypto.*`：不再提供，插件使用语言自带或链接的库。

### 5.6 文件描述符直接交给插件

`net.l2`（原始二层 socket）、`net.tuntap`、`net.udp`、`net.socket` 现在都是宿主持有 FD，插件每读写一次走一次 RPC。新设计里：

- 宿主按 `net_access` 检查权限后创建 FD（需要 `CAP_NET_RAW` 等特权的操作留在宿主），通过 unix socket 的 `SCM_RIGHTS` 交给 worker，插件直接 `recv`/`send`，用自己的线程 `epoll` 后 `post` 回串行队列。
- 宿主保留一份 dup 和所有权记录，插件停用或 worker 退出时由宿主关闭和清理；宿主热重启时 FD 仍按现在的方式交接。
- 现在的 `net.socket.watch` 及其事件不再需要。pppoe_client 的发现报文和 LCP 收发从此不经过宿主。
- eBPF map 同理：第一版用 5.2 节的 `map_*` 快路径（仍经宿主）；以后可以把 map FD 也交给 worker，插件直接 `bpf()` 读写。

### 5.7 插件之间的调用

`plugins.services.call`、`plugins.resources.*` 仍经宿主路由：宿主检查调用方的 `service_access`/`resource_access`，再把请求投递给目标插件（目标在哪个 worker 都一样）。同一 worker 内的调用以后可以在通过宿主授权后走本地捷径。

## 6. 生命周期

### 6.1 加载

1. 宿主读取 manifest，校验签名和 sha256、能力要求、权限声明。
2. 宿主照旧加载 eBPF 对象、挂载 hook、准备资源。
3. 宿主确定插件所在的 worker（不存在则启动），发送加载请求：库路径、sha256、实例配置（map 句柄、资源列表、插件私有目录）。
4. worker 校验 sha256 后 `dlopen`，调用 `veer_plugin_entry` 检查 ABI 版本，再 `create`。
5. 宿主发送 `RECONCILE`，然后开始投递订阅的事件（先投一个 `net.resync` 之类的全量同步事件，见 7.3 节）。

### 6.2 升级

- 默认：替换 `.so`，重启所在 worker，插件按持久状态 `RECONCILE`。插件的持久状态都在宿主（资源、KV、eBPF map），重启代价很低。
- 可选：实现了 `SNAPSHOT`/`RESTORE` 的插件，宿主在重启前取出内存状态，重启后送回。
- 共享 worker 里升级一个插件，会让同组插件一起重启；需要频繁升级的插件可以放进独立 worker。
- 宿主热重启：第一版让 worker 跟着重启（状态都在宿主和 eBPF map 里，keeper 保住托管进程）。以后如果插件重新 `RECONCILE` 的代价成了问题，再考虑像 keeper 一样把 worker 交接给新宿主。

### 6.3 崩溃

- worker 退出时，宿主带退避重启它，重新加载组内插件。
- worker 在进入每次 `handle` 前把实例 ID 写进与宿主共享的一页内存；崩溃后宿主据此知道是哪个插件，按 3.1 节降级。
- 同一插件在独立 worker 里反复崩溃，按现在的熔断规则停用并在页面上提示。

## 7. 事件表

### 7.1 topic

| topic | 内容 | 过滤字段 |
|---|---|---|
| `net.link` | 链路增删改（含 MTU、MAC、GSO 变化） | 接口名通配、类型 |
| `net.addr` | 地址增删 | 接口、地址族 |
| `net.neigh` | 邻居增删改 | 接口、地址族、NUD 状态 |
| `net.route` | 路由增删 | 接口、表、地址族 |
| `net.rule` | 策略规则增删 | 接口、表、优先级范围 |
| `net.offload` | 设备 offload 变化 | 接口 |
| `net.resync` | 事件可能丢失，需要全量核对 | — |
| `process.state` | 本插件托管进程的状态变化 | 进程 ID |
| `dataplane.rebuilt` | 新增：数据面重建、插件的 eBPF map 被重新创建 | 对象 |
| `resource.changed` | 资源记录变化 | 插件、资源 |
| `plugin.lifecycle` | 插件启停 | 插件 |
| `ebpf.ring` | eBPF ring buffer 记录（批量，附件是原始字节） | 对象、map |
| `net.socket` | 宿主持有的 socket 的数据、连接、关闭 | 句柄 |
| `plugin.<id>.*` | 插件自定义事件 | 前缀 |

`net.resync` 从现在挂在 `net.link` 上的 `operation: "resync"` 变成独立的 topic。新增的 `dataplane.rebuilt` 让 vpn_core 不再需要 5 秒一次的 map 检查，做到完全事件驱动。

### 7.2 过滤在宿主

订阅在 manifest 里带过滤条件，宿主在事件源处匹配后才投递。现在的 vpn_core 订阅 `net.link` 会收到所有接口的事件、在 worker 里再过滤；新设计里它只收到自己隧道、边界和链式前置出口的事件。接口授权（`net_access` 的 `link.read`）与过滤条件取交集。

### 7.3 投递语义

- 每个订阅一个有序队列。状态类 topic 可以声明合并（同一接口只保留最新一条），突发事件不会堆积。
- 队列溢出、netlink 重新订阅、规则或 offload 监听丢包、订阅刚开始时，宿主投递 `net.resync`，与现在的实现相同。
- 自定义 topic 可选持久投递（现在的 durable 语义）。

## 8. 权限与信任

- 原生插件是受信任的代码。宿主 API 仍按 manifest 检查权限和 `net_access`，但插件绕开宿主自己做系统调用时，宿主无法阻止；真正的约束来自 worker 的进程权限（3.2 节）。
- 签名、来源和稳定性决定默认放在哪个 worker。来源不明的插件只能进独立 worker，并默认不给网络。
- 文档明确写出：放进共享 worker 的插件，等同于可以影响同组其它插件。

## 9. SDK 与语言

### 9.1 C 和 C++

- `sdk/native/include/veer_plugin.h` 是唯一的权威定义。
- C++ 提供一个只含头文件的封装：RAII 管理缓冲区，边界上捕获异常，类型化的宿主调用。

### 9.2 Rust

- `veer-plugin-sys`：由头文件生成的绑定。
- `veer-plugin`：安全封装。提供 `veer_plugin!` 宏导出入口，边界上 `catch_unwind`，宿主 API 由方法目录生成带 serde 类型的接口。
- 计划先用 Rust 重写插件，worker 运行时也建议用 Rust。

### 9.3 Go

- 用 cgo 实现 C ABI，编成 `c-shared` 库。
- 限制：每个 Go 的 `c-shared` 库自带一份 Go 运行时，一个进程里放不下两个，所以 Go 插件强制放进独立 worker。
- 不使用 Go 标准库的 `plugin` 包（要求与宿主完全相同的工具链和依赖版本，而且不能卸载）。

### 9.4 Python 和其它解释型语言

- 提供一个转接库 `libveer_python.so`：它本身是普通插件，内嵌 CPython，把消息转成 Python 调用。Python 插件是 manifest 加 `.py` 文件，manifest 的 `library` 指向转接库。
- 一个 worker 只能有一个 CPython 解释器，而且受 GIL 限制，所以 Python 插件建议放进独立 worker。
- 其它语言（Lua、JS）可以用同样的方式接入。

### 9.5 测试

- `veer-plugin-test`：在测试进程里加载 `.so`，提供可编程的假宿主（相当于现在的 `test-host.cjs`）和内核状态模型，替代现有的 node 测试。
- ABI 一致性测试：用 C、Rust、Go 各写一个最小插件，验证加载、消息投递、超时、崩溃降级、升级。
- 现有的 Go 集成测试（WAN、VPN、防火墙、PPPoE）改为加载新插件后照常运行。

## 10. 宿主改动（Go）

| 去掉 | 保留并复用 | 新增 |
|---|---|---|
| goja 运行时与注册阶段 | 插件目录、安装包、签名 | worker 监管（启动、退避、降级） |
| 隔离插件宿主进程（`--plugin-host`） | 资源、KV、密钥、blob 存储 | IPC 服务：分帧、JSON 加附件，以后加 map FD 传递 |
| JS SDK、`test-host.cjs`、SDK 契约文件 | 网络租约、事务日志、无变化快路径 | 方法分发：方法名映射到现有实现并检查权限 |
| worker VM、JS 热升级 snapshot | eBPF 对象、hook、pipeline、XDP/TC 兜底 | manifest v2 解析与校验 |
| | 事件源、过滤、resync | 事件路由：源头过滤、合并、按订阅投递 |
| | 进程注册表与 keeper、WebUI | 小的 keeper 程序 |

现在 `pluginControlHost` 里的参数校验和权限检查与 `goja.Value` 绑在一起，需要拆成以 JSON 请求为输入的函数，供 IPC 分发和测试共用。预计删除约 2.7 万行，新增 5–8 千行。

## 11. 迁移计划

| 阶段 | 内容 | 完成标志 |
|---|---|---|
| 0 规范 | `veer_plugin.h` v1、方法目录（含 schema 和权限）、事件表、manifest v2 schema | 头文件和文档评审通过；一致性测试骨架 |
| 1 运行时 | Rust worker 运行时；宿主侧 worker 监管、IPC、方法分发、事件路由；C、Rust、Go 的示例插件；Python 转接原型 | 一致性测试通过；实测内存和调用延迟 |
| 2 首个插件 | 用 Rust 重写 wan_core，测试改写到 `veer-plugin-test`；WAN 和 VPN 的 Go 集成测试通过 | PVE 上新旧对比运行 |
| 3 其余插件 | vpn_core（核心管理、配置生成、健康检查）、lan_core、vtolocal、router_wizard、防火墙控制面（原 `compile.js`）、pppoe_client（最大，约 4600 行控制代码）、packet_observer | 每个插件的集成测试通过 |
| 4 清理 | 删除 goja 系统、JS SDK、隔离宿主进程；重写 PLUGIN.md | CI 只剩新系统 |
| 5 可选 | 宿主换 C++ | 另立项目评估 |

第 2、3 阶段可以与旧系统并行：宿主同时支持两种插件，逐个切换。第 5 阶段建议推迟到 v2 稳定之后：Go 宿主里有大量经过测试的数据面管理、netlink、API 和数据库代码，重写是一个独立的大项目；ABI 设计成与宿主语言无关，留着这个可能。

## 12. 风险与待定问题

风险：

- Go `c-shared` 一个进程只能有一个，Go 插件只能独占 worker。
- 目标三元组（x86_64/aarch64 × glibc/musl）使每个插件要构建四份，CI 和打包要跟上。
- 共享 worker 里的内存破坏会影响同组所有插件；Rust 能显著降低这类风险，C/C++ 插件建议先放独立 worker 试运行。
- 原生插件没有进程内沙箱，`net_access` 只约束经宿主的调用，需要在文档和页面上说清楚。
- 迁移工作量：约 1.3 万行控制代码和 5300 行测试要重写。

待定：

1. 结构化数据用 JSON 还是 CBOR（倾向第一版 JSON）。
2. 网络操作是否允许 worker 直接做 netlink（租约和事务日志在宿主数据库里，第一版倾向全部经宿主）。
3. worker 是否在宿主热重启时交接而不是重启。
4. manifest 用 JSON 还是 TOML（倾向 JSON，WebUI 和工具链已有）。
5. Python 转接的优先级。
