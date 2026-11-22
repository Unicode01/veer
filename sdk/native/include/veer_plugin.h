/*
 * Veer native plugin ABI, version 1.
 *
 * This header is the authoritative definition of the contract between a
 * plugin shared library and the Veer plugin worker that loads it. A plugin
 * exports exactly one symbol, veer_plugin_entry, and talks to the host only
 * through the veer_host_v1 table it receives in create().
 *
 * Compatibility: the first field of every table is struct_size. New fields
 * are only ever appended, and each addition bumps VEER_PLUGIN_ABI_MINOR. A
 * caller must check struct_size before touching a field it did not know
 * about when it was built. A different VEER_PLUGIN_ABI_MAJOR means the
 * tables are incompatible and the worker refuses to load the plugin.
 *
 * Data: structured values cross the boundary as UTF-8 JSON. Inputs are owned
 * by the caller and are only valid for the duration of the call. Outputs are
 * written into a veer_buf that the worker allocates through buf_reserve; a
 * plugin never frees worker memory and the worker never frees plugin memory.
 *
 * Threads: the worker calls handle() for one instance from one thread at a
 * time. Host calls (call) are only valid on that thread while handle() runs.
 * A plugin that does blocking work on its own threads returns to its serial
 * queue with post(), which delivers a VEER_MSG_WAKE message later.
 *
 * Errors: C++ exceptions and Rust panics must not cross this boundary.
 */
#ifndef VEER_PLUGIN_H
#define VEER_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VEER_PLUGIN_ABI_MAJOR 1
#define VEER_PLUGIN_ABI_MINOR 0

#define VEER_PLUGIN_ENTRY_SYMBOL "veer_plugin_entry"

/* Status codes returned by handle() and by host functions. */
#define VEER_OK 0
/* handle(): the plugin does not implement this message (an optional handler). */
#define VEER_UNHANDLED 1
/* Generic failure; the reply buffer holds a UTF-8 error message. */
#define VEER_ERROR -1
/* The request was malformed (bad JSON, unknown method). */
#define VEER_EINVAL -2
/* The call is not allowed here (wrong thread, permission, nesting). */
#define VEER_EPERM -3
/* The worker or host is shutting down, or the instance was unloaded. */
#define VEER_ESHUTDOWN -4
/* An allocation failed. */
#define VEER_ENOMEM -5

typedef struct veer_slice {
  const uint8_t *data;
  size_t len;
} veer_slice;

/* A growable output buffer owned by the worker. Grow it with buf_reserve,
 * write at most cap bytes into data and set len. */
typedef struct veer_buf {
  uint8_t *data;
  size_t len;
  size_t cap;
} veer_buf;

typedef enum veer_msg_kind {
  /* Bring everything back to the state the persistent records describe. */
  VEER_MSG_RECONCILE = 1,
  /* The plugin is being disabled or removed: release what it created. */
  VEER_MSG_DEACTIVATE = 2,
  /* A subscribed event. handler is the subscription's handler name. */
  VEER_MSG_EVENT = 3,
  /* A timer the plugin set. The payload carries the timer name. */
  VEER_MSG_TIMER = 4,
  /* An action request. For runtime_query actions the reply is the result. */
  VEER_MSG_ACTION = 5,
  /* Records of a runtime_apply resource changed. */
  VEER_MSG_RESOURCE_APPLY = 6,
  /* Convert stored records to a new schema version; reply is the result. */
  VEER_MSG_RESOURCE_MIGRATE = 7,
  /* Convert eBPF map state between schema versions; reply is the result. */
  VEER_MSG_EBPF_STATE_MIGRATE = 8,
  /* Before an upgrade: return the in-memory state to keep. */
  VEER_MSG_UPGRADE_SNAPSHOT = 9,
  /* After an upgrade: the payload carries the state the old version kept. */
  VEER_MSG_UPGRADE_RESTORE = 10,
  /* A message the plugin posted to itself with post(). */
  VEER_MSG_WAKE = 11
} veer_msg_kind;

typedef struct veer_msg {
  uint32_t struct_size;
  uint32_t kind;          /* veer_msg_kind */
  uint64_t sequence;      /* increases by one for every message to this instance */
  veer_slice handler;     /* handler name, e.g. "onReconcile" or a subscription handler */
  veer_slice payload;     /* the handler context as a JSON object */
} veer_msg;

#define VEER_LOG_DEBUG 0
#define VEER_LOG_INFO 1
#define VEER_LOG_WARN 2
#define VEER_LOG_ERROR 3

typedef struct veer_host_v1 {
  uint32_t struct_size;
  uint16_t abi_major;
  uint16_t abi_minor;
  void *ctx;
  /* Calls a host API method such as "resources.set" or "net.route.replace".
   * arguments is a JSON array holding the method's arguments in order. On
   * VEER_OK, reply holds the JSON result ("null" when there is none); on
   * failure it holds a UTF-8 error message. Only valid inside handle(). */
  int32_t (*call)(void *ctx, veer_slice method, veer_slice arguments, veer_buf *reply);
  /* Writes a log line to the plugin's log. Valid on any thread. */
  void (*log)(void *ctx, int32_t level, veer_slice message);
  /* Queues a VEER_MSG_WAKE message carrying payload (JSON) for this
   * instance. Valid on any thread; the only way back from a plugin thread. */
  int32_t (*post)(void *ctx, veer_slice payload);
  /* Grows buf to hold at least cap bytes, keeping its contents. A cap of 0
   * releases the buffer's memory and resets it to {NULL, 0, 0}; a plugin
   * does this with every reply buffer it received from call(). */
  int32_t (*buf_reserve)(void *ctx, veer_buf *buf, size_t cap);
  /* CLOCK_MONOTONIC in nanoseconds. */
  uint64_t (*monotonic_ns)(void *ctx);
} veer_host_v1;

typedef struct veer_plugin_v1 {
  uint32_t struct_size;
  uint16_t abi_major;
  uint16_t abi_minor;
  /* Must equal the manifest id. */
  const char *id;
  /* Creates an instance. config is a JSON object with the plugin identity
   * and its directory. host stays valid until destroy() returns. Returns NULL
   * on failure, after logging the reason through host->log. */
  void *(*create)(const veer_host_v1 *host, veer_slice config);
  void (*destroy)(void *instance);
  /* Handles one message. Returns VEER_OK, VEER_UNHANDLED or a negative
   * error; on error the reply holds a UTF-8 message. */
  int32_t (*handle)(void *instance, const veer_msg *msg, veer_buf *reply);
} veer_plugin_v1;

typedef const veer_plugin_v1 *(*veer_plugin_entry_fn)(uint16_t host_abi_major);

/* Returns the plugin table for the given host ABI major version, or NULL
 * when the plugin does not support it. */
const veer_plugin_v1 *veer_plugin_entry(uint16_t host_abi_major);

#ifdef __cplusplus
}
#endif

#endif /* VEER_PLUGIN_H */
