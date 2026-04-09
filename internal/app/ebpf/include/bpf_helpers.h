#ifndef __FORWARD_BPF_HELPERS_H
#define __FORWARD_BPF_HELPERS_H

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*const bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static long (*const bpf_skb_load_bytes)(struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*const bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*const bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)BPF_FUNC_l3_csum_replace;
static long (*const bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;
static __s64 (*const bpf_csum_diff)(const __be32 *from, __u32 from_size, const __be32 *to, __u32 to_size, __wsum seed) = (void *)BPF_FUNC_csum_diff;
static long (*const bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*const bpf_redirect_map)(void *map, __u32 key, __u64 flags) = (void *)BPF_FUNC_redirect_map;
static long (*const bpf_redirect_neigh)(__u32 ifindex, void *params, int plen, __u64 flags) = (void *)BPF_FUNC_redirect_neigh;
static long (*const bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *)BPF_FUNC_fib_lookup;
static long (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
#ifdef BPF_FUNC_xdp_load_bytes
static long (*const bpf_xdp_load_bytes)(struct xdp_md *xdp, __u32 offset, void *buf, __u32 len) = (void *)BPF_FUNC_xdp_load_bytes;
#endif
#ifdef BPF_FUNC_xdp_store_bytes
static long (*const bpf_xdp_store_bytes)(struct xdp_md *xdp, __u32 offset, const void *buf, __u32 len) = (void *)BPF_FUNC_xdp_store_bytes;
#endif

#endif
