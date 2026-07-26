#include <linux/bpf.h>
#include <stddef.h>

#include "include/bpf_helpers.h"

#define VEER_XDP_PROG_CHAIN_MAX_ENTRIES 24
#define VEER_XDP_PLUGIN_CONTINUE_SLOT 7
#define VEER_XDP_PLUGIN_BANK0_BASE 8
#define VEER_XDP_PLUGIN_BANK1_BASE 16
#define VEER_XDP_PLUGIN_MAX 8

struct xdp_plugin_config {
	__u32 count;
	__u32 active_bank;
	__u32 global_mask;
	__u32 generation;
};

struct xdp_plugin_if_key {
	__u32 ifindex;
	__u32 bank;
};

struct xdp_plugin_if_value {
	__u32 mask;
};

struct xdp_plugin_dispatch {
	__u32 chain_index;
	__u32 count;
	__u32 mask;
	__u32 bank;
};

struct xdp_plugin_metric {
	__u64 packets;
	__u64 bytes;
	__u64 continued;
	__u64 tail_call_misses;
};

struct bpf_map_def SEC("maps") xdp_prog_chain = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = VEER_XDP_PROG_CHAIN_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") xdp_plugin_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct xdp_plugin_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_plugin_interfaces = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct xdp_plugin_if_key),
	.value_size = sizeof(struct xdp_plugin_if_value),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") xdp_plugin_scratch = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct xdp_plugin_dispatch),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_plugin_metrics = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct xdp_plugin_metric),
	.max_entries = VEER_XDP_PLUGIN_MAX,
};

static __always_inline __u32 xdp_plugin_count_mask(__u32 count)
{
	if (count == 0)
		return 0;
	if (count >= 32)
		return ~0U;
	return (1U << count) - 1;
}

static __always_inline struct xdp_plugin_dispatch *xdp_plugin_dispatch_state(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_plugin_scratch, &key);
}

static __always_inline void xdp_plugin_metric_attempt(struct xdp_md *xdp, __u32 index)
{
	struct xdp_plugin_metric *metric;

	if (index >= VEER_XDP_PLUGIN_MAX)
		return;
	metric = bpf_map_lookup_elem(&xdp_plugin_metrics, &index);
	if (!metric)
		return;
	metric->packets++;
	metric->bytes += (__u64)((void *)(long)xdp->data_end - (void *)(long)xdp->data);
}

static __always_inline void xdp_plugin_metric_continue(__u32 chain_index)
{
	struct xdp_plugin_metric *metric;
	__u32 index;

	if (chain_index == 0)
		return;
	index = chain_index - 1;
	if (index >= VEER_XDP_PLUGIN_MAX)
		return;
	metric = bpf_map_lookup_elem(&xdp_plugin_metrics, &index);
	if (metric)
		metric->continued++;
}

static __always_inline void xdp_plugin_metric_miss(__u32 index)
{
	struct xdp_plugin_metric *metric;

	if (index >= VEER_XDP_PLUGIN_MAX)
		return;
	metric = bpf_map_lookup_elem(&xdp_plugin_metrics, &index);
	if (metric)
		metric->tail_call_misses++;
}

SEC("xdp/veer_plugin_continue")
int veer_xdp_plugin_continue(struct xdp_md *xdp)
{
	struct xdp_plugin_dispatch *dispatch = xdp_plugin_dispatch_state();
	__u32 slot_base;
	__u32 index;
	int i;

	if (!dispatch)
		return XDP_PASS;
	xdp_plugin_metric_continue(dispatch->chain_index);
	slot_base = dispatch->bank ? VEER_XDP_PLUGIN_BANK1_BASE : VEER_XDP_PLUGIN_BANK0_BASE;
#pragma unroll
	for (i = 0; i < VEER_XDP_PLUGIN_MAX; i++) {
		index = dispatch->chain_index;
		if (index >= dispatch->count || index >= VEER_XDP_PLUGIN_MAX)
			break;
		dispatch->chain_index = index + 1;
		if ((dispatch->mask & (1U << index)) == 0)
			continue;
		xdp_plugin_metric_attempt(xdp, index);
		bpf_tail_call(xdp, &xdp_prog_chain, slot_base + index);
		xdp_plugin_metric_miss(index);
	}
	return XDP_PASS;
}
SEC("xdp/veer_plugin_dispatch")
int veer_xdp_plugin_dispatch(struct xdp_md *xdp)
{
	struct xdp_plugin_if_key interface_key = {};
	struct xdp_plugin_if_value *scoped;
	struct xdp_plugin_dispatch *dispatch;
	struct xdp_plugin_config *config;
	__u32 key = 0;
	__u32 full_mask;

	dispatch = xdp_plugin_dispatch_state();
	if (!dispatch)
		return XDP_PASS;
	__builtin_memset(dispatch, 0, sizeof(*dispatch));
	config = bpf_map_lookup_elem(&xdp_plugin_config, &key);
	if (!config || config->count == 0)
		return XDP_PASS;
	dispatch->count = config->count;
	dispatch->bank = config->active_bank & 1;
	full_mask = xdp_plugin_count_mask(dispatch->count);
	dispatch->mask = config->global_mask & full_mask;
	if (dispatch->mask != full_mask) {
		interface_key.ifindex = xdp->ingress_ifindex;
		interface_key.bank = dispatch->bank;
		scoped = bpf_map_lookup_elem(&xdp_plugin_interfaces, &interface_key);
		if (scoped)
			dispatch->mask |= scoped->mask & full_mask;
	}
	if (dispatch->mask == 0)
		return XDP_PASS;
	bpf_tail_call(xdp, &xdp_prog_chain, VEER_XDP_PLUGIN_CONTINUE_SLOT);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
