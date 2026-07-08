#include "../include/fvtap_plugin_helpers.h"

#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_FUNC_map_lookup_elem 1

struct __sk_buff;

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;

struct bpf_map_def SEC("maps") packet_count = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

FVTAP_DECLARE_PROG_CHAIN_V4();

SEC("tc/fvtap/pre_forward")
int tc_pre_forward(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *value = bpf_map_lookup_elem(&packet_count, &key);
	if (value)
		*value += 1;
	fvtap_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
