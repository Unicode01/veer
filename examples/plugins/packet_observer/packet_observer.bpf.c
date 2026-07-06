#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_tail_call 12
#define TC_ACT_UNSPEC (-1)
#define FVTAP_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE 8

struct __sk_buff;

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;

struct bpf_map_def SEC("maps") packet_count = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

SEC("tc/fvtap/pre_forward")
int tc_pre_forward(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *value = bpf_map_lookup_elem(&packet_count, &key);
	if (value)
		*value += 1;
	bpf_tail_call(skb, &tc_prog_chain_v4, FVTAP_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
