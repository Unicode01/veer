#ifndef VEER_PLUGIN_HELPERS_H
#define VEER_PLUGIN_HELPERS_H

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

#define VEER_ETH_ALEN 6
#define VEER_ETH_P_IP 0x0800
#define VEER_ETH_P_8021Q 0x8100
#define VEER_ETH_P_8021AD 0x88a8
#define VEER_ETH_P_IPV6 0x86dd
#define VEER_IPPROTO_ICMP 1
#define VEER_IPPROTO_HOPOPTS 0
#define VEER_IPPROTO_TCP 6
#define VEER_IPPROTO_UDP 17
#define VEER_IPPROTO_ROUTING 43
#define VEER_IPPROTO_FRAGMENT 44
#define VEER_IPPROTO_ESP 50
#define VEER_IPPROTO_AH 51
#define VEER_IPPROTO_ICMPV6 58
#define VEER_IPPROTO_NONE 59
#define VEER_IPPROTO_DSTOPTS 60

#define VEER_PACKET_FAMILY_UNKNOWN 0
#define VEER_PACKET_FAMILY_IPV4 4
#define VEER_PACKET_FAMILY_IPV6 6
#define VEER_MAX_VLAN_DEPTH 2
#define VEER_MAX_IPV6_EXTENSION_HEADERS 6

#ifndef BPF_MAP_TYPE_PROG_ARRAY
#define BPF_MAP_TYPE_PROG_ARRAY 3
#endif

#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif

#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#endif

#ifndef BPF_FUNC_map_lookup_elem
#define BPF_FUNC_map_lookup_elem 1
#endif

#ifndef BPF_FUNC_tail_call
#define BPF_FUNC_tail_call 12
#endif

#ifndef BPF_FUNC_skb_store_bytes
#define BPF_FUNC_skb_store_bytes 9
#endif

#ifndef BPF_FUNC_l3_csum_replace
#define BPF_FUNC_l3_csum_replace 10
#endif

#ifndef BPF_FUNC_l4_csum_replace
#define BPF_FUNC_l4_csum_replace 11
#endif

#ifndef BPF_FUNC_redirect
#define BPF_FUNC_redirect 23
#endif

#ifndef BPF_FUNC_skb_pull_data
#define BPF_FUNC_skb_pull_data 39
#endif

#ifndef BPF_FUNC_skb_adjust_room
#define BPF_FUNC_skb_adjust_room 50
#endif

#ifndef BPF_ADJ_ROOM_NET
#define BPF_ADJ_ROOM_NET 0
#endif

#ifndef BPF_ADJ_ROOM_MAC
#define BPF_ADJ_ROOM_MAC 1
#endif

#ifndef BPF_F_PSEUDO_HDR
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#endif

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT 7
#endif

#define VEER_TC_PROG_CHAIN_V4_MAX_ENTRIES 111
#define VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE 8
#define VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE 9
#define VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_BASE 10
#define VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_BASE 18
#define VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_CONTINUE 27
#define VEER_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE 28
#define VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_BASE 29
#define VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_POST_REPLY_BASE 37
#define VEER_TC_PROG_V4_PLUGIN_POST_REPLY_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_POST_APPLY_CONTINUE 77
#define VEER_TC_PROG_V4_PLUGIN_REPLY_APPLY_CONTINUE 78
#define VEER_TC_PROG_V4_PLUGIN_POST_APPLY_BASE 79
#define VEER_TC_PROG_V4_PLUGIN_POST_APPLY_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_BANK1_POST_APPLY_BASE 87
#define VEER_TC_PROG_V4_PLUGIN_REPLY_APPLY_BASE 95
#define VEER_TC_PROG_V4_PLUGIN_REPLY_APPLY_MAX 8
#define VEER_TC_PROG_V4_PLUGIN_BANK1_REPLY_APPLY_BASE 103

#define VEER_XDP_PROG_CHAIN_MAX_ENTRIES 24
#define VEER_XDP_PLUGIN_CONTINUE_SLOT 7
#define VEER_PACKET_METADATA_BINDING_MAX_ENTRIES 16
#define VEER_PACKET_METADATA_MAX_NAMESPACES 32
#define VEER_PACKET_METADATA_PAYLOAD_BYTES 64
#define VEER_PACKET_METADATA_ACCESS_READ 1
#define VEER_PACKET_METADATA_ACCESS_WRITE 2
#define VEER_PACKET_METADATA_PENDING_LEN 0xffff

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
};

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct tc_plugin_ctx_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u32 rule_id;
	__u32 backend_addr;
	__u32 out_ifindex;
	__u32 nat_addr;
	__u16 src_port;
	__u16 dst_port;
	__u16 backend_port;
	__u16 rule_flags;
	__u8 proto;
	__u8 rule_wildcard_addr;
	__u8 have_rule;
	__u8 have_flow;
	__u8 direction;
	__u8 pad[3];
	__u32 front_addr;
	__u32 client_addr;
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
	__s32 final_action;
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct tc_plugin_ctx_v6 {
	__u32 ifindex;
	__u32 rule_id;
	__u32 out_ifindex;
	__u16 src_port;
	__u16 dst_port;
	__u16 backend_port;
	__u16 rule_flags;
	__u8 proto;
	__u8 rule_wildcard_addr;
	__u8 have_rule;
	__u8 have_flow;
	__u8 direction;
	__u8 pad[3];
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u8 backend_addr[16];
	__u8 nat_addr[16];
	__u8 front_addr[16];
	__u8 client_addr[16];
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
	__s32 final_action;
};

struct veer_packet_metadata_binding_v1 {
	__u32 namespace_slot;
	__u32 schema_version;
	__u16 max_bytes;
	__u8 access;
	__u8 reserved;
};

struct veer_packet_metadata_value_v1 {
	__u64 generation;
	__u32 schema_version;
	__u16 payload_len;
	__u16 capacity;
	__u8 payload[VEER_PACKET_METADATA_PAYLOAD_BYTES];
};

struct veer_ethhdr {
	__u8 h_dest[VEER_ETH_ALEN];
	__u8 h_source[VEER_ETH_ALEN];
	__u16 h_proto;
} __attribute__((packed));

struct veer_ipv4hdr {
	__u8 ver_ihl;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

struct veer_vlanhdr {
	__u16 tci;
	__u16 encapsulated_proto;
} __attribute__((packed));

struct veer_ipv6hdr {
	__u32 version_class_flow;
	__u16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

struct veer_ipv6_exthdr {
	__u8 nexthdr;
	__u8 hdrlen;
} __attribute__((packed));

struct veer_ipv6_fraghdr {
	__u8 nexthdr;
	__u8 reserved;
	__u16 frag_off;
	__u32 identification;
} __attribute__((packed));

struct veer_tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u8 doff_res;
	__u8 flags;
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
} __attribute__((packed));

struct veer_udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
} __attribute__((packed));

struct veer_packet {
	void *data;
	void *data_end;
};

struct veer_l2_info {
	struct veer_ethhdr *eth;
	void *network;
	__u16 protocol;
	__u8 vlan_depth;
	__u8 pad;
};

struct veer_l4_ports {
	__u16 source;
	__u16 dest;
};

static void (*const veer_bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;
static void *(*const veer_bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*const veer_bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static int (*const veer_bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)BPF_FUNC_l3_csum_replace;
static int (*const veer_bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;
static int (*const veer_bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static int (*const veer_bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)BPF_FUNC_skb_pull_data;
static int (*const veer_bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)BPF_FUNC_skb_adjust_room;

#define VEER_DECLARE_PROG_CHAIN_V4() \
	struct bpf_map_def SEC("maps") tc_prog_chain_v4 = { \
		.type = BPF_MAP_TYPE_PROG_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(__u32), \
		.max_entries = VEER_TC_PROG_CHAIN_V4_MAX_ENTRIES, \
	}

#define VEER_DECLARE_PLUGIN_CTX_V4() \
	struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(struct tc_plugin_ctx_v4), \
		.max_entries = 1, \
	}

#define VEER_DECLARE_XDP_PROG_CHAIN() \
	struct bpf_map_def SEC("maps") xdp_prog_chain = { \
		.type = BPF_MAP_TYPE_PROG_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(__u32), \
		.max_entries = VEER_XDP_PROG_CHAIN_MAX_ENTRIES, \
	}

#define VEER_DECLARE_PLUGIN_CTX_V6() \
	struct bpf_map_def SEC("maps") tc_plugin_ctx_v6 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(struct tc_plugin_ctx_v6), \
		.max_entries = 1, \
	}

#define VEER_DECLARE_PLUGIN_CONTEXTS() \
	VEER_DECLARE_PLUGIN_CTX_V4(); \
	VEER_DECLARE_PLUGIN_CTX_V6()

#define VEER_DECLARE_PACKET_METADATA() \
	struct bpf_map_def SEC("maps") tc_packet_meta_bindings_v1 = { \
		.type = BPF_MAP_TYPE_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(struct veer_packet_metadata_binding_v1), \
		.max_entries = VEER_PACKET_METADATA_BINDING_MAX_ENTRIES, \
	}; \
	struct bpf_map_def SEC("maps") tc_packet_meta_generation_v4 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(__u64), \
		.max_entries = 1, \
	}; \
	struct bpf_map_def SEC("maps") tc_packet_meta_generation_v6 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(__u64), \
		.max_entries = 1, \
	}; \
	struct bpf_map_def SEC("maps") tc_packet_meta_v4 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(struct veer_packet_metadata_value_v1), \
		.max_entries = VEER_PACKET_METADATA_MAX_NAMESPACES, \
	}; \
	struct bpf_map_def SEC("maps") tc_packet_meta_v6 = { \
		.type = BPF_MAP_TYPE_PERCPU_ARRAY, \
		.key_size = sizeof(__u32), \
		.value_size = sizeof(struct veer_packet_metadata_value_v1), \
		.max_entries = VEER_PACKET_METADATA_MAX_NAMESPACES, \
	}

#define veer_tail_call(skb, slot) veer_bpf_tail_call((skb), &tc_prog_chain_v4, (slot))
#define veer_xdp_continue(xdp) veer_bpf_tail_call((xdp), &xdp_prog_chain, VEER_XDP_PLUGIN_CONTINUE_SLOT)
#define veer_continue_pre_forward(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE)
#define veer_continue_post_lookup(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE)
#define veer_continue_pre_reply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_CONTINUE)
#define veer_continue_post_reply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE)
#define veer_continue_post_apply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_POST_APPLY_CONTINUE)
#define veer_continue_reply_apply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_REPLY_APPLY_CONTINUE)
#define veer_lookup_plugin_ctx_v4() ({ \
	__u32 __veer_ctx_key = 0; \
	(struct tc_plugin_ctx_v4 *)veer_bpf_map_lookup_elem(&tc_plugin_ctx_v4, &__veer_ctx_key); \
})
#define veer_lookup_plugin_ctx_v6() ({ \
	__u32 __veer_ctx_key = 0; \
	(struct tc_plugin_ctx_v6 *)veer_bpf_map_lookup_elem(&tc_plugin_ctx_v6, &__veer_ctx_key); \
})

static __always_inline struct veer_packet_metadata_value_v1 *veer_packet_metadata_read_maps(
	void *bindings_map, void *generation_map, void *metadata_map, __u32 local_slot)
{
	__u32 generation_key = 0;
	struct veer_packet_metadata_binding_v1 *binding;
	struct veer_packet_metadata_value_v1 *value;
	__u64 *generation;

	if (local_slot >= VEER_PACKET_METADATA_BINDING_MAX_ENTRIES)
		return 0;
	binding = veer_bpf_map_lookup_elem(bindings_map, &local_slot);
	if (!binding || (binding->access & VEER_PACKET_METADATA_ACCESS_READ) == 0 ||
		binding->namespace_slot >= VEER_PACKET_METADATA_MAX_NAMESPACES || binding->schema_version == 0 ||
		binding->max_bytes == 0 || binding->max_bytes > VEER_PACKET_METADATA_PAYLOAD_BYTES)
		return 0;
	generation = veer_bpf_map_lookup_elem(generation_map, &generation_key);
	if (!generation || *generation == 0)
		return 0;
	value = veer_bpf_map_lookup_elem(metadata_map, &binding->namespace_slot);
	if (!value || value->generation != *generation || value->schema_version != binding->schema_version ||
		value->capacity != binding->max_bytes || value->payload_len > binding->max_bytes)
		return 0;
	return value;
}

static __always_inline struct veer_packet_metadata_value_v1 *veer_packet_metadata_write_begin_maps(
	void *bindings_map, void *generation_map, void *metadata_map, __u32 local_slot)
{
	__u32 generation_key = 0;
	struct veer_packet_metadata_binding_v1 *binding;
	struct veer_packet_metadata_value_v1 *value;
	__u64 *generation;

	if (local_slot >= VEER_PACKET_METADATA_BINDING_MAX_ENTRIES)
		return 0;
	binding = veer_bpf_map_lookup_elem(bindings_map, &local_slot);
	if (!binding || (binding->access & VEER_PACKET_METADATA_ACCESS_WRITE) == 0 ||
		binding->namespace_slot >= VEER_PACKET_METADATA_MAX_NAMESPACES || binding->schema_version == 0 ||
		binding->max_bytes == 0 || binding->max_bytes > VEER_PACKET_METADATA_PAYLOAD_BYTES)
		return 0;
	generation = veer_bpf_map_lookup_elem(generation_map, &generation_key);
	if (!generation || *generation == 0)
		return 0;
	value = veer_bpf_map_lookup_elem(metadata_map, &binding->namespace_slot);
	if (!value)
		return 0;
	value->generation = *generation;
	value->schema_version = binding->schema_version;
	value->payload_len = VEER_PACKET_METADATA_PENDING_LEN;
	value->capacity = binding->max_bytes;
	__builtin_memset(value->payload, 0, sizeof(value->payload));
	return value;
}

static __always_inline int veer_packet_metadata_commit(struct veer_packet_metadata_value_v1 *value, __u16 payload_len)
{
	if (!value || payload_len > value->capacity || payload_len > VEER_PACKET_METADATA_PAYLOAD_BYTES)
		return -1;
	value->payload_len = payload_len;
	return 0;
}

#define veer_packet_metadata_read_v4(slot) \
	veer_packet_metadata_read_maps(&tc_packet_meta_bindings_v1, &tc_packet_meta_generation_v4, &tc_packet_meta_v4, (slot))
#define veer_packet_metadata_read_v6(slot) \
	veer_packet_metadata_read_maps(&tc_packet_meta_bindings_v1, &tc_packet_meta_generation_v6, &tc_packet_meta_v6, (slot))
#define veer_packet_metadata_write_begin_v4(slot) \
	veer_packet_metadata_write_begin_maps(&tc_packet_meta_bindings_v1, &tc_packet_meta_generation_v4, &tc_packet_meta_v4, (slot))
#define veer_packet_metadata_write_begin_v6(slot) \
	veer_packet_metadata_write_begin_maps(&tc_packet_meta_bindings_v1, &tc_packet_meta_generation_v6, &tc_packet_meta_v6, (slot))

static __always_inline int veer_skb_pull_data(struct __sk_buff *skb, __u32 len)
{
	return veer_bpf_skb_pull_data(skb, len);
}

static __always_inline int veer_skb_store_bytes(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags)
{
	return veer_bpf_skb_store_bytes(skb, offset, from, len, flags);
}

static __always_inline int veer_l3_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size)
{
	return veer_bpf_l3_csum_replace(skb, offset, from, to, size);
}

static __always_inline int veer_l4_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags)
{
	return veer_bpf_l4_csum_replace(skb, offset, from, to, flags);
}

static __always_inline int veer_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags)
{
	return veer_bpf_skb_adjust_room(skb, len_diff, mode, flags);
}

static __always_inline int veer_redirect(__u32 ifindex)
{
	return veer_bpf_redirect(ifindex, 0);
}

static __always_inline __u16 veer_bswap16(__u16 value)
{
	return (value << 8) | (value >> 8);
}

static __always_inline __u16 veer_ntohs(__u16 value)
{
	return veer_bswap16(value);
}

static __always_inline __u16 veer_htons(__u16 value)
{
	return veer_bswap16(value);
}

static __always_inline int veer_packet_from_skb(struct __sk_buff *skb, struct veer_packet *pkt)
{
	pkt->data = (void *)(long)skb->data;
	pkt->data_end = (void *)(long)skb->data_end;
	return pkt->data <= pkt->data_end;
}

static __always_inline int veer_bounds_ok(const struct veer_packet *pkt, void *ptr, __u32 len)
{
	return (char *)ptr >= (char *)pkt->data && (char *)ptr + len <= (char *)pkt->data_end;
}

static __always_inline struct veer_ethhdr *veer_eth(const struct veer_packet *pkt)
{
	struct veer_ethhdr *eth = pkt->data;

	if (!veer_bounds_ok(pkt, eth, sizeof(*eth)))
		return 0;
	return eth;
}

static __always_inline __u16 veer_eth_proto(const struct veer_ethhdr *eth)
{
	return veer_ntohs(eth->h_proto);
}

static __always_inline int veer_parse_l2(const struct veer_packet *pkt, struct veer_l2_info *info)
{
	struct veer_ethhdr *eth = veer_eth(pkt);
	void *cursor;
	__u16 protocol;
	int i;

	if (!eth || !info)
		return 0;
	cursor = eth + 1;
	protocol = veer_eth_proto(eth);
	info->eth = eth;
	info->vlan_depth = 0;
#pragma unroll
	for (i = 0; i < VEER_MAX_VLAN_DEPTH; i++) {
		struct veer_vlanhdr *vlan;

		if (protocol != VEER_ETH_P_8021Q && protocol != VEER_ETH_P_8021AD)
			break;
		vlan = cursor;
		if (!veer_bounds_ok(pkt, vlan, sizeof(*vlan)))
			return 0;
		protocol = veer_ntohs(vlan->encapsulated_proto);
		cursor = vlan + 1;
		info->vlan_depth++;
	}
	info->network = cursor;
	info->protocol = protocol;
	return 1;
}

static __always_inline int veer_packet_family(struct __sk_buff *skb)
{
	struct veer_packet pkt = {};
	struct veer_l2_info l2 = {};
	__u16 protocol;

	if (!skb)
		return VEER_PACKET_FAMILY_UNKNOWN;
	protocol = veer_ntohs((__u16)skb->protocol);
	if (protocol == VEER_ETH_P_IP)
		return VEER_PACKET_FAMILY_IPV4;
	if (protocol == VEER_ETH_P_IPV6)
		return VEER_PACKET_FAMILY_IPV6;
	if (!veer_packet_from_skb(skb, &pkt) || !veer_parse_l2(&pkt, &l2))
		return VEER_PACKET_FAMILY_UNKNOWN;
	if (l2.protocol == VEER_ETH_P_IP)
		return VEER_PACKET_FAMILY_IPV4;
	if (l2.protocol == VEER_ETH_P_IPV6)
		return VEER_PACKET_FAMILY_IPV6;
	return VEER_PACKET_FAMILY_UNKNOWN;
}

#define veer_lookup_plugin_ctx_v4_for_skb(skb) ({ \
	struct tc_plugin_ctx_v4 *__veer_ctx = 0; \
	if (veer_packet_family((skb)) == VEER_PACKET_FAMILY_IPV4) \
		__veer_ctx = veer_lookup_plugin_ctx_v4(); \
	__veer_ctx; \
})

#define veer_lookup_plugin_ctx_v6_for_skb(skb) ({ \
	struct tc_plugin_ctx_v6 *__veer_ctx = 0; \
	if (veer_packet_family((skb)) == VEER_PACKET_FAMILY_IPV6) \
		__veer_ctx = veer_lookup_plugin_ctx_v6(); \
	__veer_ctx; \
})

#define veer_packet_metadata_read_for_skb(skb, slot) ({ \
	struct veer_packet_metadata_value_v1 *__veer_metadata = 0; \
	int __veer_family = veer_packet_family((skb)); \
	if (__veer_family == VEER_PACKET_FAMILY_IPV4) \
		__veer_metadata = veer_packet_metadata_read_v4((slot)); \
	else if (__veer_family == VEER_PACKET_FAMILY_IPV6) \
		__veer_metadata = veer_packet_metadata_read_v6((slot)); \
	__veer_metadata; \
})

#define veer_packet_metadata_write_begin_for_skb(skb, slot) ({ \
	struct veer_packet_metadata_value_v1 *__veer_metadata = 0; \
	int __veer_family = veer_packet_family((skb)); \
	if (__veer_family == VEER_PACKET_FAMILY_IPV4) \
		__veer_metadata = veer_packet_metadata_write_begin_v4((slot)); \
	else if (__veer_family == VEER_PACKET_FAMILY_IPV6) \
		__veer_metadata = veer_packet_metadata_write_begin_v6((slot)); \
	__veer_metadata; \
})

static __always_inline struct veer_ipv4hdr *veer_ipv4(const struct veer_packet *pkt, const struct veer_ethhdr *eth)
{
	struct veer_ipv4hdr *ip = (void *)(eth + 1);
	__u32 ihl;

	if (!veer_bounds_ok(pkt, ip, sizeof(*ip)))
		return 0;
	if ((ip->ver_ihl >> 4) != 4)
		return 0;
	ihl = (ip->ver_ihl & 0x0f) * 4;
	if (ihl < sizeof(*ip))
		return 0;
	if (!veer_bounds_ok(pkt, ip, ihl))
		return 0;
	return ip;
}

static __always_inline struct veer_ipv4hdr *veer_ipv4_from_l2(const struct veer_packet *pkt, const struct veer_l2_info *l2)
{
	struct veer_ipv4hdr *ip;
	__u32 ihl;

	if (!l2 || l2->protocol != VEER_ETH_P_IP)
		return 0;
	ip = l2->network;
	if (!veer_bounds_ok(pkt, ip, sizeof(*ip)) || (ip->ver_ihl >> 4) != VEER_PACKET_FAMILY_IPV4)
		return 0;
	ihl = (ip->ver_ihl & 0x0f) * 4;
	if (ihl < sizeof(*ip) || !veer_bounds_ok(pkt, ip, ihl))
		return 0;
	return ip;
}

static __always_inline struct veer_ipv6hdr *veer_ipv6_from_l2(const struct veer_packet *pkt, const struct veer_l2_info *l2)
{
	struct veer_ipv6hdr *ip;
	__u8 version;

	if (!l2 || l2->protocol != VEER_ETH_P_IPV6)
		return 0;
	ip = l2->network;
	if (!veer_bounds_ok(pkt, ip, sizeof(*ip)))
		return 0;
	version = *((__u8 *)ip) >> 4;
	if (version != VEER_PACKET_FAMILY_IPV6)
		return 0;
	return ip;
}

static __always_inline __u32 veer_ipv4_header_len(const struct veer_ipv4hdr *ip)
{
	return (ip->ver_ihl & 0x0f) * 4;
}

static __always_inline __u16 veer_ipv4_total_len(const struct veer_ipv4hdr *ip)
{
	return veer_ntohs(ip->tot_len);
}

static __always_inline __u32 veer_ipv4_l4_offset(const struct veer_ethhdr *eth, const struct veer_ipv4hdr *ip)
{
	return (__u32)((char *)ip - (char *)eth) + veer_ipv4_header_len(ip);
}

static __always_inline void *veer_ipv4_l4(const struct veer_packet *pkt, const struct veer_ipv4hdr *ip)
{
	__u32 ihl = veer_ipv4_header_len(ip);
	void *l4 = (char *)ip + ihl;

	if (!veer_bounds_ok(pkt, l4, 1))
		return 0;
	return l4;
}

static __always_inline int veer_ipv4_l4_ports(const struct veer_packet *pkt, const struct veer_ipv4hdr *ip, struct veer_l4_ports *ports)
{
	void *l4 = veer_ipv4_l4(pkt, ip);
	struct veer_tcphdr *tcp = l4;
	struct veer_udphdr *udp = l4;

	if (!l4)
		return 0;
	if (ip->protocol == VEER_IPPROTO_TCP) {
		if (!veer_bounds_ok(pkt, tcp, sizeof(*tcp)))
			return 0;
		ports->source = veer_ntohs(tcp->source);
		ports->dest = veer_ntohs(tcp->dest);
		return 1;
	}
	if (ip->protocol == VEER_IPPROTO_UDP) {
		if (!veer_bounds_ok(pkt, udp, sizeof(*udp)))
			return 0;
		ports->source = veer_ntohs(udp->source);
		ports->dest = veer_ntohs(udp->dest);
		return 1;
	}
	return 0;
}

static __always_inline void *veer_ipv6_l4(const struct veer_packet *pkt, const struct veer_ipv6hdr *ip, __u8 *protocol)
{
	void *cursor;
	__u8 next;
	int i;

	if (!ip || !protocol)
		return 0;
	cursor = (void *)(ip + 1);
	next = ip->nexthdr;
#pragma unroll
	for (i = 0; i < VEER_MAX_IPV6_EXTENSION_HEADERS; i++) {
		struct veer_ipv6_exthdr *ext;
		__u32 length;

		if (next == VEER_IPPROTO_TCP || next == VEER_IPPROTO_UDP || next == VEER_IPPROTO_ICMPV6)
			break;
		if (next == VEER_IPPROTO_NONE || next == VEER_IPPROTO_ESP)
			return 0;
		if (next == VEER_IPPROTO_FRAGMENT) {
			struct veer_ipv6_fraghdr *frag = cursor;

			if (!veer_bounds_ok(pkt, frag, sizeof(*frag)))
				return 0;
			if ((veer_ntohs(frag->frag_off) & 0xfff8) != 0)
				return 0;
			next = frag->nexthdr;
			cursor = frag + 1;
			continue;
		}
		if (next != VEER_IPPROTO_HOPOPTS && next != VEER_IPPROTO_ROUTING && next != VEER_IPPROTO_DSTOPTS && next != VEER_IPPROTO_AH)
			return 0;
		ext = cursor;
		if (!veer_bounds_ok(pkt, ext, sizeof(*ext)))
			return 0;
		length = next == VEER_IPPROTO_AH ? ((__u32)ext->hdrlen + 2) * 4 : ((__u32)ext->hdrlen + 1) * 8;
		if (length < sizeof(*ext) || !veer_bounds_ok(pkt, ext, length))
			return 0;
		next = ext->nexthdr;
		cursor = (char *)cursor + length;
	}
	if (!veer_bounds_ok(pkt, cursor, 1))
		return 0;
	*protocol = next;
	return cursor;
}

static __always_inline int veer_ipv6_l4_ports(const struct veer_packet *pkt, const struct veer_ipv6hdr *ip, struct veer_l4_ports *ports)
{
	__u8 protocol = 0;
	void *l4 = veer_ipv6_l4(pkt, ip, &protocol);
	struct veer_tcphdr *tcp = l4;
	struct veer_udphdr *udp = l4;

	if (!l4 || !ports)
		return 0;
	if (protocol == VEER_IPPROTO_TCP) {
		if (!veer_bounds_ok(pkt, tcp, sizeof(*tcp)))
			return 0;
		ports->source = veer_ntohs(tcp->source);
		ports->dest = veer_ntohs(tcp->dest);
		return 1;
	}
	if (protocol == VEER_IPPROTO_UDP) {
		if (!veer_bounds_ok(pkt, udp, sizeof(*udp)))
			return 0;
		ports->source = veer_ntohs(udp->source);
		ports->dest = veer_ntohs(udp->dest);
		return 1;
	}
	return 0;
}

#endif
