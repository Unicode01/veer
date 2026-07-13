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
#define VEER_ETH_P_IPV6 0x86dd
#define VEER_IPPROTO_ICMP 1
#define VEER_IPPROTO_TCP 6
#define VEER_IPPROTO_UDP 17

#ifndef BPF_MAP_TYPE_PROG_ARRAY
#define BPF_MAP_TYPE_PROG_ARRAY 3
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

#define VEER_TC_PROG_CHAIN_V4_MAX_ENTRIES 77
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

#define veer_tail_call(skb, slot) veer_bpf_tail_call((skb), &tc_prog_chain_v4, (slot))
#define veer_continue_pre_forward(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE)
#define veer_continue_post_lookup(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE)
#define veer_continue_pre_reply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_PRE_REPLY_CONTINUE)
#define veer_continue_post_reply(skb) veer_tail_call((skb), VEER_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE)
#define veer_lookup_plugin_ctx_v4() ({ \
	__u32 __veer_ctx_key = 0; \
	(struct tc_plugin_ctx_v4 *)veer_bpf_map_lookup_elem(&tc_plugin_ctx_v4, &__veer_ctx_key); \
})

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

#endif
