#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_skb_store_bytes 9
#define BPF_FUNC_l3_csum_replace 10
#define BPF_FUNC_l4_csum_replace 11
#define BPF_FUNC_tail_call 12
#define BPF_FUNC_skb_load_bytes 26
#define BPF_FUNC_redirect 23
#define BPF_FUNC_skb_change_tail 38
#define BPF_FUNC_skb_adjust_room 50

#define BPF_ADJ_ROOM_MAC 1
#define BPF_ADJ_ROOM_NET 0
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7
#define TC_ACT_UNSPEC (-1)

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_PPP_SES 0x8864
#define PPP_IP 0x0021
#define PPP_IPV6 0x0057
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define FVTAP_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE 8
#define FVTAP_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE 28
#define PPPOE_TUNNEL_FLAG_COUPLED 0x1
#define PPPOE_ACT_CONTINUE (-2)

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
};

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__u16 h_proto;
} __attribute__((packed));

struct pppoe_ppp_hdr {
	__u8 ver_type;
	__u8 code;
	__u16 session_id;
	__u16 length;
	__u16 protocol;
} __attribute__((packed));

struct pppoe_tunnel_config {
	__u32 enabled;
	__u32 lan_ifindex;
	__u32 wan_ifindex;
	__u16 session_id;
	__u16 flags;
	__u8 lan_src_mac[6];
	__u8 lan_dst_mac[6];
	__u8 wan_src_mac[6];
	__u8 wan_dst_mac[6];
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

struct ipv4_l4_ctx {
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 has_l4_checksum;
	__u16 tot_len;
	int ip_src_off;
	int ip_dst_off;
	int ip_check_off;
	int l4_src_off;
	int l4_dst_off;
	int l4_check_off;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*const bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static int (*const bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *)BPF_FUNC_l3_csum_replace;
static int (*const bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;
static int (*const bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static int (*const bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static int (*const bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_change_tail;
static int (*const bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)BPF_FUNC_skb_adjust_room;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

struct bpf_map_def SEC("maps") pppoe_tunnel_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct pppoe_tunnel_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v4),
	.max_entries = 1,
};

static __always_inline __u16 bswap16(__u16 value)
{
	return (value << 8) | (value >> 8);
}

static __always_inline __u16 htons16(__u16 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return bswap16(value);
#else
	return value;
#endif
}

static __always_inline __u16 ntohs16(__u16 value)
{
	return htons16(value);
}

static __always_inline __u32 bswap32(__u32 value)
{
	return ((value & 0x000000ffU) << 24) |
		((value & 0x0000ff00U) << 8) |
		((value & 0x00ff0000U) >> 8) |
		((value & 0xff000000U) >> 24);
}

static __always_inline __u32 htonl32(__u32 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return bswap32(value);
#else
	return value;
#endif
}

static __always_inline int load_u16(struct __sk_buff *skb, __u32 off, __u16 *value)
{
	return bpf_skb_load_bytes(skb, off, value, sizeof(*value));
}

static __always_inline int load_u8(struct __sk_buff *skb, __u32 off, __u8 *value)
{
	return bpf_skb_load_bytes(skb, off, value, sizeof(*value));
}

static __always_inline int load_u32(struct __sk_buff *skb, __u32 off, __u32 *value)
{
	return bpf_skb_load_bytes(skb, off, value, sizeof(*value));
}

static __always_inline int store_eth(struct __sk_buff *skb, const __u8 *dst, const __u8 *src, __u16 proto)
{
	if (bpf_skb_store_bytes(skb, 0, dst, 6, 0) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, 6, src, 6, 0) < 0)
		return -1;
	proto = htons16(proto);
	if (bpf_skb_store_bytes(skb, 12, &proto, sizeof(proto), 0) < 0)
		return -1;
	return 0;
}

static __always_inline int parse_ipv4_l4(struct __sk_buff *skb, struct ipv4_l4_ctx *ctx)
{
	__u16 eth_proto = 0;
	__u8 ver_ihl = 0;
	__u16 frag_off = 0;
	__u16 src_port = 0;
	__u16 dst_port = 0;
	__u16 l4_check = 0;
	const int l3_off = 14;
	const int l4_off = 34;

	if (!ctx)
		return -1;
	if (load_u16(skb, 12, &eth_proto) < 0 || eth_proto != htons16(ETH_P_IP))
		return -1;
	if (load_u8(skb, l3_off, &ver_ihl) < 0 || ver_ihl != 0x45)
		return -1;
	if (load_u16(skb, l3_off + 6, &frag_off) < 0 || (ntohs16(frag_off) & 0x3fff) != 0)
		return -1;
	if (load_u8(skb, l3_off + 9, &ctx->proto) < 0)
		return -1;
	if (ctx->proto != IPPROTO_TCP && ctx->proto != IPPROTO_UDP)
		return -1;
	if (load_u16(skb, l3_off + 2, &ctx->tot_len) < 0)
		return -1;
	if (load_u32(skb, l3_off + 12, &ctx->src_addr) < 0)
		return -1;
	if (load_u32(skb, l3_off + 16, &ctx->dst_addr) < 0)
		return -1;
	if (load_u16(skb, l4_off, &src_port) < 0)
		return -1;
	if (load_u16(skb, l4_off + 2, &dst_port) < 0)
		return -1;
	ctx->src_port = ntohs16(src_port);
	ctx->dst_port = ntohs16(dst_port);
	ctx->ip_src_off = l3_off + 12;
	ctx->ip_dst_off = l3_off + 16;
	ctx->ip_check_off = l3_off + 10;
	ctx->l4_src_off = l4_off;
	ctx->l4_dst_off = l4_off + 2;
	ctx->l4_check_off = l4_off + (ctx->proto == IPPROTO_TCP ? 16 : 6);
	ctx->has_l4_checksum = 1;
	if (ctx->proto == IPPROTO_UDP) {
		if (load_u16(skb, ctx->l4_check_off, &l4_check) < 0)
			return -1;
		ctx->has_l4_checksum = l4_check != 0;
	}
	return 0;
}

static __always_inline int update_l4_addr_checksum(struct __sk_buff *skb, const struct ipv4_l4_ctx *ctx, __u32 old_addr, __u32 new_addr)
{
	__u64 flags;

	if (!ctx->has_l4_checksum)
		return 0;
	flags = BPF_F_PSEUDO_HDR | sizeof(__u32);
	if (ctx->proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	return bpf_l4_csum_replace(skb, ctx->l4_check_off, old_addr, new_addr, flags);
}

static __always_inline int update_l4_port_checksum(struct __sk_buff *skb, const struct ipv4_l4_ctx *ctx, __u16 old_port, __u16 new_port)
{
	__u64 flags = sizeof(__u16);

	if (!ctx->has_l4_checksum)
		return 0;
	if (ctx->proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	return bpf_l4_csum_replace(skb, ctx->l4_check_off, htons16(old_port), htons16(new_port), flags);
}

static __always_inline int rewrite_ipv4_src(struct __sk_buff *skb, const struct ipv4_l4_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	__u32 new_addr = htonl32(new_addr_host);
	__u16 new_port = htons16(new_port_host);

	if (ctx->src_addr != new_addr) {
		if (bpf_l3_csum_replace(skb, ctx->ip_check_off, ctx->src_addr, new_addr, sizeof(new_addr)) < 0)
			return -1;
		if (update_l4_addr_checksum(skb, ctx, ctx->src_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->ip_src_off, &new_addr, sizeof(new_addr), 0) < 0)
			return -1;
	}
	if (ctx->src_port != new_port_host) {
		if (update_l4_port_checksum(skb, ctx, ctx->src_port, new_port_host) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_src_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}
	return 0;
}

static __always_inline int rewrite_ipv4_dst(struct __sk_buff *skb, const struct ipv4_l4_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	__u32 new_addr = htonl32(new_addr_host);
	__u16 new_port = htons16(new_port_host);

	if (ctx->dst_addr != new_addr) {
		if (bpf_l3_csum_replace(skb, ctx->ip_check_off, ctx->dst_addr, new_addr, sizeof(new_addr)) < 0)
			return -1;
		if (update_l4_addr_checksum(skb, ctx, ctx->dst_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->ip_dst_off, &new_addr, sizeof(new_addr), 0) < 0)
			return -1;
	}
	if (ctx->dst_port != new_port_host) {
		if (update_l4_port_checksum(skb, ctx, ctx->dst_port, new_port_host) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_dst_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}
	return 0;
}

static __always_inline int shift_payload_part_left(struct __sk_buff *skb, __u32 off, __u32 size)
{
	__u8 buf[64];

	if (size > sizeof(buf))
		return -1;
	if (bpf_skb_load_bytes(skb, 14 + sizeof(struct pppoe_ppp_hdr) + off, buf, size) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, 14 + off, buf, size, 0) < 0)
		return -1;
	return 0;
}

static __always_inline int shift_payload_tail_left(struct __sk_buff *skb, __u32 off, __u32 remaining)
{
	if (remaining > 63)
		return -1;
	if (remaining & 32) {
		if (shift_payload_part_left(skb, off, 32) < 0)
			return -1;
		off += 32;
	}
	if (remaining & 16) {
		if (shift_payload_part_left(skb, off, 16) < 0)
			return -1;
		off += 16;
	}
	if (remaining & 8) {
		if (shift_payload_part_left(skb, off, 8) < 0)
			return -1;
		off += 8;
	}
	if (remaining & 4) {
		if (shift_payload_part_left(skb, off, 4) < 0)
			return -1;
		off += 4;
	}
	if (remaining & 2) {
		if (shift_payload_part_left(skb, off, 2) < 0)
			return -1;
		off += 2;
	}
	if (remaining & 1) {
		if (shift_payload_part_left(skb, off, 1) < 0)
			return -1;
	}
	return 0;
}

static __always_inline int shift_pppoe_payload_left(struct __sk_buff *skb, __u32 len)
{
	if (len > 1492)
		return -1;
#pragma unroll
	for (int i = 0; i < 24; i++) {
		__u32 off = (__u32)i * 64;

		if (len <= off)
			break;
		if (len >= off + 64) {
			if (shift_payload_part_left(skb, off, 64) < 0)
				return -1;
			continue;
		}
		if (shift_payload_tail_left(skb, off, len - off) < 0)
			return -1;
		break;
	}
	return 0;
}

static __always_inline int l3_packet_length(struct __sk_buff *skb, __u16 eth_proto, __u16 *length)
{
	__u16 raw = 0;

	if (!length)
		return -1;
	if (eth_proto == ETH_P_IP) {
		if (load_u16(skb, 16, &raw) < 0)
			return -1;
		*length = ntohs16(raw);
		return 0;
	}
	if (eth_proto == ETH_P_IPV6) {
		if (load_u16(skb, 18, &raw) < 0)
			return -1;
		*length = ntohs16(raw) + 40;
		return 0;
	}
	return -1;
}

static __always_inline int encap_l3_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	__u16 proto = 0;
	__u16 l3_len = 0;
	__u16 ppp_proto = 0;
	struct pppoe_ppp_hdr hdr = {};
	int act;

	if (load_u16(skb, 12, &proto) < 0)
		return TC_ACT_UNSPEC;
	proto = ntohs16(proto);
	if (proto == ETH_P_IP)
		ppp_proto = PPP_IP;
	else if (proto == ETH_P_IPV6)
		ppp_proto = PPP_IPV6;
	else
		return TC_ACT_UNSPEC;
	if (l3_packet_length(skb, proto, &l3_len) < 0)
		return TC_ACT_SHOT;
	if (l3_len > 1492)
		return TC_ACT_UNSPEC;

	if (bpf_skb_adjust_room(skb, sizeof(hdr), BPF_ADJ_ROOM_MAC, 0) < 0)
		return TC_ACT_SHOT;

	hdr.ver_type = 0x11;
	hdr.code = 0;
	hdr.session_id = htons16(cfg->session_id);
	hdr.length = htons16(l3_len + 2);
	hdr.protocol = htons16(ppp_proto);
	if (bpf_skb_store_bytes(skb, 14, &hdr, sizeof(hdr), 0) < 0)
		return TC_ACT_SHOT;
	if (store_eth(skb, cfg->wan_dst_mac, cfg->wan_src_mac, ETH_P_PPP_SES) < 0)
		return TC_ACT_SHOT;

	act = bpf_redirect(cfg->wan_ifindex, 0);
	return act == TC_ACT_REDIRECT ? act : TC_ACT_SHOT;
}

static __always_inline int encap_ipv4_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	__u16 proto = 0;

	if (load_u16(skb, 12, &proto) < 0 || proto != htons16(ETH_P_IP))
		return TC_ACT_UNSPEC;
	return encap_l3_to_pppoe(skb, cfg);
}

static __always_inline int decap_pppoe_to_l3(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	__u16 proto = 0;
	__u16 ppp_len;
	__u16 eth_proto = 0;
	struct pppoe_ppp_hdr hdr = {};
	int act;

	if (load_u16(skb, 12, &proto) < 0 || proto != htons16(ETH_P_PPP_SES))
		return TC_ACT_UNSPEC;
	if (bpf_skb_load_bytes(skb, 14, &hdr, sizeof(hdr)) < 0)
		return TC_ACT_SHOT;
	if (hdr.ver_type != 0x11 || hdr.code != 0 || ntohs16(hdr.session_id) != cfg->session_id)
		return TC_ACT_UNSPEC;
	if (hdr.protocol == htons16(PPP_IP))
		eth_proto = ETH_P_IP;
	else if (hdr.protocol == htons16(PPP_IPV6))
		eth_proto = ETH_P_IPV6;
	else
		return TC_ACT_UNSPEC;
	ppp_len = ntohs16(hdr.length);
	if (ppp_len < 2 || ppp_len > 1494)
		return TC_ACT_UNSPEC;

	if (shift_pppoe_payload_left(skb, (__u32)ppp_len - 2) < 0) {
		return TC_ACT_SHOT;
	}
	if (bpf_skb_change_tail(skb, skb->len - sizeof(hdr), 0) < 0) {
		return TC_ACT_SHOT;
	}
	if ((cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) != 0) {
		if (eth_proto != ETH_P_IP)
			return TC_ACT_UNSPEC;
		if (store_eth(skb, cfg->wan_src_mac, cfg->wan_dst_mac, eth_proto) < 0)
			return TC_ACT_SHOT;
		return PPPOE_ACT_CONTINUE;
	}
	if (store_eth(skb, cfg->lan_dst_mac, cfg->lan_src_mac, eth_proto) < 0) {
		return TC_ACT_SHOT;
	}

	act = bpf_redirect(cfg->lan_ifindex, 0);
	return act == TC_ACT_REDIRECT ? act : TC_ACT_SHOT;
}

static __always_inline int encap_forward_reply_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	__u32 key = 0;
	struct tc_plugin_ctx_v4 *plugin_ctx = bpf_map_lookup_elem(&tc_plugin_ctx_v4, &key);
	struct ipv4_l4_ctx pkt = {};
	int act;

	if ((cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) == 0)
		return TC_ACT_UNSPEC;
	if (skb->ifindex != cfg->lan_ifindex)
		return TC_ACT_UNSPEC;
	if (!plugin_ctx || !plugin_ctx->have_flow || plugin_ctx->direction != 2)
		return TC_ACT_UNSPEC;
	if (plugin_ctx->out_ifindex != cfg->wan_ifindex)
		return TC_ACT_UNSPEC;
	if (parse_ipv4_l4(skb, &pkt) < 0)
		return TC_ACT_UNSPEC;
	if (pkt.proto != plugin_ctx->proto)
		return TC_ACT_UNSPEC;
	if (!plugin_ctx->front_addr || !plugin_ctx->client_addr || !plugin_ctx->front_port || !plugin_ctx->client_port)
		return TC_ACT_UNSPEC;

	if (rewrite_ipv4_src(skb, &pkt, plugin_ctx->front_addr, plugin_ctx->front_port) < 0)
		return TC_ACT_SHOT;
	if (rewrite_ipv4_dst(skb, &pkt, plugin_ctx->client_addr, plugin_ctx->client_port) < 0)
		return TC_ACT_SHOT;
	act = encap_ipv4_to_pppoe(skb, cfg);
	return act;
}

SEC("tc/fvtap/pre_forward")
int tc_tunnel(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct pppoe_tunnel_config *cfg = bpf_map_lookup_elem(&pppoe_tunnel_config, &key);
	int act;

	if (!cfg || !cfg->enabled)
		goto next;
	if (skb->ifindex == cfg->lan_ifindex && (cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) == 0) {
		act = encap_l3_to_pppoe(skb, cfg);
		if (act != TC_ACT_UNSPEC)
			return act;
	} else if (skb->ifindex == cfg->wan_ifindex) {
		act = decap_pppoe_to_l3(skb, cfg);
		if (act == PPPOE_ACT_CONTINUE)
			goto next;
		if (act != TC_ACT_UNSPEC)
			return act;
	}

next:
	bpf_tail_call(skb, &tc_prog_chain_v4, FVTAP_TC_PROG_V4_PLUGIN_PRE_FORWARD_CONTINUE);
	return TC_ACT_UNSPEC;
}

SEC("tc/fvtap/post_reply")
int tc_reply_encap(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct pppoe_tunnel_config *cfg = bpf_map_lookup_elem(&pppoe_tunnel_config, &key);
	int act;

	if (!cfg || !cfg->enabled)
		goto next;
	act = encap_forward_reply_to_pppoe(skb, cfg);
	if (act != TC_ACT_UNSPEC)
		return act;

next:
	bpf_tail_call(skb, &tc_prog_chain_v4, FVTAP_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
