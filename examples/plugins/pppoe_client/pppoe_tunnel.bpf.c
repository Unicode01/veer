#include "../include/fvtap_plugin_helpers.h"

#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif

#ifndef BPF_FUNC_skb_change_tail
#define BPF_FUNC_skb_change_tail 38
#endif

#ifndef BPF_F_ADJ_ROOM_FIXED_GSO
#define BPF_F_ADJ_ROOM_FIXED_GSO (1ULL << 0)
#endif

#ifndef BPF_F_ADJ_ROOM_DECAP_L3_IPV4
#define BPF_F_ADJ_ROOM_DECAP_L3_IPV4 (1ULL << 7)
#endif

#ifndef BPF_F_ADJ_ROOM_DECAP_L3_IPV6
#define BPF_F_ADJ_ROOM_DECAP_L3_IPV6 (1ULL << 8)
#endif

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

#ifndef PPPOE_DECAP_ADJ_MODE
#define PPPOE_DECAP_ADJ_MODE BPF_ADJ_ROOM_MAC
#endif

#ifndef PPPOE_DECAP_ADJ_BASE_FLAGS
#define PPPOE_DECAP_ADJ_BASE_FLAGS BPF_F_ADJ_ROOM_FIXED_GSO
#endif

#ifndef PPPOE_DECAP_ADJ_L3_FLAGS
#define PPPOE_DECAP_ADJ_L3_FLAGS 1
#endif

#ifndef PPPOE_TUNNEL_DIAG
#define PPPOE_TUNNEL_DIAG 0
#endif

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_PPP_SES 0x8864
#define PPP_IP 0x0021
#define PPP_IPV6 0x0057
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define PPPOE_TUNNEL_FLAG_COUPLED 0x1
#define PPPOE_TUNNEL_FLAG_MANUAL_DECAP 0x2
#define PPPOE_ACT_CONTINUE (-2)

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

struct ipv4_min_hdr {
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

struct ipv6_min_hdr {
	__u32 ver_tc_flow;
	__u16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

struct tcp_min_hdr {
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

struct udp_min_hdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
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
static int (*const bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static int (*const bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_change_tail;
static int (*const bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)BPF_FUNC_skb_pull_data;
static int (*const bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)BPF_FUNC_skb_adjust_room;

FVTAP_DECLARE_PROG_CHAIN_V4();

struct bpf_map_def SEC("maps") pppoe_tunnel_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct pppoe_tunnel_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") pppoe_tunnel_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 16,
};

FVTAP_DECLARE_PLUGIN_CTX_V4();

static __always_inline void bump_tunnel_stat(__u32 index)
{
#if PPPOE_TUNNEL_DIAG
	__u64 *value = bpf_map_lookup_elem(&pppoe_tunnel_stats, &index);

	if (value)
		__sync_fetch_and_add(value, 1);
#else
	(void)index;
#endif
}

static __always_inline void set_tunnel_stat(__u32 index, __u64 stat)
{
#if PPPOE_TUNNEL_DIAG
	__u64 *value = bpf_map_lookup_elem(&pppoe_tunnel_stats, &index);

	if (value)
		*value = stat;
#else
	(void)index;
	(void)stat;
#endif
}

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

static __always_inline int store_eth(struct __sk_buff *skb, const __u8 *dst, const __u8 *src, __u16 proto)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	__builtin_memcpy(eth->h_dest, dst, 6);
	__builtin_memcpy(eth->h_source, src, 6);
	eth->h_proto = htons16(proto);
	return 0;
}

static __always_inline int mac_addr_eq(const __u8 *a, const __u8 *b)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < 6; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

static __always_inline int skb_matches_direct_lan_eth(struct __sk_buff *skb, const struct pppoe_tunnel_config *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u16 proto;

	if (!cfg || (void *)(eth + 1) > data_end)
		return 0;
	proto = ntohs16(eth->h_proto);
	if (proto != ETH_P_IP && proto != ETH_P_IPV6)
		return 0;
	if (mac_addr_eq(eth->h_dest, cfg->lan_src_mac) &&
		mac_addr_eq(eth->h_source, cfg->lan_dst_mac))
		return 1;
	return mac_addr_eq(eth->h_dest, cfg->lan_dst_mac) &&
		mac_addr_eq(eth->h_source, cfg->lan_src_mac);
}

static __always_inline int store_pppoe_hdr(struct __sk_buff *skb, const struct pppoe_ppp_hdr *hdr)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct pppoe_ppp_hdr *packet_hdr = data + 14;

	if ((void *)(packet_hdr + 1) > data_end)
		return -1;
	*packet_hdr = *hdr;
	return 0;
}

static __always_inline int parse_ipv4_l4(struct __sk_buff *skb, struct ipv4_l4_ctx *ctx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv4_min_hdr *iph;
	void *l4;
	const int l3_off = 14;
	const int l4_off = 34;

	if (!ctx)
		return -1;
	if ((void *)(eth + 1) > data_end || eth->h_proto != htons16(ETH_P_IP))
		return -1;
	iph = data + l3_off;
	if ((void *)(iph + 1) > data_end || iph->ver_ihl != 0x45)
		return -1;
	if ((ntohs16(iph->frag_off) & 0x3fff) != 0)
		return -1;
	ctx->proto = iph->protocol;
	if (ctx->proto != IPPROTO_TCP && ctx->proto != IPPROTO_UDP)
		return -1;
	ctx->tot_len = iph->tot_len;
	ctx->src_addr = iph->saddr;
	ctx->dst_addr = iph->daddr;
	ctx->ip_src_off = l3_off + 12;
	ctx->ip_dst_off = l3_off + 16;
	ctx->ip_check_off = l3_off + 10;
	ctx->l4_src_off = l4_off;
	ctx->l4_dst_off = l4_off + 2;
	ctx->l4_check_off = l4_off + (ctx->proto == IPPROTO_TCP ? 16 : 6);
	ctx->has_l4_checksum = 1;

	l4 = data + l4_off;
	if (ctx->proto == IPPROTO_TCP) {
		struct tcp_min_hdr *tcph = l4;

		if ((void *)(tcph + 1) > data_end)
			return -1;
		ctx->src_port = ntohs16(tcph->source);
		ctx->dst_port = ntohs16(tcph->dest);
		return 0;
	}
	if (ctx->proto == IPPROTO_UDP) {
		struct udp_min_hdr *udph = l4;

		if ((void *)(udph + 1) > data_end)
			return -1;
		ctx->src_port = ntohs16(udph->source);
		ctx->dst_port = ntohs16(udph->dest);
		ctx->has_l4_checksum = udph->check != 0;
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

static __always_inline int l3_packet_info(struct __sk_buff *skb, __u16 *length, __u16 *ppp_proto)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u16 eth_proto;

	if (!length || !ppp_proto)
		return -1;
	if ((void *)(eth + 1) > data_end)
		return 0;
	eth_proto = ntohs16(eth->h_proto);
	if (eth_proto == ETH_P_IP) {
		struct ipv4_min_hdr *iph = data + 14;

		if ((void *)(iph + 1) > data_end)
			return -1;
		*length = ntohs16(iph->tot_len);
		*ppp_proto = PPP_IP;
		return 1;
	}
	if (eth_proto == ETH_P_IPV6) {
		struct ipv6_min_hdr *ip6h = data + 14;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		*length = ntohs16(ip6h->payload_len) + 40;
		*ppp_proto = PPP_IPV6;
		return 1;
	}
	return 0;
}

static __always_inline int compact_pppoe_payload_to_l3(struct __sk_buff *skb, __u16 l3_len)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 copied = 0;
	__u32 new_len = 14 + (__u32)l3_len;

	if (l3_len > 1492)
		return -1;
	if (data + 22 + l3_len > data_end || data + 14 + l3_len > data_end) {
		if (bpf_skb_pull_data(skb, 22 + (__u32)l3_len) < 0) {
			bump_tunnel_stat(12);
			return -1;
		}
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;
		if (data + 22 + l3_len > data_end || data + 14 + l3_len > data_end) {
			bump_tunnel_stat(13);
			return -1;
		}
	}
#pragma clang loop unroll(disable)
	for (int i = 0; i < 187; i++) {
		void *src = data + 22 + copied;
		void *dst = data + 14 + copied;

		if (copied + 8 > l3_len)
			break;
		if (src + 8 > data_end || dst + 8 > data_end) {
			bump_tunnel_stat(13);
			return -1;
		}
		__builtin_memcpy(dst, src, 8);
		copied += 8;
	}
	if (copied < l3_len) {
#pragma clang loop unroll(full)
		for (int j = 0; j < 7; j++) {
			void *src = data + 22 + copied;
			void *dst = data + 14 + copied;

			if (copied >= l3_len)
				break;
			if (src + 1 > data_end || dst + 1 > data_end) {
				bump_tunnel_stat(13);
				return -1;
			}
			*(__u8 *)dst = *(__u8 *)src;
			copied++;
		}
	}
	if (copied != l3_len) {
		bump_tunnel_stat(14);
		return -1;
	}
	if (bpf_skb_change_tail(skb, new_len, 0) < 0) {
		bump_tunnel_stat(15);
		return -1;
	}
	return 0;
}

static __always_inline int skb_matches_ifindex(struct __sk_buff *skb, __u32 ifindex)
{
	return skb->ifindex == ifindex || skb->ingress_ifindex == ifindex;
}

static __always_inline int skb_matches_direct_lan_side(struct __sk_buff *skb, const struct pppoe_tunnel_config *cfg)
{
	if (!cfg)
		return 0;
	if (skb_matches_ifindex(skb, cfg->lan_ifindex))
		return 1;
	return skb_matches_direct_lan_eth(skb, cfg);
}

static __always_inline int encap_known_l3_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg, __u16 l3_len, __u16 ppp_proto)
{
	struct pppoe_ppp_hdr hdr = {};
	int act;

	if (l3_len > 1492)
		return TC_ACT_UNSPEC;

	if (bpf_skb_adjust_room(skb, sizeof(hdr), BPF_ADJ_ROOM_MAC, 0) < 0)
		return TC_ACT_SHOT;

	hdr.ver_type = 0x11;
	hdr.code = 0;
	hdr.session_id = htons16(cfg->session_id);
	hdr.length = htons16(l3_len + 2);
	hdr.protocol = htons16(ppp_proto);
	if (store_pppoe_hdr(skb, &hdr) < 0)
		return TC_ACT_SHOT;
	if (store_eth(skb, cfg->wan_dst_mac, cfg->wan_src_mac, ETH_P_PPP_SES) < 0)
		return TC_ACT_SHOT;

	act = bpf_redirect(cfg->wan_ifindex, 0);
	return act == TC_ACT_REDIRECT ? act : TC_ACT_SHOT;
}

static __always_inline int encap_l3_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	__u16 l3_len = 0;
	__u16 ppp_proto = 0;
	int info;

	info = l3_packet_info(skb, &l3_len, &ppp_proto);
	if (info == 0)
		return TC_ACT_UNSPEC;
	if (info < 0)
		return TC_ACT_SHOT;
	return encap_known_l3_to_pppoe(skb, cfg, l3_len, ppp_proto);
}

static __always_inline int decap_pppoe_to_l3(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct pppoe_ppp_hdr *packet_hdr;
	__u16 ppp_len;
	__u16 l3_len;
	__u16 eth_proto = 0;
	__u64 adjust_flags = PPPOE_DECAP_ADJ_BASE_FLAGS;
	struct pppoe_ppp_hdr hdr = {};
	int act;
	int ret;

	if ((void *)(eth + 1) > data_end || eth->h_proto != htons16(ETH_P_PPP_SES))
		return TC_ACT_UNSPEC;
	bump_tunnel_stat(3);
	packet_hdr = data + 14;
	if ((void *)(packet_hdr + 1) > data_end)
		return TC_ACT_SHOT;
	hdr = *packet_hdr;
	if (hdr.ver_type != 0x11 || hdr.code != 0 || ntohs16(hdr.session_id) != cfg->session_id)
		return TC_ACT_UNSPEC;
	bump_tunnel_stat(4);
	if (hdr.protocol == htons16(PPP_IP)) {
		eth_proto = ETH_P_IP;
#if PPPOE_DECAP_ADJ_L3_FLAGS
		adjust_flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4;
#endif
	} else if (hdr.protocol == htons16(PPP_IPV6)) {
		eth_proto = ETH_P_IPV6;
#if PPPOE_DECAP_ADJ_L3_FLAGS
		adjust_flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV6;
#endif
	} else {
		return TC_ACT_UNSPEC;
	}
	ppp_len = ntohs16(hdr.length);
	if (ppp_len < 2 || ppp_len > 1494)
		return TC_ACT_UNSPEC;
	l3_len = ppp_len - 2;

	if ((cfg->flags & PPPOE_TUNNEL_FLAG_MANUAL_DECAP) != 0) {
		if (compact_pppoe_payload_to_l3(skb, l3_len) < 0) {
			bump_tunnel_stat(11);
			return TC_ACT_SHOT;
		}
		bump_tunnel_stat(10);
	} else {
		ret = bpf_skb_adjust_room(skb, -(__s32)sizeof(hdr), PPPOE_DECAP_ADJ_MODE, adjust_flags);
		if (ret < 0) {
			bump_tunnel_stat(5);
			set_tunnel_stat(9, (__u64)(-ret));
			if (compact_pppoe_payload_to_l3(skb, l3_len) < 0) {
				bump_tunnel_stat(11);
				return TC_ACT_SHOT;
			}
			bump_tunnel_stat(10);
		}
	}
	if ((cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) != 0) {
		if (eth_proto != ETH_P_IP)
			return TC_ACT_UNSPEC;
		if (store_eth(skb, cfg->wan_src_mac, cfg->wan_dst_mac, eth_proto) < 0)
			return TC_ACT_SHOT;
	} else if (store_eth(skb, cfg->lan_dst_mac, cfg->lan_src_mac, eth_proto) < 0) {
		bump_tunnel_stat(6);
		return TC_ACT_SHOT;
	}
	if ((cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) != 0)
		return PPPOE_ACT_CONTINUE;

	act = bpf_redirect(cfg->lan_ifindex, 0);
	if (act == TC_ACT_REDIRECT)
		bump_tunnel_stat(7);
	else
		bump_tunnel_stat(8);
	return act == TC_ACT_REDIRECT ? act : TC_ACT_SHOT;
}

static __always_inline int encap_forward_reply_to_pppoe(struct __sk_buff *skb, struct pppoe_tunnel_config *cfg)
{
	struct tc_plugin_ctx_v4 *plugin_ctx = fvtap_lookup_plugin_ctx_v4();
	struct ipv4_l4_ctx pkt = {};
	int act;

	if ((cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) == 0)
		return TC_ACT_UNSPEC;
	if (!skb_matches_ifindex(skb, cfg->lan_ifindex))
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
	act = encap_known_l3_to_pppoe(skb, cfg, ntohs16(pkt.tot_len), PPP_IP);
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
	if (skb_matches_direct_lan_side(skb, cfg) && (cfg->flags & PPPOE_TUNNEL_FLAG_COUPLED) == 0) {
		bump_tunnel_stat(1);
		act = encap_l3_to_pppoe(skb, cfg);
		if (act != TC_ACT_UNSPEC)
			return act;
	} else {
		bump_tunnel_stat(2);
		act = decap_pppoe_to_l3(skb, cfg);
		if (act == PPPOE_ACT_CONTINUE)
			goto next;
		if (act != TC_ACT_UNSPEC)
			return act;
	}

next:
	fvtap_continue_pre_forward(skb);
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
	fvtap_continue_post_reply(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
