#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include "include/bpf_endian.h"
#include "include/bpf_helpers.h"

struct rule_key_v4 {
	__u32 ifindex;
	__u32 dst_addr;
	__u16 dst_port;
	__u8 proto;
	__u8 pad;
};

struct rule_value_v4 {
	__u32 rule_id;
	__u32 backend_addr;
	__u16 backend_port;
	__u16 flags;
	__u32 out_ifindex;
	__u32 nat_addr;
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
};

struct flow_key_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad[3];
};

struct flow_value_v4 {
	__u32 rule_id;
	__u32 front_addr;
	__u32 client_addr;
	__u32 nat_addr;
	__u32 in_ifindex;
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 flags;
	__u64 last_seen_ns;
	__u64 front_close_seen_ns;
};

struct nat_port_key_v4 {
	__u32 ifindex;
	__u32 nat_addr;
	__u16 nat_port;
	__u8 proto;
	__u8 pad;
};

struct nat_port_value_v4 {
	__u32 rule_id;
};

struct rule_stats_value_v4 {
	__u64 total_conns;
	__u64 tcp_active_conns;
	__u64 udp_nat_entries;
	__u64 bytes_in;
	__u64 bytes_out;
};

struct forward_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#ifndef FORWARD_ENABLE_TRAFFIC_STATS
#define FORWARD_ENABLE_TRAFFIC_STATS 0
#endif

struct packet_ctx {
	__be32 src_addr;
	__be32 dst_addr;
	__u8 proto;
	__u8 has_l4_checksum;
	__u8 closing;
	__u8 tos;
	__u16 src_port;
	__u16 dst_port;
	__u16 tot_len;
	int l3_off;
	int l4_off;
	int l4_check_off;
	int l4_src_off;
	int l4_dst_off;
	__u64 l4_addr_csum_flags;
	__u64 l4_port_csum_flags;
#if FORWARD_ENABLE_TRAFFIC_STATS
	__u16 payload_len;
#endif
};

#ifndef AF_INET
#define AF_INET 2
#endif

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_FLOW_FLAG_FRONT_CLOSING 0x1
#define FORWARD_FLOW_FLAG_REPLY_SEEN 0x2
#define FORWARD_FLOW_FLAG_FULL_NAT 0x4
#define FORWARD_FLOW_FLAG_FRONT_ENTRY 0x8
#define FORWARD_FLOW_FLAG_COUNTED 0x20
#define FORWARD_RULE_FLAG_FULL_NAT 0x1
#define FORWARD_RULE_FLAG_BRIDGE_L2 0x2
#define FORWARD_TCP_FLOW_REFRESH_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_REFRESH_NS (1ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)
#define FORWARD_NAT_PORT_MIN 20000U
#define FORWARD_NAT_PORT_MAX 60999U
#define FORWARD_NAT_PORT_RANGE (FORWARD_NAT_PORT_MAX - FORWARD_NAT_PORT_MIN + 1U)
#define FORWARD_NAT_PORT_PROBE_WINDOW 64
#define FORWARD_NAT_PORT_PROBE_ROUNDS 3

#if FORWARD_ENABLE_TRAFFIC_STATS
#define FORWARD_FLOW_FLAG_TRAFFIC_STATS 0x40
#define FORWARD_RULE_FLAG_TRAFFIC_STATS 0x4
#define FORWARD_RULE_TRAFFIC_ENABLED(rule) (((rule)->flags & FORWARD_RULE_FLAG_TRAFFIC_STATS) != 0)
#define FORWARD_FLOW_TRAFFIC_ENABLED(flow) (((flow)->flags & FORWARD_FLOW_FLAG_TRAFFIC_STATS) != 0)
#define FORWARD_SET_PAYLOAD_LEN(ctx, value) ((ctx)->payload_len = (__u16)(value))
#define FORWARD_GET_PAYLOAD_LEN(ctx) ((__u64)(ctx)->payload_len)
#else
#define FORWARD_FLOW_FLAG_TRAFFIC_STATS 0
#define FORWARD_RULE_FLAG_TRAFFIC_STATS 0
#define FORWARD_RULE_TRAFFIC_ENABLED(rule) 0
#define FORWARD_FLOW_TRAFFIC_ENABLED(flow) 0
#define FORWARD_SET_PAYLOAD_LEN(ctx, value) do { (void)(ctx); (void)(value); } while (0)
#define FORWARD_GET_PAYLOAD_LEN(ctx) 0ULL
#endif

struct bpf_map_def SEC("maps") rules_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct rule_key_v4),
	.value_size = sizeof(struct rule_value_v4),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") flows_v4 = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct flow_key_v4),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") nat_ports_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct nat_port_key_v4),
	.value_size = sizeof(struct nat_port_value_v4),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") stats_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rule_stats_value_v4),
	.max_entries = 16384,
};

static __always_inline int update_l4_addr_checksum(struct __sk_buff *skb, const struct packet_ctx *ctx, int check_off, __be32 old_addr, __be32 new_addr)
{
	if (!ctx->has_l4_checksum)
		return 0;
	return bpf_l4_csum_replace(skb, check_off, old_addr, new_addr, ctx->l4_addr_csum_flags);
}

static __always_inline int update_l4_port_checksum(struct __sk_buff *skb, const struct packet_ctx *ctx, int check_off, __be16 old_port, __be16 new_port)
{
	if (!ctx->has_l4_checksum)
		return 0;
	return bpf_l4_csum_replace(skb, check_off, old_port, new_port, ctx->l4_port_csum_flags);
}

static __always_inline int parse_ipv4_l4(struct __sk_buff *skb, struct packet_ctx *ctx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth;
	struct forward_vlan_hdr *vh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u16 proto;
	int l3_off;
	int l4_off;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		proto = vh->h_vlan_encapsulated_proto;
		iph = (void *)(vh + 1);
		l3_off = (int)(sizeof(*eth) + sizeof(*vh));
	} else {
		iph = (void *)(eth + 1);
		l3_off = (int)sizeof(*eth);
	}

	if (proto != bpf_htons(ETH_P_IP))
		return -1;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4)
		return -1;
	if (iph->ihl != 5)
		return -1;
	if ((bpf_ntohs(iph->frag_off) & FORWARD_IPV4_FRAG_MASK) != 0)
		return -1;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return -1;

	l4_off = l3_off + (int)sizeof(*iph);
	ctx->src_addr = iph->saddr;
	ctx->dst_addr = iph->daddr;
	ctx->proto = iph->protocol;
	ctx->tos = iph->tos;
	ctx->tot_len = bpf_ntohs(iph->tot_len);
	if (ctx->proto == IPPROTO_TCP) {
		tcph = (void *)(iph + 1);
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (tcph->doff < 5)
			return -1;
		if ((void *)tcph + ((__u32)tcph->doff << 2) > data_end)
			return -1;
		ctx->src_port = bpf_ntohs(tcph->source);
		ctx->dst_port = bpf_ntohs(tcph->dest);
		ctx->has_l4_checksum = 1;
		ctx->closing = tcph->fin || tcph->rst;
		FORWARD_SET_PAYLOAD_LEN(ctx, 0);
		if (ctx->tot_len > (sizeof(*iph) + (((__u16)tcph->doff) << 2)))
			FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*iph) + (((__u16)tcph->doff) << 2)));
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | sizeof(__be32);
		ctx->l4_port_csum_flags = sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct tcphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct tcphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct tcphdr, dest));
	} else {
		udph = (void *)(iph + 1);
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (bpf_ntohs(udph->len) < sizeof(*udph))
			return -1;
		ctx->src_port = bpf_ntohs(udph->source);
		ctx->dst_port = bpf_ntohs(udph->dest);
		ctx->has_l4_checksum = udph->check != 0;
		ctx->closing = 0;
		FORWARD_SET_PAYLOAD_LEN(ctx, bpf_ntohs(udph->len) - sizeof(*udph));
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(__be32);
		ctx->l4_port_csum_flags = BPF_F_MARK_MANGLED_0 | sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct udphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct udphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct udphdr, dest));
	}

	ctx->l3_off = l3_off;
	ctx->l4_off = l4_off;
	return 0;
}

static __always_inline struct rule_value_v4 *lookup_rule_v4(struct __sk_buff *skb, const struct packet_ctx *ctx)
{
	struct rule_key_v4 key = {
		.ifindex = skb->ifindex,
		.dst_addr = bpf_ntohl(ctx->dst_addr),
		.dst_port = ctx->dst_port,
		.proto = ctx->proto,
	};
	struct rule_value_v4 *rule;

	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = 0;
	return bpf_map_lookup_elem(&rules_v4, &key);
}

static __always_inline int rewrite_l4_dnat(struct __sk_buff *skb, const struct packet_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	const int ip_check_off = ctx->l3_off + offsetof(struct iphdr, check);
	const int ip_dst_off = ctx->l3_off + offsetof(struct iphdr, daddr);
	__be32 old_addr = ctx->dst_addr;
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->dst_port);
	__be16 new_port = bpf_htons(new_port_host);

	if (old_addr != new_addr) {
		if (bpf_l3_csum_replace(skb, ip_check_off, old_addr, new_addr, sizeof(new_addr)) < 0)
			return -1;
		if (update_l4_addr_checksum(skb, ctx, ctx->l4_check_off, old_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ip_dst_off, &new_addr, sizeof(new_addr), 0) < 0)
			return -1;
	}

	if (old_port != new_port) {
		if (update_l4_port_checksum(skb, ctx, ctx->l4_check_off, old_port, new_port) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_dst_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}

	return 0;
}

static __always_inline int rewrite_l4_snat(struct __sk_buff *skb, const struct packet_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	const int ip_check_off = ctx->l3_off + offsetof(struct iphdr, check);
	const int ip_src_off = ctx->l3_off + offsetof(struct iphdr, saddr);
	__be32 old_addr = ctx->src_addr;
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->src_port);
	__be16 new_port = bpf_htons(new_port_host);

	if (old_addr != new_addr) {
		if (bpf_l3_csum_replace(skb, ip_check_off, old_addr, new_addr, sizeof(new_addr)) < 0)
			return -1;
		if (update_l4_addr_checksum(skb, ctx, ctx->l4_check_off, old_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ip_src_off, &new_addr, sizeof(new_addr), 0) < 0)
			return -1;
	}

	if (old_port != new_port) {
		if (update_l4_port_checksum(skb, ctx, ctx->l4_check_off, old_port, new_port) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_src_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}

	return 0;
}

static __always_inline int redirect_ifindex(struct __sk_buff *skb, const struct packet_ctx *ctx, __u32 ifindex, __u32 src_addr, __u32 dst_addr, __u16 src_port, __u16 dst_port)
{
	struct bpf_fib_lookup fib = {};
	long act;

	if (!ifindex)
		return TC_ACT_SHOT;

	fib.family = AF_INET;
	fib.tos = ctx->tos;
	fib.l4_protocol = ctx->proto;
	fib.sport = bpf_htons(src_port);
	fib.dport = bpf_htons(dst_port);
	fib.tot_len = ctx->tot_len;
	fib.ipv4_src = bpf_htonl(src_addr);
	fib.ipv4_dst = bpf_htonl(dst_addr);
	fib.ifindex = ifindex;

	act = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (act == BPF_FIB_LKUP_RET_SUCCESS) {
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), fib.dmac, ETH_ALEN, 0) < 0)
			return TC_ACT_SHOT;
		if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), fib.smac, ETH_ALEN, 0) < 0)
			return TC_ACT_SHOT;
		act = bpf_redirect(fib.ifindex ? fib.ifindex : ifindex, 0);
		if (act == TC_ACT_REDIRECT)
			return (int)act;
	}

	act = bpf_redirect_neigh(ifindex, 0, 0, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	return TC_ACT_SHOT;
}

static __always_inline int redirect_bridge_ifindex(struct __sk_buff *skb, const struct rule_value_v4 *rule)
{
	if (!rule || !rule->out_ifindex)
		return TC_ACT_SHOT;
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), rule->dst_mac, ETH_ALEN, 0) < 0)
		return TC_ACT_SHOT;
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), rule->src_mac, ETH_ALEN, 0) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(rule->out_ifindex, 0);
}

static __always_inline int is_fullnat_rule(const struct rule_value_v4 *rule)
{
	return rule && (rule->flags & FORWARD_RULE_FLAG_FULL_NAT) != 0;
}

static __always_inline int is_fullnat_front_flow(const struct flow_value_v4 *flow)
{
	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) == 0)
		return 0;
	if (flow->nat_addr == 0 || flow->nat_port == 0)
		return 0;
	return 1;
}

static __always_inline int is_fullnat_reply_flow(const struct flow_value_v4 *flow)
{
	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) != 0)
		return 0;
	if (flow->nat_addr == 0 || flow->nat_port == 0)
		return 0;
	return 1;
}

static __always_inline void build_front_flow_key(struct __sk_buff *skb, const struct packet_ctx *ctx, struct flow_key_v4 *key)
{
	key->ifindex = skb->ifindex;
	key->src_addr = bpf_ntohl(ctx->src_addr);
	key->dst_addr = bpf_ntohl(ctx->dst_addr);
	key->src_port = ctx->src_port;
	key->dst_port = ctx->dst_port;
	key->proto = ctx->proto;
}

static __always_inline void build_reply_flow_key_from_front(const struct rule_value_v4 *rule, const struct flow_value_v4 *front_value, __u8 proto, struct flow_key_v4 *key)
{
	key->ifindex = rule->out_ifindex;
	key->src_addr = rule->backend_addr;
	key->dst_addr = front_value->nat_addr;
	key->src_port = rule->backend_port;
	key->dst_port = front_value->nat_port;
	key->proto = proto;
}

static __always_inline void build_front_flow_key_from_value(const struct flow_value_v4 *flow_value, __u8 proto, struct flow_key_v4 *key)
{
	key->ifindex = flow_value->in_ifindex;
	key->src_addr = flow_value->client_addr;
	key->dst_addr = flow_value->front_addr;
	key->src_port = flow_value->client_port;
	key->dst_port = flow_value->front_port;
	key->proto = proto;
}

static __always_inline void build_nat_port_key(__u32 ifindex, __u32 nat_addr, __u16 nat_port, __u8 proto, struct nat_port_key_v4 *key)
{
	key->ifindex = ifindex;
	key->nat_addr = nat_addr;
	key->nat_port = nat_port;
	key->proto = proto;
	key->pad = 0;
}

static __always_inline __u32 fullnat_seed(const struct rule_value_v4 *rule, const struct packet_ctx *ctx)
{
	__u32 x = rule->rule_id;

	x ^= bpf_ntohl(ctx->src_addr) * 2654435761U;
	x ^= bpf_ntohl(ctx->dst_addr) * 2246822519U;
	x ^= ((__u32)ctx->src_port << 16) | (__u32)ctx->dst_port;
	x ^= ((__u32)ctx->proto << 24);
	x ^= rule->backend_addr;
	x ^= ((__u32)rule->backend_port << 16) | (__u32)(rule->backend_port ^ ctx->src_port);
	x ^= x >> 16;
	x *= 2246822519U;
	x ^= x >> 13;
	x *= 3266489917U;
	x ^= x >> 16;
	return x;
}

static __always_inline int reserve_nat_port_window(__u32 seed, __u32 stride, struct nat_port_key_v4 *nat_key, const struct nat_port_value_v4 *nat_value, __u16 *nat_port)
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < FORWARD_NAT_PORT_PROBE_WINDOW; i++) {
		__u32 candidate = FORWARD_NAT_PORT_MIN + ((seed + ((__u32)i * stride)) % FORWARD_NAT_PORT_RANGE);

		nat_key->nat_port = (__u16)candidate;
		if (bpf_map_update_elem(&nat_ports_v4, nat_key, nat_value, BPF_NOEXIST) == 0) {
			*nat_port = (__u16)candidate;
			return 0;
		}
	}

	return -1;
}

static __always_inline int reserve_nat_port(const struct rule_value_v4 *rule, const struct packet_ctx *ctx, struct nat_port_key_v4 *nat_key, __u16 *nat_port)
{
	struct nat_port_value_v4 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u32 seed = fullnat_seed(rule, ctx);
	__u32 round_seed = seed;
	int round;

	nat_key->ifindex = rule->out_ifindex;
	nat_key->nat_addr = rule->nat_addr;
	nat_key->proto = ctx->proto;
	nat_key->pad = 0;

#pragma clang loop unroll(full)
	for (round = 0; round < FORWARD_NAT_PORT_PROBE_ROUNDS; round++) {
		__u32 stride = 977U + ((__u32)round * 624U);
		if (reserve_nat_port_window(round_seed, stride, nat_key, &nat_value, nat_port) == 0)
			return 0;
		round_seed ^= 0x9e3779b9U + ((__u32)round * 0x85ebca6bU);
		round_seed = (round_seed << 13) | (round_seed >> 19);
	}

	return -1;
}

static __always_inline struct rule_stats_value_v4 *lookup_rule_stats(__u32 rule_id)
{
	struct rule_stats_value_v4 initial = {};
	struct rule_stats_value_v4 *stats;

	stats = bpf_map_lookup_elem(&stats_v4, &rule_id);
	if (stats)
		return stats;
	if (bpf_map_update_elem(&stats_v4, &rule_id, &initial, BPF_NOEXIST) == 0)
		return bpf_map_lookup_elem(&stats_v4, &rule_id);

	stats = bpf_map_lookup_elem(&stats_v4, &rule_id);
	return stats;
}

static __always_inline void bump_rule_total_conns(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->total_conns += 1;
}

static __always_inline void bump_rule_tcp_active(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->tcp_active_conns += 1;
}

static __always_inline void drop_rule_tcp_active(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->tcp_active_conns -= 1;
}

static __always_inline void bump_rule_udp_nat(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->udp_nat_entries += 1;
}

static __always_inline void drop_rule_udp_nat(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->udp_nat_entries -= 1;
}

static __always_inline void add_rule_traffic_bytes(__u32 rule_id, __u64 bytes_in, __u64 bytes_out)
{
#if !FORWARD_ENABLE_TRAFFIC_STATS
	(void)rule_id;
	(void)bytes_in;
	(void)bytes_out;
	return;
#else
	struct rule_stats_value_v4 *stats;

	if (bytes_in == 0 && bytes_out == 0)
		return;

	stats = lookup_rule_stats(rule_id);
	if (!stats)
		return;
	if (bytes_in != 0)
		stats->bytes_in += bytes_in;
	if (bytes_out != 0)
		stats->bytes_out += bytes_out;
#endif
}

static __always_inline void delete_fullnat_state(const struct flow_key_v4 *reply_key, const struct flow_value_v4 *reply_value, __u8 proto)
{
	struct flow_key_v4 front_key = {};
	struct nat_port_key_v4 nat_key = {};

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_UDP)
			drop_rule_udp_nat(reply_value->rule_id);
		else
			drop_rule_tcp_active(reply_value->rule_id);
	}

	build_front_flow_key_from_value(reply_value, proto, &front_key);
	build_nat_port_key(reply_key->ifindex, reply_value->nat_addr, reply_value->nat_port, proto, &nat_key);
	bpf_map_delete_elem(&flows_v4, &front_key);
	bpf_map_delete_elem(&flows_v4, reply_key);
	bpf_map_delete_elem(&nat_ports_v4, &nat_key);
}

static __always_inline void init_fullnat_front_value(struct flow_value_v4 *front_value, const struct rule_value_v4 *rule, struct __sk_buff *skb, const struct packet_ctx *ctx, __u16 nat_port, __u64 now)
{
	front_value->rule_id = rule->rule_id;
	front_value->front_addr = bpf_ntohl(ctx->dst_addr);
	front_value->client_addr = bpf_ntohl(ctx->src_addr);
	front_value->nat_addr = rule->nat_addr;
	front_value->in_ifindex = skb->ifindex;
	front_value->front_port = ctx->dst_port;
	front_value->client_port = ctx->src_port;
	front_value->nat_port = nat_port;
	front_value->flags = FORWARD_FLOW_FLAG_FULL_NAT | FORWARD_FLOW_FLAG_FRONT_ENTRY;
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
	if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		front_value->front_close_seen_ns = now;
	}
	front_value->last_seen_ns = now;
}

static __always_inline void init_fullnat_reply_value(struct flow_value_v4 *reply_value, const struct flow_value_v4 *front_value, __u64 now)
{
	*reply_value = *front_value;
	reply_value->flags &= ~FORWARD_FLOW_FLAG_FRONT_ENTRY;
	reply_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
	reply_value->last_seen_ns = now;
}

static __always_inline int handle_transparent_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 flow_value = {};
	struct flow_value_v4 *existing_flow;
	__u64 now = 0;
	int update_flow = 0;
	int new_session = 0;
	int count_udp_now = 0;

	flow_key.ifindex = rule->out_ifindex;
	flow_key.src_addr = rule->backend_addr;
	flow_key.dst_addr = bpf_ntohl(ctx->src_addr);
	flow_key.src_port = rule->backend_port;
	flow_key.dst_port = ctx->src_port;
	flow_key.proto = ctx->proto;

	existing_flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (!existing_flow) {
		now = bpf_ktime_get_ns();
		flow_value.rule_id = rule->rule_id;
		flow_value.front_addr = bpf_ntohl(ctx->dst_addr);
		flow_value.front_port = ctx->dst_port;
		flow_value.in_ifindex = skb->ifindex;
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			flow_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->proto == IPPROTO_UDP) {
			flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (ctx->closing) {
			flow_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			flow_value.front_close_seen_ns = now;
		}
		flow_value.last_seen_ns = now;
		update_flow = 1;
		new_session = 1;
	} else if (ctx->proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (existing_flow->last_seen_ns == 0 || now < existing_flow->last_seen_ns || (now - existing_flow->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			flow_value.rule_id = rule->rule_id;
			flow_value.front_addr = bpf_ntohl(ctx->dst_addr);
			flow_value.front_port = ctx->dst_port;
			flow_value.in_ifindex = skb->ifindex;
			if (FORWARD_FLOW_TRAFFIC_ENABLED(existing_flow) || FORWARD_RULE_TRAFFIC_ENABLED(rule))
				flow_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
			if ((existing_flow->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
				flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			} else {
				flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			flow_value.last_seen_ns = now;
			update_flow = 1;
			new_session = 1;
		} else if ((now - existing_flow->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			flow_value = *existing_flow;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if (ctx->closing) {
			flow_value = *existing_flow;
			flow_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			if (flow_value.front_close_seen_ns == 0)
				flow_value.front_close_seen_ns = now;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		} else if (existing_flow->last_seen_ns == 0 || now < existing_flow->last_seen_ns || (now - existing_flow->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			flow_value = *existing_flow;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (bpf_map_update_elem(&flows_v4, &flow_key, &flow_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_udp_nat(rule->rule_id);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	if (rewrite_l4_dnat(skb, ctx, rule->backend_addr, rule->backend_port) < 0)
		return TC_ACT_SHOT;

	if ((rule->flags & FORWARD_RULE_FLAG_BRIDGE_L2) != 0)
		return redirect_bridge_ifindex(skb, rule);
	return redirect_ifindex(skb, ctx, rule->out_ifindex, bpf_ntohl(ctx->src_addr), rule->backend_addr, ctx->src_port, rule->backend_port);
}

static __always_inline int handle_fullnat_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 front_key = {};
	struct flow_key_v4 reply_key = {};
	struct nat_port_key_v4 nat_key = {};
	struct flow_value_v4 front_value = {};
	struct flow_value_v4 reply_value = {};
	struct flow_value_v4 *front_flow;
	struct flow_value_v4 *reply_flow;
	struct nat_port_value_v4 nat_value = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	int created_front = 0;
	int created_reply = 0;
	int update_front = 0;
	int update_reply = 0;
	int new_session = 0;
	int count_udp_now = 0;

	build_front_flow_key(skb, ctx, &front_key);
	front_flow = bpf_map_lookup_elem(&flows_v4, &front_key);
	if (is_fullnat_front_flow(front_flow)) {
		front_value = *front_flow;
		if (front_value.nat_addr == 0)
			front_value.nat_addr = rule->nat_addr;

		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		reply_flow = bpf_map_lookup_elem(&flows_v4, &reply_key);
		if (is_fullnat_reply_flow(reply_flow)) {
			reply_value = *reply_flow;
		} else {
			init_fullnat_reply_value(&reply_value, &front_value, now);
			if (ctx->proto == IPPROTO_UDP) {
				reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
			created_reply = 1;
		}

		build_nat_port_key(rule->out_ifindex, front_value.nat_addr, front_value.nat_port, ctx->proto, &nat_key);
		nat_value.rule_id = rule->rule_id;
		(void)bpf_map_update_elem(&nat_ports_v4, &nat_key, &nat_value, BPF_NOEXIST);
	} else {
		if (reserve_nat_port(rule, ctx, &nat_key, &nat_port) < 0)
			return TC_ACT_SHOT;

		init_fullnat_front_value(&front_value, rule, skb, ctx, nat_port, now);
		if (bpf_map_update_elem(&flows_v4, &front_key, &front_value, BPF_NOEXIST) < 0) {
			bpf_map_delete_elem(&nat_ports_v4, &nat_key);

			front_flow = bpf_map_lookup_elem(&flows_v4, &front_key);
			if (!is_fullnat_front_flow(front_flow))
				return TC_ACT_SHOT;
			front_value = *front_flow;
			if (front_value.nat_addr == 0)
				front_value.nat_addr = rule->nat_addr;
		} else {
			created_front = 1;
			new_session = 1;
		}

		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		init_fullnat_reply_value(&reply_value, &front_value, now);
		if (ctx->proto == IPPROTO_UDP) {
			reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0) {
			if (created_front)
				bpf_map_delete_elem(&flows_v4, &front_key);
			bpf_map_delete_elem(&nat_ports_v4, &nat_key);
			return TC_ACT_SHOT;
		}
		created_reply = 1;
	}

	if (ctx->proto == IPPROTO_UDP) {
		if (!created_front && (front_value.last_seen_ns == 0 || now < front_value.last_seen_ns || (now - front_value.last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			front_value.last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			reply_value.last_seen_ns = now;
			update_reply = 1;
		}
	} else if (ctx->closing) {
		front_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (front_value.front_close_seen_ns == 0)
			front_value.front_close_seen_ns = now;
		front_value.last_seen_ns = now;
		update_front = 1;

		reply_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (reply_value.front_close_seen_ns == 0)
			reply_value.front_close_seen_ns = now;
		reply_value.last_seen_ns = now;
		update_reply = 1;
	} else {
		if (!created_front && (front_value.last_seen_ns == 0 || now < front_value.last_seen_ns || (now - front_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			front_value.last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value.last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front) {
		if (bpf_map_update_elem(&flows_v4, &front_key, &front_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (update_reply) {
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_udp_nat(rule->rule_id);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	if (rewrite_l4_snat(skb, ctx, front_value.nat_addr, front_value.nat_port) < 0)
		return TC_ACT_SHOT;
	if (rewrite_l4_dnat(skb, ctx, rule->backend_addr, rule->backend_port) < 0)
		return TC_ACT_SHOT;

	if ((rule->flags & FORWARD_RULE_FLAG_BRIDGE_L2) != 0)
		return redirect_bridge_ifindex(skb, rule);
	return redirect_ifindex(skb, ctx, rule->out_ifindex, front_value.nat_addr, rule->backend_addr, front_value.nat_port, rule->backend_port);
}

static __always_inline int handle_transparent_reply(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct flow_key_v4 *flow_key, const struct flow_value_v4 *flow)
{
	struct flow_value_v4 flow_value = *flow;
	__u64 now = 0;
	int update_flow = 0;
	int closing;
	int count_tcp_now = 0;

	if (ctx->proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (flow_value.last_seen_ns == 0 || now < flow_value.last_seen_ns || (now - flow_value.last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_udp_nat(flow_value.rule_id);
			bpf_map_delete_elem(&flows_v4, flow_key);
			return TC_ACT_OK;
		}
		if ((now - flow_value.last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if ((flow_value.flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			flow_value.flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			flow_value.last_seen_ns = now;
			if (!ctx->closing) {
				flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_tcp_now = 1;
				update_flow = 1;
			}
		} else if (!ctx->closing && (flow_value.last_seen_ns == 0 || now < flow_value.last_seen_ns || (now - flow_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (bpf_map_update_elem(&flows_v4, flow_key, &flow_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(flow_value.rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(&flow_value))
		add_rule_traffic_bytes(flow_value.rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	closing = ctx->closing;
	if (rewrite_l4_snat(skb, ctx, flow_value.front_addr, flow_value.front_port) < 0)
		return TC_ACT_SHOT;

	if (closing) {
		if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
			drop_rule_tcp_active(flow_value.rule_id);
		bpf_map_delete_elem(&flows_v4, flow_key);
	}

	return redirect_ifindex(skb, ctx, flow_value.in_ifindex, flow_value.front_addr, bpf_ntohl(ctx->dst_addr), flow_value.front_port, ctx->dst_port);
}

static __always_inline int handle_fullnat_reply(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct flow_key_v4 *reply_key, const struct flow_value_v4 *flow)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 reply_value = *flow;
	struct flow_value_v4 front_value = {};
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;

	if (ctx->proto == IPPROTO_UDP) {
		if (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			delete_fullnat_state(reply_key, &reply_value, ctx->proto);
			return TC_ACT_OK;
		}
	}

	build_front_flow_key_from_value(&reply_value, ctx->proto, &front_key);
	front_flow = bpf_map_lookup_elem(&flows_v4, &front_key);
	if (is_fullnat_front_flow(front_flow)) {
		front_value = *front_flow;
	} else {
		front_value = reply_value;
		front_value.flags |= FORWARD_FLOW_FLAG_FRONT_ENTRY;
		front_value.flags |= FORWARD_FLOW_FLAG_FULL_NAT;
		update_front = 1;
	}

	if (ctx->proto == IPPROTO_UDP) {
		if (front_value.last_seen_ns == 0 || now < front_value.last_seen_ns || (now - front_value.last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			front_value.last_seen_ns = now;
			update_front = 1;
		}
		if (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			reply_value.last_seen_ns = now;
			update_reply = 1;
		}
	} else if (!ctx->closing) {
		if ((reply_value.flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			reply_value.flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			reply_value.last_seen_ns = now;
			update_reply = 1;
			count_tcp_now = 1;
		} else if (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			reply_value.last_seen_ns = now;
			update_reply = 1;
		}

		if ((front_value.flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			front_value.flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			front_value.last_seen_ns = now;
			update_front = 1;
		} else if (front_value.last_seen_ns == 0 || now < front_value.last_seen_ns || (now - front_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			front_value.last_seen_ns = now;
			update_front = 1;
		}
	}

	if (update_front) {
		if (bpf_map_update_elem(&flows_v4, &front_key, &front_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (update_reply) {
		if (bpf_map_update_elem(&flows_v4, reply_key, &reply_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value.rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(&reply_value))
		add_rule_traffic_bytes(reply_value.rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	if (rewrite_l4_snat(skb, ctx, reply_value.front_addr, reply_value.front_port) < 0)
		return TC_ACT_SHOT;
	if (rewrite_l4_dnat(skb, ctx, reply_value.client_addr, reply_value.client_port) < 0)
		return TC_ACT_SHOT;

	if (ctx->closing)
		delete_fullnat_state(reply_key, &reply_value, ctx->proto);

	return redirect_ifindex(skb, ctx, reply_value.in_ifindex, reply_value.front_addr, reply_value.client_addr, reply_value.front_port, reply_value.client_port);
}

SEC("classifier/forward_ingress")
int forward_ingress(struct __sk_buff *skb)
{
	struct packet_ctx ctx = {};
	struct rule_value_v4 *rule;

	if (parse_ipv4_l4(skb, &ctx) < 0)
		return TC_ACT_OK;

	rule = lookup_rule_v4(skb, &ctx);
	if (!rule)
		return TC_ACT_OK;

	if (is_fullnat_rule(rule))
		return handle_fullnat_forward(skb, &ctx, rule);
	return handle_transparent_forward(skb, &ctx, rule);
}

SEC("classifier/reply_ingress")
int reply_ingress(struct __sk_buff *skb)
{
	struct packet_ctx ctx = {};
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 *flow;

	if (parse_ipv4_l4(skb, &ctx) < 0)
		return TC_ACT_OK;

	flow_key.ifindex = skb->ifindex;
	flow_key.src_addr = bpf_ntohl(ctx.src_addr);
	flow_key.dst_addr = bpf_ntohl(ctx.dst_addr);
	flow_key.src_port = ctx.src_port;
	flow_key.dst_port = ctx.dst_port;
	flow_key.proto = ctx.proto;

	flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (!flow)
		return TC_ACT_OK;

	if (is_fullnat_reply_flow(flow))
		return handle_fullnat_reply(skb, &ctx, &flow_key, flow);
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) != 0)
		return TC_ACT_OK;
	return handle_transparent_reply(skb, &ctx, &flow_key, flow);
}

char _license[] SEC("license") = "GPL";
