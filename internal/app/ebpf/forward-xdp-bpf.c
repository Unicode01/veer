#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include "include/bpf_endian.h"
#include "include/bpf_helpers.h"

#ifndef AF_INET
#define AF_INET 2
#endif

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

struct rule_stats_value_v4 {
	__u64 total_conns;
	__u64 tcp_active_conns;
	__u64 udp_nat_entries;
	__u64 icmp_nat_entries;
	__u64 bytes_in;
	__u64 bytes_out;
};

struct redirect_target_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
};

struct forward_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#ifndef FORWARD_ENABLE_TRAFFIC_STATS
#define FORWARD_ENABLE_TRAFFIC_STATS 0
#endif

struct packet_ctx {
	__u32 src_addr;
	__u32 dst_addr;
	__u8 proto;
	__u8 has_l4_checksum;
	__u8 closing;
	__u8 tos;
	__u16 src_port;
	__u16 dst_port;
	__u16 tot_len;
	__u16 l3_off;
	__u16 l4_off;
#if FORWARD_ENABLE_TRAFFIC_STATS
	__u16 payload_len;
#endif
};

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_FLOW_FLAG_FRONT_CLOSING 0x1
#define FORWARD_FLOW_FLAG_REPLY_SEEN 0x2
#define FORWARD_FLOW_FLAG_FULL_NAT 0x4
#define FORWARD_FLOW_FLAG_FRONT_ENTRY 0x8
#define FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2 0x10
#define FORWARD_FLOW_FLAG_COUNTED 0x20
#define FORWARD_RULE_FLAG_FULL_NAT 0x1
#define FORWARD_RULE_FLAG_BRIDGE_L2 0x2
#define FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2 0x4
#define FORWARD_RULE_FLAG_PREPARED_L2 0x10
#define FORWARD_TCP_FLOW_REFRESH_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_REFRESH_NS (1ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)
#define FORWARD_NAT_PORT_MIN 20000U
#define FORWARD_NAT_PORT_MAX 65535U
#define FORWARD_NAT_PORT_RANGE (FORWARD_NAT_PORT_MAX - FORWARD_NAT_PORT_MIN + 1U)
#define FORWARD_NAT_PORT_PROBE_ATTEMPTS 32
#define FORWARD_CSUM_MANGLED_0 ((__sum16)0xffff)

#if FORWARD_ENABLE_TRAFFIC_STATS
#define FORWARD_FLOW_FLAG_TRAFFIC_STATS 0x40
#define FORWARD_RULE_FLAG_TRAFFIC_STATS 0x8
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

struct bpf_map_def SEC("maps") stats_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rule_stats_value_v4),
	.max_entries = 16384,
};

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

static __always_inline __sum16 csum_replace2_val(__sum16 check, __be16 old, __be16 new)
{
	__u32 csum = (~(__u32)check) & 0xffff;
	csum += (~(__u32)old) & 0xffff;
	csum += (__u32)new;
	return csum_fold_helper(csum);
}

static __always_inline __sum16 csum_replace4_val(__sum16 check, __be32 old, __be32 new)
{
	check = csum_replace2_val(check, (__be16)(old >> 16), (__be16)(new >> 16));
	return csum_replace2_val(check, (__be16)old, (__be16)new);
}

static __always_inline int parse_ipv4_l4(struct xdp_md *xdp, struct packet_ctx *ctx)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth;
	struct forward_vlan_hdr *vh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u16 proto;
	__u16 l3_off;
	__u16 l4_off;

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
		l3_off = sizeof(*eth) + sizeof(*vh);
	} else {
		iph = (void *)(eth + 1);
		l3_off = sizeof(*eth);
	}

	if (proto != bpf_htons(ETH_P_IP))
		return -1;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4 || iph->ihl != 5)
		return -1;
	if ((bpf_ntohs(iph->frag_off) & FORWARD_IPV4_FRAG_MASK) != 0)
		return -1;
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return -1;

	l4_off = l3_off + sizeof(*iph);
	ctx->src_addr = bpf_ntohl(iph->saddr);
	ctx->dst_addr = bpf_ntohl(iph->daddr);
	ctx->proto = iph->protocol;
	ctx->tos = iph->tos;
	ctx->tot_len = bpf_ntohs(iph->tot_len);
	ctx->l3_off = l3_off;
	ctx->l4_off = l4_off;

	if (ctx->proto == IPPROTO_TCP) {
		tcph = (void *)iph + sizeof(*iph);
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
		return 0;
	}

	udph = (void *)iph + sizeof(*iph);
	if ((void *)(udph + 1) > data_end)
		return -1;
	if (bpf_ntohs(udph->len) < sizeof(*udph))
		return -1;
	ctx->src_port = bpf_ntohs(udph->source);
	ctx->dst_port = bpf_ntohs(udph->dest);
	ctx->has_l4_checksum = udph->check != 0;
	ctx->closing = 0;
	FORWARD_SET_PAYLOAD_LEN(ctx, bpf_ntohs(udph->len) - sizeof(*udph));
	return 0;
}

static __always_inline struct rule_value_v4 *lookup_rule_v4(struct xdp_md *xdp, const struct packet_ctx *ctx)
{
	struct rule_key_v4 key = {
		.ifindex = xdp->ingress_ifindex,
		.dst_addr = ctx->dst_addr,
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

static __always_inline void build_front_flow_key(__u32 in_ifindex, const struct packet_ctx *ctx, struct flow_key_v4 *key)
{
	key->ifindex = in_ifindex;
	key->src_addr = ctx->src_addr;
	key->dst_addr = ctx->dst_addr;
	key->src_port = ctx->src_port;
	key->dst_port = ctx->dst_port;
	key->proto = ctx->proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
}

static __always_inline void build_reply_flow_key_from_front(const struct rule_value_v4 *rule, const struct flow_value_v4 *front_value, __u8 proto, struct flow_key_v4 *key)
{
	key->ifindex = rule->out_ifindex;
	key->src_addr = rule->backend_addr;
	key->dst_addr = front_value->nat_addr;
	key->src_port = rule->backend_port;
	key->dst_port = front_value->nat_port;
	key->proto = proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
}

static __always_inline void build_front_flow_key_from_value(const struct flow_value_v4 *flow_value, __u8 proto, struct flow_key_v4 *key)
{
	key->ifindex = flow_value->in_ifindex;
	key->src_addr = flow_value->client_addr;
	key->dst_addr = flow_value->front_addr;
	key->src_port = flow_value->client_port;
	key->dst_port = flow_value->front_port;
	key->proto = proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
}

static __always_inline void init_fullnat_front_value(struct flow_value_v4 *front_value, const struct rule_value_v4 *rule, const struct packet_ctx *ctx, __u32 in_ifindex, __u16 nat_port)
{
	front_value->rule_id = rule->rule_id;
	front_value->front_addr = ctx->dst_addr;
	front_value->client_addr = ctx->src_addr;
	front_value->nat_addr = rule->nat_addr;
	front_value->in_ifindex = in_ifindex;
	front_value->front_port = ctx->dst_port;
	front_value->client_port = ctx->src_port;
	front_value->nat_port = nat_port;
	front_value->flags = FORWARD_FLOW_FLAG_FULL_NAT | FORWARD_FLOW_FLAG_FRONT_ENTRY;
}

static __always_inline void init_fullnat_reply_value(struct flow_value_v4 *reply_value, const struct flow_value_v4 *front_value, __u64 now)
{
	*reply_value = *front_value;
	reply_value->flags &= ~FORWARD_FLOW_FLAG_FRONT_ENTRY;
	reply_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
	reply_value->last_seen_ns = now;
}

static __always_inline __u32 fullnat_seed(const struct rule_value_v4 *rule, const struct packet_ctx *ctx)
{
	__u32 x = rule->rule_id;

	x ^= ctx->src_addr * 2654435761U;
	x ^= ctx->dst_addr * 2246822519U;
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

static __always_inline __u32 mix_nat_probe_seed(__u32 seed)
{
	seed ^= seed >> 16;
	seed *= 2246822519U;
	seed ^= seed >> 13;
	seed *= 3266489917U;
	seed ^= seed >> 16;
	return seed;
}

static __always_inline __u32 nat_probe_stride(__u32 seed)
{
	__u32 stride = (seed % (FORWARD_NAT_PORT_RANGE - 1U)) + 1U;

	if ((stride & 1U) == 0)
		stride += 1U;
	if (stride >= FORWARD_NAT_PORT_RANGE)
		stride -= (FORWARD_NAT_PORT_RANGE - 1U);
	if (stride == 0)
		stride = 1U;
	return stride;
}

static __always_inline int rewrite_l4_dnat(struct xdp_md *xdp, const struct packet_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct forward_vlan_hdr *vh;
	struct iphdr *iph;
	__be32 old_addr = bpf_htonl(ctx->dst_addr);
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->dst_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		iph = (void *)(vh + 1);
	} else {
		iph = (void *)(eth + 1);
	}
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4 || iph->ihl != 5)
		return -1;

	if (old_addr != new_addr) {
		iph->check = csum_replace4_val(iph->check, old_addr, new_addr);
		iph->daddr = new_addr;
	}

	if (ctx->proto == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)(iph + 1);
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (tcph->doff < 5)
			return -1;
		if ((void *)tcph + ((__u32)tcph->doff << 2) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			tcph->check = csum_replace4_val(tcph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				tcph->check = csum_replace2_val(tcph->check, old_port, new_port);
			tcph->dest = new_port;
		}
		return 0;
	}

	{
		struct udphdr *udph = (void *)(iph + 1);
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			udph->check = csum_replace4_val(udph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				udph->check = csum_replace2_val(udph->check, old_port, new_port);
			udph->dest = new_port;
		}
		if (ctx->has_l4_checksum && udph->check == 0)
			udph->check = FORWARD_CSUM_MANGLED_0;
		return 0;
	}
}

static __always_inline int rewrite_l4_snat(struct xdp_md *xdp, const struct packet_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct forward_vlan_hdr *vh;
	struct iphdr *iph;
	__be32 old_addr = bpf_htonl(ctx->src_addr);
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->src_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		iph = (void *)(vh + 1);
	} else {
		iph = (void *)(eth + 1);
	}
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->version != 4 || iph->ihl != 5)
		return -1;

	if (old_addr != new_addr) {
		iph->check = csum_replace4_val(iph->check, old_addr, new_addr);
		iph->saddr = new_addr;
	}

	if (ctx->proto == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)(iph + 1);
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (tcph->doff < 5)
			return -1;
		if ((void *)tcph + ((__u32)tcph->doff << 2) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			tcph->check = csum_replace4_val(tcph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				tcph->check = csum_replace2_val(tcph->check, old_port, new_port);
			tcph->source = new_port;
		}
		return 0;
	}

	{
		struct udphdr *udph = (void *)(iph + 1);
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			udph->check = csum_replace4_val(udph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				udph->check = csum_replace2_val(udph->check, old_port, new_port);
			udph->source = new_port;
		}
		if (ctx->has_l4_checksum && udph->check == 0)
			udph->check = FORWARD_CSUM_MANGLED_0;
		return 0;
	}
}

static __always_inline int prepare_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct redirect_target_v4 *target)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct bpf_fib_lookup fib = {};
	long rc;

	if ((void *)(eth + 1) > data_end)
		return -1;

	fib.family = AF_INET;
	fib.tos = ctx->tos;
	fib.l4_protocol = ctx->proto;
	fib.sport = bpf_htons(target->src_port);
	fib.dport = bpf_htons(target->dst_port);
	fib.tot_len = ctx->tot_len;
	fib.ipv4_src = bpf_htonl(target->src_addr);
	fib.ipv4_dst = bpf_htonl(target->dst_addr);
	fib.ifindex = target->ifindex;

	rc = bpf_fib_lookup(xdp, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return -1;

	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	return (int)fib.ifindex;
}

static __always_inline int prepare_bridge_redirect_v4(struct xdp_md *xdp, const struct rule_value_v4 *rule)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, rule->dst_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, rule->src_mac, ETH_ALEN);
	return (int)rule->out_ifindex;
}

static __always_inline void store_bridge_ingress_macs(struct flow_value_v4 *flow_value, const struct ethhdr *eth)
{
	flow_value->client_addr = ((__u32)eth->h_dest[0] << 24) | ((__u32)eth->h_dest[1] << 16) | ((__u32)eth->h_dest[2] << 8) | (__u32)eth->h_dest[3];
	flow_value->client_port = ((__u16)eth->h_dest[4] << 8) | (__u16)eth->h_dest[5];
	flow_value->nat_addr = ((__u32)eth->h_source[0] << 24) | ((__u32)eth->h_source[1] << 16) | ((__u32)eth->h_source[2] << 8) | (__u32)eth->h_source[3];
	flow_value->nat_port = ((__u16)eth->h_source[4] << 8) | (__u16)eth->h_source[5];
}

static __always_inline void load_bridge_ingress_front_mac(const struct flow_value_v4 *flow_value, __u8 *front_mac)
{
	front_mac[0] = (__u8)(flow_value->client_addr >> 24);
	front_mac[1] = (__u8)(flow_value->client_addr >> 16);
	front_mac[2] = (__u8)(flow_value->client_addr >> 8);
	front_mac[3] = (__u8)(flow_value->client_addr);
	front_mac[4] = (__u8)(flow_value->client_port >> 8);
	front_mac[5] = (__u8)(flow_value->client_port);
}

static __always_inline void load_bridge_ingress_client_mac(const struct flow_value_v4 *flow_value, __u8 *client_mac)
{
	client_mac[0] = (__u8)(flow_value->nat_addr >> 24);
	client_mac[1] = (__u8)(flow_value->nat_addr >> 16);
	client_mac[2] = (__u8)(flow_value->nat_addr >> 8);
	client_mac[3] = (__u8)(flow_value->nat_addr);
	client_mac[4] = (__u8)(flow_value->nat_port >> 8);
	client_mac[5] = (__u8)(flow_value->nat_port);
}

static __always_inline int prepare_flow_reply_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_value_v4 *flow_value)
{
	if ((flow_value->flags & FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2) != 0) {
		void *data = (void *)(long)xdp->data;
		void *data_end = (void *)(long)xdp->data_end;
		struct ethhdr *eth = data;
		__u8 front_mac[ETH_ALEN] = {};
		__u8 client_mac[ETH_ALEN] = {};

		if ((void *)(eth + 1) > data_end)
			return -1;

		load_bridge_ingress_front_mac(flow_value, front_mac);
		load_bridge_ingress_client_mac(flow_value, client_mac);
		__builtin_memcpy(eth->h_source, front_mac, ETH_ALEN);
		__builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
		return (int)flow_value->in_ifindex;
	}

	{
		struct redirect_target_v4 target = {
			.ifindex = flow_value->in_ifindex,
			.src_addr = flow_value->front_addr,
			.src_port = flow_value->front_port,
		};

		if (is_fullnat_reply_flow(flow_value)) {
			target.dst_addr = flow_value->client_addr;
			target.dst_port = flow_value->client_port;
		} else {
			target.dst_addr = ctx->dst_addr;
			target.dst_port = ctx->dst_port;
		}

		return prepare_redirect_v4(xdp, ctx, &target);
	}
}

static __always_inline int prepare_rule_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0)
		return prepare_bridge_redirect_v4(xdp, rule);
	{
		struct redirect_target_v4 target = {
			.ifindex = rule->out_ifindex,
			.src_addr = ctx->src_addr,
			.dst_addr = rule->backend_addr,
			.src_port = ctx->src_port,
			.dst_port = rule->backend_port,
		};

		return prepare_redirect_v4(xdp, ctx, &target);
	}
}

static __always_inline int prepare_rule_fullnat_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_value_v4 *front_value)
{
	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0)
		return prepare_bridge_redirect_v4(xdp, rule);
	{
		struct redirect_target_v4 target = {
			.ifindex = rule->out_ifindex,
			.src_addr = front_value->nat_addr,
			.dst_addr = rule->backend_addr,
			.src_port = front_value->nat_port,
			.dst_port = rule->backend_port,
		};

		return prepare_redirect_v4(xdp, ctx, &target);
	}
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

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_TCP)
			drop_rule_tcp_active(reply_value->rule_id);
		else
			drop_rule_udp_nat(reply_value->rule_id);
	}

	build_front_flow_key_from_value(reply_value, proto, &front_key);
	bpf_map_delete_elem(&flows_v4, &front_key);
	bpf_map_delete_elem(&flows_v4, reply_key);
}

static __always_inline int handle_transparent_reply(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_key_v4 *flow_key, const struct flow_value_v4 *flow)
{
	struct flow_value_v4 flow_value = {};
	__u64 now = 0;
	int update_flow = 0;
	int count_tcp_now = 0;
	int redirect_ifindex = 0;

	flow_value = *flow;
	if (ctx->proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (flow_value.last_seen_ns == 0 || now < flow_value.last_seen_ns || (now - flow_value.last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_udp_nat(flow_value.rule_id);
			bpf_map_delete_elem(&flows_v4, flow_key);
			return XDP_PASS;
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
			return XDP_DROP;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(flow_value.rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(&flow_value))
		add_rule_traffic_bytes(flow_value.rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	redirect_ifindex = prepare_flow_reply_redirect_v4(xdp, ctx, &flow_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat(xdp, ctx, flow_value.front_addr, flow_value.front_port) < 0)
		return XDP_ABORTED;
	if (ctx->closing) {
		if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
			drop_rule_tcp_active(flow_value.rule_id);
		bpf_map_delete_elem(&flows_v4, flow_key);
	}
	return bpf_redirect((__u32)redirect_ifindex, 0);
}

static __always_inline int handle_transparent_forward(struct xdp_md *xdp, __u32 in_ifindex, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 flow_value = {};
	struct flow_value_v4 *flow;
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	__u64 now = 0;
	int update_flow = 0;
	int new_session = 0;
	int count_udp_now = 0;
	int redirect_ifindex = 0;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	flow_key.ifindex = rule->out_ifindex;
	flow_key.src_addr = rule->backend_addr;
	flow_key.dst_addr = ctx->src_addr;
	flow_key.src_port = rule->backend_port;
	flow_key.dst_port = ctx->src_port;
	flow_key.proto = ctx->proto;
	flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (!flow) {
		now = bpf_ktime_get_ns();
		flow_value.rule_id = rule->rule_id;
		flow_value.front_addr = ctx->dst_addr;
		flow_value.front_port = ctx->dst_port;
		flow_value.in_ifindex = in_ifindex;
		if (ctx->proto == IPPROTO_UDP) {
			flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			flow_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0) {
			flow_value.flags |= FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2;
			store_bridge_ingress_macs(&flow_value, eth);
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
		if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			flow_value.rule_id = rule->rule_id;
			flow_value.front_addr = ctx->dst_addr;
			flow_value.front_port = ctx->dst_port;
			flow_value.in_ifindex = in_ifindex;
			flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			if ((flow->flags & FORWARD_FLOW_FLAG_COUNTED) == 0)
				count_udp_now = 1;
			if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
				flow_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
			if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0) {
				flow_value.flags |= FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2;
				store_bridge_ingress_macs(&flow_value, eth);
			}
			flow_value.last_seen_ns = now;
			update_flow = 1;
			new_session = 1;
		} else if ((now - flow->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			flow_value = *flow;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if (ctx->closing) {
			flow_value = *flow;
			flow_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			if (flow_value.front_close_seen_ns == 0)
				flow_value.front_close_seen_ns = now;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		} else if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			flow_value = *flow;
			flow_value.last_seen_ns = now;
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (bpf_map_update_elem(&flows_v4, &flow_key, &flow_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_udp_nat(rule->rule_id);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	redirect_ifindex = prepare_rule_redirect_v4(xdp, ctx, rule);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_dnat(xdp, ctx, rule->backend_addr, rule->backend_port) < 0)
		return XDP_ABORTED;
	return bpf_redirect((__u32)redirect_ifindex, 0);
}

static __always_inline int handle_fullnat_reply(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_key_v4 *reply_key, const struct flow_value_v4 *flow)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 reply_value = {};
	struct flow_value_v4 front_value = {};
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;
	int redirect_ifindex = 0;

	reply_value = *flow;
	if (ctx->proto == IPPROTO_UDP) {
		if (reply_value.last_seen_ns == 0 || now < reply_value.last_seen_ns || (now - reply_value.last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			delete_fullnat_state(reply_key, &reply_value, ctx->proto);
			return XDP_PASS;
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
			return XDP_DROP;
	}
	if (update_reply) {
		if (bpf_map_update_elem(&flows_v4, reply_key, &reply_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value.rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(&reply_value))
		add_rule_traffic_bytes(reply_value.rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	redirect_ifindex = prepare_flow_reply_redirect_v4(xdp, ctx, &reply_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat(xdp, ctx, reply_value.front_addr, reply_value.front_port) < 0)
		return XDP_ABORTED;
	if (rewrite_l4_dnat(xdp, ctx, reply_value.client_addr, reply_value.client_port) < 0)
		return XDP_ABORTED;
	if (ctx->closing)
		delete_fullnat_state(reply_key, &reply_value, ctx->proto);
	return bpf_redirect((__u32)redirect_ifindex, 0);
}

static __always_inline int handle_fullnat_forward(struct xdp_md *xdp, __u32 in_ifindex, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_value_v4 *existing_front)
{
	struct flow_key_v4 front_key = {};
	struct flow_key_v4 reply_key = {};
	struct flow_value_v4 front_value = {};
	struct flow_value_v4 reply_value = {};
	struct flow_value_v4 *front_flow = (struct flow_value_v4 *)existing_front;
	struct flow_value_v4 *reply_flow;
	__u64 now = bpf_ktime_get_ns();
	__u32 seed = 0;
	__u32 start = 0;
	__u32 stride = 0;
	__u16 preferred_port = ctx->src_port;
	int created_front = 0;
	int created_reply = 0;
	int update_front = 0;
	int update_reply = 0;
	int new_session = 0;
	int count_udp_now = 0;
	int redirect_ifindex = 0;

	build_front_flow_key(in_ifindex, ctx, &front_key);
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
			if (ctx->proto == IPPROTO_UDP)
				reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
				return XDP_DROP;
			created_reply = 1;
			if (ctx->proto == IPPROTO_UDP)
				count_udp_now = 1;
		}
		goto have_session;
	}

	seed = mix_nat_probe_seed(fullnat_seed(rule, ctx) ^ ((__u32)rule->out_ifindex << 1));
	start = seed % FORWARD_NAT_PORT_RANGE;
	stride = nat_probe_stride(seed ^ 0x9e3779b9U);

	if ((__u32)preferred_port >= FORWARD_NAT_PORT_MIN && (__u32)preferred_port <= FORWARD_NAT_PORT_MAX) {
		init_fullnat_front_value(&front_value, rule, ctx, in_ifindex, preferred_port);
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			front_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value.front_close_seen_ns = now;
		}
		front_value.last_seen_ns = now;

		init_fullnat_reply_value(&reply_value, &front_value, now);
		if (ctx->proto == IPPROTO_UDP)
			reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;

		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_NOEXIST) == 0) {
			if (bpf_map_update_elem(&flows_v4, &front_key, &front_value, BPF_NOEXIST) == 0) {
				created_front = 1;
				created_reply = 1;
				new_session = 1;
				if (ctx->proto == IPPROTO_UDP)
					count_udp_now = 1;
				goto have_session;
			}
			bpf_map_delete_elem(&flows_v4, &reply_key);
			front_flow = bpf_map_lookup_elem(&flows_v4, &front_key);
			if (is_fullnat_front_flow(front_flow)) {
				front_value = *front_flow;
				if (front_value.nat_addr == 0)
					front_value.nat_addr = rule->nat_addr;
				build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
				reply_flow = bpf_map_lookup_elem(&flows_v4, &reply_key);
				if (is_fullnat_reply_flow(reply_flow)) {
					reply_value = *reply_flow;
					goto have_session;
				}
				init_fullnat_reply_value(&reply_value, &front_value, now);
				if (ctx->proto == IPPROTO_UDP)
					reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
				if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
					return XDP_DROP;
				created_reply = 1;
				if (ctx->proto == IPPROTO_UDP)
					count_udp_now = 1;
				goto have_session;
			}
		}
	}

#pragma clang loop unroll(full)
	for (int i = 0; i < FORWARD_NAT_PORT_PROBE_ATTEMPTS; i++) {
		__u16 nat_port = (__u16)(FORWARD_NAT_PORT_MIN + ((start + ((__u32)i * stride)) % FORWARD_NAT_PORT_RANGE));

		if (nat_port == preferred_port)
			continue;

		init_fullnat_front_value(&front_value, rule, ctx, in_ifindex, nat_port);
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			front_value.flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value.front_close_seen_ns = now;
		}
		front_value.last_seen_ns = now;

		init_fullnat_reply_value(&reply_value, &front_value, now);
		if (ctx->proto == IPPROTO_UDP)
			reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;

		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_NOEXIST) < 0)
			continue;
		if (bpf_map_update_elem(&flows_v4, &front_key, &front_value, BPF_NOEXIST) == 0) {
			created_front = 1;
			created_reply = 1;
			new_session = 1;
			if (ctx->proto == IPPROTO_UDP)
				count_udp_now = 1;
			goto have_session;
		}

		bpf_map_delete_elem(&flows_v4, &reply_key);
		front_flow = bpf_map_lookup_elem(&flows_v4, &front_key);
		if (!is_fullnat_front_flow(front_flow))
			continue;

		front_value = *front_flow;
		if (front_value.nat_addr == 0)
			front_value.nat_addr = rule->nat_addr;
		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		reply_flow = bpf_map_lookup_elem(&flows_v4, &reply_key);
		if (is_fullnat_reply_flow(reply_flow)) {
			reply_value = *reply_flow;
			goto have_session;
		}
		init_fullnat_reply_value(&reply_value, &front_value, now);
		if (ctx->proto == IPPROTO_UDP)
			reply_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
			return XDP_DROP;
		created_reply = 1;
		if (ctx->proto == IPPROTO_UDP)
			count_udp_now = 1;
		goto have_session;
	}

	return XDP_DROP;

have_session:
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
			return XDP_DROP;
	}
	if (update_reply) {
		build_reply_flow_key_from_front(rule, &front_value, ctx->proto, &reply_key);
		if (bpf_map_update_elem(&flows_v4, &reply_key, &reply_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_udp_nat(rule->rule_id);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	redirect_ifindex = prepare_rule_fullnat_redirect_v4(xdp, ctx, rule, &front_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat(xdp, ctx, front_value.nat_addr, front_value.nat_port) < 0)
		return XDP_ABORTED;
	if (rewrite_l4_dnat(xdp, ctx, rule->backend_addr, rule->backend_port) < 0)
		return XDP_ABORTED;
	return bpf_redirect((__u32)redirect_ifindex, 0);
}

SEC("xdp")
int forward_xdp(struct xdp_md *xdp)
{
	struct packet_ctx ctx = {};
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 *flow;
	struct rule_value_v4 *rule;
	__u32 in_ifindex;

	if (parse_ipv4_l4(xdp, &ctx) < 0)
		return XDP_PASS;
	in_ifindex = xdp->ingress_ifindex;
	build_front_flow_key(in_ifindex, &ctx, &flow_key);

	flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (flow) {
		if (is_fullnat_front_flow(flow)) {
			rule = lookup_rule_v4(xdp, &ctx);
			if (!is_fullnat_rule(rule))
				return XDP_PASS;
			return handle_fullnat_forward(xdp, in_ifindex, &ctx, rule, flow);
		}
		if (is_fullnat_reply_flow(flow))
			return handle_fullnat_reply(xdp, &ctx, &flow_key, flow);
		return handle_transparent_reply(xdp, &ctx, &flow_key, flow);
	}

	rule = lookup_rule_v4(xdp, &ctx);
	if (!rule)
		return XDP_PASS;
	if (is_fullnat_rule(rule))
		return handle_fullnat_forward(xdp, in_ifindex, &ctx, rule, NULL);
	return handle_transparent_forward(xdp, in_ifindex, &ctx, rule);
}

char _license[] SEC("license") = "GPL";
