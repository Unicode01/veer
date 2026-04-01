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
};

struct forward_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

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
};

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_FLOW_FLAG_FRONT_CLOSING 0x1
#define FORWARD_FLOW_FLAG_REPLY_SEEN 0x2
#define FORWARD_FLOW_FLAG_FULL_NAT 0x4
#define FORWARD_FLOW_FLAG_FRONT_ENTRY 0x8
#define FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2 0x10
#define FORWARD_FLOW_FLAG_COUNTED 0x20
#define FORWARD_RULE_FLAG_BRIDGE_L2 0x2
#define FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2 0x4
#define FORWARD_TCP_FLOW_REFRESH_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_REFRESH_NS (1ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)
#define FORWARD_CSUM_MANGLED_0 ((__sum16)0xffff)

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

static __always_inline void csum_replace2(__sum16 *check, __be16 old, __be16 new)
{
	__u32 csum = (~(__u32)(*check)) & 0xffff;
	csum += (~(__u32)old) & 0xffff;
	csum += (__u32)new;
	*check = csum_fold_helper(csum);
}

static __always_inline void csum_replace4(__sum16 *check, __be32 old, __be32 new)
{
	csum_replace2(check, (__be16)(old >> 16), (__be16)(new >> 16));
	csum_replace2(check, (__be16)old, (__be16)new);
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
		ctx->src_port = bpf_ntohs(tcph->source);
		ctx->dst_port = bpf_ntohs(tcph->dest);
		ctx->has_l4_checksum = 1;
		ctx->closing = tcph->fin || tcph->rst;
		return 0;
	}

	udph = (void *)iph + sizeof(*iph);
	if ((void *)(udph + 1) > data_end)
		return -1;
	ctx->src_port = bpf_ntohs(udph->source);
	ctx->dst_port = bpf_ntohs(udph->dest);
	ctx->has_l4_checksum = udph->check != 0;
	ctx->closing = 0;
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

static __always_inline int rewrite_l4_dnat(struct xdp_md *xdp, const struct packet_ctx *ctx, __u32 new_addr_host, __u16 new_port_host)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct iphdr *iph = data + ctx->l3_off;
	__be32 old_addr = bpf_htonl(ctx->dst_addr);
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->dst_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (old_addr != new_addr) {
		csum_replace4(&iph->check, old_addr, new_addr);
		iph->daddr = new_addr;
	}

	if (ctx->proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + ctx->l4_off;
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			csum_replace4(&tcph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				csum_replace2(&tcph->check, old_port, new_port);
			tcph->dest = new_port;
		}
		return 0;
	}

	{
		struct udphdr *udph = data + ctx->l4_off;
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			csum_replace4(&udph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				csum_replace2(&udph->check, old_port, new_port);
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
	struct iphdr *iph = data + ctx->l3_off;
	__be32 old_addr = bpf_htonl(ctx->src_addr);
	__be32 new_addr = bpf_htonl(new_addr_host);
	__be16 old_port = bpf_htons(ctx->src_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (old_addr != new_addr) {
		csum_replace4(&iph->check, old_addr, new_addr);
		iph->saddr = new_addr;
	}

	if (ctx->proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + ctx->l4_off;
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			csum_replace4(&tcph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				csum_replace2(&tcph->check, old_port, new_port);
			tcph->source = new_port;
		}
		return 0;
	}

	{
		struct udphdr *udph = data + ctx->l4_off;
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (ctx->has_l4_checksum && old_addr != new_addr)
			csum_replace4(&udph->check, old_addr, new_addr);
		if (old_port != new_port) {
			if (ctx->has_l4_checksum)
				csum_replace2(&udph->check, old_port, new_port);
			udph->source = new_port;
		}
		if (ctx->has_l4_checksum && udph->check == 0)
			udph->check = FORWARD_CSUM_MANGLED_0;
		return 0;
	}
}

static __always_inline int prepare_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, __u32 out_ifindex, __u32 new_src_addr, __u32 new_dst_addr, __u16 new_src_port, __u16 new_dst_port)
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
	fib.sport = bpf_htons(new_src_port);
	fib.dport = bpf_htons(new_dst_port);
	fib.tot_len = ctx->tot_len;
	fib.ipv4_src = bpf_htonl(new_src_addr);
	fib.ipv4_dst = bpf_htonl(new_dst_addr);
	fib.ifindex = out_ifindex;

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

	return prepare_redirect_v4(xdp, ctx, flow_value->in_ifindex, flow_value->front_addr, ctx->dst_addr, flow_value->front_port, ctx->dst_port);
}

static __always_inline int prepare_rule_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	if ((rule->flags & FORWARD_RULE_FLAG_BRIDGE_L2) != 0)
		return prepare_bridge_redirect_v4(xdp, rule);
	return prepare_redirect_v4(xdp, ctx, rule->out_ifindex, ctx->src_addr, rule->backend_addr, ctx->src_port, rule->backend_port);
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

SEC("xdp")
int forward_xdp(struct xdp_md *xdp)
{
	struct packet_ctx ctx = {};
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 flow_value = {};
	struct flow_value_v4 *flow;
	struct rule_value_v4 *rule;
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	__u64 now = 0;
	int update_flow = 0;
	int redirect_ifindex;
	int new_session = 0;
	int count_tcp_now = 0;
	int count_udp_now = 0;

	if (parse_ipv4_l4(xdp, &ctx) < 0)
		return XDP_PASS;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	flow_key.ifindex = xdp->ingress_ifindex;
	flow_key.src_addr = ctx.src_addr;
	flow_key.dst_addr = ctx.dst_addr;
	flow_key.src_port = ctx.src_port;
	flow_key.dst_port = ctx.dst_port;
	flow_key.proto = ctx.proto;

	flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (flow) {
		flow_value = *flow;

		if (ctx.proto == IPPROTO_UDP) {
			now = bpf_ktime_get_ns();
			if (flow_value.last_seen_ns == 0 || now < flow_value.last_seen_ns || (now - flow_value.last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
				if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
					drop_rule_udp_nat(flow_value.rule_id);
				bpf_map_delete_elem(&flows_v4, &flow_key);
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
				if (!ctx.closing) {
					flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
					count_tcp_now = 1;
					update_flow = 1;
				}
			} else if (!ctx.closing && (flow_value.last_seen_ns == 0 || now < flow_value.last_seen_ns || (now - flow_value.last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
				flow_value.last_seen_ns = now;
				update_flow = 1;
			}
		}

		if (update_flow) {
			if (bpf_map_update_elem(&flows_v4, &flow_key, &flow_value, BPF_ANY) < 0)
				return XDP_DROP;
		}
		if (count_tcp_now)
			bump_rule_tcp_active(flow_value.rule_id);

		redirect_ifindex = prepare_flow_reply_redirect_v4(xdp, &ctx, &flow_value);
		if (redirect_ifindex <= 0)
			return XDP_DROP;
		if (rewrite_l4_snat(xdp, &ctx, flow_value.front_addr, flow_value.front_port) < 0)
			return XDP_ABORTED;
		if (ctx.closing) {
			if ((flow_value.flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_tcp_active(flow_value.rule_id);
			bpf_map_delete_elem(&flows_v4, &flow_key);
		}
		return bpf_redirect((__u32)redirect_ifindex, 0);
	}

	rule = lookup_rule_v4(xdp, &ctx);
	if (!rule)
		return XDP_PASS;

	flow_key.ifindex = rule->out_ifindex;
	flow_key.src_addr = rule->backend_addr;
	flow_key.dst_addr = ctx.src_addr;
	flow_key.src_port = rule->backend_port;
	flow_key.dst_port = ctx.src_port;
	flow_key.proto = ctx.proto;

	flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
	if (!flow) {
		now = bpf_ktime_get_ns();
		flow_value.rule_id = rule->rule_id;
		flow_value.front_addr = ctx.dst_addr;
		flow_value.front_port = ctx.dst_port;
		flow_value.in_ifindex = xdp->ingress_ifindex;
		if (ctx.proto == IPPROTO_UDP) {
			flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if ((rule->flags & FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2) != 0) {
			flow_value.flags |= FORWARD_FLOW_FLAG_BRIDGE_INGRESS_L2;
			store_bridge_ingress_macs(&flow_value, eth);
		}
		if (ctx.closing) {
			flow_value.flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			flow_value.front_close_seen_ns = now;
		}
		flow_value.last_seen_ns = now;
		update_flow = 1;
		new_session = 1;
	} else if (ctx.proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			flow_value.rule_id = rule->rule_id;
			flow_value.front_addr = ctx.dst_addr;
			flow_value.front_port = ctx.dst_port;
			flow_value.in_ifindex = xdp->ingress_ifindex;
			if ((flow->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
				flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
			} else {
				flow_value.flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			if ((rule->flags & FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2) != 0) {
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
		if (ctx.closing) {
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

	redirect_ifindex = prepare_rule_redirect_v4(xdp, &ctx, rule);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_dnat(xdp, &ctx, rule->backend_addr, rule->backend_port) < 0)
		return XDP_ABORTED;
	return bpf_redirect((__u32)redirect_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
