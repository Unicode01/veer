#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
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
	__u16 pad;
	__u32 out_ifindex;
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
	__u32 in_ifindex;
	__u16 front_port;
	__u16 pad;
	__u64 last_seen_ns;
};

struct forward_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct packet_ctx {
	__be32 src_addr;
	__be32 dst_addr;
	__u8 proto;
	__u8 has_l4_checksum;
	__u8 closing;
	__u8 pad;
	__u16 src_port;
	__u16 dst_port;
	int l3_off;
	int l4_off;
	int l4_check_off;
	int l4_src_off;
	int l4_dst_off;
	__u64 l4_addr_csum_flags;
	__u64 l4_port_csum_flags;
};

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)

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
	if (ctx->proto == IPPROTO_TCP) {
		tcph = (void *)(iph + 1);
		if ((void *)(tcph + 1) > data_end)
			return -1;
		ctx->src_port = bpf_ntohs(tcph->source);
		ctx->dst_port = bpf_ntohs(tcph->dest);
		ctx->has_l4_checksum = 1;
		ctx->closing = tcph->fin || tcph->rst;
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | sizeof(__be32);
		ctx->l4_port_csum_flags = sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct tcphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct tcphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct tcphdr, dest));
	} else {
		udph = (void *)(iph + 1);
		if ((void *)(udph + 1) > data_end)
			return -1;
		ctx->src_port = bpf_ntohs(udph->source);
		ctx->dst_port = bpf_ntohs(udph->dest);
		ctx->has_l4_checksum = udph->check != 0;
		ctx->closing = 0;
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(__be32);
		ctx->l4_port_csum_flags = BPF_F_MARK_MANGLED_0 | sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct udphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct udphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct udphdr, dest));
	}

	ctx->l3_off = (int)l3_off;
	ctx->l4_off = (int)l4_off;
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

static __always_inline int redirect_ifindex(__u32 ifindex)
{
	long act;

	if (!ifindex)
		return TC_ACT_SHOT;

	act = bpf_redirect_neigh(ifindex, 0, 0, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	return TC_ACT_SHOT;
}

SEC("classifier/forward_ingress")
int forward_ingress(struct __sk_buff *skb)
{
	struct packet_ctx ctx = {};
	struct rule_value_v4 *rule;
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 flow_value = {};

	if (parse_ipv4_l4(skb, &ctx) < 0)
		return TC_ACT_OK;

	rule = lookup_rule_v4(skb, &ctx);
	if (!rule)
		return TC_ACT_OK;

	flow_key.ifindex = rule->out_ifindex;
	flow_key.src_addr = rule->backend_addr;
	flow_key.dst_addr = bpf_ntohl(ctx.src_addr);
	flow_key.src_port = rule->backend_port;
	flow_key.dst_port = ctx.src_port;
	flow_key.proto = ctx.proto;

	flow_value.rule_id = rule->rule_id;
	flow_value.front_addr = bpf_ntohl(ctx.dst_addr);
	flow_value.front_port = ctx.dst_port;
	flow_value.in_ifindex = skb->ifindex;
	flow_value.last_seen_ns = bpf_ktime_get_ns();

	if (bpf_map_update_elem(&flows_v4, &flow_key, &flow_value, BPF_ANY) < 0)
		return TC_ACT_SHOT;

	if (rewrite_l4_dnat(skb, &ctx, rule->backend_addr, rule->backend_port) < 0)
		return TC_ACT_SHOT;

	return redirect_ifindex(rule->out_ifindex);
}

SEC("classifier/reply_ingress")
int reply_ingress(struct __sk_buff *skb)
{
	struct packet_ctx ctx = {};
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 *flow;
	int closing = 0;

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

	if (ctx.proto == IPPROTO_UDP) {
		__u64 now = bpf_ktime_get_ns();
		struct flow_value_v4 refreshed;

		if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			bpf_map_delete_elem(&flows_v4, &flow_key);
			return TC_ACT_OK;
		}

		refreshed = *flow;
		refreshed.last_seen_ns = now;
		if (bpf_map_update_elem(&flows_v4, &flow_key, &refreshed, BPF_ANY) < 0)
			return TC_ACT_SHOT;
		flow = bpf_map_lookup_elem(&flows_v4, &flow_key);
		if (!flow)
			return TC_ACT_SHOT;
	}

	closing = ctx.closing;
	if (rewrite_l4_snat(skb, &ctx, flow->front_addr, flow->front_port) < 0)
		return TC_ACT_SHOT;

	if (closing)
		bpf_map_delete_elem(&flows_v4, &flow_key);

	return redirect_ifindex(flow->in_ifindex);
}

char _license[] SEC("license") = "GPL";
