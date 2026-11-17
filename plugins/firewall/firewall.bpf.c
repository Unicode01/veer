/*
 * Stateless source filter for TCP and UDP destination ports, run by the Veer
 * XDP dispatcher ahead of the TC dataplane. The control script (control.js)
 * owns every map: it writes a whole rule set into the inactive generation and
 * then flips fw_cfg.generation, so a packet never sees half of an update.
 *
 * Per packet: one fw_cfg lookup, header parsing and one fw_port_bits lookup.
 * Only packets to a port some policy covers go on to the LPM tables. Anything
 * the program cannot parse passes: the filter fails open.
 */
#include "../include/veer_plugin_helpers.h"

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_LPM_TRIE
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1
#endif

#define FW_ETH_P_PPPOE_SESSION 0x8864
#define FW_PPP_IPV4 0x0021
#define FW_PPP_IPV6 0x0057

#define FW_PROTO_TCP 0
#define FW_PROTO_UDP 1
#define FW_PORT_WORDS 1024 /* 65536 ports / 64 bits */
#define FW_PORT_WORDS_PER_GEN (2 * FW_PORT_WORDS)
#define FW_MAX_CLASSES 1024
#define FW_MAX_POLICIES 256
#define FW_COUNTERS 4

/* fw_cfg.flags */
#define FW_CFG_HAS_L3 1 /* some bound interface carries packets without Ethernet */
#define FW_CFG_ACTIVE 2 /* the generation holds at least one policy */

/* fw_ifaces values */
#define FW_IFACE_L3 1

/* fw_policy.flags */
#define FW_POLICY_VALID 1

#define FW_ACTION_PASS 0
#define FW_ACTION_DROP 1

/* fw_stats counters, per policy slot */
#define FW_CNT_PASS 0
#define FW_CNT_DROP 1
#define FW_CNT_TRUSTED 2
/* Slot 0 is no policy; its counter 3 counts packets dropped as evasive. */
#define FW_CNT_EVASIVE 3

/* fw_parse results */
#define FW_PARSE_PASS 0    /* not TCP or UDP the filter judges */
#define FW_PARSE_OK 1
#define FW_PARSE_EVASIVE 2 /* hides its ports from the filter */

struct fw_cfg {
	__u32 generation;
	__u32 flags;
};

struct fw_class {
	__u16 any_policy; /* policy for destinations no scoped policy names, 0 = none */
	__u8 has_dst;     /* some policy on these ports names destinations */
	__u8 pad;
};

struct fw_policy {
	__u8 flags;
	__u8 default_action;
	__u16 pad;
};

struct fw_verdict {
	__u8 action;
	__u8 pad[3];
};

/* LPM keys. Generation and class/policy come first so one trie holds both
 * generations and every policy; prefixlen counts their 32 bits too. */
struct fw_port_key {
	__u32 prefixlen;
	__u8 generation;
	__u8 proto;
	__u16 port; /* network order, so prefixes follow the port's high bits */
};

struct fw_addr4_key {
	__u32 prefixlen;
	__u8 generation;
	__u8 pad;
	__u16 id; /* network order: class for fw_dst4, policy for fw_src4 */
	__u32 addr;
};

struct fw_addr6_key {
	__u32 prefixlen;
	__u8 generation;
	__u8 pad;
	__u16 id;
	__u8 addr[16];
};

struct fw_pppoe_hdr {
	__u8 ver_type;
	__u8 code;
	__u16 session;
	__u16 length;
	__u16 ppp_proto;
} __attribute__((packed));

VEER_DECLARE_XDP_PROG_CHAIN();

struct bpf_map_def SEC("maps") fw_cfg = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_cfg),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") fw_ifaces = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") fw_port_bits = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 2 * FW_PORT_WORDS_PER_GEN,
};

struct bpf_map_def SEC("maps") fw_ports = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_port_key),
	.value_size = sizeof(__u32),
	.max_entries = 16384,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_class = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_class),
	.max_entries = 2 * FW_MAX_CLASSES,
};

struct bpf_map_def SEC("maps") fw_dst4 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_addr4_key),
	.value_size = sizeof(__u32),
	.max_entries = 8192,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_dst6 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_addr6_key),
	.value_size = sizeof(__u32),
	.max_entries = 8192,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_policy = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_policy),
	.max_entries = 2 * FW_MAX_POLICIES,
};

struct bpf_map_def SEC("maps") fw_src4 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_addr4_key),
	.value_size = sizeof(struct fw_verdict),
	.max_entries = 32768,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_src6 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_addr6_key),
	.value_size = sizeof(struct fw_verdict),
	.max_entries = 32768,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = FW_MAX_POLICIES * FW_COUNTERS,
};

struct fw_packet {
	__u8 family;
	__u8 proto;     /* FW_PROTO_* */
	__u16 dport;    /* network order */
	__u32 src4;
	__u32 dst4;
	__u8 src6[16];
	__u8 dst6[16];
};

static __always_inline void fw_count(__u32 slot, __u32 counter)
{
	__u32 key = slot * FW_COUNTERS + counter;
	__u64 *value = veer_bpf_map_lookup_elem(&fw_stats, &key);

	if (value)
		*value += 1;
}

#define FW_NO_NETWORK 0xffff

/*
 * Offset of the IP header: after Ethernet, up to two VLAN tags and a PPPoE
 * session header, or 0 on an L3 interface; FW_NO_NETWORK when there is none.
 * An offset rather than a pointer: the verifier knows it exactly on each path,
 * while the difference of two packet pointers would be unknown to it. Each IP
 * version is parsed once by the caller, whichever way led to it.
 */
static __always_inline __u32 fw_network(struct xdp_md *xdp, const struct veer_packet *p, const struct fw_cfg *cfg, __u16 *protocol)
{
	struct veer_l2_info l2 = {};
	__u32 off;

	if (cfg->flags & FW_CFG_HAS_L3) {
		__u32 ifindex = xdp->ingress_ifindex;
		__u32 *kind = veer_bpf_map_lookup_elem(&fw_ifaces, &ifindex);

		if (kind && *kind == FW_IFACE_L3) {
			/* Generic XDP on PPP, WireGuard or tun: the IP header comes first. */
			__u8 *first = p->data;

			if (!veer_bounds_ok(p, first, 1))
				return FW_NO_NETWORK;
			*protocol = (*first >> 4) == 6 ? VEER_ETH_P_IPV6 : VEER_ETH_P_IP;
			return 0;
		}
	}
	if (!veer_parse_l2(p, &l2))
		return FW_NO_NETWORK;
	*protocol = l2.protocol;
	off = sizeof(struct veer_ethhdr) + l2.vlan_depth * sizeof(struct veer_vlanhdr);
	if (l2.protocol == FW_ETH_P_PPPOE_SESSION) {
		struct fw_pppoe_hdr *pppoe = l2.network;

		/* Session data only; discovery and PPP control frames pass. */
		if (!veer_bounds_ok(p, pppoe, sizeof(*pppoe)) || pppoe->code != 0)
			return FW_NO_NETWORK;
		if (pppoe->ppp_proto == veer_htons(FW_PPP_IPV4))
			*protocol = VEER_ETH_P_IP;
		else if (pppoe->ppp_proto == veer_htons(FW_PPP_IPV6))
			*protocol = VEER_ETH_P_IPV6;
		else
			return FW_NO_NETWORK;
		off += sizeof(*pppoe);
	}
	return off;
}

#define FW_IPV6_MAX_EXT 6
#define FW_MAX_L4_OFFSET 2047
#define FW_L4_EVASIVE 0xffffffff

/*
 * Offset of the TCP or UDP header behind an IPv6 header whose extension
 * headers start at off; 0 for other protocols and fragments after the first;
 * FW_L4_EVASIVE for a chain longer than FW_IPV6_MAX_EXT or reaching past
 * FW_MAX_L4_OFFSET. Linux accepts such packets, so passing them would let
 * anyone reach a protected port. *fragmented tells a first fragment.
 *
 * veer_ipv6_l4 walks the chain with a packet pointer whose possible offsets
 * differ on every path, so the verifier cannot merge paths and explores every
 * combination of header types (about 280k instructions for this program).
 * Here the offset is a scalar that each step bounds and then masks behind an
 * asm barrier: every path then reaches the next step with the same range
 * (0-2047) and the verifier merges them.
 */
static __always_inline __u32 fw_ipv6_l4_offset(const struct veer_packet *p, __u32 off, __u8 next, __u8 *proto, int *fragmented)
{
#pragma unroll
	for (int i = 0; i < FW_IPV6_MAX_EXT; i++) {
		__u8 *hdr;
		__u8 hdr_next, hdr_len, frag_hi, frag_lo;

		if (next == VEER_IPPROTO_TCP || next == VEER_IPPROTO_UDP) {
			*proto = next;
			return off;
		}
		if (next != VEER_IPPROTO_HOPOPTS && next != VEER_IPPROTO_ROUTING && next != VEER_IPPROTO_DSTOPTS &&
			next != VEER_IPPROTO_AH && next != VEER_IPPROTO_FRAGMENT)
			return 0;
		/* One register for the bounds check and every read: the verifier
		 * gives the checked range only to that register and its copies. */
		hdr = (__u8 *)p->data + off;
		asm volatile("" : "+r"(hdr));
		if ((void *)(hdr + 8) > p->data_end)
			return *fragmented ? FW_L4_EVASIVE : 0;
		hdr_next = hdr[0];
		hdr_len = hdr[1];
		frag_hi = hdr[2];
		frag_lo = hdr[3];
		if (next == VEER_IPPROTO_FRAGMENT) {
			/* Offset in 8-byte units: the high 13 bits of bytes 2-3. */
			if (frag_hi || (frag_lo & 0xf8))
				return 0;
			*fragmented = 1;
			off += 8;
		} else if (next == VEER_IPPROTO_AH) {
			off += ((__u32)hdr_len + 2) * 4;
		} else {
			off += ((__u32)hdr_len + 1) * 8;
		}
		next = hdr_next;
		if (off > FW_MAX_L4_OFFSET)
			return FW_L4_EVASIVE;
		asm volatile("%0 &= 2047" : "+r"(off));
	}
	if (next == VEER_IPPROTO_TCP || next == VEER_IPPROTO_UDP) {
		*proto = next;
		return off;
	}
	if (next == VEER_IPPROTO_HOPOPTS || next == VEER_IPPROTO_ROUTING || next == VEER_IPPROTO_DSTOPTS ||
		next == VEER_IPPROTO_AH || next == VEER_IPPROTO_FRAGMENT)
		return FW_L4_EVASIVE;
	return 0;
}

/*
 * Fills pkt and returns FW_PARSE_OK for TCP or UDP the filter can judge.
 * Only the 4 port bytes of the L4 header are required. A first fragment
 * without them is FW_PARSE_EVASIVE: the host reassembles it and would hand
 * the ports to a service the filter never checked. Other packets without
 * them are truncated and the stack drops them anyway.
 */
static __always_inline int fw_parse(struct xdp_md *xdp, const struct fw_cfg *cfg, struct fw_packet *pkt)
{
	struct veer_packet p;
	struct veer_l4_ports *ports;
	void *network;
	__u16 protocol = 0;
	int fragmented = 0;
	__u32 network_off;
	__u32 off;
	__u8 l4proto;

	if (!veer_packet_from_xdp(xdp, &p))
		return FW_PARSE_PASS;
	network_off = fw_network(xdp, &p, cfg, &protocol);
	if (network_off == FW_NO_NETWORK)
		return FW_PARSE_PASS;
	network = (char *)p.data + network_off;
	if (protocol == VEER_ETH_P_IP) {
		struct veer_ipv4hdr *ip = network;
		__u16 frag;
		__u32 ihl;

		if (!veer_bounds_ok(&p, ip, sizeof(*ip)) || (ip->ver_ihl >> 4) != 4)
			return FW_PARSE_PASS;
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(*ip))
			return FW_PARSE_PASS;
		frag = veer_ntohs(ip->frag_off);
		/* Fragments after the first carry no ports. */
		if (frag & 0x1fff)
			return FW_PARSE_PASS;
		fragmented = (frag & 0x2000) != 0;
		l4proto = ip->protocol;
		ports = (void *)((char *)ip + ihl);
		pkt->family = 4;
		pkt->src4 = ip->saddr;
		pkt->dst4 = ip->daddr;
	} else if (protocol == VEER_ETH_P_IPV6) {
		struct veer_ipv6hdr *ip = network;

		if (!veer_bounds_ok(&p, ip, sizeof(*ip)) || (*((__u8 *)ip) >> 4) != 6)
			return FW_PARSE_PASS;
		l4proto = 0;
		off = fw_ipv6_l4_offset(&p, network_off + sizeof(*ip), ip->nexthdr, &l4proto, &fragmented);
		if (off == FW_L4_EVASIVE)
			return FW_PARSE_EVASIVE;
		if (!off)
			return FW_PARSE_PASS;
		ports = (void *)((char *)p.data + off);
		pkt->family = 6;
		__builtin_memcpy(pkt->src6, ip->saddr, 16);
		__builtin_memcpy(pkt->dst6, ip->daddr, 16);
	} else {
		return FW_PARSE_PASS;
	}
	if (l4proto == VEER_IPPROTO_TCP)
		pkt->proto = FW_PROTO_TCP;
	else if (l4proto == VEER_IPPROTO_UDP)
		pkt->proto = FW_PROTO_UDP;
	else
		return FW_PARSE_PASS;
	if (!veer_bounds_ok(&p, ports, sizeof(*ports)))
		return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
	pkt->dport = ports->dest;
	return FW_PARSE_OK;
}

static __always_inline __u32 fw_policy_for(const struct fw_packet *pkt, __u32 generation)
{
	struct fw_port_key port_key = {};
	struct fw_class *cls;
	__u32 *class_id;
	__u32 key;
	__u32 policy;

	port_key.prefixlen = 32;
	port_key.generation = generation;
	port_key.proto = pkt->proto;
	port_key.port = pkt->dport;
	class_id = veer_bpf_map_lookup_elem(&fw_ports, &port_key);
	if (!class_id || *class_id == 0 || *class_id >= FW_MAX_CLASSES)
		return 0;
	key = generation * FW_MAX_CLASSES + *class_id;
	cls = veer_bpf_map_lookup_elem(&fw_class, &key);
	if (!cls)
		return 0;
	policy = cls->any_policy;
	if (cls->has_dst) {
		__u32 *scoped;

		if (pkt->family == 4) {
			struct fw_addr4_key dst = {};

			dst.prefixlen = 64;
			dst.generation = generation;
			dst.id = veer_htons(*class_id);
			dst.addr = pkt->dst4;
			scoped = veer_bpf_map_lookup_elem(&fw_dst4, &dst);
		} else {
			struct fw_addr6_key dst = {};

			dst.prefixlen = 160;
			dst.generation = generation;
			dst.id = veer_htons(*class_id);
			__builtin_memcpy(dst.addr, pkt->dst6, 16);
			scoped = veer_bpf_map_lookup_elem(&fw_dst6, &dst);
		}
		if (scoped && *scoped)
			policy = *scoped;
	}
	return policy < FW_MAX_POLICIES ? policy : 0;
}

/* The verdict a source table gives pkt's source under policy, or -1 when
 * no entry covers it. */
static __always_inline int fw_source_action(const struct fw_packet *pkt, __u32 generation, __u32 policy)
{
	struct fw_verdict *verdict;

	if (pkt->family == 4) {
		struct fw_addr4_key src = {};

		src.prefixlen = 64;
		src.generation = generation;
		src.id = veer_htons(policy);
		src.addr = pkt->src4;
		verdict = veer_bpf_map_lookup_elem(&fw_src4, &src);
	} else {
		struct fw_addr6_key src = {};

		src.prefixlen = 160;
		src.generation = generation;
		src.id = veer_htons(policy);
		__builtin_memcpy(src.addr, pkt->src6, 16);
		verdict = veer_bpf_map_lookup_elem(&fw_src6, &src);
	}
	if (!verdict)
		return -1;
	return verdict->action;
}

static __always_inline int fw_filter(struct xdp_md *xdp)
{
	struct fw_packet pkt = {};
	const struct fw_cfg *cfg;
	struct fw_policy *policy;
	__u32 zero = 0;
	__u32 generation;
	__u32 key;
	__u32 slot;
	__u64 *bits;
	int action;
	int parsed;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg)
		return FW_ACTION_PASS;
	parsed = fw_parse(xdp, cfg, &pkt);
	if (parsed == FW_PARSE_EVASIVE && (cfg->flags & FW_CFG_ACTIVE)) {
		fw_count(0, FW_CNT_EVASIVE);
		return FW_ACTION_DROP;
	}
	if (parsed != FW_PARSE_OK)
		return FW_ACTION_PASS;
	generation = cfg->generation & 1;
	key = generation * FW_PORT_WORDS_PER_GEN + pkt.proto * FW_PORT_WORDS + (veer_ntohs(pkt.dport) >> 6);
	bits = veer_bpf_map_lookup_elem(&fw_port_bits, &key);
	if (!bits || !((*bits >> (veer_ntohs(pkt.dport) & 63)) & 1))
		return FW_ACTION_PASS;

	slot = fw_policy_for(&pkt, generation);
	if (!slot)
		return FW_ACTION_PASS;
	key = generation * FW_MAX_POLICIES + slot;
	policy = veer_bpf_map_lookup_elem(&fw_policy, &key);
	if (!policy || !(policy->flags & FW_POLICY_VALID))
		return FW_ACTION_PASS;

	/* Trusted sources (policy 0) pass every policy. */
	if (fw_source_action(&pkt, generation, 0) == FW_ACTION_PASS) {
		fw_count(slot, FW_CNT_TRUSTED);
		return FW_ACTION_PASS;
	}
	action = fw_source_action(&pkt, generation, slot);
	if (action < 0)
		action = policy->default_action;
	if (action == FW_ACTION_DROP) {
		fw_count(slot, FW_CNT_DROP);
		return FW_ACTION_DROP;
	}
	fw_count(slot, FW_CNT_PASS);
	return FW_ACTION_PASS;
}

SEC("xdp/veer/firewall")
int xdp_firewall(struct xdp_md *xdp)
{
	if (fw_filter(xdp) == FW_ACTION_DROP)
		return VEER_XDP_DROP;
	veer_xdp_continue(xdp);
	return VEER_XDP_PASS;
}

char __license[] SEC("license") = "GPL";
