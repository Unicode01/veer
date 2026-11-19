/*
 * Stateless source filter for TCP and UDP destination ports. Two entry points
 * share every map and the same filter code:
 *   xdp_firewall  run by the Veer XDP dispatcher, in driver mode where the NIC
 *                 supports it;
 *   tc_firewall   the hook's tc_fallback: on interfaces without native XDP the
 *                 host attaches it at TC ingress ahead of the Veer core instead
 *                 of running the dispatcher in generic mode, which would copy
 *                 every GRO aggregate into a linear buffer.
 * The control script (control.js) owns every map: it writes a whole rule set
 * into the inactive generation and then flips fw_cfg.generation, so a packet
 * never sees half of an update.
 *
 * Per packet: one fw_cfg lookup, header parsing and one fw_port_bits lookup.
 * Only packets to a port some policy covers go on to the LPM tables. Anything
 * the program cannot parse passes: the filter fails open.
 *
 * Policies with a SYN limit also count new TCP connections per source prefix
 * (fw_rate) and ban sources over the limit for a while (fw_ban). Drops are
 * sampled into the fw_events ring, rate-limited per CPU.
 */
#include "../include/veer_plugin_helpers.h"

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#endif
#ifndef BPF_MAP_TYPE_LPM_TRIE
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1
#endif
#ifndef BPF_FUNC_map_update_elem
#define BPF_FUNC_map_update_elem 2
#endif
#ifndef BPF_FUNC_ktime_get_ns
#define BPF_FUNC_ktime_get_ns 5
#endif
#ifndef BPF_FUNC_ringbuf_output
#define BPF_FUNC_ringbuf_output 130
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

static long (*const fw_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*const fw_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*const fw_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_output;

#define FW_NS_PER_SECOND 1000000000ULL

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
#define FW_POLICY_LIMIT 2 /* fw_limit holds a SYN limit for the policy */

#define FW_ACTION_PASS 0
#define FW_ACTION_DROP 1

/* fw_stats counters, per policy slot. FW_CNT_DROP counts every drop of the
 * policy, whatever the reason; fw_lstats breaks out bans and SYN limits. */
#define FW_CNT_PASS 0
#define FW_CNT_DROP 1
#define FW_CNT_TRUSTED 2
/* Slot 0 is no policy; its counter 3 counts packets dropped as evasive. */
#define FW_CNT_EVASIVE 3

/* fw_lstats counters, per policy slot; slot 0 counts the drop log. */
#define FW_LCOUNTERS 4
#define FW_LCNT_BAN 0     /* dropped: the source is banned */
#define FW_LCNT_RATE 1    /* dropped: a SYN over the limit */
#define FW_LCNT_LOGGED 2  /* slot 0: events written to fw_events */
#define FW_LCNT_LOST 3    /* slot 0: events the full ring refused */

/* fw_event.reason */
#define FW_REASON_ACL 1
#define FW_REASON_BAN 2
#define FW_REASON_RATE 3
#define FW_REASON_EVASIVE 4

#define FW_TCP_SYN 0x02
#define FW_TCP_ACK 0x10

/* fw_parse results */
#define FW_PARSE_PASS 0    /* not TCP or UDP the filter judges */
#define FW_PARSE_OK 1
#define FW_PARSE_EVASIVE 2 /* hides its ports from the filter */
#define FW_PARSE_SHORT 3   /* TC only: the headers run past the linear data */

/* TC verdicts. TC_ACT_UNSPEC (TCX_NEXT under tcx) hands the packet on to the
 * next program, the Veer core; TC_ACT_OK would end a cls_bpf walk before it. */
#define FW_TC_PASS TC_ACT_UNSPEC
#define FW_TC_DROP TC_ACT_SHOT

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

/* SYN limit of a policy, per generation like fw_policy. */
struct fw_limit {
	__u32 max_new;        /* SYNs one source prefix may send per window */
	__u32 window_seconds;
	__u32 ban_seconds;    /* 0: only drop SYNs over the limit */
	__u8 v6_prefix;       /* IPv6 sources count per /v6_prefix; IPv4 per /32 */
	__u8 pad[3];
	/* v6_prefix as a byte mask, written by the control script: masking with
	 * it has no branches, which per-byte prefix arithmetic compiled into
	 * (clang 14) and which left the verifier unable to merge paths. */
	__u8 v6_mask[16];
};

/* Source prefix under one policy: the key of fw_rate and fw_ban. Bans are
 * per policy, so a source over one policy's limit still reaches others. */
struct fw_limit_key {
	__u8 family;
	__u8 prefix;
	__u16 slot;
	__u8 addr[16]; /* IPv4 in the first 4 bytes */
};

struct fw_rate {
	__u64 window_start;
	__u64 count;
};

/* Drop log rate per CPU as a GCRA: one event per interval_ns, bursts up to
 * tolerance_ns ahead. interval_ns 0 turns the log off. */
struct fw_log_cfg {
	__u64 interval_ns;
	__u64 tolerance_ns;
};

struct fw_event {
	__u64 ts_ns;
	__u32 ifindex;
	__u16 slot;
	__u8 reason; /* FW_REASON_* */
	__u8 family;
	__u8 proto;  /* FW_PROTO_* */
	__u8 pad;
	__u16 sport; /* network order */
	__u16 dport; /* network order */
	__u16 pad2;
	__u8 src[16]; /* IPv4 in the first 4 bytes */
	__u8 dst[16];
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

struct bpf_map_def SEC("maps") fw_limit = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_limit),
	.max_entries = 2 * FW_MAX_POLICIES,
};

struct bpf_map_def SEC("maps") fw_rate = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct fw_limit_key),
	.value_size = sizeof(struct fw_rate),
	.max_entries = 65536,
};

/* Source prefix -> end of its ban (ktime ns). Expired entries stay until the
 * LRU reclaims them; a lookup past the end ignores them. */
struct bpf_map_def SEC("maps") fw_ban = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct fw_limit_key),
	.value_size = sizeof(__u64),
	.max_entries = 65536,
};

struct bpf_map_def SEC("maps") fw_lstats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = FW_MAX_POLICIES * FW_LCOUNTERS,
};

struct bpf_map_def SEC("maps") fw_log_cfg = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_log_cfg),
	.max_entries = 1,
};

/* Per CPU: the GCRA's theoretical arrival time of the next event. */
struct bpf_map_def SEC("maps") fw_log_tat = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") fw_events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 256 * 1024,
};

struct fw_packet {
	__u8 family;
	__u8 proto;     /* FW_PROTO_* */
	__u16 dport;    /* network order */
	__u16 sport;    /* network order */
	__u8 tcp_flags; /* 0 when the header is too short to hold them */
	__u8 pad;
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

static __always_inline void fw_lcount(__u32 slot, __u32 counter)
{
	__u32 key = slot * FW_LCOUNTERS + counter;
	__u64 *value = veer_bpf_map_lookup_elem(&fw_lstats, &key);

	if (value)
		*value += 1;
}

/* Whether this CPU may log one more event now. */
static __always_inline int fw_log_admit(__u64 now)
{
	struct fw_log_cfg *cfg;
	__u64 *tat;
	__u32 zero = 0;
	__u64 next;

	cfg = veer_bpf_map_lookup_elem(&fw_log_cfg, &zero);
	if (!cfg || !cfg->interval_ns)
		return 0;
	tat = veer_bpf_map_lookup_elem(&fw_log_tat, &zero);
	if (!tat)
		return 0;
	next = *tat;
	if (next < now)
		next = now;
	if (next - now > cfg->tolerance_ns)
		return 0;
	*tat = next + cfg->interval_ns;
	return 1;
}

static __always_inline void fw_log(__u32 ifindex, const struct fw_packet *pkt, __u32 slot, __u8 reason)
{
	struct fw_event event = {};
	__u64 now = fw_ktime_get_ns();

	if (!fw_log_admit(now))
		return;
	event.ts_ns = now;
	event.ifindex = ifindex;
	event.slot = slot;
	event.reason = reason;
	event.family = pkt->family;
	event.proto = pkt->proto;
	event.sport = pkt->sport;
	event.dport = pkt->dport;
	if (pkt->family == 4) {
		__builtin_memcpy(event.src, &pkt->src4, 4);
		__builtin_memcpy(event.dst, &pkt->dst4, 4);
	} else if (pkt->family == 6) {
		__builtin_memcpy(event.src, pkt->src6, 16);
		__builtin_memcpy(event.dst, pkt->dst6, 16);
	}
	if (fw_ringbuf_output(&fw_events, &event, sizeof(event), 0) == 0)
		fw_lcount(0, FW_LCNT_LOGGED);
	else
		fw_lcount(0, FW_LCNT_LOST);
}

#define FW_NO_NETWORK 0xffff
#define FW_SHORT_NETWORK 0xfffe /* the L2 headers run past data_end */

/*
 * Offset of the IP header: after Ethernet, up to two VLAN tags and a PPPoE
 * session header, or 0 on an L3 interface; FW_NO_NETWORK when there is none.
 * An offset rather than a pointer: the verifier knows it exactly on each path,
 * while the difference of two packet pointers would be unknown to it. Each IP
 * version is parsed once by the caller, whichever way led to it.
 *
 * XDP and TC ingress see the same layout. On an L3 device both start at the
 * IP header. At TC an Ethernet frame starts at its MAC header, but the stack
 * has already moved the outer VLAN tag into skb->vlan_tci, so the frame shows
 * one tag fewer than XDP sees; veer_parse_l2 takes zero to two either way.
 */
static __always_inline __u32 fw_network(const struct veer_packet *p, __u32 ifindex, const struct fw_cfg *cfg, __u16 *protocol)
{
	struct veer_l2_info l2 = {};
	__u32 off;

	if (cfg->flags & FW_CFG_HAS_L3) {
		__u32 *kind = veer_bpf_map_lookup_elem(&fw_ifaces, &ifindex);

		if (kind && *kind == FW_IFACE_L3) {
			/* PPP, WireGuard or tun: the IP header comes first. */
			__u8 *first = p->data;

			if (!veer_bounds_ok(p, first, 1))
				return FW_SHORT_NETWORK;
			*protocol = (*first >> 4) == 6 ? VEER_ETH_P_IPV6 : VEER_ETH_P_IP;
			return 0;
		}
	}
	if (!veer_parse_l2(p, &l2))
		return FW_SHORT_NETWORK;
	*protocol = l2.protocol;
	off = sizeof(struct veer_ethhdr) + l2.vlan_depth * sizeof(struct veer_vlanhdr);
	if (l2.protocol == FW_ETH_P_PPPOE_SESSION) {
		struct fw_pppoe_hdr *pppoe = l2.network;

		/* Session data only; discovery and PPP control frames pass. */
		if (!veer_bounds_ok(p, pppoe, sizeof(*pppoe)))
			return FW_SHORT_NETWORK;
		if (pppoe->code != 0)
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
#define FW_L4_SHORT 0xfffffffe

/*
 * Offset of the TCP or UDP header behind an IPv6 header whose extension
 * headers start at off; 0 for other protocols and fragments after the first;
 * FW_L4_EVASIVE for a chain longer than FW_IPV6_MAX_EXT or reaching past
 * FW_MAX_L4_OFFSET. Linux accepts such packets, so passing them would let
 * anyone reach a protected port. FW_L4_SHORT when an extension header runs
 * past data_end. *fragmented tells a first fragment.
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
			return FW_L4_SHORT;
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
 *
 * more says whether the packet may go on past p->data_end. XDP passes 0: its
 * data_end is the end of the packet. TC passes 1, since a GRO aggregate or a
 * frag-based skb may keep headers outside its linear data; every check that
 * runs out of data then returns FW_PARSE_SHORT, and the caller pulls the
 * headers into the linear area and parses again with more = 0.
 */
static __always_inline int fw_parse(const struct veer_packet *p, __u32 ifindex, int more, const struct fw_cfg *cfg, struct fw_packet *pkt)
{
	struct veer_l4_ports *ports;
	void *network;
	__u16 protocol = 0;
	int fragmented = 0;
	__u32 network_off;
	__u32 off;
	__u8 l4proto;

	network_off = fw_network(p, ifindex, cfg, &protocol);
	if (network_off == FW_NO_NETWORK)
		return FW_PARSE_PASS;
	if (network_off == FW_SHORT_NETWORK)
		return more ? FW_PARSE_SHORT : FW_PARSE_PASS;
	network = (char *)p->data + network_off;
	if (protocol == VEER_ETH_P_IP) {
		struct veer_ipv4hdr *ip = network;
		__u16 frag;
		__u32 ihl;

		if (!veer_bounds_ok(p, ip, sizeof(*ip)))
			return more ? FW_PARSE_SHORT : FW_PARSE_PASS;
		if ((ip->ver_ihl >> 4) != 4)
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

		if (!veer_bounds_ok(p, ip, sizeof(*ip)))
			return more ? FW_PARSE_SHORT : FW_PARSE_PASS;
		if ((*((__u8 *)ip) >> 4) != 6)
			return FW_PARSE_PASS;
		l4proto = 0;
		off = fw_ipv6_l4_offset(p, network_off + sizeof(*ip), ip->nexthdr, &l4proto, &fragmented);
		if (off == FW_L4_EVASIVE)
			return FW_PARSE_EVASIVE;
		if (off == FW_L4_SHORT) {
			if (more)
				return FW_PARSE_SHORT;
			return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
		}
		if (!off)
			return FW_PARSE_PASS;
		ports = (void *)((char *)p->data + off);
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
	if (!veer_bounds_ok(p, ports, sizeof(*ports))) {
		if (more)
			return FW_PARSE_SHORT;
		return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
	}
	pkt->dport = ports->dest;
	pkt->sport = ports->source;
	/* The flags byte is the 14th of the TCP header; only SYN limits read it. */
	if (pkt->proto == FW_PROTO_TCP) {
		if (veer_bounds_ok(p, ports, 14))
			pkt->tcp_flags = ((__u8 *)ports)[13];
		else if (more)
			return FW_PARSE_SHORT;
	}
	return FW_PARSE_OK;
}

/* fw_rate/fw_ban key: the source masked to its counting prefix. */
static __always_inline void fw_limit_key_of(const struct fw_packet *pkt, __u32 slot, const struct fw_limit *limit, struct fw_limit_key *key)
{
	key->family = pkt->family;
	key->slot = slot;
	if (pkt->family == 4) {
		key->prefix = 32;
		__builtin_memcpy(key->addr, &pkt->src4, 4);
		return;
	}
	key->prefix = limit->v6_prefix;
#pragma unroll
	for (int i = 0; i < 16; i++)
		key->addr[i] = pkt->src6[i] & limit->v6_mask[i];
}

/*
 * Counts one SYN of key's source in its fixed window; true once the window
 * holds more than max_new. Concurrent CPUs may lose a reset or a count now
 * and then. With -mcpu=v1 the atomic add returns nothing, so the count is read
 * again after it.
 */
static __always_inline int fw_rate_exceeded(const struct fw_limit_key *key, __u64 now, __u32 max_new, __u64 window_ns)
{
	struct fw_rate *rate = veer_bpf_map_lookup_elem(&fw_rate, key);

	if (!rate || now - rate->window_start >= window_ns) {
		struct fw_rate fresh = {.window_start = now, .count = 1};

		fw_map_update_elem(&fw_rate, key, &fresh, BPF_ANY);
		return max_new < 1;
	}
	__sync_fetch_and_add(&rate->count, 1);
	return rate->count > max_new;
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

/*
 * The filter itself, on the result of fw_parse: 0 to pass pkt, or the
 * FW_REASON_* it is dropped for. *slot names the policy that dropped it (0 for
 * evasive packets). Logging happens once, in the caller, so its code is
 * inlined only once per entry point.
 */
static __always_inline int fw_judge(const struct fw_cfg *cfg, struct fw_packet *pkt, int parsed, __u32 *slot_out)
{
	struct fw_limit_key limit_key = {};
	struct fw_policy *policy;
	__u32 generation;
	__u32 key;
	__u32 slot;
	__u64 *bits;
	__u64 now = 0;
	__u64 window_ns = 0;
	__u64 ban_ns = 0;
	__u32 max_new = 0;
	int limited = 0;
	int action;

	if (parsed == FW_PARSE_EVASIVE && (cfg->flags & FW_CFG_ACTIVE)) {
		fw_count(0, FW_CNT_EVASIVE);
		return FW_REASON_EVASIVE;
	}
	if (parsed != FW_PARSE_OK)
		return 0;
	generation = cfg->generation & 1;
	key = generation * FW_PORT_WORDS_PER_GEN + pkt->proto * FW_PORT_WORDS + (veer_ntohs(pkt->dport) >> 6);
	bits = veer_bpf_map_lookup_elem(&fw_port_bits, &key);
	if (!bits || !((*bits >> (veer_ntohs(pkt->dport) & 63)) & 1))
		return 0;

	slot = fw_policy_for(pkt, generation);
	if (!slot)
		return 0;
	key = generation * FW_MAX_POLICIES + slot;
	policy = veer_bpf_map_lookup_elem(&fw_policy, &key);
	if (!policy || !(policy->flags & FW_POLICY_VALID))
		return 0;
	*slot_out = slot;

	/* Trusted sources (policy 0) pass every policy, ban and limit. */
	if (fw_source_action(pkt, generation, 0) == FW_ACTION_PASS) {
		fw_count(slot, FW_CNT_TRUSTED);
		return 0;
	}

	/* Copied out, so later code tests a scalar, not a pointer that a
	 * condition chose (old verifiers lose track of such null tests). */
	if (policy->flags & FW_POLICY_LIMIT) {
		struct fw_limit *limit = veer_bpf_map_lookup_elem(&fw_limit, &key);

		if (limit && limit->max_new && limit->window_seconds) {
			max_new = limit->max_new;
			window_ns = (__u64)limit->window_seconds * FW_NS_PER_SECOND;
			ban_ns = (__u64)limit->ban_seconds * FW_NS_PER_SECOND;
			fw_limit_key_of(pkt, slot, limit, &limit_key);
			limited = 1;
		}
	}
	if (limited) {
		__u64 *until = veer_bpf_map_lookup_elem(&fw_ban, &limit_key);

		now = fw_ktime_get_ns();
		if (until && *until > now) {
			fw_count(slot, FW_CNT_DROP);
			fw_lcount(slot, FW_LCNT_BAN);
			return FW_REASON_BAN;
		}
	}

	action = fw_source_action(pkt, generation, slot);
	if (action < 0)
		action = policy->default_action;
	if (action == FW_ACTION_DROP) {
		fw_count(slot, FW_CNT_DROP);
		return FW_REASON_ACL;
	}

	/* Only a connection's first SYN counts, so open connections never
	 * trip the limit. */
	if (limited && pkt->proto == FW_PROTO_TCP && (pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK)) == FW_TCP_SYN &&
		fw_rate_exceeded(&limit_key, now, max_new, window_ns)) {
		if (ban_ns) {
			__u64 until = now + ban_ns;

			fw_map_update_elem(&fw_ban, &limit_key, &until, BPF_ANY);
		}
		fw_count(slot, FW_CNT_DROP);
		fw_lcount(slot, FW_LCNT_RATE);
		return FW_REASON_RATE;
	}
	fw_count(slot, FW_CNT_PASS);
	return 0;
}

SEC("xdp/veer/firewall")
int xdp_firewall(struct xdp_md *xdp)
{
	struct fw_packet pkt = {};
	struct veer_packet p;
	const struct fw_cfg *cfg;
	__u32 ifindex = xdp->ingress_ifindex;
	__u32 zero = 0;
	__u32 slot = 0;
	int reason;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg || !veer_packet_from_xdp(xdp, &p))
		goto pass;
	reason = fw_judge(cfg, &pkt, fw_parse(&p, ifindex, 0, cfg, &pkt), &slot);
	if (reason) {
		fw_log(ifindex, &pkt, slot, reason);
		return VEER_XDP_DROP;
	}
pass:
	veer_xdp_continue(xdp);
	return VEER_XDP_PASS;
}

/* The deepest byte fw_parse reads: the TCP flags behind an IPv6 extension
 * chain that ends at FW_MAX_L4_OFFSET. */
#define FW_TC_PULL_MAX (FW_MAX_L4_OFFSET + 14)

/*
 * tc_fallback of the XDP hook, attached at TC ingress ahead of the Veer core
 * on interfaces without native XDP. It sees one skb per GRO aggregate, so the
 * counters count aggregates there, and judges it in place: unlike generic
 * XDP, nothing is copied. Headers normally sit in the linear data; only when
 * parsing runs short of it are they pulled in, up to FW_TC_PULL_MAX bytes,
 * and parsed again. A failed pull passes the packet, like any packet the
 * filter cannot parse.
 */
SEC("tc/veer/firewall")
int tc_firewall(struct __sk_buff *skb)
{
	struct fw_packet pkt = {};
	struct veer_packet p;
	const struct fw_cfg *cfg;
	__u32 ifindex = skb->ingress_ifindex;
	__u32 zero = 0;
	__u32 slot = 0;
	int parsed;
	int reason;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg || !veer_packet_from_skb(skb, &p))
		return FW_TC_PASS;
	parsed = fw_parse(&p, ifindex, 1, cfg, &pkt);
	if (parsed == FW_PARSE_SHORT) {
		__u32 len = skb->len;

		if (len > FW_TC_PULL_MAX)
			len = FW_TC_PULL_MAX;
		/* The pull moves the data: every packet pointer is read again. */
		if (veer_skb_pull_data(skb, len) < 0 || !veer_packet_from_skb(skb, &p))
			return FW_TC_PASS;
		__builtin_memset(&pkt, 0, sizeof(pkt));
		parsed = fw_parse(&p, ifindex, 0, cfg, &pkt);
	}
	reason = fw_judge(cfg, &pkt, parsed, &slot);
	if (reason) {
		fw_log(ifindex, &pkt, slot, reason);
		return FW_TC_DROP;
	}
	return FW_TC_PASS;
}

char __license[] SEC("license") = "GPL";
