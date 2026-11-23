/*
 * Source filter for the interfaces it is bound to. Three entry points share
 * every map and the same code:
 *   xdp_firewall        run by the Veer XDP dispatcher, in driver mode where
 *                       the NIC supports it;
 *   tc_firewall         the hook's tc_fallback: on interfaces without native
 *                       XDP the host attaches it at TC ingress ahead of the
 *                       Veer core instead of running the dispatcher in generic
 *                       mode, which would copy every GRO aggregate into a
 *                       linear buffer;
 *   tc_firewall_egress  the hook's tc_egress program, at TC egress of the same
 *                       interfaces: with connection tracking on it records the
 *                       connections this side opens, so their replies pass.
 * The control script (control.js) owns every map: it writes a whole rule set
 * into the inactive generation and then flips fw_cfg.generation, so a packet
 * never sees half of an update.
 *
 * Packets go through these stages; anything the program cannot parse passes
 * (the filter fails open):
 *   1. ICMP the network needs (PTB, neighbour discovery, MLD) and DHCP
 *      client replies pass.
 *   2. Baseline: fragments and invalid TCP flag combinations, when turned on.
 *   3. Sources: blocklist sets, then bogon sources and reverse-path checks.
 *      Trusted sources are exempt; replies of tracked connections are exempt
 *      from the bogon and reverse-path checks, not from blocklists.
 *   4. The class of the packet: TCP/UDP destination port (a bitmap tells
 *      unprotected ports in one lookup), ICMP type and code, or the IP
 *      protocol; else the catch-all policies. No class: pass.
 *   5. Replies of tracked connections pass.
 *   6. The class's policy: trusted sources, bans, "new TCP connections
 *      only", source prefixes (longest match), source sets in order, the
 *      default action, SYN limits; drops may add the source to a set.
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
#ifndef BPF_FUNC_fib_lookup
#define BPF_FUNC_fib_lookup 69
#endif
#ifndef BPF_FUNC_ringbuf_output
#define BPF_FUNC_ringbuf_output 130
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

static long (*const fw_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*const fw_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*const fw_fib_lookup)(void *ctx, void *params, int plen, __u32 flags) = (void *)BPF_FUNC_fib_lookup;
static long (*const fw_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_output;

#define FW_NS_PER_SECOND 1000000000ULL

#define FW_ETH_P_PPPOE_SESSION 0x8864
#define FW_PPP_IPV4 0x0021
#define FW_PPP_IPV6 0x0057

/* fw_packet.proto, and the proto byte of fw_ports keys. fw_port_bits only
 * covers TCP and UDP. */
#define FW_PROTO_TCP 0
#define FW_PROTO_UDP 1
#define FW_PROTO_ICMP 2   /* port: type and code */
#define FW_PROTO_ICMPV6 3 /* port: type and code */
#define FW_PROTO_IP 4     /* any other IP protocol: port holds it in its high byte */
#define FW_PORT_WORDS 1024 /* 65536 ports / 64 bits */
#define FW_PORT_WORDS_PER_GEN (2 * FW_PORT_WORDS)
#define FW_MAX_CLASSES 1024
#define FW_MAX_POLICIES 256
#define FW_COUNTERS 4

/* fw_cfg.flags */
#define FW_CFG_HAS_L3 1 /* some bound interface carries packets without Ethernet */
#define FW_CFG_ACTIVE 2 /* the generation holds at least one policy */

/* fw_gcfg.flags: the generation's global settings. */
#define FW_G_CT 1          /* connection tracking */
#define FW_G_BOGON 2       /* drop sources in the bogon set */
#define FW_G_BAD_FLAGS 4   /* drop invalid TCP flag combinations */
#define FW_G_DROP_FRAGS 8  /* drop every IP fragment */
#define FW_G_URPF_LOOSE 16 /* drop sources without a route back */
#define FW_G_URPF_STRICT 32 /* ... or whose route back leaves elsewhere */
#define FW_G_PROTO 64      /* some policy names ICMP or another IP protocol */
/* Checks that judge every packet, whatever its port. */
#define FW_G_PACKET_CHECKS (FW_G_BOGON | FW_G_BAD_FLAGS | FW_G_DROP_FRAGS | FW_G_URPF_LOOSE | FW_G_URPF_STRICT)

/* fw_ifaces values */
#define FW_IFACE_L3 1

/* fw_policy.flags */
#define FW_POLICY_VALID 1
#define FW_POLICY_LIMIT 2 /* fw_limit holds a SYN limit for the policy */

/* fw_pext.flags */
#define FW_PX_NEW_ONLY 1 /* TCP: judge only connection attempts (SYN without ACK) */
#define FW_PX_ADD_SET 2  /* add the sources it drops to add_set */

#define FW_PX_SETS 4    /* source sets per policy */
#define FW_BLOCK_SETS 4 /* blocklist sets */

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

/* fw_gstats counters: packets that no policy saw. */
#define FW_GSTATS 16
#define FW_GCNT_ESTABLISHED 0 /* passed: reply of a tracked connection */
#define FW_GCNT_RELATED 1     /* passed: ICMP error about a tracked connection */
#define FW_GCNT_ESSENTIAL 2   /* passed: ICMP the network needs, DHCP replies */
#define FW_GCNT_BLOCKLIST 3   /* dropped: source in a blocklist set */
#define FW_GCNT_BOGON 4       /* dropped: bogon source */
#define FW_GCNT_URPF 5        /* dropped: reverse-path check */
#define FW_GCNT_FLAGS 6       /* dropped: invalid TCP flags */
#define FW_GCNT_FRAGMENT 7    /* dropped: fragment */
#define FW_GCNT_CT_NEW 8      /* egress: connection recorded */
#define FW_GCNT_CT_FULL 9     /* egress: recording failed */
#define FW_GCNT_CT_SHORT 10   /* egress: headers outside the linear data */
#define FW_GCNT_SET_ADD 11    /* source added to a set by a policy */
#define FW_GCNT_SET_FULL 12   /* ... and failed */

/* fw_event.reason */
#define FW_REASON_ACL 1
#define FW_REASON_BAN 2
#define FW_REASON_RATE 3
#define FW_REASON_EVASIVE 4
#define FW_REASON_BLOCKLIST 5
#define FW_REASON_BOGON 6
#define FW_REASON_URPF 7
#define FW_REASON_FLAGS 8
#define FW_REASON_FRAGMENT 9

#define FW_TCP_FIN 0x01
#define FW_TCP_SYN 0x02
#define FW_TCP_RST 0x04
#define FW_TCP_PSH 0x08
#define FW_TCP_ACK 0x10
#define FW_TCP_URG 0x20

/* fw_parse results */
#define FW_PARSE_PASS 0    /* nothing the filter judges */
#define FW_PARSE_OK 1      /* addresses and the L4 header the policies match */
#define FW_PARSE_EVASIVE 2 /* hides its ports from the filter */
#define FW_PARSE_SHORT 3   /* TC only: the headers run past the linear data */
#define FW_PARSE_LATER 4   /* a fragment after the first: addresses only */

/* Reserved fw_sets ids, written by the control script. */
#define FW_SET_BOGON 0xfff0

/* fw_ct.flags */
#define FW_CT_CLOSING 1 /* a FIN or RST went out */

/* Idle time after which a tracked connection is forgotten. */
#define FW_CT_TCP_NS (86400ULL * FW_NS_PER_SECOND)
#define FW_CT_TCP_CLOSING_NS (120ULL * FW_NS_PER_SECOND)
#define FW_CT_UDP_NS (180ULL * FW_NS_PER_SECOND)
#define FW_CT_ICMP_NS (30ULL * FW_NS_PER_SECOND)

/* TC verdicts. TC_ACT_UNSPEC (TCX_NEXT under tcx) hands the packet on to the
 * next program, the Veer core; TC_ACT_OK would end a cls_bpf walk before it. */
#define FW_TC_PASS TC_ACT_UNSPEC
#define FW_TC_DROP TC_ACT_SHOT

/* bpf_fib_lookup */
#define FW_AF_INET 2
#define FW_AF_INET6 10
#define FW_FIB_SUCCESS 0
#define FW_FIB_BLACKHOLE 1
#define FW_FIB_UNREACHABLE 2
#define FW_FIB_PROHIBIT 3
#define FW_FIB_NOT_FWDED 4
#define FW_FIB_NO_NEIGH 7

struct fw_cfg {
	__u32 generation;
	__u32 flags;
};

/* Per generation: the global settings of the rule set. */
struct fw_gcfg {
	__u32 flags;      /* FW_G_* */
	__u16 any_class;  /* class of the catch-all policies, 0 = none */
	__u8 block_count; /* blocklist sets in block_sets */
	__u8 pad;
	__u16 block_sets[FW_BLOCK_SETS];
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

/* Per generation and policy slot, beside fw_policy: what 1.0 policies did
 * not have. */
struct fw_pext {
	__u8 flags;        /* FW_PX_* */
	__u8 set_count;    /* source sets in sets */
	__u16 add_set;     /* FW_PX_ADD_SET: the set */
	__u32 add_seconds; /* ... and how long the source stays, 0 = until removed */
	__u16 sets[FW_PX_SETS];
	__u8 set_action[FW_PX_SETS];
	__u8 add_v6_prefix; /* IPv6 sources go in as /add_v6_prefix */
	__u8 pad[3];
	__u8 add_v6_mask[16]; /* add_v6_prefix as a byte mask */
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

/* fw_sets key: both families in one trie, so one lookup serves both.
 * prefixlen counts the 32 bits before addr. Sets are not per generation:
 * dynamic elements outlive rule set changes. */
struct fw_set_key {
	__u32 prefixlen;
	__u8 family;
	__u8 pad;
	__u16 id;      /* network order */
	__u8 addr[16]; /* IPv4 in the first 4 bytes */
};

struct fw_set_elem {
	__u64 expires_ns; /* ktime; 0 = until removed */
	__u32 kind;       /* written by the control script: static, API, policy */
	__u32 pad;
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

/* A connection this side opened, as its packets leave: local and remote
 * address and port (ICMP echo: the identifier as lport). */
struct fw_ct_key {
	__u8 family;
	__u8 proto; /* FW_PROTO_* */
	__u16 lport;
	__u16 rport;
	__u16 pad;
	__u8 laddr[16]; /* IPv4 in the first 4 bytes */
	__u8 raddr[16];
};

struct fw_ct {
	__u64 seen_ns; /* last packet either way, to the second */
	__u32 flags;   /* FW_CT_* */
	__u32 pad;
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
	__u16 slot;  /* the policy; for blocklist drops the set */
	__u8 reason; /* FW_REASON_* */
	__u8 family;
	__u8 proto;  /* FW_PROTO_* */
	__u8 pad;
	__u16 sport; /* network order */
	__u16 dport; /* network order; ICMP: type and code; other: the protocol in the high byte */
	__u16 pad2;
	__u8 src[16]; /* IPv4 in the first 4 bytes */
	__u8 dst[16];
};

/* struct bpf_fib_lookup of the kernel UAPI (64 bytes). */
struct fw_fib {
	__u8 family;
	__u8 l4_protocol;
	__u16 sport;
	__u16 dport;
	__u16 tot_len;
	__u32 ifindex;
	__u32 flowinfo;
	__u32 src[4];
	__u32 dst[4];
	__u16 h_vlan_proto;
	__u16 h_vlan_tci;
	__u8 smac[6];
	__u8 dmac[6];
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

struct bpf_map_def SEC("maps") fw_gcfg = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_gcfg),
	.max_entries = 2,
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

struct bpf_map_def SEC("maps") fw_pext = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_pext),
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

struct bpf_map_def SEC("maps") fw_sets = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct fw_set_key),
	.value_size = sizeof(struct fw_set_elem),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") fw_ct = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct fw_ct_key),
	.value_size = sizeof(struct fw_ct),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") fw_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = FW_MAX_POLICIES * FW_COUNTERS,
};

struct bpf_map_def SEC("maps") fw_gstats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = FW_GSTATS,
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

/* Per CPU: room for what does not fit the 512-byte stack beside the rest.
 * Each user fills what it reads; nothing carries over between packets. */
struct fw_scratch {
	struct fw_fib fib;
	struct fw_event event;
};

struct bpf_map_def SEC("maps") fw_scratch = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct fw_scratch),
	.max_entries = 1,
};

struct fw_packet {
	__u8 family;
	__u8 proto;     /* FW_PROTO_* */
	__u16 dport;    /* network order; ICMP: type and code; other: the protocol in the high byte */
	__u16 sport;    /* network order; ICMP: the echo identifier */
	__u8 tcp_flags; /* 0 when the header is too short to hold them */
	__u8 frag;      /* a first fragment */
	__u8 ipproto;
	__u8 icmp_type;
	__u8 icmp_code;
	__u8 pad;
	__u16 l4_off; /* offset of the L4 header from the packet start */
	__u16 pad2;
	__u8 src[16]; /* IPv4 in the first 4 bytes */
	__u8 dst[16];
};

#define FW_V4(addr) (*(__u32 *)(addr))

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

static __always_inline void fw_gcount(__u32 counter)
{
	__u64 *value = veer_bpf_map_lookup_elem(&fw_gstats, &counter);

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
	struct fw_scratch *scratch;
	struct fw_event *event;
	__u64 now = fw_ktime_get_ns();
	__u32 zero = 0;

	if (!fw_log_admit(now))
		return;
	scratch = veer_bpf_map_lookup_elem(&fw_scratch, &zero);
	if (!scratch)
		return;
	event = &scratch->event;
	event->ts_ns = now;
	event->ifindex = ifindex;
	event->slot = slot;
	event->reason = reason;
	event->family = pkt->family;
	event->proto = pkt->proto;
	event->pad = 0;
	event->sport = pkt->sport;
	event->dport = pkt->dport;
	event->pad2 = 0;
	__builtin_memcpy(event->src, pkt->src, 16);
	__builtin_memcpy(event->dst, pkt->dst, 16);
	if (fw_ringbuf_output(&fw_events, event, sizeof(*event), 0) == 0)
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
 * XDP and TC see the same layout. On an L3 device both start at the IP
 * header. At TC an Ethernet frame starts at its MAC header, but the stack
 * has already moved the outer VLAN tag into skb->vlan_tci (or, at egress, not
 * yet put it in the frame), so the frame may show one tag fewer than XDP
 * sees; veer_parse_l2 takes zero to two either way.
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
#define FW_L4_LATER 0xfffffffd

static __always_inline int fw_ipv6_ext(__u8 next)
{
	return next == VEER_IPPROTO_HOPOPTS || next == VEER_IPPROTO_ROUTING || next == VEER_IPPROTO_DSTOPTS ||
	       next == VEER_IPPROTO_AH || next == VEER_IPPROTO_FRAGMENT;
}

/*
 * Offset of the header that ends an IPv6 extension chain starting at off,
 * with its protocol in *proto; FW_L4_LATER for fragments after the first;
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

		if (!fw_ipv6_ext(next)) {
			*proto = next;
			return off;
		}
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
				return FW_L4_LATER;
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
	if (fw_ipv6_ext(next))
		return FW_L4_EVASIVE;
	*proto = next;
	return off;
}

/*
 * Fills pkt and returns FW_PARSE_OK for an IP packet the filter can judge:
 * TCP and UDP with their ports, ICMP and ICMPv6 with type and code, other
 * protocols by number. Only the 4 port bytes of a TCP or UDP header are
 * required (8 bytes of ICMP), and for TCP in a first fragment also the
 * flags. A first fragment without them is FW_PARSE_EVASIVE: the host
 * reassembles it and would hand the ports to a service the filter never
 * checked, or a SYN to it the SYN limit never counted. Other packets without
 * them are truncated and the stack drops them anyway. Fragments after the
 * first are FW_PARSE_LATER, with their addresses.
 *
 * more says whether the packet may go on past p->data_end. XDP passes 0: its
 * data_end is the end of the packet. TC passes 1, since a GRO aggregate or a
 * frag-based skb may keep headers outside its linear data; every check that
 * runs out of data then returns FW_PARSE_SHORT, and the caller pulls the
 * headers into the linear area and parses again with more = 0.
 */
static __always_inline int fw_parse(const struct veer_packet *p, __u32 ifindex, int more, const struct fw_cfg *cfg, struct fw_packet *pkt)
{
	__u8 *l4;
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
	if (protocol == VEER_ETH_P_IP) {
		struct veer_ipv4hdr *ip = (void *)((char *)p->data + network_off);
		__u16 frag;
		__u32 ihl;

		if (!veer_bounds_ok(p, ip, sizeof(*ip)))
			return more ? FW_PARSE_SHORT : FW_PARSE_PASS;
		if ((ip->ver_ihl >> 4) != 4)
			return FW_PARSE_PASS;
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(*ip))
			return FW_PARSE_PASS;
		pkt->family = 4;
		FW_V4(pkt->src) = ip->saddr;
		FW_V4(pkt->dst) = ip->daddr;
		l4proto = ip->protocol;
		pkt->ipproto = l4proto;
		frag = veer_ntohs(ip->frag_off);
		/* Fragments after the first carry no L4 header. */
		if (frag & 0x1fff)
			return FW_PARSE_LATER;
		fragmented = (frag & 0x2000) != 0;
		off = network_off + ihl;
	} else if (protocol == VEER_ETH_P_IPV6) {
		struct veer_ipv6hdr *ip = (void *)((char *)p->data + network_off);

		if (!veer_bounds_ok(p, ip, sizeof(*ip)))
			return more ? FW_PARSE_SHORT : FW_PARSE_PASS;
		if ((*((__u8 *)ip) >> 4) != 6)
			return FW_PARSE_PASS;
		pkt->family = 6;
		__builtin_memcpy(pkt->src, ip->saddr, 16);
		__builtin_memcpy(pkt->dst, ip->daddr, 16);
		l4proto = 0;
		off = fw_ipv6_l4_offset(p, network_off + sizeof(*ip), ip->nexthdr, &l4proto, &fragmented);
		if (off == FW_L4_EVASIVE)
			return FW_PARSE_EVASIVE;
		if (off == FW_L4_LATER) {
			pkt->ipproto = VEER_IPPROTO_FRAGMENT;
			return FW_PARSE_LATER;
		}
		if (off == FW_L4_SHORT) {
			if (more)
				return FW_PARSE_SHORT;
			return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
		}
		pkt->ipproto = l4proto;
	} else {
		return FW_PARSE_PASS;
	}
	pkt->frag = fragmented;
	asm volatile("%0 &= 4095" : "+r"(off));
	pkt->l4_off = off;
	l4 = (__u8 *)p->data + off;
	if (l4proto == VEER_IPPROTO_TCP || l4proto == VEER_IPPROTO_UDP) {
		struct veer_l4_ports *ports = (void *)l4;

		pkt->proto = l4proto == VEER_IPPROTO_TCP ? FW_PROTO_TCP : FW_PROTO_UDP;
		if (!veer_bounds_ok(p, ports, sizeof(*ports))) {
			if (more)
				return FW_PARSE_SHORT;
			return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
		}
		pkt->dport = ports->dest;
		pkt->sport = ports->source;
		/* The flags byte is the 14th of the TCP header. A first fragment
		 * that ends before it hides a SYN from the limit: the host
		 * reassembles it, so it is evasive like one that hides its ports. */
		if (pkt->proto == FW_PROTO_TCP) {
			if (veer_bounds_ok(p, ports, 14))
				pkt->tcp_flags = ((__u8 *)ports)[13];
			else if (more)
				return FW_PARSE_SHORT;
			else if (fragmented)
				return FW_PARSE_EVASIVE;
		}
		return FW_PARSE_OK;
	}
	if ((pkt->family == 4 && l4proto == VEER_IPPROTO_ICMP) || (pkt->family == 6 && l4proto == VEER_IPPROTO_ICMPV6)) {
		pkt->proto = pkt->family == 4 ? FW_PROTO_ICMP : FW_PROTO_ICMPV6;
		if (!veer_bounds_ok(p, l4, 8)) {
			if (more)
				return FW_PARSE_SHORT;
			return fragmented ? FW_PARSE_EVASIVE : FW_PARSE_PASS;
		}
		pkt->icmp_type = l4[0];
		pkt->icmp_code = l4[1];
		pkt->dport = *(__u16 *)l4;
		pkt->sport = *(__u16 *)(l4 + 4);
		return FW_PARSE_OK;
	}
	pkt->proto = FW_PROTO_IP;
	pkt->dport = veer_htons((__u16)l4proto << 8);
	return FW_PARSE_OK;
}

/* The ICMP the network needs, whatever the policies say: packet too big,
 * neighbour discovery and MLD (both link-local), and replies to this host's
 * DHCP client. */
static __always_inline int fw_essential(const struct fw_packet *pkt)
{
	__u8 type = pkt->icmp_type;

	if (pkt->proto == FW_PROTO_ICMP)
		return type == 3 && pkt->icmp_code == 4;
	if (pkt->proto == FW_PROTO_ICMPV6)
		return type == 2 || (type >= 130 && type <= 137) || type == 143;
	if (pkt->proto == FW_PROTO_UDP) {
		if (pkt->family == 4)
			return pkt->sport == veer_htons(67) && pkt->dport == veer_htons(68);
		return pkt->sport == veer_htons(547) && pkt->dport == veer_htons(546);
	}
	return 0;
}

/* A DHCPv4 client asking for an address: from 0.0.0.0, UDP 68 to 67. The
 * bogon (0.0.0.0/8) and reverse-path checks would stop it on an interface
 * where Veer serves DHCP; policies on port 67 still judge it. */
static __always_inline int fw_dhcp_request(const struct fw_packet *pkt)
{
	return pkt->family == 4 && pkt->proto == FW_PROTO_UDP && FW_V4(pkt->src) == 0 &&
	       pkt->sport == veer_htons(68) && pkt->dport == veer_htons(67);
}

/* Flag combinations no TCP stack sends: SYN with FIN or RST, FIN with RST,
 * FIN, PSH or URG without ACK, and no flags at all. */
static __always_inline int fw_bad_flags(__u8 flags)
{
	if ((flags & (FW_TCP_SYN | FW_TCP_FIN)) == (FW_TCP_SYN | FW_TCP_FIN))
		return 1;
	if ((flags & (FW_TCP_SYN | FW_TCP_RST)) == (FW_TCP_SYN | FW_TCP_RST))
		return 1;
	if ((flags & (FW_TCP_FIN | FW_TCP_RST)) == (FW_TCP_FIN | FW_TCP_RST))
		return 1;
	if (!(flags & FW_TCP_ACK) && (flags & (FW_TCP_FIN | FW_TCP_PSH | FW_TCP_URG)))
		return 1;
	return (flags & 0x3f) == 0;
}

/* Whether set id holds the source in key (filled by the caller). Expired
 * elements stay until the control script removes them; they no longer
 * match. *now is read once, when an element can expire. */
static __always_inline int fw_set_has(struct fw_set_key *key, __u32 id, __u64 *now)
{
	struct fw_set_elem *elem;
	__u64 expires;

	key->id = veer_htons(id);
	elem = veer_bpf_map_lookup_elem(&fw_sets, key);
	if (!elem)
		return 0;
	expires = elem->expires_ns;
	if (!expires)
		return 1;
	if (!*now)
		*now = fw_ktime_get_ns();
	return expires > *now;
}

static __always_inline void fw_set_key_of(const struct fw_packet *pkt, struct fw_set_key *key)
{
	key->prefixlen = pkt->family == 4 ? 64 : 160;
	key->family = pkt->family;
	__builtin_memcpy(key->addr, pkt->src, 16);
}

/* Adds pkt's source, as the prefix the policy adds, to the set of a policy,
 * unless the set already covers that prefix: a lookup is lock-free, an
 * update takes the trie's lock. The lookup goes no deeper than the prefix,
 * so an element it finds at exactly that prefix is the one the update would
 * replace, and the lookup said it has expired: the update may overwrite it
 * (until the control script prunes it, an expired element stays). */
static __always_inline void fw_set_add(const struct fw_packet *pkt, const struct fw_pext *px, __u64 *now)
{
	struct fw_set_key key = {};
	struct fw_set_elem elem = {};

	fw_set_key_of(pkt, &key);
	if (pkt->family == 6) {
		__u32 prefix = px->add_v6_prefix;

		key.prefixlen = 32 + (prefix >= 32 && prefix <= 128 ? prefix : 128);
#pragma unroll
		for (int i = 0; i < 16; i++)
			key.addr[i] &= px->add_v6_mask[i];
	}
	if (fw_set_has(&key, px->add_set, now))
		return;
	if (!*now)
		*now = fw_ktime_get_ns();
	if (px->add_seconds)
		elem.expires_ns = *now + (__u64)px->add_seconds * FW_NS_PER_SECOND;
	elem.kind = 3; /* added by a policy */
	if (fw_map_update_elem(&fw_sets, &key, &elem, BPF_ANY) == 0)
		fw_gcount(FW_GCNT_SET_ADD);
	else
		fw_gcount(FW_GCNT_SET_FULL);
}

/*
 * Reverse-path check of pkt's source, as the kernel's rp_filter would do it
 * if the Veer core did not forward the packet before the stack sees it: a
 * route lookup towards the source, as if a packet to it arrived on ifindex.
 * Loose fails a source without a usable route; strict also one whose route
 * leaves through another interface. Lookups that cannot tell (forwarding off
 * on the interface, lightweight tunnels) pass.
 */
static __always_inline int fw_urpf_fails(void *ctx, __u32 ifindex, __u32 gflags, const struct fw_packet *pkt)
{
	struct fw_scratch *scratch;
	struct fw_fib *params;
	__u32 zero = 0;
	long rc;

	scratch = veer_bpf_map_lookup_elem(&fw_scratch, &zero);
	if (!scratch)
		return 0;
	params = &scratch->fib;
	__builtin_memset(params, 0, sizeof(*params));
	/* IPv4 addresses sit in the first word, as in pkt. */
	params->family = pkt->family == 4 ? FW_AF_INET : FW_AF_INET6;
	__builtin_memcpy(params->dst, pkt->src, 16);
	__builtin_memcpy(params->src, pkt->dst, 16);
	params->ifindex = ifindex;
	rc = fw_fib_lookup(ctx, params, sizeof(*params), 0);
	if (rc == FW_FIB_SUCCESS || rc == FW_FIB_NO_NEIGH)
		return (gflags & FW_G_URPF_STRICT) && params->ifindex != ifindex;
	return rc == FW_FIB_BLACKHOLE || rc == FW_FIB_UNREACHABLE || rc == FW_FIB_PROHIBIT || rc == FW_FIB_NOT_FWDED;
}

/* The tuple an ICMP error quotes: the start of a packet this host sent, so
 * a key of fw_ct as its egress program wrote it. */
static __always_inline int fw_icmp_quoted(const struct veer_packet *p, const struct fw_packet *pkt, struct fw_ct_key *key)
{
	struct veer_l4_ports *ports;
	__u32 off = pkt->l4_off + 8;
	__u8 inner;

	asm volatile("%0 &= 4095" : "+r"(off));
	if (pkt->family == 4) {
		struct veer_ipv4hdr *ip = (void *)((char *)p->data + off);
		__u32 ihl;

		if (!veer_bounds_ok(p, ip, sizeof(*ip)) || (ip->ver_ihl >> 4) != 4)
			return 0;
		ihl = (ip->ver_ihl & 0x0f) * 4;
		if (ihl < sizeof(*ip) || (ip->frag_off & veer_htons(0x1fff)))
			return 0;
		inner = ip->protocol;
		ports = (void *)((char *)ip + ihl);
		if (!veer_bounds_ok(p, ports, sizeof(*ports)))
			return 0;
		FW_V4(key->laddr) = ip->saddr;
		FW_V4(key->raddr) = ip->daddr;
	} else {
		struct veer_ipv6hdr *ip = (void *)((char *)p->data + off);

		if (!veer_bounds_ok(p, ip, sizeof(*ip) + sizeof(*ports)))
			return 0;
		inner = ip->nexthdr;
		ports = (void *)(ip + 1);
		__builtin_memcpy(key->laddr, ip->saddr, 16);
		__builtin_memcpy(key->raddr, ip->daddr, 16);
	}
	if (inner == VEER_IPPROTO_TCP)
		key->proto = FW_PROTO_TCP;
	else if (inner == VEER_IPPROTO_UDP)
		key->proto = FW_PROTO_UDP;
	else
		return 0;
	key->lport = ports->source;
	key->rport = ports->dest;
	return 1;
}

static __always_inline __u64 fw_ct_timeout(__u8 proto, __u32 flags)
{
	if (proto == FW_PROTO_TCP)
		return (flags & FW_CT_CLOSING) ? FW_CT_TCP_CLOSING_NS : FW_CT_TCP_NS;
	if (proto == FW_PROTO_UDP)
		return FW_CT_UDP_NS;
	return FW_CT_ICMP_NS;
}

/*
 * Whether pkt answers a connection this side opened: 1 for a reply (TCP,
 * UDP, ICMP echo reply), 2 for an ICMP error about one, 0 otherwise. A reply
 * refreshes the connection at most once a second.
 */
static __always_inline int fw_ct_ingress(const struct veer_packet *p, const struct fw_packet *pkt, __u64 *now)
{
	struct fw_ct_key key = {};
	struct fw_ct *ct;
	__u8 type = pkt->icmp_type;
	__u64 seen;
	__u32 flags;
	int state = 1;

	key.family = pkt->family;
	if (pkt->proto == FW_PROTO_TCP || pkt->proto == FW_PROTO_UDP) {
		key.proto = pkt->proto;
		key.lport = pkt->dport;
		key.rport = pkt->sport;
		__builtin_memcpy(key.laddr, pkt->dst, 16);
		__builtin_memcpy(key.raddr, pkt->src, 16);
	} else if ((pkt->proto == FW_PROTO_ICMP && type == 0) || (pkt->proto == FW_PROTO_ICMPV6 && type == 129)) {
		key.proto = pkt->proto;
		key.lport = pkt->sport;
		__builtin_memcpy(key.laddr, pkt->dst, 16);
		__builtin_memcpy(key.raddr, pkt->src, 16);
	} else if ((pkt->proto == FW_PROTO_ICMP && (type == 3 || type == 11 || type == 12)) ||
		   (pkt->proto == FW_PROTO_ICMPV6 && (type == 1 || type == 3 || type == 4))) {
		if (!fw_icmp_quoted(p, pkt, &key))
			return 0;
		state = 2;
	} else {
		return 0;
	}
	ct = veer_bpf_map_lookup_elem(&fw_ct, &key);
	if (!ct)
		return 0;
	seen = ct->seen_ns;
	flags = ct->flags;
	if (!*now)
		*now = fw_ktime_get_ns();
	/* Another CPU may have written a time later than this one read. */
	if (*now > seen) {
		if (*now - seen >= fw_ct_timeout(key.proto, flags))
			return 0;
		if (state == 1 && *now - seen > FW_NS_PER_SECOND)
			ct->seen_ns = *now;
	}
	return state;
}

/* Whether the TCP or UDP port of the generation's bitmap is protected. */
static __always_inline int fw_port_covered(__u32 generation, __u8 proto, __u16 port)
{
	__u32 key = generation * FW_PORT_WORDS_PER_GEN + proto * FW_PORT_WORDS + (veer_ntohs(port) >> 6);
	__u64 *bits = veer_bpf_map_lookup_elem(&fw_port_bits, &key);

	return bits && ((*bits >> (veer_ntohs(port) & 63)) & 1);
}

/*
 * Records the connection an outgoing packet belongs to. Only this side's
 * connection attempts open an entry: a TCP SYN without ACK, a UDP packet
 * from a port no UDP policy covers, an ICMP echo request. Connections that
 * come in (their replies leave from a protected port, or as a SYN-ACK) never
 * get one, so policies keep judging every packet of them: a rule change
 * applies to them at once, and a session kept alive across an apply cannot
 * confirm rules that block new connections.
 */
static __always_inline void fw_ct_track(__u32 generation, const struct fw_packet *pkt)
{
	struct fw_ct_key key = {};
	struct fw_ct fresh = {};
	struct fw_ct *ct;
	__u8 flags = pkt->tcp_flags;
	__u64 now;
	int open = 0;

	key.family = pkt->family;
	key.proto = pkt->proto;
	__builtin_memcpy(key.laddr, pkt->src, 16);
	__builtin_memcpy(key.raddr, pkt->dst, 16);
	if (pkt->proto == FW_PROTO_TCP) {
		key.lport = pkt->sport;
		key.rport = pkt->dport;
		open = (flags & (FW_TCP_SYN | FW_TCP_ACK)) == FW_TCP_SYN;
	} else if (pkt->proto == FW_PROTO_UDP) {
		key.lport = pkt->sport;
		key.rport = pkt->dport;
		open = !fw_port_covered(generation, FW_PROTO_UDP, pkt->sport);
	} else if ((pkt->proto == FW_PROTO_ICMP && pkt->icmp_type == 8) || (pkt->proto == FW_PROTO_ICMPV6 && pkt->icmp_type == 128)) {
		key.lport = pkt->sport;
		open = 1;
	} else {
		return;
	}
	ct = veer_bpf_map_lookup_elem(&fw_ct, &key);
	if (!ct && !open)
		return;
	now = fw_ktime_get_ns();
	if (ct) {
		__u32 state = ct->flags;

		if (pkt->proto == FW_PROTO_TCP) {
			if (flags & (FW_TCP_FIN | FW_TCP_RST)) {
				if (!(state & FW_CT_CLOSING))
					ct->flags = state | FW_CT_CLOSING;
			} else if (open && (state & FW_CT_CLOSING)) {
				/* The same tuple opens again. */
				ct->flags = 0;
			}
		}
		if (now > ct->seen_ns + FW_NS_PER_SECOND)
			ct->seen_ns = now;
		return;
	}
	fresh.seen_ns = now;
	if (fw_map_update_elem(&fw_ct, &key, &fresh, BPF_ANY) == 0)
		fw_gcount(FW_GCNT_CT_NEW);
	else
		fw_gcount(FW_GCNT_CT_FULL);
}

/* fw_rate/fw_ban key: the source masked to its counting prefix. */
static __always_inline void fw_limit_key_of(const struct fw_packet *pkt, __u32 slot, const struct fw_limit *limit, struct fw_limit_key *key)
{
	key->family = pkt->family;
	key->slot = slot;
	if (pkt->family == 4) {
		key->prefix = 32;
		__builtin_memcpy(key->addr, pkt->src, 4);
		return;
	}
	key->prefix = limit->v6_prefix;
#pragma unroll
	for (int i = 0; i < 16; i++)
		key->addr[i] = pkt->src[i] & limit->v6_mask[i];
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

/* The class of pkt: by TCP/UDP port, ICMP type and code, or IP protocol. */
static __always_inline __u32 fw_class_of(const struct fw_packet *pkt, __u32 generation)
{
	struct fw_port_key port_key = {};
	__u32 *class_id;

	port_key.prefixlen = 32;
	port_key.generation = generation;
	port_key.proto = pkt->proto;
	port_key.port = pkt->dport;
	class_id = veer_bpf_map_lookup_elem(&fw_ports, &port_key);
	if (!class_id || *class_id >= FW_MAX_CLASSES)
		return 0;
	return *class_id;
}

static __always_inline __u32 fw_policy_of(const struct fw_packet *pkt, __u32 generation, __u32 class_id)
{
	struct fw_class *cls;
	__u32 key;
	__u32 policy;

	if (!class_id || class_id >= FW_MAX_CLASSES)
		return 0;
	key = generation * FW_MAX_CLASSES + class_id;
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
			dst.id = veer_htons(class_id);
			dst.addr = FW_V4(pkt->dst);
			scoped = veer_bpf_map_lookup_elem(&fw_dst4, &dst);
		} else {
			struct fw_addr6_key dst = {};

			dst.prefixlen = 160;
			dst.generation = generation;
			dst.id = veer_htons(class_id);
			__builtin_memcpy(dst.addr, pkt->dst, 16);
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
		src.addr = FW_V4(pkt->src);
		verdict = veer_bpf_map_lookup_elem(&fw_src4, &src);
	} else {
		struct fw_addr6_key src = {};

		src.prefixlen = 160;
		src.generation = generation;
		src.id = veer_htons(policy);
		__builtin_memcpy(src.addr, pkt->src, 16);
		verdict = veer_bpf_map_lookup_elem(&fw_src6, &src);
	}
	if (!verdict)
		return -1;
	return verdict->action;
}

/*
 * The filter itself, on the result of fw_parse: 0 to pass pkt, or the
 * FW_REASON_* it is dropped for. *slot_out names the policy that dropped it
 * (0 for drops before the policies, the set for blocklist drops). Logging
 * happens once, in the caller, so its code is inlined only once per entry
 * point. ctx is the program's context, for the route lookup.
 */
static __always_inline int fw_judge(void *ctx, const struct veer_packet *p, __u32 ifindex, const struct fw_cfg *cfg,
				    const struct fw_gcfg *g, struct fw_packet *pkt, int parsed, __u32 *slot_out)
{
	struct fw_limit_key limit_key = {};
	struct fw_set_key skey = {};
	struct fw_policy *policy;
	struct fw_pext *px;
	__u32 gflags = g->flags;
	__u32 generation;
	__u32 class_id = 0;
	__u32 key;
	__u32 slot;
	__u64 now = 0;
	__u64 window_ns = 0;
	__u64 ban_ns = 0;
	__u32 max_new = 0;
	int limited = 0;
	int reason = 0;
	int covered = 0;
	int action;

	if (parsed == FW_PARSE_EVASIVE && (cfg->flags & FW_CFG_ACTIVE)) {
		fw_count(0, FW_CNT_EVASIVE);
		return FW_REASON_EVASIVE;
	}
	if (parsed == FW_PARSE_LATER && (gflags & FW_G_DROP_FRAGS)) {
		fw_gcount(FW_GCNT_FRAGMENT);
		return FW_REASON_FRAGMENT;
	}
	if (parsed != FW_PARSE_OK)
		return 0;
	generation = cfg->generation & 1;
	/* Most traffic: TCP or UDP to a port no policy covers, with no global
	 * check on. It passes after the port bitmap, as in 1.0. */
	if (pkt->proto == FW_PROTO_TCP || pkt->proto == FW_PROTO_UDP) {
		covered = fw_port_covered(generation, pkt->proto, pkt->dport);
		if (!covered && !g->any_class && !g->block_count && !(gflags & FW_G_PACKET_CHECKS))
			return 0;
	}
	if (fw_essential(pkt)) {
		fw_gcount(FW_GCNT_ESSENTIAL);
		return 0;
	}
	if (pkt->frag && (gflags & FW_G_DROP_FRAGS)) {
		fw_gcount(FW_GCNT_FRAGMENT);
		return FW_REASON_FRAGMENT;
	}
	if (pkt->proto == FW_PROTO_TCP && (gflags & FW_G_BAD_FLAGS) && fw_bad_flags(pkt->tcp_flags)) {
		fw_gcount(FW_GCNT_FLAGS);
		return FW_REASON_FLAGS;
	}

	/* Where the packet comes from, before any policy. */
	if (g->block_count || (gflags & FW_G_BOGON))
		fw_set_key_of(pkt, &skey);
#pragma unroll
	for (int i = 0; i < FW_BLOCK_SETS; i++) {
		if (i >= g->block_count)
			break;
		if (fw_set_has(&skey, g->block_sets[i], &now)) {
			*slot_out = g->block_sets[i];
			reason = FW_REASON_BLOCKLIST;
			break;
		}
	}
	if (!reason && (gflags & (FW_G_BOGON | FW_G_URPF_LOOSE | FW_G_URPF_STRICT)) && !fw_dhcp_request(pkt)) {
		if ((gflags & FW_G_BOGON) && fw_set_has(&skey, FW_SET_BOGON, &now))
			reason = FW_REASON_BOGON;
		else if ((gflags & (FW_G_URPF_LOOSE | FW_G_URPF_STRICT)) && fw_urpf_fails(ctx, ifindex, gflags, pkt))
			reason = FW_REASON_URPF;
	}

	/* Where it goes: the port bitmap said whether a TCP/UDP port is covered. */
	if (pkt->proto == FW_PROTO_TCP || pkt->proto == FW_PROTO_UDP) {
		if (covered)
			class_id = fw_class_of(pkt, generation);
	} else if (gflags & FW_G_PROTO) {
		class_id = fw_class_of(pkt, generation);
	}
	if (!class_id)
		class_id = g->any_class;

	/* Replies of tracked connections: past every policy, the bogon and
	 * reverse-path checks; never past a blocklist. Only looked up when
	 * something would judge the packet. */
	if ((gflags & FW_G_CT) && reason != FW_REASON_BLOCKLIST && (class_id || reason)) {
		int state = fw_ct_ingress(p, pkt, &now);

		if (state) {
			fw_gcount(state == 1 ? FW_GCNT_ESTABLISHED : FW_GCNT_RELATED);
			return 0;
		}
	}
	if (reason) {
		/* Trusted sources are never dropped for where they come from. */
		if (fw_source_action(pkt, generation, 0) == FW_ACTION_PASS)
			return 0;
		fw_gcount(reason == FW_REASON_BLOCKLIST ? FW_GCNT_BLOCKLIST : reason == FW_REASON_BOGON ? FW_GCNT_BOGON : FW_GCNT_URPF);
		return reason;
	}

	slot = fw_policy_of(pkt, generation, class_id);
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
	/* An array: present for every slot, zero for policies without it. */
	px = veer_bpf_map_lookup_elem(&fw_pext, &key);
	if (!px)
		return 0;

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

		if (!now)
			now = fw_ktime_get_ns();
		if (until && *until > now) {
			fw_count(slot, FW_CNT_DROP);
			fw_lcount(slot, FW_LCNT_BAN);
			return FW_REASON_BAN;
		}
	}

	/* Only connection attempts: other TCP packets pass. */
	if ((px->flags & FW_PX_NEW_ONLY) && pkt->proto == FW_PROTO_TCP &&
	    (pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK)) != FW_TCP_SYN) {
		fw_count(slot, FW_CNT_PASS);
		return 0;
	}

	action = fw_source_action(pkt, generation, slot);
	if (action < 0 && px->set_count) {
		fw_set_key_of(pkt, &skey);
#pragma unroll
		for (int i = 0; i < FW_PX_SETS; i++) {
			if (i >= px->set_count)
				break;
			if (fw_set_has(&skey, px->sets[i], &now)) {
				action = px->set_action[i];
				break;
			}
		}
	}
	if (action < 0)
		action = policy->default_action;
	if (action == FW_ACTION_DROP) {
		/* Only attempts go to the set: a reply to someone else's spoofed
		 * connection must not put its victim there. */
		if ((px->flags & FW_PX_ADD_SET) &&
		    (pkt->proto != FW_PROTO_TCP || (pkt->tcp_flags & (FW_TCP_SYN | FW_TCP_ACK)) == FW_TCP_SYN))
			fw_set_add(pkt, px, &now);
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

/* The generation's global settings; zero when never written. An array, so
 * the lookup only fails for a corrupt generation. */
static __always_inline const struct fw_gcfg *fw_gcfg_of(const struct fw_cfg *cfg)
{
	__u32 generation = cfg->generation & 1;

	return veer_bpf_map_lookup_elem(&fw_gcfg, &generation);
}

SEC("xdp/veer/firewall")
int xdp_firewall(struct xdp_md *xdp)
{
	struct fw_packet pkt = {};
	struct veer_packet p;
	const struct fw_cfg *cfg;
	const struct fw_gcfg *g;
	__u32 ifindex = xdp->ingress_ifindex;
	__u32 zero = 0;
	__u32 slot = 0;
	int reason;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg || !veer_packet_from_xdp(xdp, &p))
		goto pass;
	g = fw_gcfg_of(cfg);
	if (!g)
		goto pass;
	reason = fw_judge(xdp, &p, ifindex, cfg, g, &pkt, fw_parse(&p, ifindex, 0, cfg, &pkt), &slot);
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
	const struct fw_gcfg *g;
	__u32 ifindex = skb->ingress_ifindex;
	__u32 zero = 0;
	__u32 slot = 0;
	int parsed;
	int reason;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg || !veer_packet_from_skb(skb, &p))
		return FW_TC_PASS;
	g = fw_gcfg_of(cfg);
	if (!g)
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
	reason = fw_judge(skb, &p, ifindex, cfg, g, &pkt, parsed, &slot);
	if (reason) {
		fw_log(ifindex, &pkt, slot, reason);
		return FW_TC_DROP;
	}
	return FW_TC_PASS;
}

/*
 * tc_egress program of the XDP hook, at the head of TC egress of every bound
 * interface: with connection tracking on it records the connections this
 * side opens (fw_ct_track), whether the packet comes from the host itself or
 * from the Veer core forwarding it. It sees the packet as it leaves, after
 * NAT. It reads the headers in place and never pulls them: local TCP
 * packets are clones that a pull would copy. Headers outside the linear
 * data are counted and skipped. It never drops.
 */
SEC("tc/veer/firewall_egress")
int tc_firewall_egress(struct __sk_buff *skb)
{
	struct fw_packet pkt = {};
	struct veer_packet p;
	const struct fw_cfg *cfg;
	const struct fw_gcfg *g;
	__u32 zero = 0;
	int parsed;

	cfg = veer_bpf_map_lookup_elem(&fw_cfg, &zero);
	if (!cfg)
		return FW_TC_PASS;
	g = fw_gcfg_of(cfg);
	if (!g || !(g->flags & FW_G_CT) || !veer_packet_from_skb(skb, &p))
		return FW_TC_PASS;
	parsed = fw_parse(&p, skb->ifindex, 1, cfg, &pkt);
	if (parsed == FW_PARSE_SHORT)
		fw_gcount(FW_GCNT_CT_SHORT);
	else if (parsed == FW_PARSE_OK)
		fw_ct_track(cfg->generation & 1, &pkt);
	return FW_TC_PASS;
}

char __license[] SEC("license") = "GPL";
