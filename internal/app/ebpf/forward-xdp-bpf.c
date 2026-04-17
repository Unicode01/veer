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
#include "include/forward_addr_helpers.h"
#include "include/bpf_helpers.h"

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

struct icmp_echo_hdr {
	__be16 id;
	__be16 sequence;
};

struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	union {
		struct icmp_echo_hdr echo;
		__u32 word;
	} un;
};

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct ipv6hdr {
	__be32 ver_tc_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

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
	__u8 front_mac[ETH_ALEN];
	__u8 client_mac[ETH_ALEN];
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

struct rule_key_v6 {
	__u32 ifindex;
	__u8 dst_addr[16];
	__u16 dst_port;
	__u8 proto;
	__u8 pad;
};

struct rule_value_v6 {
	__u32 rule_id;
	__u8 backend_addr[16];
	__u16 backend_port;
	__u16 flags;
	__u32 out_ifindex;
	__u8 nat_addr[16];
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
};

struct flow_key_v6 {
	__u32 ifindex;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
	__u8 pad[3];
};

struct flow_value_v6 {
	__u32 rule_id;
	__u8 front_addr[16];
	__u8 client_addr[16];
	__u8 nat_addr[16];
	__u32 in_ifindex;
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 flags;
	__u8 front_mac[ETH_ALEN];
	__u8 client_mac[ETH_ALEN];
	__u32 pad;
	__u64 last_seen_ns;
	__u64 front_close_seen_ns;
};

struct nat_port_key_v6 {
	__u32 ifindex;
	__u8 nat_addr[16];
	__u16 nat_port;
	__u8 proto;
	__u8 pad;
};

struct nat_port_value_v6 {
	__u32 rule_id;
};

union flow_nat_key_v4 {
	struct flow_key_v4 flow;
	struct nat_port_key_v4 nat;
};

union flow_nat_key_v6 {
	struct flow_key_v6 flow;
	struct nat_port_key_v6 nat;
};

struct rule_stats_value_v4 {
	__u64 total_conns;
	__u64 tcp_active_conns;
	__u64 udp_nat_entries;
	__u64 icmp_nat_entries;
	__u64 bytes_in;
	__u64 bytes_out;
};

struct kernel_diag_value_v4 {
	__u64 fib_non_success;
	__u64 redirect_neigh_used;
	__u64 redirect_drop;
	__u64 nat_reserve_fail;
	__u64 nat_self_heal_insert;
	__u64 flow_update_fail;
	__u64 nat_update_fail;
	__u64 rewrite_fail;
	__u64 nat_probe_round2_used;
	__u64 nat_probe_round3_used;
	__u64 reply_flow_recreated;
	__u64 tcp_close_delete;
	__u64 xdp_v4_transparent_enter;
	__u64 xdp_v4_fullnat_forward_enter;
	__u64 xdp_v4_fullnat_reply_enter;
	__u64 xdp_redirect_invoked;
	__u64 xdp_v4_transparent_reply_flow_hit;
	__u64 xdp_v4_transparent_forward_rule_hit;
	__u64 xdp_v4_transparent_no_match_pass;
	__u64 xdp_v4_transparent_reply_closing_handled;
};

struct kernel_occupancy_value_v4 {
	__s64 flow_entries;
	__s64 nat_entries;
	__u32 flow_capacity;
	__u32 nat_capacity;
	__u32 pad;
};

struct kernel_nat_config_value_v4 {
	__u32 port_min;
	__u32 port_max;
	__u32 pad0;
	__u32 pad1;
};

struct nat_probe_window_v4 {
	__u32 port_min;
	__u32 port_range;
	__u32 start;
	__u32 stride;
};

struct redirect_target_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
};

struct redirect_target_v6 {
	__u32 ifindex;
	__u8 src_addr[16];
	__u8 dst_addr[16];
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
	__u8 tcp_flags;
	__u8 tos;
	__u8 pad;
	__u16 src_port;
	__u16 dst_port;
	__u16 tot_len;
	__u16 l3_off;
	__u16 l4_off;
#if FORWARD_ENABLE_TRAFFIC_STATS
	__u16 payload_len;
#endif
};

struct packet_ctx_v6 {
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u8 proto;
	__u8 has_l4_checksum;
	__u8 closing;
	__u8 tcp_flags;
	__u16 src_port;
	__u16 dst_port;
	__u16 tot_len;
	__u16 l3_off;
	__u16 l4_off;
#if FORWARD_ENABLE_TRAFFIC_STATS
	__u16 payload_len;
#endif
};

struct xdp_dispatch_ctx_v4 {
	struct packet_ctx ctx;
	struct flow_key_v4 flow_key;
	struct flow_value_v4 flow_value;
	struct rule_value_v4 rule_value;
	__u32 in_ifindex;
	__u8 flow_bank;
	__u8 have_flow;
	__u8 have_rule;
	__u8 pad0;
};

struct xdp_dispatch_ctx_v6 {
	struct packet_ctx_v6 ctx;
	struct flow_key_v6 flow_key;
	struct flow_value_v6 flow_value;
	struct rule_value_v6 rule_value;
	__u32 in_ifindex;
	__u8 flow_bank;
	__u8 have_flow;
	__u8 have_rule;
	__u8 pad0;
};

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_FLOW_FLAG_FRONT_CLOSING 0x1
#define FORWARD_FLOW_FLAG_REPLY_SEEN 0x2
#define FORWARD_FLOW_FLAG_FULL_NAT 0x4
#define FORWARD_FLOW_FLAG_FRONT_ENTRY 0x8
#define FORWARD_FLOW_FLAG_EGRESS_NAT 0x10
#define FORWARD_FLOW_FLAG_COUNTED 0x20
#define FORWARD_FLOW_FLAG_TRAFFIC_STATS 0x40
#define FORWARD_FLOW_FLAG_FULL_CONE 0x80
#define FORWARD_RULE_FLAG_FULL_NAT 0x1
#define FORWARD_RULE_FLAG_BRIDGE_L2 0x2
#define FORWARD_RULE_FLAG_BRIDGE_INGRESS_L2 0x4
#define FORWARD_RULE_FLAG_TRAFFIC_STATS 0x8
#define FORWARD_RULE_FLAG_PREPARED_L2 0x10
#define FORWARD_RULE_FLAG_EGRESS_NAT 0x20
#define FORWARD_RULE_FLAG_FULL_CONE 0x40
#define FORWARD_TCP_FLOW_REFRESH_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_REFRESH_NS (1ULL * 1000000000ULL)
#define FORWARD_ICMP_FLOW_IDLE_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)
#define FORWARD_DATAGRAM_FLOW_IDLE_NS(proto) ((proto) == IPPROTO_ICMP ? FORWARD_ICMP_FLOW_IDLE_NS : FORWARD_UDP_FLOW_IDLE_NS)
#define FORWARD_NAT_PORT_MIN 20000U
#define FORWARD_NAT_PORT_MAX 65535U
#define FORWARD_NAT_PORT_RANGE (FORWARD_NAT_PORT_MAX - FORWARD_NAT_PORT_MIN + 1U)
#define FORWARD_NAT_PORT_PROBE_ATTEMPTS 32
#if FORWARD_NAT_PORT_PROBE_ATTEMPTS != 32
#error FORWARD_NAT_PORT_PROBE_ATTEMPTS requires updating manual unroll sites
#endif
#define FORWARD_UNROLL_32(M) \
	M(0);  M(1);  M(2);  M(3);  M(4);  M(5);  M(6);  M(7); \
	M(8);  M(9);  M(10); M(11); M(12); M(13); M(14); M(15); \
	M(16); M(17); M(18); M(19); M(20); M(21); M(22); M(23); \
	M(24); M(25); M(26); M(27); M(28); M(29); M(30); M(31)
#define FORWARD_CSUM_MANGLED_0 ((__sum16)0xffff)
#define FORWARD_FULLNAT_STATE_CREATED_FRONT 0x1
#define FORWARD_FULLNAT_STATE_CREATED_REPLY 0x2
#define FORWARD_FULLNAT_STATE_NEW_SESSION 0x4
#define FORWARD_FULLNAT_STATE_COUNT_UDP_NOW 0x8
#define FORWARD_FULLNAT_STATE_FLOW_BANK_OLD 0x10
#define FORWARD_TCP_FLAG_FIN 0x01
#define FORWARD_TCP_FLAG_SYN 0x02
#define FORWARD_TCP_FLAG_RST 0x04
#define FORWARD_TCP_FLAG_ACK 0x10
#define FORWARD_XDP_FLOW_BANK_ACTIVE 0
#define FORWARD_XDP_FLOW_BANK_OLD 1
#define FORWARD_XDP_FLOW_MIGRATION_V4_OLD 0x1
#define FORWARD_XDP_FLOW_MIGRATION_V6_OLD 0x2

#if FORWARD_ENABLE_TRAFFIC_STATS
#define FORWARD_RULE_TRAFFIC_ENABLED(rule) (((rule)->flags & FORWARD_RULE_FLAG_TRAFFIC_STATS) != 0)
#define FORWARD_FLOW_TRAFFIC_ENABLED(flow) (((flow)->flags & FORWARD_FLOW_FLAG_TRAFFIC_STATS) != 0)
#define FORWARD_SET_PAYLOAD_LEN(ctx, value) ((ctx)->payload_len = (__u16)(value))
#define FORWARD_GET_PAYLOAD_LEN(ctx) ((__u64)(ctx)->payload_len)
#else
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

/*
 * XDP flow state is pruned explicitly from userspace during steady-state and
 * hot-restart draining. Plain HASH avoids LRU single-entry evictions that can
 * break full-NAT front/reply pairs and old-bank drain guarantees.
 */
struct bpf_map_def SEC("maps") flows_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key_v4),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") flows_old_v4 = {
	.type = BPF_MAP_TYPE_HASH,
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

struct bpf_map_def SEC("maps") nat_ports_old_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct nat_port_key_v4),
	.value_size = sizeof(struct nat_port_value_v4),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") rules_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct rule_key_v6),
	.value_size = sizeof(struct rule_value_v6),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") flows_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key_v6),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") flows_old_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key_v6),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") nat_ports_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct nat_port_key_v6),
	.value_size = sizeof(struct nat_port_value_v6),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") nat_ports_old_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct nat_port_key_v6),
	.value_size = sizeof(struct nat_port_value_v6),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") local_ipv4s_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") xdp_redirect_map = {
	.type = BPF_MAP_TYPE_DEVMAP_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") xdp_prog_chain = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 7,
};

struct bpf_map_def SEC("maps") xdp_flow_migration_state = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_fib_scratch = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bpf_fib_lookup),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_scratch_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_aux_scratch_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_aux_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_key_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_flow_aux_key_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_packet_ctx_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct packet_ctx_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_rule_key_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rule_key_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_dispatch_scratch_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct xdp_dispatch_ctx_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") xdp_dispatch_scratch_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct xdp_dispatch_ctx_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") stats_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rule_stats_value_v4),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") diag_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kernel_diag_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") occupancy_v4 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kernel_occupancy_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") nat_config_v4 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kernel_nat_config_value_v4),
	.max_entries = 1,
};

enum {
	FORWARD_XDP_PROG_V4 = 0,
	FORWARD_XDP_PROG_V6 = 1,
	FORWARD_XDP_PROG_V4_TRANSPARENT = 2,
	FORWARD_XDP_PROG_V4_FULLNAT_FORWARD = 3,
	FORWARD_XDP_PROG_V4_FULLNAT_REPLY = 4,
	FORWARD_XDP_PROG_V6_FULLNAT_FORWARD = 5,
	FORWARD_XDP_PROG_V6_FULLNAT_REPLY = 6,
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

static __always_inline __sum16 csum_replace_ipv6_addr_val(__sum16 check, const __u8 old_addr[16], const __u8 new_addr[16])
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i += 2) {
		/*
		 * Match the native-endian values produced by direct __be16 packet loads.
		 * The incremental checksum helpers operate on those raw values.
		 */
		__be16 old_word = (__be16)(((__u16)old_addr[i + 1] << 8) | (__u16)old_addr[i]);
		__be16 new_word = (__be16)(((__u16)new_addr[i + 1] << 8) | (__u16)new_addr[i]);

		check = csum_replace2_val(check, old_word, new_word);
	}
	return check;
}

static __always_inline struct bpf_fib_lookup *lookup_xdp_fib_scratch(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_fib_scratch, &key);
}

static __always_inline struct flow_value_v4 *lookup_xdp_flow_scratch_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_scratch_v4, &key);
}

static __always_inline struct flow_value_v4 *lookup_xdp_flow_aux_scratch_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_aux_scratch_v4, &key);
}

static __always_inline struct flow_value_v6 *lookup_xdp_flow_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_scratch_v6, &key);
}

static __always_inline struct flow_value_v6 *lookup_xdp_flow_aux_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_aux_scratch_v6, &key);
}

static __always_inline struct flow_key_v6 *lookup_xdp_flow_key_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_key_scratch_v6, &key);
}

static __always_inline struct flow_key_v6 *lookup_xdp_flow_aux_key_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_flow_aux_key_scratch_v6, &key);
}

static __always_inline struct packet_ctx_v6 *lookup_xdp_packet_ctx_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_packet_ctx_scratch_v6, &key);
}

static __always_inline struct rule_key_v6 *lookup_xdp_rule_key_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_rule_key_scratch_v6, &key);
}

static __always_inline struct xdp_dispatch_ctx_v4 *lookup_xdp_dispatch_scratch_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_dispatch_scratch_v4, &key);
}

static __always_inline struct xdp_dispatch_ctx_v6 *lookup_xdp_dispatch_scratch_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&xdp_dispatch_scratch_v6, &key);
}

static __always_inline struct kernel_diag_value_v4 *lookup_xdp_diag_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&diag_v4, &key);
}

static __always_inline void xdp_diag_fib_non_success(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->fib_non_success += 1;
}

static __always_inline void xdp_diag_redirect_drop(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->redirect_drop += 1;
}

static __always_inline void xdp_diag_nat_reserve_fail(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->nat_reserve_fail += 1;
}

static __always_inline void xdp_diag_flow_update_fail(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->flow_update_fail += 1;
}

static __always_inline void xdp_diag_rewrite_fail(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->rewrite_fail += 1;
}

static __always_inline void xdp_diag_reply_flow_recreated(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->reply_flow_recreated += 1;
}

static __always_inline void xdp_diag_v4_transparent_enter(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_transparent_enter += 1;
}

static __always_inline void xdp_diag_v4_fullnat_forward_enter(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_fullnat_forward_enter += 1;
}

static __always_inline void xdp_diag_v4_fullnat_reply_enter(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_fullnat_reply_enter += 1;
}

static __always_inline void xdp_diag_redirect_invoked(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_redirect_invoked += 1;
}

static __always_inline void xdp_diag_v4_transparent_reply_flow_hit(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_transparent_reply_flow_hit += 1;
}

static __always_inline void xdp_diag_v4_transparent_forward_rule_hit(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_transparent_forward_rule_hit += 1;
}

static __always_inline void xdp_diag_v4_transparent_no_match_pass(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_transparent_no_match_pass += 1;
}

static __always_inline void xdp_diag_v4_transparent_reply_closing_handled(void)
{
	struct kernel_diag_value_v4 *diag = lookup_xdp_diag_v4();

	if (diag)
		diag->xdp_v4_transparent_reply_closing_handled += 1;
}

static __always_inline __u32 xdp_flow_migration_flags(void)
{
	__u32 key = 0;
	__u32 *flags = bpf_map_lookup_elem(&xdp_flow_migration_state, &key);

	return flags ? *flags : 0;
}

static __always_inline int xdp_flow_old_bank_enabled_v4(void)
{
	return (xdp_flow_migration_flags() & FORWARD_XDP_FLOW_MIGRATION_V4_OLD) != 0;
}

static __always_inline int xdp_flow_old_bank_enabled_v6(void)
{
	return (xdp_flow_migration_flags() & FORWARD_XDP_FLOW_MIGRATION_V6_OLD) != 0;
}

static __always_inline struct flow_value_v4 *lookup_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&flows_old_v4, key);
	return bpf_map_lookup_elem(&flows_v4, key);
}

static __always_inline struct flow_value_v6 *lookup_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&flows_old_v6, key);
	return bpf_map_lookup_elem(&flows_v6, key);
}

static __always_inline struct flow_value_v4 *lookup_flow_v4_active_or_old(const struct flow_key_v4 *key, __u8 *bank)
{
	struct flow_value_v4 *flow;

	if (bank)
		*bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	flow = lookup_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!xdp_flow_old_bank_enabled_v4())
		return 0;
	flow = lookup_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_XDP_FLOW_BANK_OLD;
	return flow;
}

static __always_inline struct nat_port_value_v4 *lookup_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&nat_ports_old_v4, key);
	return bpf_map_lookup_elem(&nat_ports_v4, key);
}

static __always_inline struct nat_port_value_v6 *lookup_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&nat_ports_old_v6, key);
	return bpf_map_lookup_elem(&nat_ports_v6, key);
}

static __always_inline struct flow_value_v6 *lookup_flow_v6_active_or_old(const struct flow_key_v6 *key, __u8 *bank)
{
	struct flow_value_v6 *flow;

	if (bank)
		*bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	flow = lookup_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!xdp_flow_old_bank_enabled_v6())
		return 0;
	flow = lookup_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_XDP_FLOW_BANK_OLD;
	return flow;
}

static __always_inline int update_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key, const struct flow_value_v4 *value, __u64 flags)
{
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_update_elem(&flows_old_v4, key, value, flags);
	if (flags == BPF_NOEXIST && xdp_flow_old_bank_enabled_v4() && lookup_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&flows_v4, key, value, flags);
}

static __always_inline int update_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key, const struct flow_value_v6 *value, __u64 flags)
{
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_update_elem(&flows_old_v6, key, value, flags);
	if (flags == BPF_NOEXIST && xdp_flow_old_bank_enabled_v6() && lookup_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&flows_v6, key, value, flags);
}

static __always_inline int update_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key, const struct nat_port_value_v4 *value, __u64 flags)
{
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_update_elem(&nat_ports_old_v4, key, value, flags);
	if (flags == BPF_NOEXIST && xdp_flow_old_bank_enabled_v4() && lookup_nat_port_v4_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&nat_ports_v4, key, value, flags);
}

static __always_inline int update_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key, const struct nat_port_value_v6 *value, __u64 flags)
{
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_update_elem(&nat_ports_old_v6, key, value, flags);
	if (flags == BPF_NOEXIST && xdp_flow_old_bank_enabled_v6() && lookup_nat_port_v6_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&nat_ports_v6, key, value, flags);
}

static __always_inline int delete_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD) {
		return bpf_map_delete_elem(&flows_old_v4, key);
	}
	return bpf_map_delete_elem(&flows_v4, key);
}

static __always_inline int delete_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD) {
		return bpf_map_delete_elem(&flows_old_v6, key);
	}
	return bpf_map_delete_elem(&flows_v6, key);
}

static __always_inline int delete_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_delete_elem(&nat_ports_old_v4, key);
	return bpf_map_delete_elem(&nat_ports_v4, key);
}

static __always_inline int delete_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_XDP_FLOW_BANK_OLD)
		return bpf_map_delete_elem(&nat_ports_old_v6, key);
	return bpf_map_delete_elem(&nat_ports_v6, key);
}

static __always_inline int load_packet_macs(struct xdp_md *xdp, __u8 dst_mac[ETH_ALEN], __u8 src_mac[ETH_ALEN])
{
#ifdef BPF_FUNC_xdp_load_bytes
	if (bpf_xdp_load_bytes(xdp, 0, dst_mac, ETH_ALEN) < 0)
		return -1;
	if (bpf_xdp_load_bytes(xdp, ETH_ALEN, src_mac, ETH_ALEN) < 0)
		return -1;
	return 0;
#else
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth;

	if (data + sizeof(struct ethhdr) > data_end)
		return -1;
	eth = data;

	dst_mac[0] = eth->h_dest[0];
	dst_mac[1] = eth->h_dest[1];
	dst_mac[2] = eth->h_dest[2];
	dst_mac[3] = eth->h_dest[3];
	dst_mac[4] = eth->h_dest[4];
	dst_mac[5] = eth->h_dest[5];
	src_mac[0] = eth->h_source[0];
	src_mac[1] = eth->h_source[1];
	src_mac[2] = eth->h_source[2];
	src_mac[3] = eth->h_source[3];
	src_mac[4] = eth->h_source[4];
	src_mac[5] = eth->h_source[5];
	return 0;
#endif
}

static __always_inline void store_packet_macs_v4(struct xdp_md *xdp, struct flow_value_v4 *flow_value)
{
	if (!flow_value)
		return;
	if (load_packet_macs(xdp, flow_value->front_mac, flow_value->client_mac) < 0) {
		__builtin_memset(flow_value->front_mac, 0, sizeof(flow_value->front_mac));
		__builtin_memset(flow_value->client_mac, 0, sizeof(flow_value->client_mac));
	}
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
	struct icmphdr *icmph;
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
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
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
		ctx->tcp_flags =
			(tcph->fin ? FORWARD_TCP_FLAG_FIN : 0) |
			(tcph->syn ? FORWARD_TCP_FLAG_SYN : 0) |
			(tcph->rst ? FORWARD_TCP_FLAG_RST : 0) |
			(tcph->ack ? FORWARD_TCP_FLAG_ACK : 0);
		ctx->closing = tcph->fin || tcph->rst;
		FORWARD_SET_PAYLOAD_LEN(ctx, 0);
		if (ctx->tot_len > (sizeof(*iph) + (((__u16)tcph->doff) << 2)))
			FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*iph) + (((__u16)tcph->doff) << 2)));
		return 0;
	}

	if (ctx->proto == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (bpf_ntohs(udph->len) < sizeof(*udph))
			return -1;
		ctx->src_port = bpf_ntohs(udph->source);
		ctx->dst_port = bpf_ntohs(udph->dest);
		ctx->has_l4_checksum = udph->check != 0;
		ctx->tcp_flags = 0;
		ctx->closing = 0;
		FORWARD_SET_PAYLOAD_LEN(ctx, bpf_ntohs(udph->len) - sizeof(*udph));
		return 0;
	}

	icmph = (void *)iph + sizeof(*iph);
	if ((void *)(icmph + 1) > data_end)
		return -1;
	if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY)
		return -1;
	if (icmph->type == ICMP_ECHO) {
		ctx->src_port = bpf_ntohs(icmph->un.echo.id);
		ctx->dst_port = 0;
	} else {
		ctx->src_port = 0;
		ctx->dst_port = bpf_ntohs(icmph->un.echo.id);
	}
	ctx->has_l4_checksum = 1;
	ctx->tcp_flags = 0;
	ctx->closing = 0;
	FORWARD_SET_PAYLOAD_LEN(ctx, 0);
	if (ctx->tot_len > (sizeof(*iph) + sizeof(*icmph)))
		FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*iph) + sizeof(*icmph)));
	return 0;
}

static __always_inline int parse_ipv6_l4(struct xdp_md *xdp, struct packet_ctx_v6 *ctx)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth;
	struct forward_vlan_hdr *vh;
	struct ipv6hdr *ip6h;
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
		ip6h = (void *)(vh + 1);
		l3_off = sizeof(*eth) + sizeof(*vh);
	} else {
		ip6h = (void *)(eth + 1);
		l3_off = sizeof(*eth);
	}

	if (proto != bpf_htons(ETH_P_IPV6))
		return -1;
	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if ((bpf_ntohl(ip6h->ver_tc_flow) >> 28) != 6)
		return -1;
	if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
		return -1;

	l4_off = l3_off + sizeof(*ip6h);
	copy_ipv6_addr(ctx->src_addr, ip6h->saddr);
	copy_ipv6_addr(ctx->dst_addr, ip6h->daddr);
	ctx->proto = ip6h->nexthdr;
	ctx->tot_len = sizeof(*ip6h) + bpf_ntohs(ip6h->payload_len);
	ctx->l3_off = l3_off;
	ctx->l4_off = l4_off;

	if (ctx->proto == IPPROTO_TCP) {
		tcph = (void *)ip6h + sizeof(*ip6h);
		if ((void *)(tcph + 1) > data_end)
			return -1;
		if (tcph->doff < 5)
			return -1;
		if ((void *)tcph + ((__u32)tcph->doff << 2) > data_end)
			return -1;
		ctx->src_port = bpf_ntohs(tcph->source);
		ctx->dst_port = bpf_ntohs(tcph->dest);
		ctx->has_l4_checksum = 1;
		ctx->tcp_flags =
			(tcph->fin ? FORWARD_TCP_FLAG_FIN : 0) |
			(tcph->syn ? FORWARD_TCP_FLAG_SYN : 0) |
			(tcph->rst ? FORWARD_TCP_FLAG_RST : 0) |
			(tcph->ack ? FORWARD_TCP_FLAG_ACK : 0);
		ctx->closing = tcph->fin || tcph->rst;
		FORWARD_SET_PAYLOAD_LEN(ctx, 0);
		if (ctx->tot_len > (sizeof(*ip6h) + (((__u16)tcph->doff) << 2)))
			FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*ip6h) + (((__u16)tcph->doff) << 2)));
		return 0;
	}

	udph = (void *)ip6h + sizeof(*ip6h);
	if ((void *)(udph + 1) > data_end)
		return -1;
	if (bpf_ntohs(udph->len) < sizeof(*udph))
		return -1;
	ctx->src_port = bpf_ntohs(udph->source);
	ctx->dst_port = bpf_ntohs(udph->dest);
	ctx->has_l4_checksum = 1;
	ctx->tcp_flags = 0;
	ctx->closing = 0;
	FORWARD_SET_PAYLOAD_LEN(ctx, bpf_ntohs(udph->len) - sizeof(*udph));
	return 0;
}

static __always_inline __be16 forward_xdp_eth_proto(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct forward_vlan_hdr *vh;
	__be16 proto;

	if ((void *)(eth + 1) > data_end)
		return 0;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return 0;
		proto = vh->h_vlan_encapsulated_proto;
	}
	return proto;
}

static __always_inline struct rule_value_v4 *lookup_rule_v4_for_ifindex(__u32 in_ifindex, const struct packet_ctx *ctx)
{
	struct rule_key_v4 key = {
		.ifindex = in_ifindex,
		.dst_addr = ctx->dst_addr,
		.dst_port = ctx->dst_port,
		.proto = ctx->proto,
	};
	struct rule_value_v4 *rule;

	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = 0;
	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = ctx->dst_addr;
	key.dst_port = 0;
	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = 0;
	return bpf_map_lookup_elem(&rules_v4, &key);
}

static __always_inline struct rule_value_v4 *lookup_rule_v4(struct xdp_md *xdp, const struct packet_ctx *ctx)
{
	return lookup_rule_v4_for_ifindex(xdp->ingress_ifindex, ctx);
}

static __always_inline struct rule_value_v6 *lookup_rule_v6_for_ifindex(__u32 in_ifindex, const struct packet_ctx_v6 *ctx)
{
	struct rule_key_v6 *key = lookup_xdp_rule_key_scratch_v6();
	struct rule_value_v6 *rule;

	if (!key)
		return 0;
	key->ifindex = in_ifindex;
	key->dst_port = ctx->dst_port;
	key->proto = ctx->proto;
	key->pad = 0;
	copy_ipv6_addr(key->dst_addr, ctx->dst_addr);
	rule = bpf_map_lookup_elem(&rules_v6, key);
	if (rule)
		return rule;

	__builtin_memset(key->dst_addr, 0, sizeof(key->dst_addr));
	return bpf_map_lookup_elem(&rules_v6, key);
}

static __always_inline struct rule_value_v6 *lookup_rule_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx)
{
	return lookup_rule_v6_for_ifindex(xdp->ingress_ifindex, ctx);
}

static __always_inline int is_fullnat_rule(const struct rule_value_v4 *rule)
{
	return rule && (rule->flags & FORWARD_RULE_FLAG_FULL_NAT) != 0;
}

static __always_inline int is_egress_nat_rule(const struct rule_value_v4 *rule)
{
	return rule && (rule->flags & FORWARD_RULE_FLAG_EGRESS_NAT) != 0;
}

static __always_inline int is_full_cone_egress_nat_rule(const struct rule_value_v4 *rule)
{
	return is_egress_nat_rule(rule) && (rule->flags & FORWARD_RULE_FLAG_FULL_CONE) != 0;
}

static __always_inline int is_egress_nat_flow(const struct flow_value_v4 *flow)
{
	return flow && (flow->flags & FORWARD_FLOW_FLAG_EGRESS_NAT) != 0;
}

static __always_inline int is_full_cone_flow(const struct flow_value_v4 *flow)
{
	return flow && (flow->flags & FORWARD_FLOW_FLAG_FULL_CONE) != 0;
}

static __always_inline int is_datagram_proto(__u8 proto)
{
	return proto == IPPROTO_UDP || proto == IPPROTO_ICMP;
}

static __always_inline int is_initial_tcp_syn(const struct packet_ctx *ctx)
{
	if (!ctx || ctx->proto != IPPROTO_TCP)
		return 0;
	return ctx->tcp_flags == FORWARD_TCP_FLAG_SYN;
}

static __always_inline int is_initial_tcp_syn_v6(const struct packet_ctx_v6 *ctx)
{
	if (!ctx || ctx->proto != IPPROTO_TCP)
		return 0;
	return ctx->tcp_flags == FORWARD_TCP_FLAG_SYN;
}

static __always_inline int is_local_ipv4(__u32 addr)
{
	__u32 key = addr;
	__u8 *present = bpf_map_lookup_elem(&local_ipv4s_v4, &key);

	return present && *present != 0;
}

static __always_inline int is_fullnat_rule_v6(const struct rule_value_v6 *rule)
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

static __always_inline int is_fullnat_front_flow_v6(const struct flow_value_v6 *flow)
{
	int i;
	__u8 addr_nonzero = 0;

	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) == 0)
		return 0;
	if (flow->nat_port == 0)
		return 0;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++)
		addr_nonzero |= flow->nat_addr[i];
	return addr_nonzero != 0;
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

static __always_inline int is_full_cone_front_flow(const struct flow_value_v4 *flow)
{
	return is_fullnat_front_flow(flow) && is_full_cone_flow(flow);
}

static __always_inline int is_full_cone_reply_flow(const struct flow_value_v4 *flow)
{
	return is_fullnat_reply_flow(flow) && is_full_cone_flow(flow);
}

static __always_inline int is_fullnat_reply_flow_v6(const struct flow_value_v6 *flow)
{
	int i;
	__u8 addr_nonzero = 0;

	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) != 0)
		return 0;
	if (flow->nat_port == 0)
		return 0;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++)
		addr_nonzero |= flow->nat_addr[i];
	return addr_nonzero != 0;
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

static __always_inline void build_full_cone_front_flow_key(__u32 in_ifindex, const struct packet_ctx *ctx, struct flow_key_v4 *key)
{
	key->ifindex = in_ifindex;
	key->src_addr = ctx->src_addr;
	key->dst_addr = 0;
	key->src_port = ctx->src_port;
	key->dst_port = 0;
	key->proto = ctx->proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
}

static __always_inline void build_front_flow_key_v6(__u32 in_ifindex, const struct packet_ctx_v6 *ctx, struct flow_key_v6 *key)
{
	key->ifindex = in_ifindex;
	copy_ipv6_addr(key->src_addr, ctx->src_addr);
	copy_ipv6_addr(key->dst_addr, ctx->dst_addr);
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
	if (is_egress_nat_rule(rule)) {
		key->src_addr = front_value->front_addr;
		key->src_port = front_value->front_port;
	} else {
		key->src_addr = rule->backend_addr;
		key->src_port = rule->backend_port;
	}
	key->dst_addr = front_value->nat_addr;
	key->dst_port = front_value->nat_port;
	key->proto = proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
}

static __always_inline struct flow_value_v4 *lookup_reply_flow_v4_in_bank(__u8 bank, struct flow_key_v4 *key)
{
	struct flow_key_v4 lookup_key = {};
	struct flow_value_v4 *flow;

	if (!key)
		return 0;
	lookup_key = *key;
	flow = lookup_flow_v4_in_bank(bank, &lookup_key);
	if (flow) {
		*key = lookup_key;
		return flow;
	}

	lookup_key.src_addr = 0;
	lookup_key.src_port = 0;
	flow = lookup_flow_v4_in_bank(bank, &lookup_key);
	if (flow)
		*key = lookup_key;
	return flow;
}

static __always_inline struct flow_value_v4 *lookup_reply_flow_v4(struct flow_key_v4 *key, __u8 *bank)
{
	struct flow_value_v4 *flow;

	if (bank)
		*bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	flow = lookup_reply_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!xdp_flow_old_bank_enabled_v4())
		return 0;
	flow = lookup_reply_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_XDP_FLOW_BANK_OLD;
	return flow;
}

static __always_inline void build_reply_flow_key_from_front_v6(const struct rule_value_v6 *rule, const struct flow_value_v6 *front_value, __u8 proto, struct flow_key_v6 *key)
{
	key->ifindex = rule->out_ifindex;
	copy_ipv6_addr(key->src_addr, rule->backend_addr);
	copy_ipv6_addr(key->dst_addr, front_value->nat_addr);
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

static __always_inline void build_front_flow_key_from_value_v6(const struct flow_value_v6 *flow_value, __u8 proto, struct flow_key_v6 *key)
{
	key->ifindex = flow_value->in_ifindex;
	copy_ipv6_addr(key->src_addr, flow_value->client_addr);
	copy_ipv6_addr(key->dst_addr, flow_value->front_addr);
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

static __always_inline void init_fullnat_front_value_v6(struct flow_value_v6 *front_value, const struct rule_value_v6 *rule, const struct packet_ctx_v6 *ctx, __u32 in_ifindex, __u16 nat_port)
{
	front_value->rule_id = rule->rule_id;
	copy_ipv6_addr(front_value->front_addr, ctx->dst_addr);
	copy_ipv6_addr(front_value->client_addr, ctx->src_addr);
	copy_ipv6_addr(front_value->nat_addr, rule->nat_addr);
	front_value->in_ifindex = in_ifindex;
	front_value->front_port = ctx->dst_port;
	front_value->client_port = ctx->src_port;
	front_value->nat_port = nat_port;
	front_value->flags = FORWARD_FLOW_FLAG_FULL_NAT | FORWARD_FLOW_FLAG_FRONT_ENTRY;
	front_value->pad = 0;
	front_value->last_seen_ns = 0;
	front_value->front_close_seen_ns = 0;
}

static __always_inline void init_fullnat_reply_value(struct flow_value_v4 *reply_value, const struct flow_value_v4 *front_value, __u64 now)
{
	*reply_value = *front_value;
	reply_value->flags &= ~FORWARD_FLOW_FLAG_FRONT_ENTRY;
	reply_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
	reply_value->last_seen_ns = now;
}

static __always_inline void init_fullnat_reply_value_v6(struct flow_value_v6 *reply_value, const struct flow_value_v6 *front_value, __u64 now)
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

static __always_inline __u32 fullcone_seed(const struct rule_value_v4 *rule, const struct packet_ctx *ctx)
{
	__u32 x = rule->rule_id;

	x ^= ctx->src_addr * 2654435761U;
	x ^= ((__u32)ctx->src_port << 16) | ((__u32)ctx->proto << 24);
	x ^= rule->nat_addr;
	x ^= rule->out_ifindex * 2246822519U;
	x ^= x >> 16;
	x *= 2246822519U;
	x ^= x >> 13;
	x *= 3266489917U;
	x ^= x >> 16;
	return x;
}

static __always_inline __u32 fullnat_seed_v6(const struct rule_value_v6 *rule, const struct packet_ctx_v6 *ctx)
{
	__u32 x = rule->rule_id;

	x = mix_ipv6_addr_seed(x, ctx->src_addr);
	x = mix_ipv6_addr_seed(x ^ 0x9e3779b9U, ctx->dst_addr);
	x ^= ((__u32)ctx->src_port << 16) | (__u32)ctx->dst_port;
	x ^= ((__u32)ctx->proto << 24);
	x = mix_ipv6_addr_seed(x ^ 0x85ebca6bU, rule->backend_addr);
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

static __always_inline struct kernel_nat_config_value_v4 *lookup_kernel_nat_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&nat_config_v4, &key);
}

static __always_inline void load_nat_port_window(__u32 *port_min, __u32 *port_range)
{
	struct kernel_nat_config_value_v4 *cfg = lookup_kernel_nat_config();
	__u32 min_port = FORWARD_NAT_PORT_MIN;
	__u32 max_port = FORWARD_NAT_PORT_MAX;

	if (cfg) {
		if (cfg->port_min >= 1024U && cfg->port_min <= 65535U)
			min_port = cfg->port_min;
		if (cfg->port_max >= min_port && cfg->port_max <= 65535U)
			max_port = cfg->port_max;
	}

	*port_min = min_port;
	*port_range = max_port - min_port + 1U;
}

static __always_inline __u32 nat_probe_stride(__u32 seed, __u32 port_range)
{
	__u32 stride;

	if (port_range <= 1U)
		return 1U;

	stride = (seed % (port_range - 1U)) + 1U;

	if ((stride & 1U) == 0)
		stride += 1U;
	if (stride >= port_range)
		stride -= (port_range - 1U);
	if (stride == 0)
		stride = 1U;
	return stride;
}

static __always_inline void bump_kernel_nat_occupancy(void);
static __always_inline void drop_kernel_nat_occupancy(void);

static __always_inline int try_reserve_nat_port(__u32 candidate, struct nat_port_key_v4 *nat_key, const struct nat_port_value_v4 *nat_value, __u16 *nat_port)
{
	nat_key->nat_port = (__u16)candidate;
	if (update_nat_port_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, nat_key, nat_value, BPF_NOEXIST) == 0) {
		*nat_port = (__u16)candidate;
		bump_kernel_nat_occupancy();
		return 0;
	}
	return -1;
}

static __always_inline int reserve_nat_port_fullcone(const struct rule_value_v4 *rule, const struct packet_ctx *ctx, struct nat_port_key_v4 *nat_key, __u16 *nat_port)
{
	struct nat_port_value_v4 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u32 seed;
	__u32 port_min = 0;
	__u32 port_range = 0;
	__u32 start;
	__u32 stride;

	nat_key->ifindex = rule->out_ifindex;
	nat_key->nat_addr = rule->nat_addr;
	nat_key->proto = ctx->proto;
	nat_key->pad = 0;

	load_nat_port_window(&port_min, &port_range);
	if (port_range == 0)
		return -1;

	if ((__u32)ctx->src_port >= port_min && (__u32)ctx->src_port < (port_min + port_range)) {
		if (try_reserve_nat_port((__u32)ctx->src_port, nat_key, &nat_value, nat_port) == 0)
			return 0;
	}

	seed = mix_nat_probe_seed(fullcone_seed(rule, ctx) ^ ((__u32)ctx->src_port << 16) ^ ((__u32)rule->out_ifindex << 1));
	start = seed % port_range;
	stride = nat_probe_stride(seed ^ 0x9e3779b9U, port_range);

#define FORWARD_XDP_FULLCONE_NAT_ATTEMPT(idx) \
	do { \
		__u32 candidate = port_min + ((start + ((__u32)(idx) * stride)) % port_range); \
		if (try_reserve_nat_port(candidate, nat_key, &nat_value, nat_port) == 0) \
			return 0; \
	} while (0)
	FORWARD_UNROLL_32(FORWARD_XDP_FULLCONE_NAT_ATTEMPT);
#undef FORWARD_XDP_FULLCONE_NAT_ATTEMPT

	return -1;
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

	if (ctx->proto == IPPROTO_UDP) {
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

	{
		struct icmphdr *icmph = (void *)(iph + 1);
		if ((void *)(icmph + 1) > data_end)
			return -1;
		if (old_port != new_port) {
			icmph->checksum = csum_replace2_val(icmph->checksum, old_port, new_port);
			icmph->un.echo.id = new_port;
		}
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

	if (ctx->proto == IPPROTO_UDP) {
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

	{
		struct icmphdr *icmph = (void *)(iph + 1);
		if ((void *)(icmph + 1) > data_end)
			return -1;
		if (old_port != new_port) {
			icmph->checksum = csum_replace2_val(icmph->checksum, old_port, new_port);
			icmph->un.echo.id = new_port;
		}
		return 0;
	}
}

static __always_inline int rewrite_l4_dnat_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const __u8 new_addr[16], __u16 new_port_host)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct forward_vlan_hdr *vh;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u16 proto;
	__be16 old_port = bpf_htons(ctx->dst_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(eth + 1) > data_end)
		return -1;
	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		proto = vh->h_vlan_encapsulated_proto;
		ip6h = (void *)(vh + 1);
	} else {
		ip6h = (void *)(eth + 1);
	}
	if (proto != bpf_htons(ETH_P_IPV6))
		return -1;
	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if (!ipv6_addr_equal(ip6h->daddr, new_addr)) {
		if (ctx->proto == IPPROTO_TCP) {
			tcph = (void *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)
				return -1;
			tcph->check = csum_replace_ipv6_addr_val(tcph->check, ip6h->daddr, new_addr);
		} else {
			udph = (void *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)
				return -1;
			udph->check = csum_replace_ipv6_addr_val(udph->check, ip6h->daddr, new_addr);
			if (udph->check == 0)
				udph->check = FORWARD_CSUM_MANGLED_0;
		}
		copy_ipv6_addr(ip6h->daddr, new_addr);
	}

	if (old_port != new_port) {
		if (ctx->proto == IPPROTO_TCP) {
			tcph = (void *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)
				return -1;
			tcph->check = csum_replace2_val(tcph->check, old_port, new_port);
			tcph->dest = new_port;
		} else {
			udph = (void *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)
				return -1;
			udph->check = csum_replace2_val(udph->check, old_port, new_port);
			if (udph->check == 0)
				udph->check = FORWARD_CSUM_MANGLED_0;
			udph->dest = new_port;
		}
	}
	return 0;
}

static __always_inline int rewrite_l4_snat_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const __u8 new_addr[16], __u16 new_port_host)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct forward_vlan_hdr *vh;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u16 proto;
	__be16 old_port = bpf_htons(ctx->src_port);
	__be16 new_port = bpf_htons(new_port_host);

	if ((void *)(eth + 1) > data_end)
		return -1;
	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		proto = vh->h_vlan_encapsulated_proto;
		ip6h = (void *)(vh + 1);
	} else {
		ip6h = (void *)(eth + 1);
	}
	if (proto != bpf_htons(ETH_P_IPV6))
		return -1;
	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if (!ipv6_addr_equal(ip6h->saddr, new_addr)) {
		if (ctx->proto == IPPROTO_TCP) {
			tcph = (void *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)
				return -1;
			tcph->check = csum_replace_ipv6_addr_val(tcph->check, ip6h->saddr, new_addr);
		} else {
			udph = (void *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)
				return -1;
			udph->check = csum_replace_ipv6_addr_val(udph->check, ip6h->saddr, new_addr);
			if (udph->check == 0)
				udph->check = FORWARD_CSUM_MANGLED_0;
		}
		copy_ipv6_addr(ip6h->saddr, new_addr);
	}

	if (old_port != new_port) {
		if (ctx->proto == IPPROTO_TCP) {
			tcph = (void *)(ip6h + 1);
			if ((void *)(tcph + 1) > data_end)
				return -1;
			tcph->check = csum_replace2_val(tcph->check, old_port, new_port);
			tcph->source = new_port;
		} else {
			udph = (void *)(ip6h + 1);
			if ((void *)(udph + 1) > data_end)
				return -1;
			udph->check = csum_replace2_val(udph->check, old_port, new_port);
			if (udph->check == 0)
				udph->check = FORWARD_CSUM_MANGLED_0;
			udph->source = new_port;
		}
	}
	return 0;
}

static __always_inline int prepare_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct redirect_target_v4 *target)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct bpf_fib_lookup *fib;
	long rc;

	if (!target || !target->ifindex)
		return -1;
	if ((void *)(eth + 1) > data_end)
		return -1;
	fib = lookup_xdp_fib_scratch();
	if (!fib)
		return -1;
	__builtin_memset(fib, 0, sizeof(*fib));

	fib->family = AF_INET;
	fib->tos = ctx->tos;
	fib->l4_protocol = ctx->proto;
	fib->sport = bpf_htons(target->src_port);
	fib->dport = bpf_htons(target->dst_port);
	fib->tot_len = ctx->tot_len;
	fib->ipv4_src = bpf_htonl(target->src_addr);
	fib->ipv4_dst = bpf_htonl(target->dst_addr);
	fib->ifindex = target->ifindex;

	rc = bpf_fib_lookup(xdp, fib, sizeof(*fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		xdp_diag_fib_non_success();
		return -1;
	}

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, fib->dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib->smac, sizeof(eth->h_source));
	return (int)(fib->ifindex ? fib->ifindex : target->ifindex);
}

static __always_inline int prepare_redirect_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct redirect_target_v6 *target)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	struct bpf_fib_lookup *fib;
	long rc;

	if (!target || !target->ifindex)
		return -1;
	if ((void *)(eth + 1) > data_end)
		return -1;
	fib = lookup_xdp_fib_scratch();
	if (!fib)
		return -1;
	__builtin_memset(fib, 0, sizeof(*fib));

	fib->family = AF_INET6;
	fib->l4_protocol = ctx->proto;
	fib->sport = bpf_htons(target->src_port);
	fib->dport = bpf_htons(target->dst_port);
	fib->tot_len = ctx->tot_len;
	__builtin_memcpy(fib->ipv6_src, target->src_addr, sizeof(fib->ipv6_src));
	__builtin_memcpy(fib->ipv6_dst, target->dst_addr, sizeof(fib->ipv6_dst));
	fib->ifindex = target->ifindex;

	rc = bpf_fib_lookup(xdp, fib, sizeof(*fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		xdp_diag_fib_non_success();
		return -1;
	}

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, fib->dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib->smac, sizeof(eth->h_source));
	return (int)(fib->ifindex ? fib->ifindex : target->ifindex);
}

static __always_inline int prepare_bridge_redirect_v4(struct xdp_md *xdp, const struct rule_value_v4 *rule)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;

	if (!rule || !rule->out_ifindex)
		return -1;
	if ((void *)(eth + 1) > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, rule->dst_mac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, rule->src_mac, sizeof(eth->h_source));
	return (int)rule->out_ifindex;
}

static __always_inline int prepare_bridge_redirect_macs(struct xdp_md *xdp, __u32 ifindex, const __u8 src_mac[ETH_ALEN], const __u8 dst_mac[ETH_ALEN])
{
	if (!ifindex)
		return -1;
#ifdef BPF_FUNC_xdp_store_bytes
	if (bpf_xdp_store_bytes(xdp, 0, dst_mac, ETH_ALEN) < 0)
		return -1;
	if (bpf_xdp_store_bytes(xdp, ETH_ALEN, src_mac, ETH_ALEN) < 0)
		return -1;
	return (int)ifindex;
#else
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth;

	if (data + sizeof(struct ethhdr) > data_end)
		return -1;
	eth = data;

	eth->h_dest[0] = dst_mac[0];
	eth->h_dest[1] = dst_mac[1];
	eth->h_dest[2] = dst_mac[2];
	eth->h_dest[3] = dst_mac[3];
	eth->h_dest[4] = dst_mac[4];
	eth->h_dest[5] = dst_mac[5];
	eth->h_source[0] = src_mac[0];
	eth->h_source[1] = src_mac[1];
	eth->h_source[2] = src_mac[2];
	eth->h_source[3] = src_mac[3];
	eth->h_source[4] = src_mac[4];
	eth->h_source[5] = src_mac[5];
	return (int)ifindex;
#endif
}

static __always_inline int xdp_redirect_ifindex(__u32 ifindex)
{
	if (!ifindex)
		return XDP_DROP;
	return bpf_redirect_map(&xdp_redirect_map, ifindex, XDP_DROP);
}

static __always_inline int prepare_flow_reply_redirect_v4(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_value_v4 *flow_value)
{
	if (!mac_addr_is_zero(flow_value->front_mac) && !mac_addr_is_zero(flow_value->client_mac))
		return prepare_bridge_redirect_macs(xdp, flow_value->in_ifindex, flow_value->front_mac, flow_value->client_mac);
	{
		struct redirect_target_v4 target = {
			.ifindex = flow_value->in_ifindex,
		};

		if (is_full_cone_reply_flow(flow_value)) {
			target.src_addr = ctx->src_addr;
			target.src_port = ctx->src_port;
			target.dst_addr = flow_value->client_addr;
			target.dst_port = flow_value->client_port;
		} else if (is_fullnat_reply_flow(flow_value)) {
			target.src_addr = flow_value->front_addr;
			target.src_port = flow_value->front_port;
			target.dst_addr = flow_value->client_addr;
			target.dst_port = flow_value->client_port;
		} else {
			target.src_addr = flow_value->front_addr;
			target.src_port = flow_value->front_port;
			target.dst_addr = ctx->dst_addr;
			target.dst_port = ctx->dst_port;
		}

		return prepare_redirect_v4(xdp, ctx, &target);
	}
}

static __always_inline int prepare_flow_reply_redirect_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct flow_value_v6 *flow_value)
{
	(void)ctx;
	if (mac_addr_is_zero(flow_value->front_mac) || mac_addr_is_zero(flow_value->client_mac))
		return -1;
	return prepare_bridge_redirect_macs(xdp, flow_value->in_ifindex, flow_value->front_mac, flow_value->client_mac);
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

static __always_inline int prepare_rule_fullnat_redirect_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, const struct flow_value_v6 *front_value)
{
	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0)
		return prepare_bridge_redirect_macs(xdp, rule->out_ifindex, rule->src_mac, rule->dst_mac);
	{
		void *data = (void *)(long)xdp->data;
		void *data_end = (void *)(long)xdp->data_end;
		struct ethhdr *eth = data;
		struct bpf_fib_lookup *fib;
		long rc;

		if (!rule->out_ifindex)
			return -1;
		if ((void *)(eth + 1) > data_end)
			return -1;
		fib = lookup_xdp_fib_scratch();
		if (!fib)
			return -1;
		__builtin_memset(fib, 0, sizeof(*fib));

		fib->family = AF_INET6;
		fib->l4_protocol = ctx->proto;
		fib->sport = bpf_htons(front_value->nat_port);
		fib->dport = bpf_htons(rule->backend_port);
		fib->tot_len = ctx->tot_len;
		copy_ipv6_addr((__u8 *)fib->ipv6_src, front_value->nat_addr);
		copy_ipv6_addr((__u8 *)fib->ipv6_dst, rule->backend_addr);
		fib->ifindex = rule->out_ifindex;

		rc = bpf_fib_lookup(xdp, fib, sizeof(*fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (rc != BPF_FIB_LKUP_RET_SUCCESS)
			return -1;

		data = (void *)(long)xdp->data;
		data_end = (void *)(long)xdp->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return -1;

		__builtin_memcpy(eth->h_dest, fib->dmac, sizeof(eth->h_dest));
		__builtin_memcpy(eth->h_source, fib->smac, sizeof(eth->h_source));
		return (int)(fib->ifindex ? fib->ifindex : rule->out_ifindex);
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
			.src_port = front_value->nat_port,
		};
		if (is_egress_nat_rule(rule)) {
			target.dst_addr = front_value->front_addr;
			target.dst_port = front_value->front_port;
		} else {
			target.dst_addr = rule->backend_addr;
			target.dst_port = rule->backend_port;
		}

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

static __always_inline void bump_rule_icmp_nat(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->icmp_nat_entries += 1;
}

static __always_inline void drop_rule_udp_nat(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->udp_nat_entries -= 1;
}

static __always_inline void drop_rule_icmp_nat(__u32 rule_id)
{
	struct rule_stats_value_v4 *stats = lookup_rule_stats(rule_id);

	if (stats)
		stats->icmp_nat_entries -= 1;
}

static __always_inline void bump_rule_datagram_nat(__u32 rule_id, __u8 proto)
{
	if (proto == IPPROTO_ICMP)
		bump_rule_icmp_nat(rule_id);
	else
		bump_rule_udp_nat(rule_id);
}

static __always_inline void drop_rule_datagram_nat(__u32 rule_id, __u8 proto)
{
	if (proto == IPPROTO_ICMP)
		drop_rule_icmp_nat(rule_id);
	else
		drop_rule_udp_nat(rule_id);
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

static __always_inline struct kernel_occupancy_value_v4 *lookup_kernel_occupancy(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&occupancy_v4, &key);
}

static __always_inline void bump_kernel_flow_occupancy(void)
{
	struct kernel_occupancy_value_v4 *occupancy = lookup_kernel_occupancy();

	if (!occupancy)
		return;
	if (occupancy->flow_capacity != 0 && occupancy->flow_entries >= (__s64)occupancy->flow_capacity)
		return;
	__sync_fetch_and_add(&occupancy->flow_entries, 1);
}

static __always_inline void drop_kernel_flow_occupancy(void)
{
	struct kernel_occupancy_value_v4 *occupancy = lookup_kernel_occupancy();

	if (!occupancy)
		return;
	if (occupancy->flow_entries <= 0)
		return;
	__sync_fetch_and_add(&occupancy->flow_entries, -1);
}

static __always_inline void bump_kernel_nat_occupancy(void)
{
	struct kernel_occupancy_value_v4 *occupancy = lookup_kernel_occupancy();

	if (!occupancy)
		return;
	if (occupancy->nat_capacity != 0 && occupancy->nat_entries >= (__s64)occupancy->nat_capacity)
		return;
	__sync_fetch_and_add(&occupancy->nat_entries, 1);
}

static __always_inline void drop_kernel_nat_occupancy(void)
{
	struct kernel_occupancy_value_v4 *occupancy = lookup_kernel_occupancy();

	if (!occupancy)
		return;
	if (occupancy->nat_entries <= 0)
		return;
	__sync_fetch_and_add(&occupancy->nat_entries, -1);
}

static __always_inline void delete_fullnat_state(const struct flow_key_v4 *reply_key, const struct flow_value_v4 *reply_value, __u8 proto, __u8 flow_bank)
{
	struct flow_key_v4 front_key = {};
	struct nat_port_key_v4 nat_key = {};
	int full_cone = is_full_cone_flow(reply_value);

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_TCP)
			drop_rule_tcp_active(reply_value->rule_id);
		else if (is_datagram_proto(proto))
			drop_rule_datagram_nat(reply_value->rule_id, proto);
	}

	if (full_cone) {
		front_key.ifindex = reply_value->in_ifindex;
		front_key.src_addr = reply_value->client_addr;
		front_key.dst_addr = 0;
		front_key.src_port = reply_value->client_port;
		front_key.dst_port = 0;
		front_key.proto = proto;
	} else {
		build_front_flow_key_from_value(reply_value, proto, &front_key);
	}
	if (delete_flow_v4_in_bank(flow_bank, &front_key) == 0)
		drop_kernel_flow_occupancy();
	if (delete_flow_v4_in_bank(flow_bank, reply_key) == 0)
		drop_kernel_flow_occupancy();
	if (full_cone && reply_key) {
		nat_key.ifindex = reply_key->ifindex;
		nat_key.nat_addr = reply_value->nat_addr;
		nat_key.nat_port = reply_value->nat_port;
		nat_key.proto = proto;
		if (delete_nat_port_v4_in_bank(flow_bank, &nat_key) == 0)
			drop_kernel_nat_occupancy();
	}
}

static __always_inline void delete_fullnat_state_v6(const struct flow_key_v6 *reply_key, const struct flow_value_v6 *reply_value, __u8 proto, __u8 flow_bank)
{
	struct flow_key_v6 front_key = {};
	struct nat_port_key_v6 nat_key = {};

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_TCP)
			drop_rule_tcp_active(reply_value->rule_id);
		else if (is_datagram_proto(proto))
			drop_rule_datagram_nat(reply_value->rule_id, proto);
	}

	build_front_flow_key_from_value_v6(reply_value, proto, &front_key);
	if (delete_flow_v6_in_bank(flow_bank, &front_key) == 0)
		drop_kernel_flow_occupancy();
	if (delete_flow_v6_in_bank(flow_bank, reply_key) == 0)
		drop_kernel_flow_occupancy();
	if (reply_key) {
		nat_key.ifindex = reply_key->ifindex;
		copy_ipv6_addr(nat_key.nat_addr, reply_value->nat_addr);
		nat_key.nat_port = reply_value->nat_port;
		nat_key.proto = proto;
		if (delete_nat_port_v6_in_bank(flow_bank, &nat_key) == 0)
			drop_kernel_nat_occupancy();
	}
}

static __always_inline int handle_transparent_reply(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_key_v4 *flow_key, const struct flow_value_v4 *flow, __u8 flow_bank)
{
	struct flow_value_v4 *flow_value = lookup_xdp_flow_scratch_v4();
	__u64 now = 0;
	int update_flow = 0;
	int count_tcp_now = 0;
	int redirect_ifindex = 0;

	if (!flow_value)
		return XDP_DROP;
	*flow_value = *flow;
	if (ctx->proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (flow_value->last_seen_ns == 0 || now < flow_value->last_seen_ns || (now - flow_value->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			if ((flow_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_udp_nat(flow_value->rule_id);
			if (delete_flow_v4_in_bank(flow_bank, flow_key) == 0)
				drop_kernel_flow_occupancy();
			return XDP_PASS;
		}
		if ((now - flow_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if ((flow_value->flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			flow_value->flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			flow_value->last_seen_ns = now;
			if (!ctx->closing) {
				flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_tcp_now = 1;
				update_flow = 1;
			}
		} else if (!ctx->closing && (flow_value->last_seen_ns == 0 || now < flow_value->last_seen_ns || (now - flow_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
		if (ctx->closing) {
			flow_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			if (flow_value->front_close_seen_ns == 0)
				flow_value->front_close_seen_ns = now;
			flow_value->last_seen_ns = now;
			if ((flow_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
				drop_rule_tcp_active(flow_value->rule_id);
				flow_value->flags &= ~FORWARD_FLOW_FLAG_COUNTED;
			}
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (update_flow_v4_in_bank(flow_bank, flow_key, flow_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(flow_value->rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(flow_value))
		add_rule_traffic_bytes(flow_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	redirect_ifindex = prepare_flow_reply_redirect_v4(xdp, ctx, flow_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat(xdp, ctx, flow_value->front_addr, flow_value->front_port) < 0)
		return XDP_ABORTED;
	xdp_diag_redirect_invoked();
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __always_inline int handle_transparent_forward(struct xdp_md *xdp, __u32 in_ifindex, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 flow_key = {};
	struct flow_value_v4 *flow_value = lookup_xdp_flow_scratch_v4();
	struct flow_value_v4 *flow;
	__u8 flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	__u64 now = 0;
	int update_flow = 0;
	int new_session = 0;
	int count_udp_now = 0;
	int close_complete = 0;
	int redirect_ifindex = 0;

	if (!flow_value)
		return XDP_DROP;
	__builtin_memset(flow_value, 0, sizeof(*flow_value));
	flow_key.ifindex = rule->out_ifindex;
	flow_key.src_addr = rule->backend_addr;
	flow_key.dst_addr = ctx->src_addr;
	flow_key.src_port = rule->backend_port;
	flow_key.dst_port = ctx->src_port;
	flow_key.proto = ctx->proto;

	flow = lookup_flow_v4_active_or_old(&flow_key, &flow_bank);
	if (!flow) {
		if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
			return XDP_DROP;
		now = bpf_ktime_get_ns();
		flow_value->rule_id = rule->rule_id;
		flow_value->front_addr = ctx->dst_addr;
		flow_value->front_port = ctx->dst_port;
		flow_value->in_ifindex = in_ifindex;
		store_packet_macs_v4(xdp, flow_value);
		if (ctx->proto == IPPROTO_UDP) {
			flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			flow_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			flow_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			flow_value->front_close_seen_ns = now;
		}
		flow_value->last_seen_ns = now;
		update_flow = 1;
		new_session = 1;
		flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	} else if (ctx->proto == IPPROTO_UDP) {
		now = bpf_ktime_get_ns();
		if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			if ((flow->flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_udp_nat(flow->rule_id);
			if (delete_flow_v4_in_bank(flow_bank, &flow_key) == 0)
				drop_kernel_flow_occupancy();
			__builtin_memset(flow_value, 0, sizeof(*flow_value));
			now = bpf_ktime_get_ns();
			flow_value->rule_id = rule->rule_id;
			flow_value->front_addr = ctx->dst_addr;
			flow_value->front_port = ctx->dst_port;
			flow_value->in_ifindex = in_ifindex;
			store_packet_macs_v4(xdp, flow_value);
			flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
			if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
				flow_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
			flow_value->last_seen_ns = now;
			update_flow = 1;
			new_session = 1;
			flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
		} else if ((now - flow->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			*flow_value = *flow;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if (ctx->closing) {
			*flow_value = *flow;
			flow_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			if (flow_value->front_close_seen_ns == 0)
				flow_value->front_close_seen_ns = now;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		} else if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_CLOSING) != 0 && ctx->tcp_flags == FORWARD_TCP_FLAG_ACK) {
			close_complete = 1;
		} else if (flow->last_seen_ns == 0 || now < flow->last_seen_ns || (now - flow->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			*flow_value = *flow;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (update_flow_v4_in_bank(flow_bank, &flow_key, flow_value, BPF_ANY) < 0)
			return XDP_DROP;
		if (new_session)
			bump_kernel_flow_occupancy();
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
	xdp_diag_redirect_invoked();
	{
		int action = xdp_redirect_ifindex((__u32)redirect_ifindex);

		if (close_complete && action == XDP_REDIRECT && delete_flow_v4_in_bank(flow_bank, &flow_key) == 0)
			drop_kernel_flow_occupancy();
		return action;
	}
}

static __always_inline int handle_fullnat_reply(struct xdp_md *xdp, const struct packet_ctx *ctx, const struct flow_key_v4 *reply_key, const struct flow_value_v4 *flow, __u8 flow_bank)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 *reply_value = lookup_xdp_flow_scratch_v4();
	struct flow_value_v4 *front_value = lookup_xdp_flow_aux_scratch_v4();
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int full_cone = is_full_cone_flow(flow);
	int recreated_front = 0;
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;
	int redirect_ifindex = 0;

	if (!reply_value || !front_value)
		return XDP_DROP;
	xdp_diag_v4_fullnat_reply_enter();
	*reply_value = *flow;
	if (is_datagram_proto(ctx->proto)) {
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) > FORWARD_DATAGRAM_FLOW_IDLE_NS(ctx->proto)) {
			delete_fullnat_state(reply_key, reply_value, ctx->proto, flow_bank);
			return XDP_PASS;
		}
	}

	if (full_cone) {
		front_key.ifindex = reply_value->in_ifindex;
		front_key.src_addr = reply_value->client_addr;
		front_key.dst_addr = 0;
		front_key.src_port = reply_value->client_port;
		front_key.dst_port = 0;
		front_key.proto = ctx->proto;
	} else {
		build_front_flow_key_from_value(reply_value, ctx->proto, &front_key);
	}
	front_flow = lookup_flow_v4_in_bank(flow_bank, &front_key);
	if (full_cone ? is_full_cone_front_flow(front_flow) : is_fullnat_front_flow(front_flow)) {
		*front_value = *front_flow;
	} else {
		*front_value = *reply_value;
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_ENTRY;
		front_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
		if (is_egress_nat_flow(reply_value)) {
			front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
			if (full_cone)
				front_value->flags |= FORWARD_FLOW_FLAG_FULL_CONE;
		}
		xdp_diag_reply_flow_recreated();
		recreated_front = 1;
		update_front = 1;
	}

	if (is_datagram_proto(ctx->proto)) {
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	} else if (!ctx->closing) {
		if ((reply_value->flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			reply_value->flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			reply_value->last_seen_ns = now;
			update_reply = 1;
			count_tcp_now = 1;
		} else if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}

		if ((front_value->flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			front_value->flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			front_value->last_seen_ns = now;
			update_front = 1;
		} else if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
	}

	if (update_front) {
		if (update_flow_v4_in_bank(flow_bank, &front_key, front_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
		if (recreated_front)
			bump_kernel_flow_occupancy();
	}
	if (update_reply) {
		if (update_flow_v4_in_bank(flow_bank, reply_key, reply_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value->rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(reply_value))
		add_rule_traffic_bytes(reply_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	redirect_ifindex = prepare_flow_reply_redirect_v4(xdp, ctx, reply_value);
	if (redirect_ifindex <= 0) {
		xdp_diag_redirect_drop();
		return XDP_DROP;
	}
	if (!full_cone) {
		if (rewrite_l4_snat(xdp, ctx, reply_value->front_addr, reply_value->front_port) < 0) {
			xdp_diag_rewrite_fail();
			return XDP_ABORTED;
		}
	}
	if (rewrite_l4_dnat(xdp, ctx, reply_value->client_addr, reply_value->client_port) < 0) {
		xdp_diag_rewrite_fail();
		return XDP_ABORTED;
	}
	if (ctx->closing)
		delete_fullnat_state(reply_key, reply_value, ctx->proto, flow_bank);
	xdp_diag_redirect_invoked();
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __always_inline int handle_egress_nat_forward_full_cone(struct xdp_md *xdp, __u32 in_ifindex, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	union flow_nat_key_v4 reply_or_nat = {};
	struct flow_value_v4 *front_value = lookup_xdp_flow_scratch_v4();
	struct flow_value_v4 *reply_value = lookup_xdp_flow_aux_scratch_v4();
	struct flow_value_v4 *front_flow;
	struct flow_value_v4 *reply_flow = 0;
	struct nat_port_value_v4 nat_value = {};
	struct redirect_target_v4 target = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	int created_front = 0;
	int created_reply = 0;
	int update_front = 0;
	int update_reply = 0;
	int new_session = 0;
	int count_udp_now = 0;
	int redirect_ifindex = 0;
	__u8 flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;

	if (!front_value || !reply_value)
		return XDP_DROP;
	xdp_diag_v4_fullnat_forward_enter();
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	build_full_cone_front_flow_key(in_ifindex, ctx, &reply_or_nat.flow);
	front_flow = lookup_flow_v4_active_or_old(&reply_or_nat.flow, &flow_bank);
	if (front_flow && !is_egress_nat_flow(front_flow))
		return XDP_PASS;
	if (is_full_cone_front_flow(front_flow)) {
		*front_value = *front_flow;
		if (front_value->nat_addr == 0)
			front_value->nat_addr = rule->nat_addr;
		front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
		reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_or_nat.flow);
		if (is_full_cone_reply_flow(reply_flow)) {
			*reply_value = *reply_flow;
		} else {
			init_fullnat_reply_value(reply_value, front_value, now);
			reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;
			if (is_datagram_proto(ctx->proto)) {
				reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0) {
				xdp_diag_flow_update_fail();
				return XDP_DROP;
			}
			xdp_diag_reply_flow_recreated();
			created_reply = 1;
		}
	} else {
		if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
			return XDP_DROP;
		if (reserve_nat_port_fullcone(rule, ctx, &reply_or_nat.nat, &nat_port) < 0) {
			xdp_diag_nat_reserve_fail();
			return XDP_DROP;
		}

		init_fullnat_front_value(front_value, rule, ctx, in_ifindex, nat_port);
		front_value->front_addr = 0;
		front_value->front_port = 0;
		store_packet_macs_v4(xdp, front_value);
		front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value->front_close_seen_ns = now;
		}
		front_value->last_seen_ns = now;
		if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_or_nat.flow, front_value, BPF_NOEXIST) < 0) {
			delete_nat_port_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_or_nat.nat);
			drop_kernel_nat_occupancy();

			build_full_cone_front_flow_key(in_ifindex, ctx, &reply_or_nat.flow);
			front_flow = lookup_flow_v4_active_or_old(&reply_or_nat.flow, &flow_bank);
			if (front_flow && !is_egress_nat_flow(front_flow))
				return XDP_PASS;
			if (!is_full_cone_front_flow(front_flow))
				return XDP_DROP;
			*front_value = *front_flow;
			if (front_value->nat_addr == 0)
				front_value->nat_addr = rule->nat_addr;
			front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;
		} else {
			created_front = 1;
			new_session = 1;
			bump_kernel_flow_occupancy();
		}

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
		init_fullnat_reply_value(reply_value, front_value, now);
		reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;
		if (is_datagram_proto(ctx->proto)) {
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_or_nat.flow, reply_value, BPF_ANY) < 0) {
			if (created_front) {
				build_full_cone_front_flow_key(in_ifindex, ctx, &reply_or_nat.flow);
				if (delete_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_or_nat.flow) == 0)
					drop_kernel_flow_occupancy();
			}
			reply_or_nat.nat.ifindex = rule->out_ifindex;
			reply_or_nat.nat.nat_addr = front_value->nat_addr;
			reply_or_nat.nat.nat_port = front_value->nat_port;
			reply_or_nat.nat.proto = ctx->proto;
			reply_or_nat.nat.pad = 0;
			if (delete_nat_port_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_or_nat.nat) == 0)
				drop_kernel_nat_occupancy();
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
		created_reply = 1;
		bump_kernel_flow_occupancy();
	}

	if (is_datagram_proto(ctx->proto)) {
		if (!created_front && (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	} else if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (front_value->front_close_seen_ns == 0)
			front_value->front_close_seen_ns = now;
		front_value->last_seen_ns = now;
		update_front = 1;

		reply_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (reply_value->front_close_seen_ns == 0)
			reply_value->front_close_seen_ns = now;
		reply_value->last_seen_ns = now;
		update_reply = 1;
	} else {
		if (!created_front && (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front) {
		build_full_cone_front_flow_key(in_ifindex, ctx, &reply_or_nat.flow);
		if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, front_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
	}
	if (update_reply) {
		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
		if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
	}
	if (!created_front && (created_reply || update_front || update_reply)) {
		reply_or_nat.nat.ifindex = rule->out_ifindex;
		reply_or_nat.nat.nat_addr = front_value->nat_addr;
		reply_or_nat.nat.nat_port = front_value->nat_port;
		reply_or_nat.nat.proto = ctx->proto;
		reply_or_nat.nat.pad = 0;
		nat_value.rule_id = rule->rule_id;
		if (update_nat_port_v4_in_bank(flow_bank, &reply_or_nat.nat, &nat_value, BPF_NOEXIST) == 0)
			bump_kernel_nat_occupancy();
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	target.ifindex = rule->out_ifindex;
	target.src_addr = front_value->nat_addr;
	target.dst_addr = ctx->dst_addr;
	target.src_port = front_value->nat_port;
	target.dst_port = ctx->dst_port;
	redirect_ifindex = prepare_redirect_v4(xdp, ctx, &target);
	if (redirect_ifindex <= 0) {
		xdp_diag_redirect_drop();
		return XDP_DROP;
	}
	if (rewrite_l4_snat(xdp, ctx, front_value->nat_addr, front_value->nat_port) < 0) {
		xdp_diag_rewrite_fail();
		return XDP_ABORTED;
	}
	xdp_diag_redirect_invoked();
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __always_inline int handle_fullnat_forward(struct xdp_md *xdp, __u32 in_ifindex, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_value_v4 *existing_front)
{
	struct xdp_dispatch_ctx_v4 *dispatch = lookup_xdp_dispatch_scratch_v4();
	struct flow_key_v4 front_key = {};
	struct flow_key_v4 reply_key = {};
	struct flow_value_v4 *front_value = lookup_xdp_flow_scratch_v4();
	struct flow_value_v4 *reply_value = lookup_xdp_flow_aux_scratch_v4();
	struct flow_value_v4 *front_flow = (struct flow_value_v4 *)existing_front;
	struct flow_value_v4 *reply_flow;
	__u64 now = bpf_ktime_get_ns();
	__u32 seed = 0;
	__u32 port_min = 0;
	__u32 port_range = 0;
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
	__u8 flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;

	if (is_full_cone_egress_nat_rule(rule))
		return handle_egress_nat_forward_full_cone(xdp, in_ifindex, ctx, rule);
	if (!front_value || !reply_value)
		return XDP_DROP;
	xdp_diag_v4_fullnat_forward_enter();
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));
	build_front_flow_key(in_ifindex, ctx, &front_key);
	if (dispatch && dispatch->have_flow && is_fullnat_front_flow(front_flow))
		flow_bank = dispatch->flow_bank;
	if (!is_fullnat_front_flow(front_flow))
		flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	if (is_egress_nat_rule(rule) && front_flow && !is_egress_nat_flow(front_flow))
		return XDP_PASS;
	if (is_fullnat_front_flow(front_flow)) {
		*front_value = *front_flow;
		if (front_value->nat_addr == 0)
			front_value->nat_addr = rule->nat_addr;
		if (is_egress_nat_rule(rule))
			front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
		reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_key);
		if (is_fullnat_reply_flow(reply_flow)) {
			*reply_value = *reply_flow;
		} else {
			init_fullnat_reply_value(reply_value, front_value, now);
			if (is_egress_nat_rule(rule))
				reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
			if (is_datagram_proto(ctx->proto))
				reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0) {
				xdp_diag_flow_update_fail();
				return XDP_DROP;
			}
			xdp_diag_reply_flow_recreated();
			created_reply = 1;
			if (is_datagram_proto(ctx->proto))
				count_udp_now = 1;
		}
		goto have_session;
	}
	if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
		return XDP_DROP;

	load_nat_port_window(&port_min, &port_range);
	if (port_range == 0)
		return XDP_DROP;

	seed = mix_nat_probe_seed(fullnat_seed(rule, ctx) ^ ((__u32)rule->out_ifindex << 1));
	start = seed % port_range;
	stride = nat_probe_stride(seed ^ 0x9e3779b9U, port_range);

	if ((__u32)preferred_port >= port_min && (__u32)preferred_port < (port_min + port_range)) {
		__builtin_memset(front_value, 0, sizeof(*front_value));
		__builtin_memset(reply_value, 0, sizeof(*reply_value));
		init_fullnat_front_value(front_value, rule, ctx, in_ifindex, preferred_port);
		store_packet_macs_v4(xdp, front_value);
		if (is_egress_nat_rule(rule))
			front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value->front_close_seen_ns = now;
		}
		front_value->last_seen_ns = now;

		init_fullnat_reply_value(reply_value, front_value, now);
		if (is_egress_nat_rule(rule))
			reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
		if (is_datagram_proto(ctx->proto))
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
		if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_key, reply_value, BPF_NOEXIST) == 0) {
			if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &front_key, front_value, BPF_NOEXIST) == 0) {
				created_front = 1;
				created_reply = 1;
				new_session = 1;
				if (is_datagram_proto(ctx->proto))
					count_udp_now = 1;
				flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
				goto have_session;
			}
			delete_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_key);
			front_flow = lookup_flow_v4_active_or_old(&front_key, &flow_bank);
			if (is_fullnat_front_flow(front_flow)) {
				*front_value = *front_flow;
				if (front_value->nat_addr == 0)
					front_value->nat_addr = rule->nat_addr;
				if (is_egress_nat_rule(rule))
					front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
				build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
				reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_key);
				if (is_fullnat_reply_flow(reply_flow)) {
					*reply_value = *reply_flow;
					goto have_session;
				}
				init_fullnat_reply_value(reply_value, front_value, now);
				if (is_egress_nat_rule(rule))
					reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
				if (is_datagram_proto(ctx->proto))
					reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0) {
					xdp_diag_flow_update_fail();
					return XDP_DROP;
				}
				xdp_diag_reply_flow_recreated();
				created_reply = 1;
				if (is_datagram_proto(ctx->proto))
					count_udp_now = 1;
				goto have_session;
			}
		}
	}

#define FORWARD_XDP_FULLNAT_V4_ATTEMPT(idx) \
	do { \
		__u16 nat_port = (__u16)(port_min + ((start + ((__u32)(idx) * stride)) % port_range)); \
		if (nat_port != preferred_port) { \
			__builtin_memset(front_value, 0, sizeof(*front_value)); \
			__builtin_memset(reply_value, 0, sizeof(*reply_value)); \
			init_fullnat_front_value(front_value, rule, ctx, in_ifindex, nat_port); \
			store_packet_macs_v4(xdp, front_value); \
			if (is_egress_nat_rule(rule)) \
				front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT; \
			if (FORWARD_RULE_TRAFFIC_ENABLED(rule)) \
				front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS; \
			if (ctx->closing) { \
				front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING; \
				front_value->front_close_seen_ns = now; \
			} \
			front_value->last_seen_ns = now; \
			init_fullnat_reply_value(reply_value, front_value, now); \
			if (is_egress_nat_rule(rule)) \
				reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT; \
			if (is_datagram_proto(ctx->proto)) \
				reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED; \
			build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key); \
			if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_key, reply_value, BPF_NOEXIST) == 0) { \
				if (update_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &front_key, front_value, BPF_NOEXIST) == 0) { \
					created_front = 1; \
					created_reply = 1; \
					new_session = 1; \
					if (is_datagram_proto(ctx->proto)) \
						count_udp_now = 1; \
					flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE; \
					goto have_session; \
				} \
				delete_flow_v4_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &reply_key); \
				front_flow = lookup_flow_v4_active_or_old(&front_key, &flow_bank); \
				if (is_fullnat_front_flow(front_flow)) { \
					*front_value = *front_flow; \
					if (front_value->nat_addr == 0) \
						front_value->nat_addr = rule->nat_addr; \
					if (is_egress_nat_rule(rule)) \
						front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT; \
					build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key); \
					reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_key); \
					if (is_fullnat_reply_flow(reply_flow)) { \
						*reply_value = *reply_flow; \
						goto have_session; \
					} \
					init_fullnat_reply_value(reply_value, front_value, now); \
					if (is_egress_nat_rule(rule)) \
						reply_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT; \
					if (is_datagram_proto(ctx->proto)) \
						reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED; \
					if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0) { \
						xdp_diag_flow_update_fail(); \
						return XDP_DROP; \
					} \
					xdp_diag_reply_flow_recreated(); \
					created_reply = 1; \
					if (is_datagram_proto(ctx->proto)) \
						count_udp_now = 1; \
					goto have_session; \
				} \
			} \
		} \
	} while (0)
	FORWARD_UNROLL_32(FORWARD_XDP_FULLNAT_V4_ATTEMPT);
#undef FORWARD_XDP_FULLNAT_V4_ATTEMPT

	xdp_diag_nat_reserve_fail();
	return XDP_DROP;

have_session:
	if (is_datagram_proto(ctx->proto)) {
		if (!created_front && (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	} else if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (front_value->front_close_seen_ns == 0)
			front_value->front_close_seen_ns = now;
		front_value->last_seen_ns = now;
		update_front = 1;

		reply_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (reply_value->front_close_seen_ns == 0)
			reply_value->front_close_seen_ns = now;
		reply_value->last_seen_ns = now;
		update_reply = 1;
	} else {
		if (!created_front && (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front) {
		if (update_flow_v4_in_bank(flow_bank, &front_key, front_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
	}
	if (update_reply) {
		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
		if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0) {
			xdp_diag_flow_update_fail();
			return XDP_DROP;
		}
	}
	if (created_front)
		bump_kernel_flow_occupancy();
	if (created_reply)
		bump_kernel_flow_occupancy();
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	redirect_ifindex = prepare_rule_fullnat_redirect_v4(xdp, ctx, rule, front_value);
	if (redirect_ifindex <= 0) {
		xdp_diag_redirect_drop();
		return XDP_DROP;
	}
	if (rewrite_l4_snat(xdp, ctx, front_value->nat_addr, front_value->nat_port) < 0) {
		xdp_diag_rewrite_fail();
		return XDP_ABORTED;
	}
	if (!is_egress_nat_rule(rule)) {
		if (rewrite_l4_dnat(xdp, ctx, rule->backend_addr, rule->backend_port) < 0) {
			xdp_diag_rewrite_fail();
			return XDP_ABORTED;
		}
	}
	xdp_diag_redirect_invoked();
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __always_inline int handle_fullnat_reply_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct flow_key_v6 *reply_key, const struct flow_value_v6 *flow, __u8 flow_bank)
{
	struct flow_key_v6 *front_key = lookup_xdp_flow_aux_key_scratch_v6();
	struct flow_value_v6 *reply_value = lookup_xdp_flow_scratch_v6();
	struct flow_value_v6 *front_value = lookup_xdp_flow_aux_scratch_v6();
	struct flow_value_v6 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int created_front = 0;
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;
	int redirect_ifindex = 0;

	if (!front_key || !reply_value || !front_value)
		return XDP_DROP;
	*reply_value = *flow;
	if (ctx->proto == IPPROTO_UDP) {
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) > FORWARD_UDP_FLOW_IDLE_NS) {
			delete_fullnat_state_v6(reply_key, reply_value, ctx->proto, flow_bank);
			return XDP_PASS;
		}
	}

	build_front_flow_key_from_value_v6(reply_value, ctx->proto, front_key);
	front_flow = lookup_flow_v6_in_bank(flow_bank, front_key);
	if (is_fullnat_front_flow_v6(front_flow)) {
		*front_value = *front_flow;
	} else {
		*front_value = *reply_value;
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_ENTRY;
		front_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
		created_front = 1;
		update_front = 1;
	}

	if (ctx->proto == IPPROTO_UDP) {
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	} else if (!ctx->closing) {
		if ((reply_value->flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			reply_value->flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			reply_value->last_seen_ns = now;
			update_reply = 1;
			count_tcp_now = 1;
		} else if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}

		if ((front_value->flags & FORWARD_FLOW_FLAG_REPLY_SEEN) == 0) {
			front_value->flags |= FORWARD_FLOW_FLAG_REPLY_SEEN;
			front_value->last_seen_ns = now;
			update_front = 1;
		} else if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
	}

	if (update_front) {
		if (update_flow_v6_in_bank(flow_bank, front_key, front_value, BPF_ANY) < 0)
			return XDP_DROP;
		if (created_front)
			bump_kernel_flow_occupancy();
	}
	if (update_reply) {
		if (update_flow_v6_in_bank(flow_bank, reply_key, reply_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value->rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(reply_value))
		add_rule_traffic_bytes(reply_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	redirect_ifindex = prepare_flow_reply_redirect_v6(xdp, ctx, reply_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat_v6(xdp, ctx, reply_value->front_addr, reply_value->front_port) < 0)
		return XDP_ABORTED;
	if (rewrite_l4_dnat_v6(xdp, ctx, reply_value->client_addr, reply_value->client_port) < 0)
		return XDP_ABORTED;
	if (ctx->closing)
		delete_fullnat_state_v6(reply_key, reply_value, ctx->proto, flow_bank);
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __attribute__((noinline)) int ensure_fullnat_existing_session_v6(const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, const struct flow_value_v6 *front_flow, __u8 flow_bank, __u64 now)
{
	struct flow_key_v6 *reply_key = lookup_xdp_flow_aux_key_scratch_v6();
	struct flow_value_v6 *front_value = lookup_xdp_flow_scratch_v6();
	struct flow_value_v6 *reply_value = lookup_xdp_flow_aux_scratch_v6();
	struct flow_value_v6 *reply_flow;
	__u8 state = 0;

	if (!reply_key || !front_value || !reply_value)
		return -1;
	if (flow_bank == FORWARD_XDP_FLOW_BANK_OLD)
		state |= FORWARD_FULLNAT_STATE_FLOW_BANK_OLD;

	*front_value = *front_flow;
	if (ipv6_addr_is_zero(front_value->nat_addr))
		copy_ipv6_addr(front_value->nat_addr, rule->nat_addr);

	build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, reply_key);
	reply_flow = lookup_flow_v6_in_bank(flow_bank, reply_key);
	if (is_fullnat_reply_flow_v6(reply_flow)) {
		*reply_value = *reply_flow;
		return state;
	}

	init_fullnat_reply_value_v6(reply_value, front_value, now);
	if (ctx->proto == IPPROTO_UDP)
		reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
	if (update_flow_v6_in_bank(flow_bank, reply_key, reply_value, BPF_ANY) < 0)
		return -1;

	state |= FORWARD_FULLNAT_STATE_CREATED_REPLY;
	if (ctx->proto == IPPROTO_UDP)
		state |= FORWARD_FULLNAT_STATE_COUNT_UDP_NOW;
	return state;
}

static __attribute__((noinline)) int try_create_fullnat_session_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, __u64 now, __u16 nat_port)
{
	struct flow_key_v6 *front_key = lookup_xdp_flow_key_scratch_v6();
	struct flow_key_v6 *reply_key = lookup_xdp_flow_aux_key_scratch_v6();
	struct flow_value_v6 *front_value = lookup_xdp_flow_scratch_v6();
	struct flow_value_v6 *reply_value = lookup_xdp_flow_aux_scratch_v6();
	struct flow_value_v6 *front_flow;
	struct nat_port_key_v6 nat_key = {};
	struct nat_port_value_v6 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u8 flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	__u8 state = 0;

	if (!front_key || !reply_key || !front_value || !reply_value)
		return -1;

	nat_key.ifindex = rule->out_ifindex;
	copy_ipv6_addr(nat_key.nat_addr, rule->nat_addr);
	nat_key.nat_port = nat_port;
	nat_key.proto = ctx->proto;
	nat_key.pad = 0;
	if (update_nat_port_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &nat_key, &nat_value, BPF_NOEXIST) < 0)
		return -2;
	bump_kernel_nat_occupancy();

	build_front_flow_key_v6(xdp->ingress_ifindex, ctx, front_key);
	init_fullnat_front_value_v6(front_value, rule, ctx, xdp->ingress_ifindex, nat_port);
	if (load_packet_macs(xdp, front_value->front_mac, front_value->client_mac) < 0) {
		delete_nat_port_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();
		return -1;
	}
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
	if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		front_value->front_close_seen_ns = now;
	}
	front_value->last_seen_ns = now;

	init_fullnat_reply_value_v6(reply_value, front_value, now);
	if (ctx->proto == IPPROTO_UDP)
		reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;

	build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, reply_key);
	if (update_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, reply_key, reply_value, BPF_NOEXIST) < 0) {
		delete_nat_port_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();
		return -2;
	}
	if (update_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, front_key, front_value, BPF_NOEXIST) == 0) {
		state |= FORWARD_FULLNAT_STATE_CREATED_FRONT;
		state |= FORWARD_FULLNAT_STATE_CREATED_REPLY;
		state |= FORWARD_FULLNAT_STATE_NEW_SESSION;
		if (ctx->proto == IPPROTO_UDP)
			state |= FORWARD_FULLNAT_STATE_COUNT_UDP_NOW;
		return state;
	}

	delete_flow_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, reply_key);
	if (delete_nat_port_v6_in_bank(FORWARD_XDP_FLOW_BANK_ACTIVE, &nat_key) == 0)
		drop_kernel_nat_occupancy();
	front_flow = lookup_flow_v6_active_or_old(front_key, &flow_bank);
	if (!is_fullnat_front_flow_v6(front_flow))
		return -2;

	return ensure_fullnat_existing_session_v6(ctx, rule, front_flow, flow_bank, now);
}

static __always_inline int prepare_fullnat_forward_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, __u8 *flow_bank_out)
{
	struct flow_key_v6 *front_key = lookup_xdp_flow_key_scratch_v6();
	struct flow_value_v6 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	__u32 seed;
	__u32 port_min = 0;
	__u32 port_range = 0;
	__u32 start;
	__u32 stride;
	__u16 preferred_port = ctx->src_port;
	__u8 flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	int state;

	if (!front_key)
		return -1;

	build_front_flow_key_v6(xdp->ingress_ifindex, ctx, front_key);
	front_flow = lookup_flow_v6_active_or_old(front_key, &flow_bank);
	if (is_fullnat_front_flow_v6(front_flow)) {
		state = ensure_fullnat_existing_session_v6(ctx, rule, front_flow, flow_bank, now);
		if (state >= 0 && flow_bank_out) {
			if ((state & FORWARD_FULLNAT_STATE_FLOW_BANK_OLD) != 0)
				*flow_bank_out = FORWARD_XDP_FLOW_BANK_OLD;
			else
				*flow_bank_out = FORWARD_XDP_FLOW_BANK_ACTIVE;
		}
		return state;
	}
	if (flow_bank_out)
		*flow_bank_out = FORWARD_XDP_FLOW_BANK_ACTIVE;
	if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn_v6(ctx))
		return -2;

	load_nat_port_window(&port_min, &port_range);
	if (port_range == 0)
		return -1;

	seed = mix_nat_probe_seed(fullnat_seed_v6(rule, ctx) ^ ((__u32)rule->out_ifindex << 1));
	start = seed % port_range;
	stride = nat_probe_stride(seed ^ 0x9e3779b9U, port_range);

	if ((__u32)preferred_port >= port_min && (__u32)preferred_port < (port_min + port_range)) {
		state = try_create_fullnat_session_v6(xdp, ctx, rule, now, preferred_port);
		if (state >= 0) {
			if (flow_bank_out) {
				if ((state & FORWARD_FULLNAT_STATE_FLOW_BANK_OLD) != 0)
					*flow_bank_out = FORWARD_XDP_FLOW_BANK_OLD;
				else
					*flow_bank_out = FORWARD_XDP_FLOW_BANK_ACTIVE;
			}
			return state;
		}
		if (state == -1)
			return -1;
	}

#define FORWARD_XDP_FULLNAT_V6_ATTEMPT(idx) \
	do { \
		__u16 nat_port = (__u16)(port_min + ((start + ((__u32)(idx) * stride)) % port_range)); \
		if (nat_port != preferred_port) { \
			state = try_create_fullnat_session_v6(xdp, ctx, rule, now, nat_port); \
			if (state >= 0) { \
				if (flow_bank_out) { \
					if ((state & FORWARD_FULLNAT_STATE_FLOW_BANK_OLD) != 0) \
						*flow_bank_out = FORWARD_XDP_FLOW_BANK_OLD; \
					else \
						*flow_bank_out = FORWARD_XDP_FLOW_BANK_ACTIVE; \
				} \
				return state; \
			} \
			if (state == -1) \
				return -1; \
		} \
	} while (0)
	FORWARD_UNROLL_32(FORWARD_XDP_FULLNAT_V6_ATTEMPT);
#undef FORWARD_XDP_FULLNAT_V6_ATTEMPT

	return -1;
}

static __always_inline int finalize_fullnat_forward_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, __u8 state, __u8 flow_bank)
{
	struct flow_key_v6 *front_key = lookup_xdp_flow_key_scratch_v6();
	struct flow_key_v6 *reply_key = lookup_xdp_flow_aux_key_scratch_v6();
	struct flow_value_v6 *front_value = lookup_xdp_flow_scratch_v6();
	struct flow_value_v6 *reply_value = lookup_xdp_flow_aux_scratch_v6();
	__u64 now = bpf_ktime_get_ns();
	__u8 update_front = 0;
	__u8 update_reply = 0;

	if (!front_key || !reply_key || !front_value || !reply_value)
		return XDP_DROP;

	if (ctx->proto == IPPROTO_UDP) {
		if ((state & FORWARD_FULLNAT_STATE_CREATED_FRONT) == 0 &&
			(front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if ((state & FORWARD_FULLNAT_STATE_CREATED_REPLY) == 0 &&
			(reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	} else if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (front_value->front_close_seen_ns == 0)
			front_value->front_close_seen_ns = now;
		front_value->last_seen_ns = now;
		update_front = 1;

		reply_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		if (reply_value->front_close_seen_ns == 0)
			reply_value->front_close_seen_ns = now;
		reply_value->last_seen_ns = now;
		update_reply = 1;
	} else {
		if ((state & FORWARD_FULLNAT_STATE_CREATED_FRONT) == 0 &&
			(front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if ((state & FORWARD_FULLNAT_STATE_CREATED_REPLY) == 0 &&
			(reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front) {
		if (update_flow_v6_in_bank(flow_bank, front_key, front_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if (update_reply) {
		build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, reply_key);
		if (update_flow_v6_in_bank(flow_bank, reply_key, reply_value, BPF_ANY) < 0)
			return XDP_DROP;
	}
	if ((state & FORWARD_FULLNAT_STATE_CREATED_FRONT) != 0)
		bump_kernel_flow_occupancy();
	if ((state & FORWARD_FULLNAT_STATE_CREATED_REPLY) != 0)
		bump_kernel_flow_occupancy();
	if ((state & FORWARD_FULLNAT_STATE_NEW_SESSION) != 0)
		bump_rule_total_conns(rule->rule_id);
	if ((state & FORWARD_FULLNAT_STATE_COUNT_UDP_NOW) != 0)
		bump_rule_udp_nat(rule->rule_id);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	int redirect_ifindex = prepare_rule_fullnat_redirect_v6(xdp, ctx, rule, front_value);
	if (redirect_ifindex <= 0)
		return XDP_DROP;
	if (rewrite_l4_snat_v6(xdp, ctx, front_value->nat_addr, front_value->nat_port) < 0)
		return XDP_ABORTED;
	if (rewrite_l4_dnat_v6(xdp, ctx, rule->backend_addr, rule->backend_port) < 0)
		return XDP_ABORTED;
	return xdp_redirect_ifindex((__u32)redirect_ifindex);
}

static __always_inline int handle_fullnat_forward_v6(struct xdp_md *xdp, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule, __u8 existing_flow_bank)
{
	__u8 flow_bank = existing_flow_bank;
	int state = prepare_fullnat_forward_v6(xdp, ctx, rule, &flow_bank);

	if (state == -2)
		return XDP_PASS;
	if (state < 0)
		return XDP_DROP;
	return finalize_fullnat_forward_v6(xdp, ctx, rule, (__u8)state, flow_bank);
}

static __always_inline int forward_xdp_v4_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v4 *dispatch = lookup_xdp_dispatch_scratch_v4();
	struct flow_value_v4 *flow;
	struct rule_value_v4 *rule;
	__u32 in_ifindex;

	if (!dispatch)
		return XDP_PASS;
	dispatch->flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	dispatch->have_flow = 0;
	dispatch->have_rule = 0;

	if (parse_ipv4_l4(xdp, &dispatch->ctx) < 0)
		return XDP_PASS;

	in_ifindex = xdp->ingress_ifindex;
	dispatch->in_ifindex = in_ifindex;
	build_front_flow_key(in_ifindex, &dispatch->ctx, &dispatch->flow_key);

	flow = lookup_flow_v4_active_or_old(&dispatch->flow_key, &dispatch->flow_bank);
	if (flow) {
		dispatch->flow_value = *flow;
		dispatch->have_flow = 1;
		if (is_fullnat_front_flow(flow)) {
			rule = lookup_rule_v4_for_ifindex(in_ifindex, &dispatch->ctx);
			if (!is_fullnat_rule(rule))
				return XDP_PASS;
			dispatch->rule_value = *rule;
			dispatch->have_rule = 1;
			bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_FULLNAT_FORWARD);
			return XDP_PASS;
		}
		if (is_fullnat_reply_flow(flow)) {
			bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_FULLNAT_REPLY);
			return XDP_PASS;
		}
		xdp_diag_v4_transparent_reply_flow_hit();
		bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_TRANSPARENT);
		return XDP_PASS;
	}
	flow = lookup_reply_flow_v4(&dispatch->flow_key, &dispatch->flow_bank);
	if (flow && is_fullnat_reply_flow(flow)) {
		dispatch->flow_value = *flow;
		dispatch->have_flow = 1;
		bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_FULLNAT_REPLY);
		return XDP_PASS;
	}

	rule = lookup_rule_v4_for_ifindex(in_ifindex, &dispatch->ctx);
	if (!rule) {
		xdp_diag_v4_transparent_no_match_pass();
		return XDP_PASS;
	}
	dispatch->rule_value = *rule;
	dispatch->have_rule = 1;
	if (is_fullnat_rule(rule)) {
		if (is_egress_nat_rule(rule) && is_local_ipv4(dispatch->ctx.dst_addr))
			return XDP_PASS;
		bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_FULLNAT_FORWARD);
		return XDP_PASS;
	}
	xdp_diag_v4_transparent_forward_rule_hit();
	bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4_TRANSPARENT);
	return XDP_PASS;
}

static __always_inline int forward_xdp_v4_transparent_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v4 *dispatch = lookup_xdp_dispatch_scratch_v4();
	struct rule_value_v4 *rule;

	if (!dispatch)
		return XDP_PASS;
	xdp_diag_v4_transparent_enter();

	if (dispatch->have_flow) {
		if (is_fullnat_front_flow(&dispatch->flow_value) || is_fullnat_reply_flow(&dispatch->flow_value))
			return XDP_PASS;
		return handle_transparent_reply(xdp, &dispatch->ctx, &dispatch->flow_key, &dispatch->flow_value, dispatch->flow_bank);
	}

	if (!dispatch->have_rule) {
		rule = lookup_rule_v4_for_ifindex(dispatch->in_ifindex, &dispatch->ctx);
		if (!rule)
			return XDP_PASS;
		dispatch->rule_value = *rule;
		dispatch->have_rule = 1;
	}

	if (is_fullnat_rule(&dispatch->rule_value))
		return XDP_PASS;
	return handle_transparent_forward(xdp, dispatch->in_ifindex, &dispatch->ctx, &dispatch->rule_value);
}

static __always_inline int forward_xdp_v4_fullnat_forward_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v4 *dispatch = lookup_xdp_dispatch_scratch_v4();
	struct flow_value_v4 *flow = NULL;
	struct rule_value_v4 *rule;

	if (!dispatch)
		return XDP_PASS;

	if (dispatch->have_flow && is_fullnat_front_flow(&dispatch->flow_value))
		flow = &dispatch->flow_value;

	if (!dispatch->have_rule) {
		rule = lookup_rule_v4_for_ifindex(dispatch->in_ifindex, &dispatch->ctx);
		if (!rule)
			return XDP_PASS;
		dispatch->rule_value = *rule;
		dispatch->have_rule = 1;
	}
	rule = &dispatch->rule_value;

	if (!is_fullnat_rule(rule))
		return XDP_PASS;
	if (is_egress_nat_rule(rule) && is_local_ipv4(dispatch->ctx.dst_addr))
		return XDP_PASS;
	return handle_fullnat_forward(xdp, dispatch->in_ifindex, &dispatch->ctx, rule, flow);
}

static __always_inline int forward_xdp_v4_fullnat_reply_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v4 *dispatch = lookup_xdp_dispatch_scratch_v4();

	if (!dispatch)
		return XDP_PASS;

	if (!dispatch->have_flow || !is_fullnat_reply_flow(&dispatch->flow_value))
		return XDP_PASS;
	return handle_fullnat_reply(xdp, &dispatch->ctx, &dispatch->flow_key, &dispatch->flow_value, dispatch->flow_bank);
}

static __always_inline int forward_xdp_v6_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v6 *dispatch = lookup_xdp_dispatch_scratch_v6();
	struct flow_value_v6 *flow_v6;
	struct rule_value_v6 *rule_v6;

	if (!dispatch)
		return XDP_PASS;
	dispatch->flow_bank = FORWARD_XDP_FLOW_BANK_ACTIVE;
	dispatch->have_flow = 0;
	dispatch->have_rule = 0;

	if (parse_ipv6_l4(xdp, &dispatch->ctx) < 0)
		return XDP_PASS;

	dispatch->in_ifindex = xdp->ingress_ifindex;
	build_front_flow_key_v6(dispatch->in_ifindex, &dispatch->ctx, &dispatch->flow_key);
	flow_v6 = lookup_flow_v6_active_or_old(&dispatch->flow_key, &dispatch->flow_bank);
	if (flow_v6) {
		dispatch->flow_value = *flow_v6;
		dispatch->have_flow = 1;
		if (is_fullnat_front_flow_v6(flow_v6)) {
			rule_v6 = lookup_rule_v6_for_ifindex(dispatch->in_ifindex, &dispatch->ctx);
			if (!is_fullnat_rule_v6(rule_v6))
				return XDP_PASS;
			dispatch->rule_value = *rule_v6;
			dispatch->have_rule = 1;
			bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V6_FULLNAT_FORWARD);
			return XDP_PASS;
		}
		if (is_fullnat_reply_flow_v6(flow_v6)) {
			bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V6_FULLNAT_REPLY);
			return XDP_PASS;
		}
		return XDP_PASS;
	}

	rule_v6 = lookup_rule_v6_for_ifindex(dispatch->in_ifindex, &dispatch->ctx);
	if (!is_fullnat_rule_v6(rule_v6))
		return XDP_PASS;
	dispatch->rule_value = *rule_v6;
	dispatch->have_rule = 1;
	bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V6_FULLNAT_FORWARD);
	return XDP_PASS;
}

static __always_inline int forward_xdp_v6_fullnat_forward_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v6 *dispatch = lookup_xdp_dispatch_scratch_v6();
	struct rule_value_v6 *rule_v6;

	if (!dispatch)
		return XDP_PASS;
	if (!dispatch->have_rule) {
		rule_v6 = lookup_rule_v6_for_ifindex(dispatch->in_ifindex, &dispatch->ctx);
		if (!rule_v6)
			return XDP_PASS;
		dispatch->rule_value = *rule_v6;
		dispatch->have_rule = 1;
	}

	rule_v6 = &dispatch->rule_value;
	if (!is_fullnat_rule_v6(rule_v6))
		return XDP_PASS;
	return handle_fullnat_forward_v6(xdp, &dispatch->ctx, rule_v6, dispatch->flow_bank);
}

static __always_inline int forward_xdp_v6_fullnat_reply_impl(struct xdp_md *xdp)
{
	struct xdp_dispatch_ctx_v6 *dispatch = lookup_xdp_dispatch_scratch_v6();

	if (!dispatch)
		return XDP_PASS;

	if (!dispatch->have_flow || !is_fullnat_reply_flow_v6(&dispatch->flow_value))
		return XDP_PASS;
	return handle_fullnat_reply_v6(xdp, &dispatch->ctx, &dispatch->flow_key, &dispatch->flow_value, dispatch->flow_bank);
}

SEC("xdp")
int forward_xdp(struct xdp_md *xdp)
{
	__be16 proto = forward_xdp_eth_proto(xdp);

	if (proto == bpf_htons(ETH_P_IP))
		bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V4);
	else if (proto == bpf_htons(ETH_P_IPV6))
		bpf_tail_call(xdp, &xdp_prog_chain, FORWARD_XDP_PROG_V6);
	return XDP_PASS;
}

SEC("xdp")
int forward_xdp_v4(struct xdp_md *xdp)
{
	return forward_xdp_v4_impl(xdp);
}

SEC("xdp")
int forward_xdp_v6(struct xdp_md *xdp)
{
	return forward_xdp_v6_impl(xdp);
}

SEC("xdp")
int forward_xdp_v4_transparent(struct xdp_md *xdp)
{
	return forward_xdp_v4_transparent_impl(xdp);
}

SEC("xdp")
int forward_xdp_v4_fullnat_forward(struct xdp_md *xdp)
{
	return forward_xdp_v4_fullnat_forward_impl(xdp);
}

SEC("xdp")
int forward_xdp_v4_fullnat_reply(struct xdp_md *xdp)
{
	return forward_xdp_v4_fullnat_reply_impl(xdp);
}

SEC("xdp")
int forward_xdp_v6_fullnat_forward(struct xdp_md *xdp)
{
	return forward_xdp_v6_fullnat_forward_impl(xdp);
}

SEC("xdp")
int forward_xdp_v6_fullnat_reply(struct xdp_md *xdp)
{
	return forward_xdp_v6_fullnat_reply_impl(xdp);
}

char _license[] SEC("license") = "GPL";
