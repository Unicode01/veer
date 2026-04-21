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
#include "include/forward_addr_helpers.h"
#include "include/bpf_helpers.h"

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

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

struct reply_l2_value_v4 {
	__u8 front_mac[ETH_ALEN];
	__u8 client_mac[ETH_ALEN];
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

#ifndef FORWARD_TC_PREFER_REDIRECT_NEIGH
#define FORWARD_TC_PREFER_REDIRECT_NEIGH 0
#endif

struct packet_ctx {
	__be32 src_addr;
	__be32 dst_addr;
	__u8 proto;
	__u8 icmp_type;
	__u8 tcp_flags;
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

struct packet_ctx_v6 {
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u8 proto;
	__u8 tcp_flags;
	__u8 has_l4_checksum;
	__u8 closing;
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

struct tc_dispatch_ctx_v4 {
	struct packet_ctx ctx;
	struct flow_key_v4 flow_key;
	struct flow_value_v4 flow_value;
	struct rule_value_v4 rule_value;
	__u8 have_flow;
	__u8 have_rule;
	__u8 flow_bank;
	__u8 pad0;
};

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define FORWARD_IPV4_FRAG_MASK 0x3fff
#define FORWARD_FLOW_FLAG_FRONT_CLOSING 0x1
#define FORWARD_FLOW_FLAG_REPLY_SEEN 0x2
#define FORWARD_FLOW_FLAG_FULL_NAT 0x4
#define FORWARD_FLOW_FLAG_FRONT_ENTRY 0x8
#define FORWARD_FLOW_FLAG_EGRESS_NAT 0x10
#define FORWARD_FLOW_FLAG_COUNTED 0x20
#define FORWARD_FLOW_FLAG_FULL_CONE 0x80
#define FORWARD_RULE_FLAG_FULL_NAT 0x1
#define FORWARD_RULE_FLAG_BRIDGE_L2 0x2
#define FORWARD_RULE_FLAG_EGRESS_NAT 0x8
#define FORWARD_RULE_FLAG_PASSTHROUGH 0x10
#define FORWARD_RULE_FLAG_FULL_CONE 0x20
#define FORWARD_RULE_FLAG_PREPARED_L2 0x40
#define FORWARD_TCP_FLOW_REFRESH_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_REFRESH_NS (1ULL * 1000000000ULL)
#define FORWARD_ICMP_FLOW_IDLE_NS (30ULL * 1000000000ULL)
#define FORWARD_UDP_FLOW_IDLE_NS (300ULL * 1000000000ULL)
#define FORWARD_DATAGRAM_FLOW_IDLE_NS(proto) ((proto) == IPPROTO_ICMP ? FORWARD_ICMP_FLOW_IDLE_NS : FORWARD_UDP_FLOW_IDLE_NS)
#define FORWARD_NAT_PORT_MIN 20000U
#define FORWARD_NAT_PORT_MAX 65535U
#define FORWARD_NAT_PORT_RANGE (FORWARD_NAT_PORT_MAX - FORWARD_NAT_PORT_MIN + 1U)
#define FORWARD_NAT_PORT_PROBE_WINDOW 64
#define FORWARD_NAT_PORT_PROBE_ROUNDS 3
#define FORWARD_TC_FLOW_BANK_ACTIVE 0
#define FORWARD_TC_FLOW_BANK_OLD 1
#define FORWARD_NAT_CONFIG_FLAG_TC_REDIRECT_NEIGH_FAST 0x1U
#define FORWARD_NAT_CONFIG_FLAG_TC_REPLY_L2_CACHE 0x2U
#define FORWARD_TC_FLOW_BANK_MASK 0x1
#define FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT 0x80
#define FORWARD_TC_FLOW_MIGRATION_V4_OLD 0x1
#define FORWARD_TC_FLOW_MIGRATION_V6_OLD 0x2
#define FORWARD_TCP_FLAG_FIN 0x01
#define FORWARD_TCP_FLAG_SYN 0x02
#define FORWARD_TCP_FLAG_RST 0x04
#define FORWARD_TCP_FLAG_ACK 0x10
#if FORWARD_NAT_PORT_PROBE_ROUNDS > 3
#error FORWARD_NAT_PORT_PROBE_ROUNDS above 3 requires extending reserve_nat_port()
#endif

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

/*
 * TC flow state is pruned explicitly from userspace. Using plain HASH here
 * avoids LRU single-entry evictions that can break full-NAT front/reply pairs
 * during hot-restart migration.
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

struct bpf_map_def SEC("maps") reply_l2_cache_v4 = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct flow_key_v4),
	.value_size = sizeof(struct reply_l2_value_v4),
	.max_entries = 131072,
};

struct bpf_map_def SEC("maps") scratch_flow_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_flow_aux_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct packet_ctx),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_fib_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bpf_fib_lookup),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_flow_key_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 7,
};

struct bpf_map_def SEC("maps") tc_dispatch_scratch_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_dispatch_ctx_v4),
	.max_entries = 1,
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

struct bpf_map_def SEC("maps") scratch_flow_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_flow_aux_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_value_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_ctx_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct packet_ctx_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_fib_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bpf_fib_lookup),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratch_flow_key_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct flow_key_v6),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") if_parent_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") local_ipv4s_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") egress_wildcard_fast_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct rule_key_v4),
	.value_size = sizeof(__u8),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") nat_config_v4 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kernel_nat_config_value_v4),
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

struct bpf_map_def SEC("maps") tc_flow_migration_state = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

enum {
	FORWARD_TC_PROG_V4_TRANSPARENT = 0,
	FORWARD_TC_PROG_V4_FULLNAT_FORWARD = 1,
	FORWARD_TC_PROG_V4_EGRESS_NAT_FORWARD = 2,
	FORWARD_TC_PROG_V4_REPLY_TRANSPARENT = 3,
	FORWARD_TC_PROG_V4_REPLY_FULLNAT = 4,
	FORWARD_TC_PROG_V4_FULLNAT_EXISTING = 5,
	FORWARD_TC_PROG_V4_FULLNAT_NEW = 6,
};

static __always_inline struct kernel_occupancy_value_v4 *lookup_kernel_occupancy(void);
static __always_inline struct kernel_nat_config_value_v4 *lookup_kernel_nat_config(void);
static __always_inline __u32 load_kernel_nat_config_flags(void);
static __always_inline void load_nat_port_window(__u32 *port_min, __u32 *port_range);
static __always_inline __u32 mix_nat_probe_seed(__u32 seed);
static __always_inline __u32 nat_probe_stride(__u32 seed, __u32 port_range);
static __always_inline int try_reserve_nat_port(__u32 candidate, struct nat_port_key_v4 *nat_key, const struct nat_port_value_v4 *nat_value, __u16 *nat_port);
static __always_inline int try_reserve_nat_port_v6(__u32 candidate, struct nat_port_key_v6 *nat_key, const struct nat_port_value_v6 *nat_value, __u16 *nat_port);
static __always_inline __u32 tc_flow_migration_flags(void);
static __always_inline int tc_flow_old_bank_enabled_v4(void);
static __always_inline int tc_flow_old_bank_enabled_v6(void);
static __always_inline int is_fullnat_front_flow(const struct flow_value_v4 *flow);
static __always_inline struct flow_value_v4 *lookup_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key);
static __always_inline struct flow_value_v6 *lookup_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key);
static __always_inline struct nat_port_value_v4 *lookup_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key);
static __always_inline struct nat_port_value_v6 *lookup_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key);
static __always_inline struct flow_value_v4 *lookup_flow_v4_active_or_old(const struct flow_key_v4 *key, __u8 *bank);
static __always_inline struct flow_value_v6 *lookup_flow_v6_active_or_old(const struct flow_key_v6 *key, __u8 *bank);
static __always_inline int update_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key, const struct flow_value_v4 *value, __u64 flags);
static __always_inline int update_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key, const struct flow_value_v6 *value, __u64 flags);
static __always_inline int update_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key, const struct nat_port_value_v4 *value, __u64 flags);
static __always_inline int update_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key, const struct nat_port_value_v6 *value, __u64 flags);
static __always_inline int delete_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key);
static __always_inline void delete_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key);
static __always_inline int delete_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key);
static __always_inline void delete_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key);
static __always_inline void bump_kernel_flow_occupancy(void);
static __always_inline void drop_kernel_flow_occupancy(void);
static __always_inline void bump_kernel_nat_occupancy(void);
static __always_inline void drop_kernel_nat_occupancy(void);
static __always_inline struct flow_value_v4 *lookup_scratch_flow_v4(void);
static __always_inline struct flow_value_v4 *lookup_scratch_flow_aux_v4(void);
static __always_inline struct packet_ctx *lookup_scratch_ctx_v4(void);
static __always_inline struct bpf_fib_lookup *lookup_scratch_fib_v4(void);
static __always_inline struct flow_key_v4 *lookup_scratch_flow_key_v4(void);
static __always_inline struct tc_dispatch_ctx_v4 *lookup_tc_dispatch_scratch_v4(void);
static __always_inline struct flow_value_v6 *lookup_scratch_flow_v6(void);
static __always_inline struct flow_value_v6 *lookup_scratch_flow_aux_v6(void);
static __always_inline struct packet_ctx_v6 *lookup_scratch_ctx_v6(void);
static __always_inline struct bpf_fib_lookup *lookup_scratch_fib_v6(void);
static __always_inline struct flow_key_v6 *lookup_scratch_flow_key_v6(void);
static __always_inline struct kernel_diag_value_v4 *lookup_tc_diag_v4(void);
static __always_inline int handle_forward_ingress_v4_transparent(struct __sk_buff *skb);
static __always_inline int handle_forward_ingress_v4_fullnat(struct __sk_buff *skb);
static __always_inline int handle_forward_ingress_v4_egress_nat(struct __sk_buff *skb);
static __always_inline int handle_forward_ingress_v4_fullnat_existing(struct __sk_buff *skb);
static __always_inline int handle_forward_ingress_v4_fullnat_new(struct __sk_buff *skb);
static __always_inline int handle_egress_nat_forward_existing(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, struct flow_value_v4 *front_flow, __u8 flow_bank);
static __always_inline int handle_reply_ingress_v4_transparent(struct __sk_buff *skb);
static __always_inline int handle_reply_ingress_v4_fullnat(struct __sk_buff *skb);

static __always_inline struct flow_value_v4 *lookup_scratch_flow_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_v4, &key);
}

static __always_inline struct flow_value_v4 *lookup_scratch_flow_aux_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_aux_v4, &key);
}

static __always_inline struct packet_ctx *lookup_scratch_ctx_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_ctx_v4, &key);
}

static __always_inline struct bpf_fib_lookup *lookup_scratch_fib_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_fib_v4, &key);
}

static __always_inline struct flow_key_v4 *lookup_scratch_flow_key_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_key_v4, &key);
}

static __always_inline struct tc_dispatch_ctx_v4 *lookup_tc_dispatch_scratch_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&tc_dispatch_scratch_v4, &key);
}

static __always_inline struct flow_value_v6 *lookup_scratch_flow_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_v6, &key);
}

static __always_inline struct flow_value_v6 *lookup_scratch_flow_aux_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_aux_v6, &key);
}

static __always_inline struct packet_ctx_v6 *lookup_scratch_ctx_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_ctx_v6, &key);
}

static __always_inline struct bpf_fib_lookup *lookup_scratch_fib_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_fib_v6, &key);
}

static __always_inline struct flow_key_v6 *lookup_scratch_flow_key_v6(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&scratch_flow_key_v6, &key);
}

static __always_inline struct kernel_diag_value_v4 *lookup_tc_diag_v4(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&diag_v4, &key);
}

static __always_inline void tc_diag_fib_non_success(void)
{
	struct kernel_diag_value_v4 *diag = lookup_tc_diag_v4();

	if (diag)
		diag->fib_non_success += 1;
}

static __always_inline void tc_diag_redirect_neigh_used(void)
{
	struct kernel_diag_value_v4 *diag = lookup_tc_diag_v4();

	if (diag)
		diag->redirect_neigh_used += 1;
}

static __always_inline void tc_diag_redirect_drop(void)
{
	struct kernel_diag_value_v4 *diag = lookup_tc_diag_v4();

	if (diag)
		diag->redirect_drop += 1;
}

static __always_inline __u32 tc_flow_migration_flags(void)
{
	__u32 key = 0;
	__u32 *flags = bpf_map_lookup_elem(&tc_flow_migration_state, &key);

	return flags ? *flags : 0;
}

static __always_inline int tc_flow_old_bank_enabled_v4(void)
{
	return (tc_flow_migration_flags() & FORWARD_TC_FLOW_MIGRATION_V4_OLD) != 0;
}

static __always_inline int tc_flow_old_bank_enabled_v6(void)
{
	return (tc_flow_migration_flags() & FORWARD_TC_FLOW_MIGRATION_V6_OLD) != 0;
}

static __always_inline struct flow_value_v4 *lookup_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&flows_old_v4, key);
	return bpf_map_lookup_elem(&flows_v4, key);
}

static __always_inline struct flow_value_v6 *lookup_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&flows_old_v6, key);
	return bpf_map_lookup_elem(&flows_v6, key);
}

static __always_inline struct nat_port_value_v4 *lookup_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&nat_ports_old_v4, key);
	return bpf_map_lookup_elem(&nat_ports_v4, key);
}

static __always_inline struct nat_port_value_v6 *lookup_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key)
{
	if (!key)
		return 0;
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_lookup_elem(&nat_ports_old_v6, key);
	return bpf_map_lookup_elem(&nat_ports_v6, key);
}

static __always_inline struct flow_value_v4 *lookup_flow_v4_active_or_old(const struct flow_key_v4 *key, __u8 *bank)
{
	struct flow_value_v4 *flow;

	if (bank)
		*bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!tc_flow_old_bank_enabled_v4())
		return 0;
	flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_TC_FLOW_BANK_OLD;
	return flow;
}

static __always_inline struct flow_value_v6 *lookup_flow_v6_active_or_old(const struct flow_key_v6 *key, __u8 *bank)
{
	struct flow_value_v6 *flow;

	if (bank)
		*bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	flow = lookup_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!tc_flow_old_bank_enabled_v6())
		return 0;
	flow = lookup_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_TC_FLOW_BANK_OLD;
	return flow;
}

static __always_inline int update_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key, const struct flow_value_v4 *value, __u64 flags)
{
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_update_elem(&flows_old_v4, key, value, flags);
	return bpf_map_update_elem(&flows_v4, key, value, flags);
}

static __always_inline int update_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key, const struct flow_value_v6 *value, __u64 flags)
{
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_update_elem(&flows_old_v6, key, value, flags);
	return bpf_map_update_elem(&flows_v6, key, value, flags);
}

static __always_inline int update_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key, const struct nat_port_value_v4 *value, __u64 flags)
{
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_update_elem(&nat_ports_old_v4, key, value, flags);
	if (flags == BPF_NOEXIST && tc_flow_old_bank_enabled_v4() && lookup_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&nat_ports_v4, key, value, flags);
}

static __always_inline int update_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key, const struct nat_port_value_v6 *value, __u64 flags)
{
	if (bank == FORWARD_TC_FLOW_BANK_OLD)
		return bpf_map_update_elem(&nat_ports_old_v6, key, value, flags);
	if (flags == BPF_NOEXIST && tc_flow_old_bank_enabled_v6() && lookup_nat_port_v6_in_bank(FORWARD_TC_FLOW_BANK_OLD, key))
		return -1;
	return bpf_map_update_elem(&nat_ports_v6, key, value, flags);
}

static __always_inline int delete_flow_v4_in_bank(__u8 bank, const struct flow_key_v4 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_TC_FLOW_BANK_OLD) {
		return bpf_map_delete_elem(&flows_old_v4, key);
	}
	return bpf_map_delete_elem(&flows_v4, key);
}

static __always_inline void delete_flow_v6_in_bank(__u8 bank, const struct flow_key_v6 *key)
{
	if (!key)
		return;
	if (bank == FORWARD_TC_FLOW_BANK_OLD) {
		bpf_map_delete_elem(&flows_old_v6, key);
		return;
	}
	bpf_map_delete_elem(&flows_v6, key);
}

static __always_inline int delete_nat_port_v4_in_bank(__u8 bank, const struct nat_port_key_v4 *key)
{
	if (!key)
		return -1;
	if (bank == FORWARD_TC_FLOW_BANK_OLD) {
		return bpf_map_delete_elem(&nat_ports_old_v4, key);
	}
	return bpf_map_delete_elem(&nat_ports_v4, key);
}

static __always_inline void delete_nat_port_v6_in_bank(__u8 bank, const struct nat_port_key_v6 *key)
{
	if (!key)
		return;
	if (bank == FORWARD_TC_FLOW_BANK_OLD) {
		bpf_map_delete_elem(&nat_ports_old_v6, key);
		return;
	}
	bpf_map_delete_elem(&nat_ports_v6, key);
}

static __always_inline int rewrite_eth_addrs(struct __sk_buff *skb, const __u8 dst[ETH_ALEN], const __u8 src[ETH_ALEN])
{
	__u8 mac_addrs[ETH_ALEN * 2];

	__builtin_memcpy(mac_addrs, dst, ETH_ALEN);
	__builtin_memcpy(mac_addrs + ETH_ALEN, src, ETH_ALEN);
	return bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), mac_addrs, sizeof(mac_addrs), 0);
}

static __always_inline int load_packet_macs(struct __sk_buff *skb, struct reply_l2_value_v4 *value)
{
	if (!value)
		return -1;
	return bpf_skb_load_bytes(skb, 0, value, sizeof(*value));
}

static __always_inline int update_l4_addr_checksum(struct __sk_buff *skb, const struct packet_ctx *ctx, int check_off, __be32 old_addr, __be32 new_addr)
{
	if (!ctx->has_l4_checksum)
		return 0;
	if (ctx->proto == IPPROTO_ICMP)
		return 0;
	return bpf_l4_csum_replace(skb, check_off, old_addr, new_addr, ctx->l4_addr_csum_flags);
}

static __always_inline int update_l4_port_checksum(struct __sk_buff *skb, const struct packet_ctx *ctx, int check_off, __be16 old_port, __be16 new_port)
{
	if (!ctx->has_l4_checksum)
		return 0;
	return bpf_l4_csum_replace(skb, check_off, old_port, new_port, ctx->l4_port_csum_flags);
}

static __always_inline int update_l4_addr_checksum_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const __u8 old_addr[16], const __u8 new_addr[16])
{
	__s64 diff;

	if (!ctx->has_l4_checksum)
		return 0;

	diff = bpf_csum_diff((const __be32 *)old_addr, sizeof(__u8) * 16, (const __be32 *)new_addr, sizeof(__u8) * 16, 0);
	if (diff < 0)
		return -1;
	return bpf_l4_csum_replace(skb, ctx->l4_check_off, 0, (__u64)diff, ctx->l4_addr_csum_flags);
}

static __always_inline int update_l4_port_checksum_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, __be16 old_port, __be16 new_port)
{
	if (!ctx->has_l4_checksum)
		return 0;
	return bpf_l4_csum_replace(skb, ctx->l4_check_off, old_port, new_port, ctx->l4_port_csum_flags);
}

static __always_inline int parse_eth_proto(struct __sk_buff *skb, __u16 *proto, int *l3_off)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth;
	struct forward_vlan_hdr *vh;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	*proto = eth->h_proto;
	if (*proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD)) {
		vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return -1;
		*proto = vh->h_vlan_encapsulated_proto;
		*l3_off = (int)(sizeof(*eth) + sizeof(*vh));
		return 0;
	}

	*l3_off = (int)sizeof(*eth);
	return 0;
}

static __always_inline int parse_ipv4_l4(struct __sk_buff *skb, struct packet_ctx *ctx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	__u16 proto;
	int l3_off;
	int l4_off;

	if (parse_eth_proto(skb, &proto, &l3_off) < 0)
		return -1;

	iph = data + l3_off;

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
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
		return -1;

	l4_off = l3_off + (int)sizeof(*iph);
	ctx->src_addr = iph->saddr;
	ctx->dst_addr = iph->daddr;
	ctx->proto = iph->protocol;
	ctx->icmp_type = 0;
	ctx->tcp_flags = 0;
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
		ctx->tcp_flags =
			(tcph->fin ? FORWARD_TCP_FLAG_FIN : 0) |
			(tcph->syn ? FORWARD_TCP_FLAG_SYN : 0) |
			(tcph->rst ? FORWARD_TCP_FLAG_RST : 0) |
			(tcph->ack ? FORWARD_TCP_FLAG_ACK : 0);
		ctx->closing = tcph->fin || tcph->rst;
		FORWARD_SET_PAYLOAD_LEN(ctx, 0);
		if (ctx->tot_len > (sizeof(*iph) + (((__u16)tcph->doff) << 2)))
			FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*iph) + (((__u16)tcph->doff) << 2)));
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | sizeof(__be32);
		ctx->l4_port_csum_flags = sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct tcphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct tcphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct tcphdr, dest));
	} else if (ctx->proto == IPPROTO_UDP) {
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
	} else {
		icmph = (void *)(iph + 1);
		if ((void *)(icmph + 1) > data_end)
			return -1;
		if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY)
			return -1;
		ctx->icmp_type = icmph->type;
		if (icmph->type == ICMP_ECHO) {
			ctx->src_port = bpf_ntohs(icmph->un.echo.id);
			ctx->dst_port = 0;
		} else {
			ctx->src_port = 0;
			ctx->dst_port = bpf_ntohs(icmph->un.echo.id);
		}
		ctx->has_l4_checksum = 1;
		ctx->closing = 0;
		FORWARD_SET_PAYLOAD_LEN(ctx, 0);
		if (ctx->tot_len > (sizeof(*iph) + sizeof(*icmph)))
			FORWARD_SET_PAYLOAD_LEN(ctx, ctx->tot_len - (sizeof(*iph) + sizeof(*icmph)));
		ctx->l4_addr_csum_flags = 0;
		ctx->l4_port_csum_flags = sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct icmphdr, checksum));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct icmphdr, un.echo.id));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct icmphdr, un.echo.id));
	}

	ctx->l3_off = l3_off;
	ctx->l4_off = l4_off;
	return 0;
}

static __always_inline int parse_ipv6_l4(struct __sk_buff *skb, struct packet_ctx_v6 *ctx)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u16 proto;
	int l3_off;
	int l4_off;

	if (parse_eth_proto(skb, &proto, &l3_off) < 0)
		return -1;

	ip6h = data + l3_off;
	if (proto != bpf_htons(ETH_P_IPV6))
		return -1;
	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if ((bpf_ntohl(ip6h->ver_tc_flow) >> 28) != 6)
		return -1;
	if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
		return -1;

	l4_off = l3_off + (int)sizeof(*ip6h);
	copy_ipv6_addr(ctx->src_addr, ip6h->saddr);
	copy_ipv6_addr(ctx->dst_addr, ip6h->daddr);
	ctx->proto = ip6h->nexthdr;
	ctx->tcp_flags = 0;
	ctx->tot_len = (int)sizeof(*ip6h) + bpf_ntohs(ip6h->payload_len);
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
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR;
		ctx->l4_port_csum_flags = sizeof(__be16);
		ctx->l4_check_off = (int)(l4_off + offsetof(struct tcphdr, check));
		ctx->l4_src_off = (int)(l4_off + offsetof(struct tcphdr, source));
		ctx->l4_dst_off = (int)(l4_off + offsetof(struct tcphdr, dest));
	} else {
		udph = (void *)ip6h + sizeof(*ip6h);
		if ((void *)(udph + 1) > data_end)
			return -1;
		if (bpf_ntohs(udph->len) < sizeof(*udph))
			return -1;
		ctx->src_port = bpf_ntohs(udph->source);
		ctx->dst_port = bpf_ntohs(udph->dest);
		ctx->has_l4_checksum = 1;
		ctx->closing = 0;
		FORWARD_SET_PAYLOAD_LEN(ctx, bpf_ntohs(udph->len) - sizeof(*udph));
		ctx->l4_addr_csum_flags = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0;
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
	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = bpf_ntohl(ctx->dst_addr);
	key.dst_port = 0;
	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	key.dst_addr = 0;
	if (bpf_map_lookup_elem(&egress_wildcard_fast_v4, &key)) {
		rule = bpf_map_lookup_elem(&rules_v4, &key);
		if (rule)
			return rule;
	}

	rule = bpf_map_lookup_elem(&rules_v4, &key);
	if (rule)
		return rule;

	return 0;
}

static __always_inline struct rule_value_v6 *lookup_rule_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx)
{
	struct rule_key_v6 key = {
		.ifindex = skb->ifindex,
		.dst_port = ctx->dst_port,
		.proto = ctx->proto,
	};
	struct rule_value_v6 *rule;

	copy_ipv6_addr(key.dst_addr, ctx->dst_addr);
	rule = bpf_map_lookup_elem(&rules_v6, &key);
	if (rule)
		return rule;

	__builtin_memset(key.dst_addr, 0, sizeof(key.dst_addr));
	rule = bpf_map_lookup_elem(&rules_v6, &key);
	if (rule)
		return rule;

	copy_ipv6_addr(key.dst_addr, ctx->dst_addr);
	key.dst_port = 0;
	rule = bpf_map_lookup_elem(&rules_v6, &key);
	if (rule)
		return rule;

	__builtin_memset(key.dst_addr, 0, sizeof(key.dst_addr));
	rule = bpf_map_lookup_elem(&rules_v6, &key);
	if (rule)
		return rule;

	return 0;
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

static __always_inline int rewrite_l4_dnat_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const __u8 new_addr[16], __u16 new_port_host)
{
	const int ip_dst_off = ctx->l3_off + offsetof(struct ipv6hdr, daddr);
	__be16 old_port = bpf_htons(ctx->dst_port);
	__be16 new_port = bpf_htons(new_port_host);

	if (!ipv6_addr_equal(ctx->dst_addr, new_addr)) {
		if (update_l4_addr_checksum_v6(skb, ctx, ctx->dst_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ip_dst_off, new_addr, sizeof(__u8) * 16, 0) < 0)
			return -1;
	}

	if (old_port != new_port) {
		if (update_l4_port_checksum_v6(skb, ctx, old_port, new_port) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_dst_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}

	return 0;
}

static __always_inline int rewrite_l4_snat_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const __u8 new_addr[16], __u16 new_port_host)
{
	const int ip_src_off = ctx->l3_off + offsetof(struct ipv6hdr, saddr);
	__be16 old_port = bpf_htons(ctx->src_port);
	__be16 new_port = bpf_htons(new_port_host);

	if (!ipv6_addr_equal(ctx->src_addr, new_addr)) {
		if (update_l4_addr_checksum_v6(skb, ctx, ctx->src_addr, new_addr) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ip_src_off, new_addr, sizeof(__u8) * 16, 0) < 0)
			return -1;
	}

	if (old_port != new_port) {
		if (update_l4_port_checksum_v6(skb, ctx, old_port, new_port) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, ctx->l4_src_off, &new_port, sizeof(new_port), 0) < 0)
			return -1;
	}

	return 0;
}

static __always_inline int prefer_redirect_neigh_fast(__u32 nat_cfg_flags)
{
#if FORWARD_TC_PREFER_REDIRECT_NEIGH
	return 1;
#else
	return (nat_cfg_flags & FORWARD_NAT_CONFIG_FLAG_TC_REDIRECT_NEIGH_FAST) != 0;
#endif
}

static __always_inline int prefer_reply_l2_cache(__u32 nat_cfg_flags)
{
	return (nat_cfg_flags & FORWARD_NAT_CONFIG_FLAG_TC_REPLY_L2_CACHE) != 0;
}

static __always_inline void update_reply_l2_cache_v4(struct __sk_buff *skb, const struct flow_key_v4 *reply_key, __u32 nat_cfg_flags)
{
	struct reply_l2_value_v4 value = {};

	if (!skb || !reply_key || !prefer_reply_l2_cache(nat_cfg_flags))
		return;
	if (load_packet_macs(skb, &value) < 0)
		return;
	if (mac_addr_is_zero(value.front_mac) || mac_addr_is_zero(value.client_mac))
		return;
	bpf_map_update_elem(&reply_l2_cache_v4, reply_key, &value, BPF_ANY);
}

static __always_inline int redirect_reply_l2_cache_v4(struct __sk_buff *skb, const struct flow_key_v4 *reply_key, __u32 ifindex, __u32 nat_cfg_flags)
{
	struct reply_l2_value_v4 *value;
	long act;

	if (!skb || !reply_key || !ifindex || !prefer_reply_l2_cache(nat_cfg_flags))
		return -1;
	value = bpf_map_lookup_elem(&reply_l2_cache_v4, reply_key);
	if (!value)
		return -1;
	if (mac_addr_is_zero(value->front_mac) || mac_addr_is_zero(value->client_mac))
		return -1;
	if (rewrite_eth_addrs(skb, value->client_mac, value->front_mac) < 0)
		return -1;
	act = bpf_redirect(ifindex, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	return -1;
}

static __always_inline int redirect_ifindex(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct redirect_target_v4 *target, __u32 nat_cfg_flags)
{
	long act;

	if (!ctx || !target || !target->ifindex)
		return TC_ACT_SHOT;
	if (prefer_redirect_neigh_fast(nat_cfg_flags)) {
		tc_diag_redirect_neigh_used();
		act = bpf_redirect_neigh(target->ifindex, 0, 0, 0);
		if (act == TC_ACT_REDIRECT)
			return (int)act;
		tc_diag_redirect_drop();
		return TC_ACT_SHOT;
	}
	{
		struct bpf_fib_lookup *fib = lookup_scratch_fib_v4();

		if (!fib)
			return TC_ACT_SHOT;
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

		act = bpf_fib_lookup(skb, fib, sizeof(*fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
		if (act == BPF_FIB_LKUP_RET_SUCCESS) {
			if (rewrite_eth_addrs(skb, fib->dmac, fib->smac) < 0) {
				tc_diag_redirect_drop();
				return TC_ACT_SHOT;
			}
			act = bpf_redirect(fib->ifindex ? fib->ifindex : target->ifindex, 0);
			if (act == TC_ACT_REDIRECT)
				return (int)act;
		} else {
			tc_diag_fib_non_success();
		}
	}

	tc_diag_redirect_neigh_used();
	act = bpf_redirect_neigh(target->ifindex, 0, 0, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	tc_diag_redirect_drop();
	return TC_ACT_SHOT;
}

static __always_inline int redirect_ifindex_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const struct redirect_target_v6 *target)
{
	struct bpf_fib_lookup *fib = lookup_scratch_fib_v6();
	long act;

	if (!fib || !target)
		return TC_ACT_SHOT;
	__builtin_memset(fib, 0, sizeof(*fib));

	if (!target->ifindex)
		return TC_ACT_SHOT;

	fib->family = AF_INET6;
	fib->l4_protocol = ctx->proto;
	fib->sport = bpf_htons(target->src_port);
	fib->dport = bpf_htons(target->dst_port);
	fib->tot_len = ctx->tot_len;
	__builtin_memcpy(fib->ipv6_src, target->src_addr, sizeof(fib->ipv6_src));
	__builtin_memcpy(fib->ipv6_dst, target->dst_addr, sizeof(fib->ipv6_dst));
	fib->ifindex = target->ifindex;

	act = bpf_fib_lookup(skb, fib, sizeof(*fib), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (act == BPF_FIB_LKUP_RET_SUCCESS) {
		if (rewrite_eth_addrs(skb, fib->dmac, fib->smac) < 0) {
			tc_diag_redirect_drop();
			return TC_ACT_SHOT;
		}
		act = bpf_redirect(fib->ifindex ? fib->ifindex : target->ifindex, 0);
		if (act == TC_ACT_REDIRECT)
			return (int)act;
	} else {
		tc_diag_fib_non_success();
	}

	tc_diag_redirect_neigh_used();
	act = bpf_redirect_neigh(target->ifindex, 0, 0, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	tc_diag_redirect_drop();
	return TC_ACT_SHOT;
}

static __always_inline int redirect_prepared_l2_ifindex(struct __sk_buff *skb, const struct rule_value_v4 *rule)
{
	long act;

	if (!rule || !rule->out_ifindex)
		return TC_ACT_SHOT;
	if (rewrite_eth_addrs(skb, rule->dst_mac, rule->src_mac) < 0) {
		tc_diag_redirect_drop();
		return TC_ACT_SHOT;
	}
	act = bpf_redirect(rule->out_ifindex, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	tc_diag_redirect_drop();
	return TC_ACT_SHOT;
}

static __always_inline int redirect_prepared_l2_ifindex_v6(struct __sk_buff *skb, const struct rule_value_v6 *rule)
{
	long act;

	if (!rule || !rule->out_ifindex)
		return TC_ACT_SHOT;
	if (rewrite_eth_addrs(skb, rule->dst_mac, rule->src_mac) < 0) {
		tc_diag_redirect_drop();
		return TC_ACT_SHOT;
	}
	act = bpf_redirect(rule->out_ifindex, 0);
	if (act == TC_ACT_REDIRECT)
		return (int)act;
	tc_diag_redirect_drop();
	return TC_ACT_SHOT;
}

static __always_inline int is_fullnat_rule(const struct rule_value_v4 *rule)
{
	return rule && (rule->flags & FORWARD_RULE_FLAG_FULL_NAT) != 0;
}

static __always_inline int is_fullnat_rule_v6(const struct rule_value_v6 *rule)
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

static __always_inline int is_passthrough_rule(const struct rule_value_v4 *rule)
{
	return rule && (rule->flags & FORWARD_RULE_FLAG_PASSTHROUGH) != 0;
}

static __always_inline int is_local_ipv4(__be32 addr)
{
	__u32 key = bpf_ntohl(addr);
	__u8 *present = bpf_map_lookup_elem(&local_ipv4s_v4, &key);

	return present && *present != 0;
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

static __always_inline int is_egress_nat_flow(const struct flow_value_v4 *flow)
{
	return flow && (flow->flags & FORWARD_FLOW_FLAG_EGRESS_NAT) != 0;
}

static __always_inline int is_full_cone_flow(const struct flow_value_v4 *flow)
{
	return flow && (flow->flags & FORWARD_FLOW_FLAG_FULL_CONE) != 0;
}

static __always_inline int is_full_cone_front_flow(const struct flow_value_v4 *flow)
{
	return is_fullnat_front_flow(flow) && is_full_cone_flow(flow);
}

static __always_inline int is_full_cone_reply_flow(const struct flow_value_v4 *flow)
{
	return is_fullnat_reply_flow(flow) && is_full_cone_flow(flow);
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

static __always_inline void build_front_flow_key(struct __sk_buff *skb, const struct packet_ctx *ctx, struct flow_key_v4 *key)
{
	key->ifindex = skb->ifindex;
	key->src_addr = bpf_ntohl(ctx->src_addr);
	key->dst_addr = bpf_ntohl(ctx->dst_addr);
	key->src_port = ctx->src_port;
	key->dst_port = ctx->dst_port;
	key->proto = ctx->proto;
}

static __always_inline void build_full_cone_front_flow_key(struct __sk_buff *skb, const struct packet_ctx *ctx, struct flow_key_v4 *key)
{
	key->ifindex = skb->ifindex;
	key->src_addr = bpf_ntohl(ctx->src_addr);
	key->dst_addr = 0;
	key->src_port = ctx->src_port;
	key->dst_port = 0;
	key->proto = ctx->proto;
}

static __always_inline __u32 resolve_parent_ifindex(__u32 ifindex)
{
	__u32 key = ifindex;
	__u32 *parent = bpf_map_lookup_elem(&if_parent_v4, &key);

	if (parent && *parent != 0)
		return *parent;
	return ifindex;
}

static __always_inline struct flow_value_v4 *lookup_reply_flow_v4_in_bank(__u8 bank, struct flow_key_v4 *key)
{
	struct flow_key_v4 lookup_key = {};
	struct flow_value_v4 *flow;
	__u32 parent_ifindex;

	if (!key)
		return 0;
	lookup_key = *key;
	flow = lookup_flow_v4_in_bank(bank, &lookup_key);
	if (flow) {
		*key = lookup_key;
		return flow;
	}

	parent_ifindex = resolve_parent_ifindex(lookup_key.ifindex);
	if (parent_ifindex != lookup_key.ifindex) {
		lookup_key.ifindex = parent_ifindex;
		flow = lookup_flow_v4_in_bank(bank, &lookup_key);
		if (flow) {
			*key = lookup_key;
			return flow;
		}
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
		*bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	flow = lookup_reply_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!tc_flow_old_bank_enabled_v4())
		return 0;
	flow = lookup_reply_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_TC_FLOW_BANK_OLD;
	return flow;
}

static __always_inline struct flow_value_v6 *lookup_reply_flow_v6_in_bank(__u8 bank, struct flow_key_v6 *key)
{
	struct flow_key_v6 lookup_key = {};
	struct flow_value_v6 *flow;
	__u32 parent_ifindex;

	if (!key)
		return 0;
	lookup_key = *key;
	flow = lookup_flow_v6_in_bank(bank, &lookup_key);
	if (flow) {
		*key = lookup_key;
		return flow;
	}

	parent_ifindex = resolve_parent_ifindex(lookup_key.ifindex);
	if (parent_ifindex == lookup_key.ifindex)
		return 0;

	lookup_key.ifindex = parent_ifindex;
	flow = lookup_flow_v6_in_bank(bank, &lookup_key);
	if (flow)
		*key = lookup_key;
	return flow;
}

static __always_inline struct flow_value_v6 *lookup_reply_flow_v6(struct flow_key_v6 *key, __u8 *bank)
{
	struct flow_value_v6 *flow;

	if (bank)
		*bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	flow = lookup_reply_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, key);
	if (flow)
		return flow;
	if (!tc_flow_old_bank_enabled_v6())
		return 0;
	flow = lookup_reply_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_OLD, key);
	if (flow && bank)
		*bank = FORWARD_TC_FLOW_BANK_OLD;
	return flow;
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

static __always_inline void build_front_flow_key_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, struct flow_key_v6 *key)
{
	key->ifindex = skb->ifindex;
	copy_ipv6_addr(key->src_addr, ctx->src_addr);
	copy_ipv6_addr(key->dst_addr, ctx->dst_addr);
	key->src_port = ctx->src_port;
	key->dst_port = ctx->dst_port;
	key->proto = ctx->proto;
	key->pad[0] = 0;
	key->pad[1] = 0;
	key->pad[2] = 0;
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

static __always_inline void build_nat_port_key_v6(__u32 ifindex, const __u8 nat_addr[16], __u16 nat_port, __u8 proto, struct nat_port_key_v6 *key)
{
	key->ifindex = ifindex;
	copy_ipv6_addr(key->nat_addr, nat_addr);
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

static __always_inline __u32 fullcone_seed(const struct rule_value_v4 *rule, const struct packet_ctx *ctx)
{
	__u32 x = rule->rule_id;

	x ^= bpf_ntohl(ctx->src_addr) * 2654435761U;
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

static __always_inline struct kernel_nat_config_value_v4 *lookup_kernel_nat_config(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&nat_config_v4, &key);
}

static __always_inline __u32 load_kernel_nat_config_flags(void)
{
	struct kernel_nat_config_value_v4 *cfg = lookup_kernel_nat_config();

	if (!cfg)
		return 0;
	return cfg->pad0;
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

static __always_inline __u32 mix_nat_probe_seed(__u32 seed)
{
	seed ^= seed >> 16;
	seed *= 2246822519U;
	seed ^= seed >> 13;
	seed *= 3266489917U;
	seed ^= seed >> 16;
	return seed;
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

static __always_inline int try_reserve_nat_port(__u32 candidate, struct nat_port_key_v4 *nat_key, const struct nat_port_value_v4 *nat_value, __u16 *nat_port)
{
	nat_key->nat_port = (__u16)candidate;
	if (update_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, nat_key, nat_value, BPF_NOEXIST) == 0) {
		*nat_port = (__u16)candidate;
		bump_kernel_nat_occupancy();
		return 0;
	}
	return -1;
}

static __always_inline int try_reserve_nat_port_v6(__u32 candidate, struct nat_port_key_v6 *nat_key, const struct nat_port_value_v6 *nat_value, __u16 *nat_port)
{
	nat_key->nat_port = (__u16)candidate;
	if (update_nat_port_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, nat_key, nat_value, BPF_NOEXIST) == 0) {
		*nat_port = (__u16)candidate;
		bump_kernel_nat_occupancy();
		return 0;
	}
	return -1;
}

static __always_inline int reserve_nat_port_window(const struct nat_probe_window_v4 *window, struct nat_port_key_v4 *nat_key, const struct nat_port_value_v4 *nat_value, __u16 *nat_port)
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < FORWARD_NAT_PORT_PROBE_WINDOW; i++) {
		__u32 candidate = window->port_min + ((window->start + ((__u32)i * window->stride)) % window->port_range);

		if (try_reserve_nat_port(candidate, nat_key, nat_value, nat_port) == 0)
			return 0;
	}

	return -1;
}

static __always_inline int reserve_nat_port(const struct rule_value_v4 *rule, const struct packet_ctx *ctx, struct nat_port_key_v4 *nat_key, __u16 *nat_port)
{
	struct nat_port_value_v4 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u32 seed;
	__u32 round_seed;
	__u32 port_min = 0;
	__u32 port_range = 0;
	struct nat_probe_window_v4 window = {};

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

	seed = mix_nat_probe_seed(fullnat_seed(rule, ctx) ^ ((__u32)ctx->src_port << 16) ^ (__u32)ctx->dst_port ^ ((__u32)rule->out_ifindex << 1));
	round_seed = seed;
	window.port_min = port_min;
	window.port_range = port_range;
	window.start = round_seed % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x9e3779b9U, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;
	round_seed = mix_nat_probe_seed(round_seed ^ 0x9e3779b9U);

	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 1)
		return -1;
	window.start = (round_seed + ((__u32)ctx->src_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x85ebca6bU, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;
	round_seed = mix_nat_probe_seed(round_seed ^ 0x23c2a438U);

	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 2)
		return -1;
	window.start = (round_seed + ((__u32)ctx->dst_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0xc2b2ae35U, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;

	return -1;
}

static __always_inline int reserve_nat_port_fullcone(const struct rule_value_v4 *rule, const struct packet_ctx *ctx, struct nat_port_key_v4 *nat_key, __u16 *nat_port)
{
	struct nat_port_value_v4 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u32 seed;
	__u32 round_seed;
	__u32 port_min = 0;
	__u32 port_range = 0;
	struct nat_probe_window_v4 window = {};

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
	round_seed = seed;
	window.port_min = port_min;
	window.port_range = port_range;
	window.start = round_seed % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x9e3779b9U, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;
	round_seed = mix_nat_probe_seed(round_seed ^ 0x9e3779b9U);

	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 1)
		return -1;
	window.start = (round_seed + ((__u32)ctx->src_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x85ebca6bU, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;
	round_seed = mix_nat_probe_seed(round_seed ^ 0x23c2a438U);

	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 2)
		return -1;
	window.start = (round_seed + ((__u32)ctx->dst_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0xc2b2ae35U, port_range);
	if (reserve_nat_port_window(&window, nat_key, &nat_value, nat_port) == 0)
		return 0;

	return -1;
}

static __always_inline int reserve_nat_port_v6(const struct rule_value_v6 *rule, const struct packet_ctx_v6 *ctx, struct nat_port_key_v6 *nat_key, __u16 *nat_port)
{
	struct nat_port_value_v6 nat_value = {
		.rule_id = rule->rule_id,
	};
	__u32 seed;
	__u32 round_seed;
	__u32 port_min = 0;
	__u32 port_range = 0;
	struct nat_probe_window_v4 window = {};

	nat_key->ifindex = rule->out_ifindex;
	copy_ipv6_addr(nat_key->nat_addr, rule->nat_addr);
	nat_key->proto = ctx->proto;
	nat_key->pad = 0;

	load_nat_port_window(&port_min, &port_range);
	if (port_range == 0)
		return -1;

	if ((__u32)ctx->src_port >= port_min && (__u32)ctx->src_port < (port_min + port_range)) {
		if (try_reserve_nat_port_v6((__u32)ctx->src_port, nat_key, &nat_value, nat_port) == 0)
			return 0;
	}

	seed = mix_nat_probe_seed(fullnat_seed_v6(rule, ctx) ^ ((__u32)ctx->src_port << 16) ^ (__u32)ctx->dst_port ^ ((__u32)rule->out_ifindex << 1));
	round_seed = seed;
	window.port_min = port_min;
	window.port_range = port_range;
	window.start = round_seed % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x9e3779b9U, port_range);

#pragma clang loop unroll(full)
	for (int i = 0; i < FORWARD_NAT_PORT_PROBE_WINDOW; i++) {
		__u32 candidate = window.port_min + ((window.start + ((__u32)i * window.stride)) % window.port_range);

		if (try_reserve_nat_port_v6(candidate, nat_key, &nat_value, nat_port) == 0)
			return 0;
	}

	round_seed = mix_nat_probe_seed(round_seed ^ 0x9e3779b9U);
	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 1)
		return -1;
	window.start = (round_seed + ((__u32)ctx->src_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0x85ebca6bU, port_range);

#pragma clang loop unroll(full)
	for (int i = 0; i < FORWARD_NAT_PORT_PROBE_WINDOW; i++) {
		__u32 candidate = window.port_min + ((window.start + ((__u32)i * window.stride)) % window.port_range);

		if (try_reserve_nat_port_v6(candidate, nat_key, &nat_value, nat_port) == 0)
			return 0;
	}

	round_seed = mix_nat_probe_seed(round_seed ^ 0x23c2a438U);
	if (FORWARD_NAT_PORT_PROBE_ROUNDS <= 2)
		return -1;
	window.start = (round_seed + ((__u32)ctx->dst_port << 1)) % port_range;
	window.stride = nat_probe_stride(round_seed ^ 0xc2b2ae35U, port_range);

#pragma clang loop unroll(full)
	for (int i = 0; i < FORWARD_NAT_PORT_PROBE_WINDOW; i++) {
		__u32 candidate = window.port_min + ((window.start + ((__u32)i * window.stride)) % window.port_range);

		if (try_reserve_nat_port_v6(candidate, nat_key, &nat_value, nat_port) == 0)
			return 0;
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

static __always_inline void delete_fullnat_state(__u8 flow_bank, const struct flow_key_v4 *reply_key, const struct flow_value_v4 *reply_value, __u8 proto)
{
	struct flow_key_v4 front_key = {};
	struct nat_port_key_v4 nat_key = {};

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_TCP)
			drop_rule_tcp_active(reply_value->rule_id);
		else
			drop_rule_datagram_nat(reply_value->rule_id, proto);
	}

	build_front_flow_key_from_value(reply_value, proto, &front_key);
	build_nat_port_key(reply_key->ifindex, reply_value->nat_addr, reply_value->nat_port, proto, &nat_key);
	delete_flow_v4_in_bank(flow_bank, &front_key);
	delete_flow_v4_in_bank(flow_bank, reply_key);
	delete_nat_port_v4_in_bank(flow_bank, &nat_key);
	drop_kernel_flow_occupancy();
	drop_kernel_flow_occupancy();
	drop_kernel_nat_occupancy();
}

static __always_inline void delete_fullnat_state_v6(__u8 flow_bank, const struct flow_key_v6 *reply_key, const struct flow_value_v6 *reply_value, __u8 proto)
{
	struct flow_key_v6 front_key = {};
	struct nat_port_key_v6 nat_key = {};

	if ((reply_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
		if (proto == IPPROTO_TCP)
			drop_rule_tcp_active(reply_value->rule_id);
		else
			drop_rule_datagram_nat(reply_value->rule_id, proto);
	}

	build_front_flow_key_from_value_v6(reply_value, proto, &front_key);
	build_nat_port_key_v6(reply_key->ifindex, reply_value->nat_addr, reply_value->nat_port, proto, &nat_key);
	delete_flow_v6_in_bank(flow_bank, &front_key);
	delete_flow_v6_in_bank(flow_bank, reply_key);
	delete_nat_port_v6_in_bank(flow_bank, &nat_key);
	drop_kernel_flow_occupancy();
	drop_kernel_flow_occupancy();
	drop_kernel_nat_occupancy();
}

static __always_inline void init_fullnat_front_value(struct flow_value_v4 *front_value, const struct rule_value_v4 *rule, const struct packet_ctx *ctx, __u32 in_ifindex, __u16 nat_port)
{
	front_value->rule_id = rule->rule_id;
	front_value->front_addr = bpf_ntohl(ctx->dst_addr);
	front_value->client_addr = bpf_ntohl(ctx->src_addr);
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
}

static __always_inline void init_fullnat_reply_value_v6(struct flow_value_v6 *reply_value, const struct flow_value_v6 *front_value, __u64 now)
{
	*reply_value = *front_value;
	reply_value->flags &= ~FORWARD_FLOW_FLAG_FRONT_ENTRY;
	reply_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
	reply_value->last_seen_ns = now;
}

static __always_inline int is_fullnat_front_flow_v6(const struct flow_value_v6 *flow)
{
	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) == 0)
		return 0;
	if (ipv6_addr_is_zero(flow->nat_addr) || flow->nat_port == 0)
		return 0;
	return 1;
}

static __always_inline int is_fullnat_reply_flow_v6(const struct flow_value_v6 *flow)
{
	if (!flow)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) == 0)
		return 0;
	if ((flow->flags & FORWARD_FLOW_FLAG_FRONT_ENTRY) != 0)
		return 0;
	if (ipv6_addr_is_zero(flow->nat_addr) || flow->nat_port == 0)
		return 0;
	return 1;
}

static __always_inline int handle_transparent_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 *flow_key = lookup_scratch_flow_key_v4();
	struct flow_value_v4 *flow_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *existing_flow;
	struct flow_key_v4 close_key = {};
	__u64 now = 0;
	__u8 update_flow = 0;
	__u8 new_session = 0;
	__u8 count_udp_now = 0;
	int close_complete = 0;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!flow_key || !flow_value)
		return TC_ACT_SHOT;
	__builtin_memset(flow_key, 0, sizeof(*flow_key));
	__builtin_memset(flow_value, 0, sizeof(*flow_value));

	flow_key->ifindex = rule->out_ifindex;
	flow_key->src_addr = rule->backend_addr;
	flow_key->dst_addr = bpf_ntohl(ctx->src_addr);
	flow_key->src_port = rule->backend_port;
	flow_key->dst_port = ctx->src_port;
	flow_key->proto = ctx->proto;

	existing_flow = lookup_flow_v4_active_or_old(flow_key, &flow_bank);
	if (!existing_flow) {
		if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
			return TC_ACT_SHOT;
		now = bpf_ktime_get_ns();
		flow_value->rule_id = rule->rule_id;
		flow_value->front_addr = bpf_ntohl(ctx->dst_addr);
		flow_value->front_port = ctx->dst_port;
		flow_value->in_ifindex = skb->ifindex;
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			flow_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (is_datagram_proto(ctx->proto)) {
			flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (ctx->closing) {
			flow_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			flow_value->front_close_seen_ns = now;
		}
		flow_value->last_seen_ns = now;
		update_flow = 1;
		new_session = 1;
	} else if (is_datagram_proto(ctx->proto)) {
		now = bpf_ktime_get_ns();
		if (existing_flow->last_seen_ns == 0 || now < existing_flow->last_seen_ns || (now - existing_flow->last_seen_ns) > FORWARD_DATAGRAM_FLOW_IDLE_NS(ctx->proto)) {
			flow_value->rule_id = rule->rule_id;
			flow_value->front_addr = bpf_ntohl(ctx->dst_addr);
			flow_value->front_port = ctx->dst_port;
			flow_value->in_ifindex = skb->ifindex;
			if (FORWARD_FLOW_TRAFFIC_ENABLED(existing_flow) || FORWARD_RULE_TRAFFIC_ENABLED(rule))
				flow_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
			if ((existing_flow->flags & FORWARD_FLOW_FLAG_COUNTED) != 0) {
				flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			} else {
				flow_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			flow_value->last_seen_ns = now;
			update_flow = 1;
			new_session = 1;
		} else if ((now - existing_flow->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
			*flow_value = *existing_flow;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
	} else {
		now = bpf_ktime_get_ns();
		if (ctx->closing) {
			*flow_value = *existing_flow;
			flow_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			if (flow_value->front_close_seen_ns == 0)
				flow_value->front_close_seen_ns = now;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		} else if ((existing_flow->flags & FORWARD_FLOW_FLAG_FRONT_CLOSING) != 0 && ctx->tcp_flags == FORWARD_TCP_FLAG_ACK) {
			close_key = *flow_key;
			close_complete = 1;
		} else if (existing_flow->last_seen_ns == 0 || now < existing_flow->last_seen_ns || (now - existing_flow->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			*flow_value = *existing_flow;
			flow_value->last_seen_ns = now;
			update_flow = 1;
		}
	}

	if (update_flow) {
		if (existing_flow) {
			*existing_flow = *flow_value;
		} else if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, flow_key, flow_value, BPF_ANY) < 0) {
			return TC_ACT_SHOT;
		}
		if (new_session)
			bump_kernel_flow_occupancy();
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);
	update_reply_l2_cache_v4(skb, flow_key, nat_cfg_flags);

	if (rewrite_l4_dnat(skb, ctx, rule->backend_addr, rule->backend_port) < 0)
		return TC_ACT_SHOT;

	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0) {
		int action = redirect_prepared_l2_ifindex(skb, rule);

		if (close_complete && action == TC_ACT_REDIRECT && delete_flow_v4_in_bank(flow_bank, flow_key) == 0)
			drop_kernel_flow_occupancy();
		return action;
	}
	flow_key->ifindex = rule->out_ifindex;
	flow_key->src_addr = bpf_ntohl(ctx->src_addr);
	flow_key->dst_addr = rule->backend_addr;
	flow_key->src_port = ctx->src_port;
	flow_key->dst_port = rule->backend_port;
	{
		int action = redirect_ifindex(skb, ctx, (const struct redirect_target_v4 *)flow_key, nat_cfg_flags);

		if (close_complete && action == TC_ACT_REDIRECT && delete_flow_v4_in_bank(flow_bank, &close_key) == 0)
			drop_kernel_flow_occupancy();
		return action;
	}
}

static __always_inline int redirect_fullnat_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_value_v4 *front_value)
{
	struct redirect_target_v4 redirect = {
		.ifindex = rule->out_ifindex,
		.src_addr = front_value->nat_addr,
		.dst_addr = rule->backend_addr,
		.src_port = front_value->nat_port,
		.dst_port = rule->backend_port,
	};

	if (rewrite_l4_snat(skb, ctx, front_value->nat_addr, front_value->nat_port) < 0) {
		return TC_ACT_SHOT;
	}
	if (rewrite_l4_dnat(skb, ctx, rule->backend_addr, rule->backend_port) < 0) {
		return TC_ACT_SHOT;
	}
	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0)
		return redirect_prepared_l2_ifindex(skb, rule);
	return redirect_ifindex(skb, ctx, &redirect, load_kernel_nat_config_flags());
}

static __always_inline int handle_fullnat_forward_existing(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, struct flow_value_v4 *existing_front, __u8 flow_bank)
{
	struct flow_key_v4 front_key = {};
	struct flow_key_v4 reply_key = {};
	struct nat_port_key_v4 nat_key = {};
	struct flow_value_v4 *front_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *reply_value = lookup_scratch_flow_aux_v4();
	struct flow_value_v4 *reply_flow = 0;
	struct nat_port_value_v4 nat_value = {};
	__u64 now = bpf_ktime_get_ns();
	__u8 created_reply = 0;
	__u8 update_front = 0;
	__u8 update_reply = 0;
	__u8 count_udp_now = 0;
	__u8 bank = flow_bank & FORWARD_TC_FLOW_BANK_MASK;
	int front_live = (flow_bank & FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT) == 0;

	if (!front_value || !reply_value || !existing_front)
		return TC_ACT_SHOT;
	*front_value = *existing_front;
	__builtin_memset(reply_value, 0, sizeof(*reply_value));
	if (front_value->nat_addr == 0)
		front_value->nat_addr = rule->nat_addr;
	build_front_flow_key_from_value(front_value, ctx->proto, &front_key);

	build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
	reply_flow = lookup_flow_v4_in_bank(bank, &reply_key);
	if (is_fullnat_reply_flow(reply_flow)) {
		*reply_value = *reply_flow;
	} else {
		init_fullnat_reply_value(reply_value, front_value, now);
		if (is_datagram_proto(ctx->proto)) {
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (update_flow_v4_in_bank(bank, &reply_key, reply_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
		created_reply = 1;
		bump_kernel_flow_occupancy();
	}

	build_nat_port_key(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &nat_key);
	nat_value.rule_id = rule->rule_id;
	if (update_nat_port_v4_in_bank(bank, &nat_key, &nat_value, BPF_NOEXIST) == 0)
		bump_kernel_nat_occupancy();

	if (is_datagram_proto(ctx->proto)) {
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
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
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front || created_reply) {
		if (front_live && !created_reply) {
			*existing_front = *front_value;
		} else if (update_flow_v4_in_bank(bank, &front_key, front_value, BPF_ANY) < 0) {
			if (created_reply) {
				delete_flow_v4_in_bank(bank, &reply_key);
				drop_kernel_flow_occupancy();
			}
			return TC_ACT_SHOT;
		}
	}
	if (update_reply) {
		if (reply_flow) {
			*reply_flow = *reply_value;
		} else if (update_flow_v4_in_bank(bank, &reply_key, reply_value, BPF_ANY) < 0) {
			return TC_ACT_SHOT;
		}
	}
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);
	update_reply_l2_cache_v4(skb, &reply_key, load_kernel_nat_config_flags());
	return redirect_fullnat_forward(skb, ctx, rule, front_value);
}

static __always_inline int handle_fullnat_forward_new(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_key_v4 *front_key)
{
	struct flow_key_v4 front_key_local = {};
	struct flow_key_v4 reply_key = {};
	struct nat_port_key_v4 nat_key = {};
	struct flow_value_v4 *front_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *reply_value = lookup_scratch_flow_aux_v4();
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	__u8 created_front = 0;
	__u8 count_udp_now = 0;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;

	if (!front_value || !reply_value || !front_key)
		return TC_ACT_SHOT;
	if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
		return TC_ACT_SHOT;
	front_key_local = *front_key;
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	if (reserve_nat_port(rule, ctx, &nat_key, &nat_port) < 0) {
		return TC_ACT_SHOT;
	}

	init_fullnat_front_value(front_value, rule, ctx, skb->ifindex, nat_port);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
	if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		front_value->front_close_seen_ns = now;
	}
	front_value->last_seen_ns = now;
	if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &front_key_local, front_value, BPF_NOEXIST) < 0) {
		delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();

		front_flow = lookup_flow_v4_active_or_old(&front_key_local, &flow_bank);
		if (!is_fullnat_front_flow(front_flow))
			return TC_ACT_SHOT;
		return handle_fullnat_forward_existing(skb, ctx, rule, front_flow, flow_bank);
	}
	created_front = 1;
	bump_kernel_flow_occupancy();

	build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
	init_fullnat_reply_value(reply_value, front_value, now);
	if (is_datagram_proto(ctx->proto)) {
		reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
		count_udp_now = 1;
	}
	if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_key, reply_value, BPF_ANY) < 0) {
		if (created_front) {
			delete_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &front_key_local);
			drop_kernel_flow_occupancy();
		}
		delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();
		return TC_ACT_SHOT;
	}
	bump_kernel_flow_occupancy();
	bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);
	update_reply_l2_cache_v4(skb, &reply_key, load_kernel_nat_config_flags());
	return redirect_fullnat_forward(skb, ctx, rule, front_value);
}

static __always_inline int handle_fullnat_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 *front_flow;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;

	if (!ctx || !rule)
		return TC_ACT_SHOT;
	build_front_flow_key(skb, ctx, &front_key);
	front_flow = lookup_flow_v4_active_or_old(&front_key, &flow_bank);
	if (is_fullnat_front_flow(front_flow))
		return handle_fullnat_forward_existing(skb, ctx, rule, front_flow, flow_bank);
	return handle_fullnat_forward_new(skb, ctx, rule, &front_key);
}

static __always_inline int redirect_egress_nat_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_value_v4 *front_value, __u32 nat_cfg_flags)
{
	struct redirect_target_v4 redirect = {};

	if (rewrite_l4_snat(skb, ctx, front_value->nat_addr, front_value->nat_port) < 0)
		return TC_ACT_SHOT;

	redirect.ifindex = rule->out_ifindex;
	redirect.src_addr = front_value->nat_addr;
	redirect.dst_addr = front_value->front_addr;
	redirect.src_port = front_value->nat_port;
	redirect.dst_port = front_value->front_port;
	return redirect_ifindex(skb, ctx, &redirect, nat_cfg_flags);
}

static __always_inline int handle_egress_nat_forward_existing(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, struct flow_value_v4 *front_flow, __u8 flow_bank)
{
	struct flow_key_v4 front_key = {};
	struct flow_key_v4 reply_key = {};
	struct flow_value_v4 *front_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *reply_value = lookup_scratch_flow_aux_v4();
	struct flow_value_v4 *reply_flow = 0;
	struct nat_port_value_v4 nat_value = {};
	__u64 now = bpf_ktime_get_ns();
	__u8 created_reply = 0;
	__u8 update_front = 0;
	__u8 update_reply = 0;
	__u8 count_udp_now = 0;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!front_value || !reply_value || !front_flow)
		return TC_ACT_SHOT;
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	*front_value = *front_flow;
	if (front_value->nat_addr == 0)
		front_value->nat_addr = rule->nat_addr;

	build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
	reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_key);
	if (is_fullnat_reply_flow(reply_flow)) {
		*reply_value = *reply_flow;
	} else {
		init_fullnat_reply_value(reply_value, front_value, now);
		if (is_datagram_proto(ctx->proto)) {
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0)
			return TC_ACT_SHOT;
		created_reply = 1;
		bump_kernel_flow_occupancy();
	}

	if (is_datagram_proto(ctx->proto)) {
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_UDP_FLOW_REFRESH_NS) {
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
		if (front_value->last_seen_ns == 0 || now < front_value->last_seen_ns || (now - front_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS) {
			front_value->last_seen_ns = now;
			update_front = 1;
		}
		if (!created_reply && (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) >= FORWARD_TCP_FLOW_REFRESH_NS)) {
			reply_value->last_seen_ns = now;
			update_reply = 1;
		}
	}

	if (update_front) {
		if (!created_reply && front_flow) {
			*front_flow = *front_value;
		} else {
			build_front_flow_key(skb, ctx, &front_key);
			if (update_flow_v4_in_bank(flow_bank, &front_key, front_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (update_reply) {
		if (!created_reply && reply_flow) {
			*reply_flow = *reply_value;
		} else {
			if (update_flow_v4_in_bank(flow_bank, &reply_key, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (created_reply || update_front || update_reply) {
		struct nat_port_key_v4 nat_key = {};

		build_nat_port_key(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &nat_key);
		nat_value.rule_id = rule->rule_id;
		if (update_nat_port_v4_in_bank(flow_bank, &nat_key, &nat_value, BPF_NOEXIST) == 0)
			bump_kernel_nat_occupancy();
	}
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);
	update_reply_l2_cache_v4(skb, &reply_key, nat_cfg_flags);

	return redirect_egress_nat_forward(skb, ctx, rule, front_value, nat_cfg_flags);
}

static __always_inline int handle_egress_nat_forward_new(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule, const struct flow_key_v4 *front_key)
{
	struct flow_key_v4 reply_key = {};
	struct nat_port_key_v4 nat_key = {};
	struct flow_value_v4 *front_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *reply_value = lookup_scratch_flow_aux_v4();
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	__u8 created_front = 0;
	__u8 count_udp_now = 0;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!front_value || !reply_value || !front_key)
		return TC_ACT_SHOT;
	if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn(ctx))
		return TC_ACT_SHOT;
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	if (reserve_nat_port(rule, ctx, &nat_key, &nat_port) < 0)
		return TC_ACT_SHOT;

	init_fullnat_front_value(front_value, rule, ctx, (__u32)skb->ifindex, nat_port);
	front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT;
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
	if (ctx->closing) {
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
		front_value->front_close_seen_ns = now;
	}
	front_value->last_seen_ns = now;
	if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, front_key, front_value, BPF_NOEXIST) < 0) {
		delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();

		front_flow = lookup_flow_v4_active_or_old(front_key, &flow_bank);
		if (front_flow && !is_egress_nat_flow(front_flow))
			return TC_ACT_OK;
		if (!is_fullnat_front_flow(front_flow))
			return TC_ACT_SHOT;
		return handle_egress_nat_forward_existing(skb, ctx, rule, front_flow, flow_bank);
	}
	created_front = 1;
	bump_kernel_flow_occupancy();

	build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_key);
	init_fullnat_reply_value(reply_value, front_value, now);
	if (is_datagram_proto(ctx->proto)) {
		reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
		count_udp_now = 1;
	}
	if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_key, reply_value, BPF_ANY) < 0) {
		if (created_front) {
			delete_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, front_key);
			drop_kernel_flow_occupancy();
		}
		delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &nat_key);
		drop_kernel_nat_occupancy();
		return TC_ACT_SHOT;
	}
	bump_kernel_flow_occupancy();
	bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);
	update_reply_l2_cache_v4(skb, &reply_key, nat_cfg_flags);
	return redirect_egress_nat_forward(skb, ctx, rule, front_value, nat_cfg_flags);
}

static __always_inline int handle_egress_nat_forward_non_full_cone(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 *front_flow;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;

	if (!ctx || !rule)
		return TC_ACT_SHOT;
	build_front_flow_key(skb, ctx, &front_key);
	front_flow = lookup_flow_v4_active_or_old(&front_key, &flow_bank);
	if (front_flow && !is_egress_nat_flow(front_flow))
		return TC_ACT_OK;
	if (is_fullnat_front_flow(front_flow))
		return handle_egress_nat_forward_existing(skb, ctx, rule, front_flow, flow_bank);
	return handle_egress_nat_forward_new(skb, ctx, rule, &front_key);
}

static __always_inline int handle_egress_nat_forward_full_cone(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	union flow_nat_key_v4 reply_or_nat = {};
	struct flow_value_v4 *front_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *reply_value = lookup_scratch_flow_aux_v4();
	struct flow_value_v4 *front_flow;
	struct flow_value_v4 *reply_flow = 0;
	struct nat_port_value_v4 nat_value = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	__u8 created_front = 0;
	__u8 created_reply = 0;
	__u8 update_front = 0;
	__u8 update_reply = 0;
	__u8 new_session = 0;
	__u8 count_udp_now = 0;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!front_value || !reply_value)
		return TC_ACT_SHOT;
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	build_full_cone_front_flow_key(skb, ctx, &reply_or_nat.flow);
	front_flow = lookup_flow_v4_active_or_old(&reply_or_nat.flow, &flow_bank);
	if (front_flow && !is_egress_nat_flow(front_flow))
		return TC_ACT_OK;
	if (is_full_cone_front_flow(front_flow)) {
		*front_value = *front_flow;
		if (front_value->nat_addr == 0)
			front_value->nat_addr = rule->nat_addr;

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
		reply_flow = lookup_flow_v4_in_bank(flow_bank, &reply_or_nat.flow);
		if (is_full_cone_reply_flow(reply_flow)) {
			*reply_value = *reply_flow;
		} else {
			init_fullnat_reply_value(reply_value, front_value, now);
			if (is_datagram_proto(ctx->proto)) {
				reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
			created_reply = 1;
			bump_kernel_flow_occupancy();
		}
	} else {
		if (reserve_nat_port_fullcone(rule, ctx, &reply_or_nat.nat, &nat_port) < 0)
			return TC_ACT_SHOT;

		init_fullnat_front_value(front_value, rule, ctx, (__u32)skb->ifindex, nat_port);
		front_value->front_addr = 0;
		front_value->front_port = 0;
		front_value->flags |= FORWARD_FLOW_FLAG_EGRESS_NAT | FORWARD_FLOW_FLAG_FULL_CONE;
		if (FORWARD_RULE_TRAFFIC_ENABLED(rule))
			front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value->front_close_seen_ns = now;
		}
		front_value->last_seen_ns = now;
		if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow, front_value, BPF_NOEXIST) < 0) {
			delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.nat);
			drop_kernel_nat_occupancy();

			build_full_cone_front_flow_key(skb, ctx, &reply_or_nat.flow);
			front_flow = lookup_flow_v4_active_or_old(&reply_or_nat.flow, &flow_bank);
			if (front_flow && !is_egress_nat_flow(front_flow))
				return TC_ACT_OK;
			if (!is_full_cone_front_flow(front_flow))
				return TC_ACT_SHOT;
			*front_value = *front_flow;
			if (front_value->nat_addr == 0)
				front_value->nat_addr = rule->nat_addr;
		} else {
			created_front = 1;
			new_session = 1;
			bump_kernel_flow_occupancy();
		}

		build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
		init_fullnat_reply_value(reply_value, front_value, now);
		if (is_datagram_proto(ctx->proto)) {
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (update_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow, reply_value, BPF_ANY) < 0) {
			if (created_front) {
				build_full_cone_front_flow_key(skb, ctx, &reply_or_nat.flow);
				delete_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow);
				drop_kernel_flow_occupancy();
			}
			build_nat_port_key(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &reply_or_nat.nat);
			delete_nat_port_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.nat);
			drop_kernel_nat_occupancy();
			return TC_ACT_SHOT;
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
		if (!created_front && !created_reply && front_flow) {
			*front_flow = *front_value;
		} else {
			build_full_cone_front_flow_key(skb, ctx, &reply_or_nat.flow);
			if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, front_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (update_reply) {
		if (!created_front && !created_reply && reply_flow) {
			*reply_flow = *reply_value;
		} else {
			build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
			if (update_flow_v4_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (!created_front && (created_reply || update_front || update_reply)) {
		build_nat_port_key(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &reply_or_nat.nat);
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
	build_reply_flow_key_from_front(rule, front_value, ctx->proto, &reply_or_nat.flow);
	update_reply_l2_cache_v4(skb, &reply_or_nat.flow, nat_cfg_flags);

	if (rewrite_l4_snat(skb, ctx, front_value->nat_addr, front_value->nat_port) < 0)
		return TC_ACT_SHOT;

	reply_or_nat.flow.ifindex = rule->out_ifindex;
	reply_or_nat.flow.src_addr = front_value->nat_addr;
	reply_or_nat.flow.src_port = front_value->nat_port;
	reply_or_nat.flow.dst_addr = bpf_ntohl(ctx->dst_addr);
	reply_or_nat.flow.dst_port = ctx->dst_port;
	return redirect_ifindex(skb, ctx, (const struct redirect_target_v4 *)&reply_or_nat.flow, nat_cfg_flags);
}

static __always_inline int handle_egress_nat_forward(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct rule_value_v4 *rule)
{
	if (is_full_cone_egress_nat_rule(rule))
		return handle_egress_nat_forward_full_cone(skb, ctx, rule);
	return handle_egress_nat_forward_non_full_cone(skb, ctx, rule);
}

static __always_inline __u32 resolve_reply_redirect_ifindex(const struct flow_value_v4 *reply_value)
{
	if (!reply_value)
		return 0;
	if ((reply_value->flags & FORWARD_FLOW_FLAG_EGRESS_NAT) != 0)
		return resolve_parent_ifindex(reply_value->in_ifindex);
	return reply_value->in_ifindex;
}

static __always_inline int handle_transparent_reply(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct flow_key_v4 *flow_key, struct flow_value_v4 *flow, __u8 flow_bank)
{
	struct flow_value_v4 *flow_value = lookup_scratch_flow_v4();
	struct redirect_target_v4 redirect = {};
	__u64 now = 0;
	int update_flow = 0;
	int count_tcp_now = 0;
	__u8 bank = flow_bank & FORWARD_TC_FLOW_BANK_MASK;
	int flow_live = (flow_bank & FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT) == 0;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!flow_value)
		return TC_ACT_SHOT;
	*flow_value = *flow;

	if (is_datagram_proto(ctx->proto)) {
		now = bpf_ktime_get_ns();
		if (flow_value->last_seen_ns == 0 || now < flow_value->last_seen_ns || (now - flow_value->last_seen_ns) > FORWARD_DATAGRAM_FLOW_IDLE_NS(ctx->proto)) {
			if ((flow_value->flags & FORWARD_FLOW_FLAG_COUNTED) != 0)
				drop_rule_datagram_nat(flow_value->rule_id, ctx->proto);
			delete_flow_v4_in_bank(bank, flow_key);
			drop_kernel_flow_occupancy();
			return TC_ACT_OK;
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
		if (flow_live) {
			*flow = *flow_value;
		} else if (update_flow_v4_in_bank(bank, flow_key, flow_value, BPF_ANY) < 0) {
			return TC_ACT_SHOT;
		}
	}
	if (count_tcp_now)
		bump_rule_tcp_active(flow_value->rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(flow_value))
		add_rule_traffic_bytes(flow_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	if (rewrite_l4_snat(skb, ctx, flow_value->front_addr, flow_value->front_port) < 0)
		return TC_ACT_SHOT;

	redirect.ifindex = resolve_reply_redirect_ifindex(flow_value);
	{
		int action = redirect_reply_l2_cache_v4(skb, flow_key, redirect.ifindex, nat_cfg_flags);

		if (action == TC_ACT_REDIRECT)
			return action;
	}

	redirect.src_addr = flow_value->front_addr;
	redirect.dst_addr = bpf_ntohl(ctx->dst_addr);
	redirect.src_port = flow_value->front_port;
	redirect.dst_port = ctx->dst_port;
	return redirect_ifindex(skb, ctx, &redirect, nat_cfg_flags);
}

static __always_inline int handle_fullnat_reply(struct __sk_buff *skb, const struct packet_ctx *ctx, const struct flow_key_v4 *reply_key, struct flow_value_v4 *flow, __u8 flow_bank)
{
	struct flow_key_v4 front_key = {};
	struct flow_value_v4 *reply_value = lookup_scratch_flow_v4();
	struct flow_value_v4 *front_value = lookup_scratch_flow_aux_v4();
	struct redirect_target_v4 redirect = {};
	struct flow_value_v4 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int full_cone = is_full_cone_flow(flow);
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;
	int recreated_front = 0;
	__u8 bank = flow_bank & FORWARD_TC_FLOW_BANK_MASK;
	int flow_live = (flow_bank & FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT) == 0;
	__u32 nat_cfg_flags = load_kernel_nat_config_flags();

	if (!reply_value || !front_value)
		return TC_ACT_SHOT;
	*reply_value = *flow;
	__builtin_memset(front_value, 0, sizeof(*front_value));

	if (is_datagram_proto(ctx->proto)) {
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) > FORWARD_DATAGRAM_FLOW_IDLE_NS(ctx->proto)) {
			delete_fullnat_state(bank, reply_key, reply_value, ctx->proto);
			return TC_ACT_OK;
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
	front_flow = lookup_flow_v4_in_bank(bank, &front_key);
	if (full_cone ? is_full_cone_front_flow(front_flow) : is_fullnat_front_flow(front_flow)) {
		*front_value = *front_flow;
	} else {
		*front_value = *reply_value;
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_ENTRY;
		front_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
		if (full_cone)
			front_value->flags |= FORWARD_FLOW_FLAG_FULL_CONE;
		update_front = 1;
		recreated_front = 1;
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
		if (recreated_front || !front_flow) {
			if (update_flow_v4_in_bank(bank, &front_key, front_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		} else {
			*front_flow = *front_value;
		}
		if (recreated_front)
			bump_kernel_flow_occupancy();
	}
	if (update_reply) {
		if (recreated_front || !flow_live) {
			if (update_flow_v4_in_bank(bank, reply_key, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		} else {
			*flow = *reply_value;
		}
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value->rule_id);
	if (FORWARD_FLOW_TRAFFIC_ENABLED(reply_value))
		add_rule_traffic_bytes(reply_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	if (!full_cone) {
		if (rewrite_l4_snat(skb, ctx, reply_value->front_addr, reply_value->front_port) < 0)
			return TC_ACT_SHOT;
	}
	if (rewrite_l4_dnat(skb, ctx, reply_value->client_addr, reply_value->client_port) < 0)
		return TC_ACT_SHOT;

	if (ctx->closing) {
		delete_fullnat_state(bank, reply_key, reply_value, ctx->proto);
	}

	redirect.ifindex = resolve_reply_redirect_ifindex(reply_value);
	{
		int action = redirect_reply_l2_cache_v4(skb, reply_key, redirect.ifindex, nat_cfg_flags);

		if (action == TC_ACT_REDIRECT)
			return action;
	}
	redirect.dst_addr = reply_value->client_addr;
	redirect.dst_port = reply_value->client_port;
	if (full_cone) {
		redirect.src_addr = bpf_ntohl(ctx->src_addr);
		redirect.src_port = ctx->src_port;
	} else {
		redirect.src_addr = reply_value->front_addr;
		redirect.src_port = reply_value->front_port;
	}
	return redirect_ifindex(skb, ctx, &redirect, nat_cfg_flags);
}

static __always_inline int handle_fullnat_forward_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const struct rule_value_v6 *rule)
{
	union flow_nat_key_v6 reply_or_nat = {};
	struct flow_value_v6 *front_value = lookup_scratch_flow_v6();
	struct flow_value_v6 *reply_value = lookup_scratch_flow_aux_v6();
	struct flow_value_v6 *front_flow;
	struct flow_value_v6 *reply_flow = 0;
	struct nat_port_value_v6 nat_value = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 nat_port = 0;
	__u8 created_front = 0;
	__u8 created_reply = 0;
	__u8 update_front = 0;
	__u8 update_reply = 0;
	__u8 new_session = 0;
	__u8 count_udp_now = 0;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;

	if (!front_value || !reply_value)
		return TC_ACT_SHOT;
	__builtin_memset(front_value, 0, sizeof(*front_value));
	__builtin_memset(reply_value, 0, sizeof(*reply_value));

	build_front_flow_key_v6(skb, ctx, &reply_or_nat.flow);
	front_flow = lookup_flow_v6_active_or_old(&reply_or_nat.flow, &flow_bank);
	if (is_fullnat_front_flow_v6(front_flow)) {
		*front_value = *front_flow;
		if (ipv6_addr_is_zero(front_value->nat_addr))
			copy_ipv6_addr(front_value->nat_addr, rule->nat_addr);

		build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, &reply_or_nat.flow);
		reply_flow = lookup_flow_v6_in_bank(flow_bank, &reply_or_nat.flow);
		if (is_fullnat_reply_flow_v6(reply_flow)) {
			*reply_value = *reply_flow;
		} else {
			init_fullnat_reply_value_v6(reply_value, front_value, now);
			if (is_datagram_proto(ctx->proto)) {
				reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
				count_udp_now = 1;
			}
			if (update_flow_v6_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
			created_reply = 1;
			bump_kernel_flow_occupancy();
		}

		build_nat_port_key_v6(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &reply_or_nat.nat);
		nat_value.rule_id = rule->rule_id;
		if (update_nat_port_v6_in_bank(flow_bank, &reply_or_nat.nat, &nat_value, BPF_NOEXIST) == 0)
			bump_kernel_nat_occupancy();
	} else {
		if (ctx->proto == IPPROTO_TCP && !is_initial_tcp_syn_v6(ctx))
			return TC_ACT_SHOT;
		if (reserve_nat_port_v6(rule, ctx, &reply_or_nat.nat, &nat_port) < 0)
			return TC_ACT_SHOT;

		init_fullnat_front_value_v6(front_value, rule, ctx, (__u32)skb->ifindex, nat_port);
		if ((rule->flags & FORWARD_RULE_FLAG_TRAFFIC_STATS) != 0)
			front_value->flags |= FORWARD_FLOW_FLAG_TRAFFIC_STATS;
		if (ctx->closing) {
			front_value->flags |= FORWARD_FLOW_FLAG_FRONT_CLOSING;
			front_value->front_close_seen_ns = now;
		}
		front_value->last_seen_ns = now;
		if (update_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow, front_value, BPF_NOEXIST) < 0) {
			delete_nat_port_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.nat);
			drop_kernel_nat_occupancy();

			build_front_flow_key_v6(skb, ctx, &reply_or_nat.flow);
			front_flow = lookup_flow_v6_active_or_old(&reply_or_nat.flow, &flow_bank);
			if (!is_fullnat_front_flow_v6(front_flow))
				return TC_ACT_SHOT;
			*front_value = *front_flow;
			if (ipv6_addr_is_zero(front_value->nat_addr))
				copy_ipv6_addr(front_value->nat_addr, rule->nat_addr);
		} else {
			created_front = 1;
			new_session = 1;
			bump_kernel_flow_occupancy();
		}

		build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, &reply_or_nat.flow);
		init_fullnat_reply_value_v6(reply_value, front_value, now);
		if (is_datagram_proto(ctx->proto)) {
			reply_value->flags |= FORWARD_FLOW_FLAG_COUNTED;
			count_udp_now = 1;
		}
		if (update_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow, reply_value, BPF_ANY) < 0) {
			if (created_front) {
				build_front_flow_key_v6(skb, ctx, &reply_or_nat.flow);
				delete_flow_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.flow);
				drop_kernel_flow_occupancy();
			}
			build_nat_port_key_v6(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &reply_or_nat.nat);
			delete_nat_port_v6_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &reply_or_nat.nat);
			drop_kernel_nat_occupancy();
			return TC_ACT_SHOT;
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
		if (!created_front && !created_reply && front_flow) {
			*front_flow = *front_value;
		} else {
			build_front_flow_key_v6(skb, ctx, &reply_or_nat.flow);
			if (update_flow_v6_in_bank(flow_bank, &reply_or_nat.flow, front_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (update_reply) {
		if (!created_front && !created_reply && reply_flow) {
			*reply_flow = *reply_value;
		} else {
			build_reply_flow_key_from_front_v6(rule, front_value, ctx->proto, &reply_or_nat.flow);
			if (update_flow_v6_in_bank(flow_bank, &reply_or_nat.flow, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		}
	}
	if (!created_front && (created_reply || update_front || update_reply)) {
		build_nat_port_key_v6(rule->out_ifindex, front_value->nat_addr, front_value->nat_port, ctx->proto, &reply_or_nat.nat);
		nat_value.rule_id = rule->rule_id;
		if (update_nat_port_v6_in_bank(flow_bank, &reply_or_nat.nat, &nat_value, BPF_NOEXIST) == 0)
			bump_kernel_nat_occupancy();
	}
	if (new_session)
		bump_rule_total_conns(rule->rule_id);
	if (count_udp_now)
		bump_rule_datagram_nat(rule->rule_id, ctx->proto);
	if ((rule->flags & FORWARD_RULE_FLAG_TRAFFIC_STATS) != 0)
		add_rule_traffic_bytes(rule->rule_id, FORWARD_GET_PAYLOAD_LEN(ctx), 0);

	if (rewrite_l4_snat_v6(skb, ctx, front_value->nat_addr, front_value->nat_port) < 0)
		return TC_ACT_SHOT;
	if (rewrite_l4_dnat_v6(skb, ctx, rule->backend_addr, rule->backend_port) < 0)
		return TC_ACT_SHOT;

	if ((rule->flags & (FORWARD_RULE_FLAG_BRIDGE_L2 | FORWARD_RULE_FLAG_PREPARED_L2)) != 0)
		return redirect_prepared_l2_ifindex_v6(skb, rule);
	reply_or_nat.flow.ifindex = rule->out_ifindex;
	copy_ipv6_addr(reply_or_nat.flow.src_addr, front_value->nat_addr);
	copy_ipv6_addr(reply_or_nat.flow.dst_addr, rule->backend_addr);
	reply_or_nat.flow.src_port = front_value->nat_port;
	reply_or_nat.flow.dst_port = rule->backend_port;
	return redirect_ifindex_v6(skb, ctx, (const struct redirect_target_v6 *)&reply_or_nat.flow);
}

static __always_inline int handle_fullnat_reply_v6(struct __sk_buff *skb, const struct packet_ctx_v6 *ctx, const struct flow_key_v6 *reply_key, struct flow_value_v6 *flow, __u8 flow_bank)
{
	struct flow_key_v6 front_key = {};
	struct flow_value_v6 *reply_value = lookup_scratch_flow_v6();
	struct flow_value_v6 *front_value = lookup_scratch_flow_aux_v6();
	struct flow_value_v6 *front_flow;
	__u64 now = bpf_ktime_get_ns();
	int update_front = 0;
	int update_reply = 0;
	int count_tcp_now = 0;
	int recreated_front = 0;

	if (!reply_value || !front_value)
		return TC_ACT_SHOT;
	__builtin_memset(reply_value, 0, sizeof(*reply_value));
	__builtin_memset(front_value, 0, sizeof(*front_value));
	*reply_value = *flow;

	if (is_datagram_proto(ctx->proto)) {
		if (reply_value->last_seen_ns == 0 || now < reply_value->last_seen_ns || (now - reply_value->last_seen_ns) > FORWARD_DATAGRAM_FLOW_IDLE_NS(ctx->proto)) {
			delete_fullnat_state_v6(flow_bank, reply_key, reply_value, ctx->proto);
			return TC_ACT_OK;
		}
	}

	build_front_flow_key_from_value_v6(reply_value, ctx->proto, &front_key);
	front_flow = lookup_flow_v6_in_bank(flow_bank, &front_key);
	if (is_fullnat_front_flow_v6(front_flow)) {
		*front_value = *front_flow;
	} else {
		*front_value = *reply_value;
		front_value->flags |= FORWARD_FLOW_FLAG_FRONT_ENTRY;
		front_value->flags |= FORWARD_FLOW_FLAG_FULL_NAT;
		update_front = 1;
		recreated_front = 1;
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
		if (recreated_front || !front_flow) {
			if (update_flow_v6_in_bank(flow_bank, &front_key, front_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		} else {
			*front_flow = *front_value;
		}
		if (recreated_front)
			bump_kernel_flow_occupancy();
	}
	if (update_reply) {
		if (recreated_front) {
			if (update_flow_v6_in_bank(flow_bank, reply_key, reply_value, BPF_ANY) < 0)
				return TC_ACT_SHOT;
		} else {
			*flow = *reply_value;
		}
	}
	if (count_tcp_now)
		bump_rule_tcp_active(reply_value->rule_id);
	if ((reply_value->flags & FORWARD_FLOW_FLAG_TRAFFIC_STATS) != 0)
		add_rule_traffic_bytes(reply_value->rule_id, 0, FORWARD_GET_PAYLOAD_LEN(ctx));

	if (rewrite_l4_snat_v6(skb, ctx, reply_value->front_addr, reply_value->front_port) < 0)
		return TC_ACT_SHOT;
	if (rewrite_l4_dnat_v6(skb, ctx, reply_value->client_addr, reply_value->client_port) < 0)
		return TC_ACT_SHOT;

	if (ctx->closing)
		delete_fullnat_state_v6(flow_bank, reply_key, reply_value, ctx->proto);

	front_key.ifindex = reply_value->in_ifindex;
	copy_ipv6_addr(front_key.src_addr, reply_value->front_addr);
	copy_ipv6_addr(front_key.dst_addr, reply_value->client_addr);
	front_key.src_port = reply_value->front_port;
	front_key.dst_port = reply_value->client_port;
	return redirect_ifindex_v6(skb, ctx, (const struct redirect_target_v6 *)&front_key);
}

static __always_inline int handle_forward_ingress_v4(struct __sk_buff *skb)
{
	struct packet_ctx *ctx = lookup_scratch_ctx_v4();
	struct rule_value_v4 *rule;

	/* Non-matches must fall through so sibling family filters can run. */
	if (!ctx)
		return TC_ACT_UNSPEC;
	__builtin_memset(ctx, 0, sizeof(*ctx));

	if (parse_ipv4_l4(skb, ctx) < 0) {
		return TC_ACT_UNSPEC;
	}

	rule = lookup_rule_v4(skb, ctx);
	if (!rule) {
		return TC_ACT_UNSPEC;
	}

	if (is_passthrough_rule(rule))
		return TC_ACT_OK;
	if (is_egress_nat_rule(rule) && is_local_ipv4(ctx->dst_addr))
		return TC_ACT_OK;
	if (is_egress_nat_rule(rule)) {
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_EGRESS_NAT_FORWARD);
		return TC_ACT_UNSPEC;
	}
	if (is_fullnat_rule(rule)) {
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_FULLNAT_FORWARD);
		return TC_ACT_UNSPEC;
	}
	return handle_transparent_forward(skb, ctx, rule);
}

static __always_inline int handle_reply_ingress_v4(struct __sk_buff *skb)
{
	struct packet_ctx *ctx = lookup_scratch_ctx_v4();
	struct flow_key_v4 *flow_key = lookup_scratch_flow_key_v4();
	struct flow_value_v4 *flow;
	__u8 flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;

	/* Non-matches must fall through so sibling family filters can run. */
	if (!ctx || !flow_key)
		return TC_ACT_UNSPEC;
	__builtin_memset(ctx, 0, sizeof(*ctx));
	__builtin_memset(flow_key, 0, sizeof(*flow_key));

	if (parse_ipv4_l4(skb, ctx) < 0) {
		return TC_ACT_UNSPEC;
	}

	flow_key->ifindex = skb->ifindex;
	flow_key->src_addr = bpf_ntohl(ctx->src_addr);
	flow_key->dst_addr = bpf_ntohl(ctx->dst_addr);
	flow_key->src_port = ctx->src_port;
	flow_key->dst_port = ctx->dst_port;
	flow_key->proto = ctx->proto;

	flow = lookup_reply_flow_v4(flow_key, &flow_bank);
	if (!flow) {
		return TC_ACT_UNSPEC;
	}

	if (is_fullnat_reply_flow(flow)) {
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_REPLY_FULLNAT);
		return TC_ACT_UNSPEC;
	}
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) != 0)
		return TC_ACT_UNSPEC;
	return handle_transparent_reply(skb, ctx, flow_key, flow, flow_bank);
}

static __always_inline int dispatch_forward_ingress_v4(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();
	struct rule_value_v4 *rule;
	struct flow_value_v4 *front_flow;
	struct flow_value_v4 *active_flow;
	struct flow_value_v4 *old_flow = 0;

	if (!dispatch)
		return TC_ACT_UNSPEC;
	dispatch->have_flow = 0;
	dispatch->have_rule = 0;
	__builtin_memset(&dispatch->ctx, 0, sizeof(dispatch->ctx));

	if (parse_ipv4_l4(skb, &dispatch->ctx) < 0) {
		return TC_ACT_UNSPEC;
	}

	rule = lookup_rule_v4(skb, &dispatch->ctx);
	if (!rule) {
		return TC_ACT_UNSPEC;
	}

	dispatch->rule_value = *rule;
	dispatch->have_rule = 1;
	if (is_passthrough_rule(rule))
		return TC_ACT_OK;
	if (is_egress_nat_rule(rule)) {
		if (is_local_ipv4(dispatch->ctx.dst_addr))
			return TC_ACT_OK;
		if (!is_full_cone_egress_nat_rule(rule)) {
			/* Keep established egress NAT sessions on the current program across
			 * hot-restart handoff so they don't depend on a successor-only tail call.
			 */
			__builtin_memset(&dispatch->flow_key, 0, sizeof(dispatch->flow_key));
			dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
			build_front_flow_key(skb, &dispatch->ctx, &dispatch->flow_key);
			front_flow = lookup_flow_v4_active_or_old(&dispatch->flow_key, &dispatch->flow_bank);
			if (front_flow && !is_egress_nat_flow(front_flow))
				return TC_ACT_OK;
			if (is_fullnat_front_flow(front_flow))
				return handle_egress_nat_forward_existing(skb, &dispatch->ctx, &dispatch->rule_value, front_flow, dispatch->flow_bank);
		}
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_EGRESS_NAT_FORWARD);
		return TC_ACT_UNSPEC;
	}
	if (is_fullnat_rule(rule)) {
		/* Keep established full-NAT sessions on the dispatcher during the
		 * predecessor/successor gap; new sessions can still use the split path.
		 */
		__builtin_memset(&dispatch->flow_key, 0, sizeof(dispatch->flow_key));
		dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
		build_front_flow_key(skb, &dispatch->ctx, &dispatch->flow_key);
		active_flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &dispatch->flow_key);
		if (tc_flow_old_bank_enabled_v4())
			old_flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_OLD, &dispatch->flow_key);
		front_flow = active_flow;
		if (front_flow) {
			dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
		} else if (old_flow) {
			dispatch->flow_bank = FORWARD_TC_FLOW_BANK_OLD;
			front_flow = old_flow;
		}
		if (is_fullnat_front_flow(front_flow)) {
			dispatch->flow_value = *front_flow;
			dispatch->have_flow = 1;
			return handle_forward_ingress_v4_fullnat_existing(skb);
		}
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_FULLNAT_NEW);
		return TC_ACT_UNSPEC;
	}
	return handle_forward_ingress_v4_transparent(skb);
}

static __always_inline int dispatch_reply_ingress_v4(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();
	struct flow_value_v4 *flow;

	if (!dispatch)
		return TC_ACT_UNSPEC;
	dispatch->have_flow = 0;
	dispatch->have_rule = 0;
	__builtin_memset(&dispatch->ctx, 0, sizeof(dispatch->ctx));
	__builtin_memset(&dispatch->flow_key, 0, sizeof(dispatch->flow_key));

	if (parse_ipv4_l4(skb, &dispatch->ctx) < 0) {
		return TC_ACT_UNSPEC;
	}

	dispatch->flow_key.ifindex = skb->ifindex;
	dispatch->flow_key.src_addr = bpf_ntohl(dispatch->ctx.src_addr);
	dispatch->flow_key.dst_addr = bpf_ntohl(dispatch->ctx.dst_addr);
	dispatch->flow_key.src_port = dispatch->ctx.src_port;
	dispatch->flow_key.dst_port = dispatch->ctx.dst_port;
	dispatch->flow_key.proto = dispatch->ctx.proto;

	dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	flow = lookup_reply_flow_v4(&dispatch->flow_key, &dispatch->flow_bank);
	if (!flow) {
		return TC_ACT_UNSPEC;
	}

	dispatch->flow_value = *flow;
	dispatch->have_flow = 1;
	/* Established reply traffic must keep working before the successor reattaches,
	 * so handle reply flows here instead of relying on a tail-call target.
	 */
	if (is_fullnat_reply_flow(flow))
		return handle_fullnat_reply(skb, &dispatch->ctx, &dispatch->flow_key, flow, dispatch->flow_bank);
	if ((flow->flags & FORWARD_FLOW_FLAG_FULL_NAT) != 0)
		return TC_ACT_UNSPEC;
	return handle_transparent_reply(skb, &dispatch->ctx, &dispatch->flow_key, flow, dispatch->flow_bank);
}

static __always_inline int handle_forward_ingress_v4_transparent(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_rule)
		return TC_ACT_UNSPEC;
	if (is_passthrough_rule(&dispatch->rule_value) || is_fullnat_rule(&dispatch->rule_value))
		return TC_ACT_UNSPEC;
	return handle_transparent_forward(skb, &dispatch->ctx, &dispatch->rule_value);
}

static __always_inline int handle_forward_ingress_v4_fullnat(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();
	struct flow_value_v4 *front_flow;
	struct flow_value_v4 *active_flow;
	struct flow_value_v4 *old_flow = 0;

	if (!dispatch || !dispatch->have_rule)
		return TC_ACT_UNSPEC;
	if (!is_fullnat_rule(&dispatch->rule_value) || is_egress_nat_rule(&dispatch->rule_value))
		return TC_ACT_UNSPEC;
	dispatch->have_flow = 0;
	dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	__builtin_memset(&dispatch->flow_key, 0, sizeof(dispatch->flow_key));
	build_front_flow_key(skb, &dispatch->ctx, &dispatch->flow_key);
	active_flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_ACTIVE, &dispatch->flow_key);
	if (tc_flow_old_bank_enabled_v4())
		old_flow = lookup_flow_v4_in_bank(FORWARD_TC_FLOW_BANK_OLD, &dispatch->flow_key);
	front_flow = active_flow;
	if (front_flow) {
		dispatch->flow_bank = FORWARD_TC_FLOW_BANK_ACTIVE;
	} else if (old_flow) {
		dispatch->flow_bank = FORWARD_TC_FLOW_BANK_OLD;
		front_flow = old_flow;
	}
	if (is_fullnat_front_flow(front_flow)) {
		dispatch->flow_value = *front_flow;
		dispatch->have_flow = 1;
		bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_FULLNAT_EXISTING);
		return TC_ACT_UNSPEC;
	}
	bpf_tail_call(skb, &tc_prog_chain_v4, FORWARD_TC_PROG_V4_FULLNAT_NEW);
	return TC_ACT_UNSPEC;
}

static __always_inline int handle_forward_ingress_v4_egress_nat(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_rule)
		return TC_ACT_UNSPEC;
	if (!is_egress_nat_rule(&dispatch->rule_value))
		return TC_ACT_UNSPEC;
	if (is_local_ipv4(dispatch->ctx.dst_addr))
		return TC_ACT_OK;
	return handle_egress_nat_forward(skb, &dispatch->ctx, &dispatch->rule_value);
}

static __always_inline int handle_forward_ingress_v4_fullnat_existing(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_rule || !dispatch->have_flow)
		return TC_ACT_UNSPEC;
	if (!is_fullnat_front_flow(&dispatch->flow_value))
		return TC_ACT_UNSPEC;
	return handle_fullnat_forward_existing(
		skb,
		&dispatch->ctx,
		&dispatch->rule_value,
		&dispatch->flow_value,
		dispatch->flow_bank | FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT
	);
}

static __always_inline int handle_forward_ingress_v4_fullnat_new(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_rule || dispatch->have_flow)
		return TC_ACT_UNSPEC;
	return handle_fullnat_forward_new(skb, &dispatch->ctx, &dispatch->rule_value, &dispatch->flow_key);
}

static __always_inline int handle_reply_ingress_v4_transparent(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_flow)
		return TC_ACT_UNSPEC;
	if ((dispatch->flow_value.flags & FORWARD_FLOW_FLAG_FULL_NAT) != 0)
		return TC_ACT_UNSPEC;
	if (is_fullnat_reply_flow(&dispatch->flow_value))
		return TC_ACT_UNSPEC;
	return handle_transparent_reply(skb, &dispatch->ctx, &dispatch->flow_key, &dispatch->flow_value, dispatch->flow_bank | FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT);
}

static __always_inline int handle_reply_ingress_v4_fullnat(struct __sk_buff *skb)
{
	struct tc_dispatch_ctx_v4 *dispatch = lookup_tc_dispatch_scratch_v4();

	if (!dispatch || !dispatch->have_flow)
		return TC_ACT_UNSPEC;
	if (!is_fullnat_reply_flow(&dispatch->flow_value))
		return TC_ACT_UNSPEC;
	return handle_fullnat_reply(skb, &dispatch->ctx, &dispatch->flow_key, &dispatch->flow_value, dispatch->flow_bank | FORWARD_TC_FLOW_BANK_DISPATCH_SNAPSHOT);
}

SEC("classifier/forward_ingress")
int forward_ingress(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4(skb);
}

SEC("classifier/forward_ingress_dispatch")
int forward_ingress_dispatch(struct __sk_buff *skb)
{
	return dispatch_forward_ingress_v4(skb);
}

SEC("classifier/forward_ingress_v4_transparent")
int forward_ingress_v4_transparent(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4_transparent(skb);
}

SEC("classifier/forward_ingress_v4_fullnat")
int forward_ingress_v4_fullnat(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4_fullnat(skb);
}

SEC("classifier/forward_ingress_v4_fullnat_existing")
int forward_ingress_v4_fullnat_existing(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4_fullnat_existing(skb);
}

SEC("classifier/forward_ingress_v4_fullnat_new")
int forward_ingress_v4_fullnat_new(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4_fullnat_new(skb);
}

SEC("classifier/forward_ingress_v4_egress_nat")
int forward_ingress_v4_egress_nat(struct __sk_buff *skb)
{
	return handle_forward_ingress_v4_egress_nat(skb);
}

SEC("classifier/forward_ingress_v6")
int forward_ingress_v6(struct __sk_buff *skb)
{
	struct packet_ctx_v6 *ctx_v6;
	struct rule_value_v6 *rule_v6;

	ctx_v6 = lookup_scratch_ctx_v6();
	if (!ctx_v6)
		return TC_ACT_UNSPEC;
	__builtin_memset(ctx_v6, 0, sizeof(*ctx_v6));
	if (parse_ipv6_l4(skb, ctx_v6) < 0)
		return TC_ACT_UNSPEC;
	rule_v6 = lookup_rule_v6(skb, ctx_v6);
	if (!rule_v6)
		return TC_ACT_UNSPEC;
	if (!is_fullnat_rule_v6(rule_v6))
		return TC_ACT_UNSPEC;
	return handle_fullnat_forward_v6(skb, ctx_v6, rule_v6);
}

SEC("classifier/reply_ingress")
int reply_ingress(struct __sk_buff *skb)
{
	return handle_reply_ingress_v4(skb);
}

SEC("classifier/reply_ingress_dispatch")
int reply_ingress_dispatch(struct __sk_buff *skb)
{
	return dispatch_reply_ingress_v4(skb);
}

SEC("classifier/reply_ingress_v4_transparent")
int reply_ingress_v4_transparent(struct __sk_buff *skb)
{
	return handle_reply_ingress_v4_transparent(skb);
}

SEC("classifier/reply_ingress_v4_fullnat")
int reply_ingress_v4_fullnat(struct __sk_buff *skb)
{
	return handle_reply_ingress_v4_fullnat(skb);
}

SEC("classifier/reply_ingress_v6")
int reply_ingress_v6(struct __sk_buff *skb)
{
	struct packet_ctx_v6 *ctx_v6;
	struct flow_key_v6 *flow_key_v6;
	struct flow_value_v6 *flow_v6;
	__u8 flow_bank_v6 = FORWARD_TC_FLOW_BANK_ACTIVE;

	ctx_v6 = lookup_scratch_ctx_v6();
	flow_key_v6 = lookup_scratch_flow_key_v6();
	if (!ctx_v6 || !flow_key_v6)
		return TC_ACT_UNSPEC;
	__builtin_memset(ctx_v6, 0, sizeof(*ctx_v6));
	__builtin_memset(flow_key_v6, 0, sizeof(*flow_key_v6));
	if (parse_ipv6_l4(skb, ctx_v6) < 0)
		return TC_ACT_UNSPEC;

	flow_key_v6->ifindex = skb->ifindex;
	copy_ipv6_addr(flow_key_v6->src_addr, ctx_v6->src_addr);
	copy_ipv6_addr(flow_key_v6->dst_addr, ctx_v6->dst_addr);
	flow_key_v6->src_port = ctx_v6->src_port;
	flow_key_v6->dst_port = ctx_v6->dst_port;
	flow_key_v6->proto = ctx_v6->proto;

	flow_v6 = lookup_reply_flow_v6(flow_key_v6, &flow_bank_v6);
	if (!flow_v6)
		return TC_ACT_UNSPEC;
	if (!is_fullnat_reply_flow_v6(flow_v6))
		return TC_ACT_UNSPEC;
	return handle_fullnat_reply_v6(skb, ctx_v6, flow_key_v6, flow_v6, flow_bank_v6);
}

char _license[] SEC("license") = "GPL";
