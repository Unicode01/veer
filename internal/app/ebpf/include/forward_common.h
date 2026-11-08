/*
 * Helpers shared by forward-tc-bpf.c and forward-xdp-bpf.c.
 *
 * Each dataplane includes this after its maps and prototypes. The structs,
 * maps and per-bank helpers used here come from the including file, so a
 * helper only belongs here when both dataplanes need the same source text.
 */
#ifndef FORWARD_COMMON_H
#define FORWARD_COMMON_H

#define FORWARD_TCP_CLOSE_NONE 0
#define FORWARD_TCP_CLOSE_UPDATE 1
#define FORWARD_TCP_CLOSE_DELETE 2

static __always_inline __u64 new_flow_session_id(void)
{
	__u64 session_id = ((__u64)bpf_get_prandom_u32() << 32) | (__u64)bpf_get_prandom_u32();

	return session_id ? session_id : 1;
}

static __always_inline int flow_matches_rule_v4(const struct flow_value_v4 *flow, const struct rule_value_v4 *rule)
{
	return flow && rule && flow->rule_id == rule->rule_id && flow->rule_revision == rule->revision;
}

static __always_inline int flow_matches_rule_v6(const struct flow_value_v6 *flow, const struct rule_value_v6 *rule)
{
	return flow && rule && flow->rule_id == rule->rule_id && flow->rule_revision == rule->revision;
}

static __always_inline int delete_flow_v4_session_in_bank(__u8 bank, const struct flow_key_v4 *key, __u64 session_id)
{
	struct flow_value_v4 *current = lookup_flow_v4_in_bank(bank, key);

	if (!current || current->session_id != session_id)
		return -1;
	return delete_flow_v4_in_bank(bank, key);
}

static __always_inline int delete_flow_v6_session_in_bank(__u8 bank, const struct flow_key_v6 *key, __u64 session_id)
{
	struct flow_value_v6 *current = lookup_flow_v6_in_bank(bank, key);

	if (!current || current->session_id != session_id)
		return -1;
	return delete_flow_v6_in_bank(bank, key);
}

static __always_inline int delete_nat_port_v4_session_in_bank(__u8 bank, const struct nat_port_key_v4 *key, __u64 session_id)
{
	struct nat_port_value_v4 *current = lookup_nat_port_v4_in_bank(bank, key);

	if (!current || current->session_id != session_id)
		return -1;
	return delete_nat_port_v4_in_bank(bank, key);
}

static __always_inline int delete_nat_port_v6_session_in_bank(__u8 bank, const struct nat_port_key_v6 *key, __u64 session_id)
{
	struct nat_port_value_v6 *current = lookup_nat_port_v6_in_bank(bank, key);

	if (!current || current->session_id != session_id)
		return -1;
	return delete_nat_port_v6_in_bank(bank, key);
}

static __always_inline int mac_is_zero(const __u8 mac[ETH_ALEN])
{
#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++) {
		if (mac[i] != 0)
			return 0;
	}
	return 1;
}

static __always_inline int mac_equal(const __u8 left[ETH_ALEN], const __u8 right[ETH_ALEN])
{
#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++) {
		if (left[i] != right[i])
			return 0;
	}
	return 1;
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

static __always_inline int tcp_packet_is_rst(__u8 proto, __u8 tcp_flags)
{
	return proto == IPPROTO_TCP && (tcp_flags & FORWARD_TCP_FLAG_RST) != 0;
}

static __always_inline int tcp_packet_has_fin(__u8 proto, __u8 tcp_flags)
{
	return proto == IPPROTO_TCP && (tcp_flags & FORWARD_TCP_FLAG_FIN) != 0;
}

static __always_inline int tcp_flow_close_complete(__u16 flow_flags, __u8 proto, __u8 tcp_flags)
{
	return proto == IPPROTO_TCP &&
		tcp_flags == FORWARD_TCP_FLAG_ACK &&
		(flow_flags & (FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING)) ==
			(FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING);
}

static __always_inline void mark_tcp_flow_closing_v4(struct flow_value_v4 *flow, __u16 direction, __u64 now)
{
	__u16 old_flags;

	if (!flow)
		return;
	old_flags = flow->flags;
	flow->flags |= direction;
	if ((old_flags & direction) == 0 &&
		(flow->front_close_seen_ns == 0 ||
		 (flow->flags & (FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING)) ==
			(FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING)))
		flow->front_close_seen_ns = now;
	flow->last_seen_ns = now;
}

static __always_inline void mark_tcp_flow_closing_v6(struct flow_value_v6 *flow, __u16 direction, __u64 now)
{
	__u16 old_flags;

	if (!flow)
		return;
	old_flags = flow->flags;
	flow->flags |= direction;
	if ((old_flags & direction) == 0 &&
		(flow->front_close_seen_ns == 0 ||
		 (flow->flags & (FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING)) ==
			(FORWARD_FLOW_FLAG_FRONT_CLOSING | FORWARD_FLOW_FLAG_REPLY_CLOSING)))
		flow->front_close_seen_ns = now;
	flow->last_seen_ns = now;
}

static __always_inline int update_tcp_flow_pair_close_v4(struct flow_value_v4 *front, struct flow_value_v4 *reply, __u8 proto, __u8 tcp_flags, __u16 direction, __u64 now)
{
	if (tcp_packet_is_rst(proto, tcp_flags))
		return FORWARD_TCP_CLOSE_DELETE;
	if (tcp_packet_has_fin(proto, tcp_flags)) {
		mark_tcp_flow_closing_v4(front, direction, now);
		mark_tcp_flow_closing_v4(reply, direction, now);
		return FORWARD_TCP_CLOSE_UPDATE;
	}
	if (reply && tcp_flow_close_complete(reply->flags, proto, tcp_flags))
		return FORWARD_TCP_CLOSE_DELETE;
	return FORWARD_TCP_CLOSE_NONE;
}

static __always_inline int update_tcp_flow_pair_close_v6(struct flow_value_v6 *front, struct flow_value_v6 *reply, __u8 proto, __u8 tcp_flags, __u16 direction, __u64 now)
{
	if (tcp_packet_is_rst(proto, tcp_flags))
		return FORWARD_TCP_CLOSE_DELETE;
	if (tcp_packet_has_fin(proto, tcp_flags)) {
		mark_tcp_flow_closing_v6(front, direction, now);
		mark_tcp_flow_closing_v6(reply, direction, now);
		return FORWARD_TCP_CLOSE_UPDATE;
	}
	if (reply && tcp_flow_close_complete(reply->flags, proto, tcp_flags))
		return FORWARD_TCP_CLOSE_DELETE;
	return FORWARD_TCP_CLOSE_NONE;
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

static __always_inline __u32 mix_nat_probe_seed(__u32 seed)
{
	seed ^= seed >> 16;
	seed *= 2246822519U;
	seed ^= seed >> 13;
	seed *= 3266489917U;
	seed ^= seed >> 16;
	return seed;
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

#endif /* FORWARD_COMMON_H */
