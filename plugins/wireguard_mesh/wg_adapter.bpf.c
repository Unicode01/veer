#include "../include/veer_plugin_helpers.h"

VEER_DECLARE_PROG_CHAIN_V4();

// The kernel removes Ethernet on redirect to an ARPHRD_NONE WireGuard device.
// Decrypted L3 packets need an Ethernet header before returning through veth.
// See Linux net/core/filter.c: __bpf_redirect_no_mac, bpf_skb_change_head.
static int (*const change_head)(struct __sk_buff *, __u32, __u64) = (void *)43;

struct wg_link {
	__u32 direction;
	__u32 output;
	__u8 source[6];
	__u8 destination[6];
	__u32 mtu;
};

struct bpf_map_def SEC("maps") wg_links = {
	.type = 1, // BPF_MAP_TYPE_HASH
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct wg_link),
	.max_entries = 32,
};

static int (*const load_bytes)(struct __sk_buff *, __u32, void *, __u32) = (void *)26;

// Only SYN/SYN-ACK options are rewritten. Established packets take the short path.
__attribute__((noinline)) int clamp_options(struct __sk_buff *skb, __u32 offset, __u32 end, __u32 start, __u16 clamp)
{
#pragma clang loop unroll(disable)
	for (int i = 0; i < 40; i++) {
		__u8 kind = 0, length = 0;
		__u16 previous = 0, next = veer_htons(clamp);
		if (offset >= end) break;
		if (load_bytes(skb, offset, &kind, 1)) return -1;
		if (!kind) break;
		if (kind == 1) { offset++; continue; }
		if (offset + 2 > end || load_bytes(skb, offset + 1, &length, 1)) return -1;
		if (length < 2 || offset + length > end) return -1;
		if (kind == 2 && length == 4) {
			if (load_bytes(skb, offset + 2, &previous, 2)) return -1;
			if (veer_ntohs(previous) > clamp) {
				// The TCP checksum is always 16 bytes after its start.
				__u32 checksum = start + 16;
				if (veer_l4_csum_replace(skb, checksum, previous, next, 2) ||
				    veer_skb_store_bytes(skb, offset + 2, &next, 2, 0)) return -1;
			}
			break;
		}
		offset += length;
	}
	return 0;
}

static __always_inline int clamp_mss(struct __sk_buff *skb, __u16 protocol, __u32 mtu)
{
	struct veer_packet pkt = {};
	struct veer_l2_info l2 = {};
	veer_packet_from_skb(skb, &pkt);
	if (!veer_parse_l2(&pkt, &l2)) return -1;
	void *l4 = 0;
	__u32 overhead = 0;
	if (protocol == veer_htons(VEER_ETH_P_IP)) {
		struct veer_ipv4hdr *ip = veer_ipv4_from_l2(&pkt, &l2);
		if (!ip || ip->protocol != VEER_IPPROTO_TCP || (veer_ntohs(ip->frag_off) & 0x3fff)) return 0;
		l4 = veer_ipv4_l4(&pkt, ip);
		overhead = veer_ipv4_header_len(ip) + 20;
	} else {
		struct veer_ipv6hdr *ip = veer_ipv6_from_l2(&pkt, &l2);
		if (!ip) return 0;
		__u8 next = ip->nexthdr;
		void *cursor = ip + 1;
#pragma clang loop unroll(disable)
		for (int i = 0; i < VEER_MAX_IPV6_EXTENSION_HEADERS; i++) {
			if (next == VEER_IPPROTO_TCP) break;
			// Do not rewrite fragments or authenticated packets.
			if (next != VEER_IPPROTO_HOPOPTS && next != VEER_IPPROTO_ROUTING && next != VEER_IPPROTO_DSTOPTS) return 0;
			struct veer_ipv6_exthdr *ext = cursor;
			if ((void *)(ext + 1) > pkt.data_end) return 0;
			__u32 length = ((__u32)ext->hdrlen + 1) * 8;
			next = ext->nexthdr;
			cursor = (char *)cursor + length;
			if (cursor > pkt.data_end) return 0;
		}
		l4 = cursor;
		if (next != VEER_IPPROTO_TCP) return 0;
		overhead = (__u32)((long)l4 - (long)ip) + 20;
	}
	struct veer_tcphdr *tcp = l4;
	if (!tcp || (void *)(tcp + 1) > pkt.data_end || !(tcp->flags & 2)) return 0;
	__u32 start = (__u32)((long)l4 - (long)pkt.data);
	__u32 length = (tcp->doff_res >> 4) * 4;
	if (length <= 20 || length > 60 || start > 65535 || mtu <= overhead || mtu > 9000) return 0;
	return clamp_options(skb, start + 20, start + length, start, mtu - overhead);
}

SEC("tc/veer/pre_forward")
int tc_adapter(struct __sk_buff *skb)
{
	__u32 index = skb->ifindex;
	struct wg_link *link = veer_bpf_map_lookup_elem(&wg_links, &index);
	if (!link || !link->output)
		return TC_ACT_SHOT;
	if (link->direction == 1) {
		struct veer_packet packet = {};
		veer_packet_from_skb(skb, &packet);
		struct veer_l2_info l2 = {};
		if (!veer_parse_l2(&packet, &l2) || l2.vlan_depth != 0 ||
		    (l2.protocol != VEER_ETH_P_IP && l2.protocol != VEER_ETH_P_IPV6))
			return TC_ACT_SHOT;
		__u32 output = link->output, mtu = link->mtu;
		if (clamp_mss(skb, veer_htons(l2.protocol), mtu)) return TC_ACT_SHOT;
		return veer_redirect(output);
	}
	if (link->direction != 2)
		return TC_ACT_SHOT;
	__u16 protocol = (__u16)skb->protocol;
	if (protocol != veer_htons(VEER_ETH_P_IP) && protocol != veer_htons(VEER_ETH_P_IPV6))
		return TC_ACT_SHOT;
	// Copy configuration to the stack before the helper invalidates packet pointers.
	struct wg_link config = *link;
	if (change_head(skb, sizeof(struct veer_ethhdr), 0))
		return TC_ACT_SHOT;
	struct veer_packet packet = {};
	veer_packet_from_skb(skb, &packet);
	struct veer_ethhdr *eth = packet.data;
	if ((void *)(eth + 1) > packet.data_end)
		return TC_ACT_SHOT;
	__builtin_memcpy(eth->h_source, config.source, 6);
	__builtin_memcpy(eth->h_dest, config.destination, 6);
	eth->h_proto = protocol;
	if (clamp_mss(skb, protocol, config.mtu)) return TC_ACT_SHOT;
	return veer_redirect(config.output);
}

char SEC("license") LICENSE[] = "GPL";
