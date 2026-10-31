// SPDX-License-Identifier: GPL-2.0-only
/* Optional, versioned TC capabilities. The current BPF skb is never mutated:
 * a clone owns all changes, segmentation and submission. This is essential on
 * kernels whose kfunc verifier cannot invalidate direct packet pointers.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#error "Veer kfuncs require Linux 6.1 or newer"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#include <net/gso.h>
#endif
#include <net/net_namespace.h>
#include <net/sch_generic.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/checksum.h>

#ifndef __bpf_kfunc
#define __bpf_kfunc noinline
#endif
#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START BTF_SET8_START
#define BTF_KFUNCS_END BTF_SET8_END
#endif

/* Keep in sync with plugins/include/veer_kfuncs.h. All fields are host order. */
struct veer_handoff_v1 {
	u32 output;
	u32 mtu;
	u16 session;
	u16 operation;
	u8 source[ETH_ALEN];
	u8 destination[ETH_ALEN];
	u16 mss_v4;
	u16 mss_v6;
};
enum { VEER_PPPOE_ENCAP = 1, VEER_PPPOE_DECAP, VEER_L3_TO_ETH, VEER_ETH_TO_L3 };
struct veer_pppoe { u8 version, code; __be16 session, length, protocol; } __packed;

u32 veer_kfuncs_abi_v1(void);
int veer_skb_handoff_v1(struct __sk_buff *skb_ctx, const struct veer_handoff_v1 *config);

__bpf_kfunc u32 veer_kfuncs_abi_v1(void) { return 1; }
static DEFINE_PER_CPU(unsigned int, veer_send_depth);

static int veer_send(struct sk_buff *skb, struct net_device *dev, bool ingress)
{
	int err;
	if (ingress)
		return dev_forward_skb(dev, skb);
	local_bh_disable();
	if (unlikely(this_cpu_read(veer_send_depth) >= 4)) {
		local_bh_enable();
		kfree_skb(skb);
		return -ELOOP;
	}
	skb->dev = dev;
	skb_clear_tstamp(skb);
	this_cpu_inc(veer_send_depth);
	err = dev_queue_xmit(skb);
	this_cpu_dec(veer_send_depth);
	local_bh_enable();
	return net_xmit_eval(err);
}

static void veer_eth(struct sk_buff *skb, const struct veer_handoff_v1 *c, __be16 proto)
{
	struct ethhdr *eth = (void *)skb->data;
	ether_addr_copy(eth->h_source, c->source);
	ether_addr_copy(eth->h_dest, c->destination);
	eth->h_proto = proto;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_len(skb);
	skb->protocol = proto;
}

/* Expose complete transport headers to the next TC program without copying
 * payload frags. Only SYN option changes need a writable private header.
 */
static int veer_clamp(struct sk_buff *skb, const struct veer_handoff_v1 *c)
{
	unsigned int off = skb_network_offset(skb), end, pos;
	u8 protocol;
	u16 clamp;
	struct tcphdr *tcp;
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *ip;
		if (!pskb_may_pull(skb, off + sizeof(*ip))) return -EINVAL;
		ip = (void *)(skb->data + off);
		if (ip->version != 4 || ip->ihl < 5) return -EINVAL;
		if (ip_is_fragment(ip)) return 0;
		protocol = ip->protocol;
		off += ip->ihl * 4;
		clamp = c->mss_v4;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		unsigned int depth;
		if (!pskb_may_pull(skb, off + sizeof(struct ipv6hdr))) return -EINVAL;
		protocol = ((struct ipv6hdr *)(skb->data + off))->nexthdr;
		off += sizeof(struct ipv6hdr);
		for (depth = 0; depth < 8 && protocol != IPPROTO_TCP; depth++) {
			struct ipv6_opt_hdr *ext;
			if (protocol == IPPROTO_UDP || protocol == IPPROTO_ICMPV6) break;
			/* Never alter fragments or authenticated TCP packets. */
			if (protocol != NEXTHDR_HOP && protocol != NEXTHDR_ROUTING && protocol != NEXTHDR_DEST) return 0;
			if (!pskb_may_pull(skb, off + sizeof(*ext))) return -EINVAL;
			ext = (void *)(skb->data + off);
			protocol = ext->nexthdr;
			off += (ext->hdrlen + 1) * 8;
		}
		clamp = c->mss_v6;
	} else return -EPROTONOSUPPORT;
	if (protocol != IPPROTO_TCP) {
		if (protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
			return pskb_may_pull(skb, off + 8) ? 0 : -EINVAL;
		return 0;
	}
	if (off - skb_network_offset(skb) + sizeof(*tcp) >= c->mtu) return -EMSGSIZE;
	clamp = min_t(u16, clamp, c->mtu - (off - skb_network_offset(skb)) - sizeof(*tcp));
	if (!pskb_may_pull(skb, off + sizeof(*tcp))) return -EINVAL;
	tcp = (void *)(skb->data + off);
	end = off + tcp->doff * 4;
	if (tcp->doff < 5 || !pskb_may_pull(skb, end)) return -EINVAL;
	if (!clamp || !((struct tcphdr *)(skb->data + off))->syn) return 0;
	if (skb_ensure_writable(skb, end)) return -EINVAL;
	tcp = (void *)(skb->data + off);
	for (pos = off + sizeof(*tcp); pos < end;) {
		u8 *opt = skb->data + pos;
		__be16 old, value = htons(clamp);
		if (!opt[0]) break;
		if (opt[0] == TCPOPT_NOP) { pos++; continue; }
		if (pos + 2 > end || opt[1] < 2 || pos + opt[1] > end) return -EINVAL;
		if (opt[0] == TCPOPT_MSS && opt[1] == TCPOLEN_MSS) {
			memcpy(&old, opt + 2, 2);
			if (ntohs(old) > clamp) {
				inet_proto_csum_replace2(&tcp->check, skb, old, value, false);
				memcpy(opt + 2, &value, 2);
			}
			break;
		}
		pos += opt[1];
	}
	return 0;
}

/* Called only on owned, non-GSO segments. skb_push leaves payload/frags in place. */
static int veer_pppoe_encap(struct sk_buff *skb, const struct veer_handoff_v1 *c)
{
	struct veer_pppoe *ppp;
	__be16 proto;
	u32 len;
	if (skb_is_gso(skb) || !pskb_may_pull(skb, ETH_HLEN) || skb->len < ETH_HLEN)
		return -EINVAL;
	proto = ((struct ethhdr *)skb->data)->h_proto;
	if (proto != htons(ETH_P_IP) && proto != htons(ETH_P_IPV6))
		return -EPROTONOSUPPORT;
	if (proto == htons(ETH_P_IP)) {
		struct iphdr *ip;
		if (!pskb_may_pull(skb, ETH_HLEN + sizeof(*ip))) return -EINVAL;
		ip = (void *)(skb->data + ETH_HLEN);
		len = ntohs(ip->tot_len);
		if (ip->version != 4 || ip->ihl < 5 || len < ip->ihl * 4) return -EINVAL;
	} else {
		struct ipv6hdr *ip;
		if (!pskb_may_pull(skb, ETH_HLEN + sizeof(*ip))) return -EINVAL;
		ip = (void *)(skb->data + ETH_HLEN);
		len = sizeof(*ip) + ntohs(ip->payload_len);
		if (ip->version != 6) return -EINVAL;
	}
	if (len > skb->len - ETH_HLEN || pskb_trim(skb, ETH_HLEN + len)) return -EINVAL;
	if (len > c->mtu || len > 1492)
		return -EMSGSIZE;
	/* PPPoE Ethernet devices cannot generally offload inner checksums. */
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return -EINVAL;
	if (skb_cow_head(skb, sizeof(*ppp)))
		return -ENOMEM;
	skb_push(skb, sizeof(*ppp));
	veer_eth(skb, c, htons(ETH_P_PPP_SES));
	ppp = (void *)(skb->data + ETH_HLEN);
	ppp->version = 0x11;
	ppp->code = 0;
	ppp->session = htons(c->session);
	ppp->length = htons(len + 2);
	ppp->protocol = htons(proto == htons(ETH_P_IP) ? 0x21 : 0x57);
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int veer_pppoe_decap(struct sk_buff *skb, const struct veer_handoff_v1 *c)
{
	struct veer_pppoe ppp;
	__be16 proto;
	u32 len;
	if (skb_is_gso(skb) || !pskb_may_pull(skb, ETH_HLEN + sizeof(ppp)))
		return -EINVAL;
	memcpy(&ppp, skb->data + ETH_HLEN, sizeof(ppp));
	if (((struct ethhdr *)skb->data)->h_proto != htons(ETH_P_PPP_SES) ||
	    ppp.version != 0x11 || ppp.code || ntohs(ppp.session) != c->session)
		return -EINVAL;
	if (ppp.protocol == htons(0x21))
		proto = htons(ETH_P_IP);
	else if (ppp.protocol == htons(0x57))
		proto = htons(ETH_P_IPV6);
	else
		return -EPROTONOSUPPORT;
	len = ntohs(ppp.length);
	if (len < 2 || len > c->mtu + 2 || len > 1494 ||
	    skb->len < ETH_HLEN + sizeof(ppp) + len - 2)
		return -EMSGSIZE;
	if (pskb_trim(skb, ETH_HLEN + sizeof(ppp) + len - 2) || skb_cow_head(skb, 0))
		return -ENOMEM;
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return -EINVAL;
	skb_pull(skb, sizeof(ppp));
	veer_eth(skb, c, proto);
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

/* One source skb may create many PPPoE frames. Ownership stays entirely in C.
 * The BPF caller MUST terminate its path with TC_ACT_SHOT, including on error.
 */
__bpf_kfunc int veer_skb_handoff_v1(struct __sk_buff *skb_ctx, const struct veer_handoff_v1 *config)
{
	/* The verifier accepts the TC context type; its runtime value is sk_buff.
	 * Using the UAPI name also supports kernels predating ctx projections.
	 */
	struct sk_buff *skb = (struct sk_buff *)skb_ctx;
	struct veer_handoff_v1 c = *config;
	struct net_device *dev;
	struct sk_buff *copy, *segs, *next;
	int err = 0, result = 0;
	bool ingress = c.operation == VEER_PPPOE_DECAP;

	if (!skb->dev || !c.output || c.mtu < 68 || c.mtu > 9000 ||
	    c.operation < VEER_PPPOE_ENCAP || c.operation > VEER_ETH_TO_L3)
		return -EINVAL;
	rcu_read_lock();
	dev = dev_get_by_index_rcu(dev_net(skb->dev), c.output);
	if (!dev || !(dev->flags & IFF_UP) || dev == skb->dev ||
	    (c.operation == VEER_ETH_TO_L3 ? dev->type != ARPHRD_NONE : dev->type != ARPHRD_ETHER)) {
		result = -ENODEV;
		goto out;
	}
	copy = skb_clone(skb, GFP_ATOMIC);
	if (!copy) { result = -ENOMEM; goto out; }
	if (c.operation == VEER_PPPOE_ENCAP) {
		if (!c.session || c.mtu > 1492 || !pskb_may_pull(copy, ETH_HLEN)) {
			err = -EINVAL; goto drop;
		}
		skb_reset_mac_header(copy);
		skb_set_network_header(copy, ETH_HLEN);
		copy->protocol = ((struct ethhdr *)copy->data)->h_proto;
		if (skb_is_gso(copy)) {
			/* Unshare before GSO updates checksums or shared info. */
			if (skb_cow_head(copy, 0)) { err = -ENOMEM; goto drop; }
			segs = skb_gso_segment(copy, NETIF_F_SG);
			if (IS_ERR_OR_NULL(segs)) {
				err = segs ? PTR_ERR(segs) : -EINVAL; goto drop;
			}
			consume_skb(copy);
			copy = segs;
		}
		while (copy) {
			next = copy->next;
			skb_mark_not_on_list(copy);
			err = veer_pppoe_encap(copy, &c);
			if (err) { kfree_skb(copy); result = err; }
			else if (veer_send(copy, dev, false)) result = -ENOBUFS;
			copy = next;
		}
		goto out;
	}
	if (c.operation == VEER_PPPOE_DECAP) {
		err = veer_pppoe_decap(copy, &c);
	} else if (c.operation == VEER_L3_TO_ETH) {
		__be16 proto = copy->protocol;
		if (proto != htons(ETH_P_IP) && proto != htons(ETH_P_IPV6)) {
			err = -EPROTONOSUPPORT; goto drop;
		}
		if (skb_cow_head(copy, ETH_HLEN)) { err = -ENOMEM; goto drop; }
		skb_push(copy, ETH_HLEN);
		veer_eth(copy, &c, proto);
	} else {
		__be16 proto;
		if (!pskb_may_pull(copy, ETH_HLEN)) { err = -EINVAL; goto drop; }
		proto = ((struct ethhdr *)copy->data)->h_proto;
		if (proto != htons(ETH_P_IP) && proto != htons(ETH_P_IPV6)) {
			err = -EPROTONOSUPPORT; goto drop;
		}
		if (!skb_at_tc_ingress(skb))
			skb_postpull_rcsum(copy, copy->data, ETH_HLEN);
		skb_pull(copy, ETH_HLEN);
		skb_reset_mac_header(copy);
		skb_reset_network_header(copy);
		skb_reset_mac_len(copy);
		copy->protocol = proto;
	}
	if (!err) err = veer_clamp(copy, &c);
	if (err) goto drop;
	result = veer_send(copy, dev, ingress) ? -ENOBUFS : 0;
	goto out;
drop:
	kfree_skb(copy);
	result = err;
out:
	rcu_read_unlock();
	return result;
}

BTF_KFUNCS_START(veer_kfuncs_ids)
BTF_ID_FLAGS(func, veer_kfuncs_abi_v1)
BTF_ID_FLAGS(func, veer_skb_handoff_v1)
BTF_KFUNCS_END(veer_kfuncs_ids)
static const struct btf_kfunc_id_set veer_kfuncs_set = {
	.owner = THIS_MODULE, .set = &veer_kfuncs_ids,
};
static unsigned long long instance;
module_param(instance, ullong, 0444);
MODULE_PARM_DESC(instance, "Read-only identity of this module load (Veer ownership tracking)");
static int __init veer_kfuncs_init(void)
{
	int err;
	instance = get_random_u64();
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &veer_kfuncs_set);
	if (err) pr_err("veer_kfuncs: TC kfunc registration failed: %d\n", err);
	return err;
}
static void __exit veer_kfuncs_exit(void) {}
module_init(veer_kfuncs_init);
module_exit(veer_kfuncs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Optional Veer TC packet capabilities");
MODULE_VERSION("1.0.0");
