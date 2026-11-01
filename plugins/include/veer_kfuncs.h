/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef VEER_KFUNCS_H
#define VEER_KFUNCS_H
struct veer_handoff_v1 {
	__u32 output;
	__u32 mtu;
	__u16 session;
	__u16 operation;
	__u8 source[6];
	__u8 destination[6];
	__u16 mss_v4;
	__u16 mss_v6;
};
#define VEER_PPPOE_ENCAP 1
#define VEER_PPPOE_DECAP 2
#define VEER_L3_TO_ETH 3
#define VEER_ETH_TO_L3 4
extern __u32 veer_kfuncs_abi_v1(void) __attribute__((section(".ksyms")));
/* Optional helper-owned Ethernet WAN boundary with receive GRO cells. */
extern __u32 veer_kfuncs_wan_v1(void) __attribute__((section(".ksyms")));
extern int veer_skb_handoff_v1(struct __sk_buff *, const struct veer_handoff_v1 *) __attribute__((section(".ksyms")));
/* Optional receive injection: L3_TO_ETH followed by target TC ingress. */
extern int veer_skb_handoff_ingress_v1(struct __sk_buff *, const struct veer_handoff_v1 *) __attribute__((section(".ksyms")));
/* Always terminate afterwards so TC releases the original skb: STOLEN on
 * success (required for local egress), SHOT on error. Ingress callers may
 * also return SHOT on success. Never fall through to host routing.
 */
#endif
