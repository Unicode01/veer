#ifndef FORWARD_ADDR_HELPERS_H
#define FORWARD_ADDR_HELPERS_H

static __always_inline void copy_ipv6_addr(__u8 dst[16], const __u8 src[16])
{
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	dst[4] = src[4];
	dst[5] = src[5];
	dst[6] = src[6];
	dst[7] = src[7];
	dst[8] = src[8];
	dst[9] = src[9];
	dst[10] = src[10];
	dst[11] = src[11];
	dst[12] = src[12];
	dst[13] = src[13];
	dst[14] = src[14];
	dst[15] = src[15];
}

static __always_inline int ipv6_addr_equal(const __u8 a[16], const __u8 b[16])
{
	int i;
	__u8 diff = 0;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

static __always_inline int ipv6_addr_is_zero(const __u8 addr[16])
{
	int i;
	__u8 acc = 0;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++)
		acc |= addr[i];
	return acc == 0;
}

static __always_inline int mac_addr_is_zero(const __u8 addr[ETH_ALEN])
{
	int i;
	__u8 acc = 0;

#pragma clang loop unroll(full)
	for (i = 0; i < ETH_ALEN; i++)
		acc |= addr[i];
	return acc == 0;
}

static __always_inline __u32 mix_ipv6_addr_seed(__u32 seed, const __u8 addr[16])
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < 16; i++) {
		seed ^= ((__u32)addr[i]) << ((i & 3) * 8);
		seed *= 2246822519U;
		seed ^= seed >> 13;
	}
	return seed;
}

#endif
