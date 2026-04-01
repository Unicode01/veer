#ifndef __FORWARD_BPF_ENDIAN_H
#define __FORWARD_BPF_ENDIAN_H

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#else
#define bpf_htons(x) ((__u16)(x))
#define bpf_ntohs(x) ((__u16)(x))
#define bpf_htonl(x) ((__u32)(x))
#define bpf_ntohl(x) ((__u32)(x))
#endif

#endif
