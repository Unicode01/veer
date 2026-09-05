#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t __u32;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#include "../internal/app/ebpf/include/forward_nat_probe.h"

int main(void)
{
	const uint32_t widths[] = {1, 2, 3, 6, 9, 15, 30, 32, 33, 64, 255, 1024, 45536};
	unsigned char seen[65536];
	for (unsigned int w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
		uint32_t width = widths[w];
		for (uint32_t seed = 0; seed < 64; seed++) {
			memset(seen, 0, sizeof(seen));
			uint32_t stride = nat_probe_stride(seed, width);
			for (uint32_t i = 0; i < width; i++) {
				uint32_t port = ((seed % width) + i * stride) % width;
				if (seen[port]) {
					fprintf(stderr, "repeated NAT probe: width=%u seed=%u i=%u\n", width, seed, i);
					return 1;
				}
				seen[port] = 1;
			}
		}
	}
	puts("NAT probe coverage tests passed");
	return 0;
}
