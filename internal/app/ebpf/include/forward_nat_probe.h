#ifndef FORWARD_NAT_PROBE_H
#define FORWARD_NAT_PROBE_H

static __always_inline __u32 nat_probe_stride(__u32 seed, __u32 port_range)
{
	/* The start is randomized separately. Forward/reverse linear probes visit each port once
	 * for every pool width; an odd stride is not necessarily coprime. */
	if (port_range <= 1U || (seed & 1U))
		return 1U;
	return port_range - 1U;
}

#endif
