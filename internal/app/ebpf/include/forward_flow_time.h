#ifndef FORWARD_FLOW_TIME_H
#define FORWARD_FLOW_TIME_H

#include <linux/types.h>

/* Another CPU can refresh a shared flow after this packet samples its clock.
 * A newer last_seen is active; subtracting it would underflow and expire it.
 */
static inline __attribute__((always_inline)) int forward_flow_idle_expired(__u64 now, __u64 last_seen, __u64 timeout)
{
	return last_seen == 0 || (now >= last_seen && now - last_seen > timeout);
}

#endif
