#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../internal/app/ebpf/include/forward_flow_time.h"

int main(void)
{
	const uint64_t second = 1000000000ULL;
	const uint64_t now = 1000 * second;
	const uint64_t idle = 300 * second;

	assert(!forward_flow_idle_expired(now, now + 1, idle));
	assert(!forward_flow_idle_expired(now, now + 1000000, idle));
	assert(!forward_flow_idle_expired(now, now + second, idle));
	assert(!forward_flow_idle_expired(now, UINT64_MAX, idle));
	assert(!forward_flow_idle_expired(now, now, idle));
	assert(!forward_flow_idle_expired(now, now - 1, idle));
	assert(!forward_flow_idle_expired(now, now - idle, idle));
	assert(forward_flow_idle_expired(now, now - idle - 1, idle));
	assert(forward_flow_idle_expired(now, 0, idle));
	puts("flow timestamp boundaries passed");
	return 0;
}
