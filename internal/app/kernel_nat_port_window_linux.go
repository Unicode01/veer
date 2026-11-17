//go:build linux

package app

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Unicode01/veer/internal/netutil"
)

const hostEphemeralPortRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

// readHostEphemeralPortRange returns the range the kernel picks local ports
// of the host's own connections from. Tests replace it.
var readHostEphemeralPortRange = func() (int, int, error) {
	data, err := os.ReadFile(hostEphemeralPortRangePath)
	if err != nil {
		return 0, 0, err
	}
	var low, high int
	if _, err := fmt.Sscan(strings.TrimSpace(string(data)), &low, &high); err != nil {
		return 0, 0, fmt.Errorf("parse %s: %w", hostEphemeralPortRangePath, err)
	}
	return low, high, nil
}

// effectiveKernelNATPortWindow is the port window the kernel NAT allocates
// from: the configured pool less the host's ephemeral range, so that a NAT
// mapping never takes the replies of a connection the host itself opened
// from the same address (see netutil.KernelNATPortWindow).
func effectiveKernelNATPortWindow(engine string, configuredMin int, configuredMax int) (int, int) {
	poolMin, poolMax := effectiveKernelNATPortRange(configuredMin, configuredMax)
	ephemeralMin, ephemeralMax, err := readHostEphemeralPortRange()
	if err != nil {
		log.Printf("%s dataplane: kernel NAT uses ports %d-%d; the host's ephemeral port range is unknown (%v), so they may collide with the host's own connections", engine, poolMin, poolMax, err)
		return poolMin, poolMax
	}
	portMin, portMax, shared := netutil.KernelNATPortWindow(poolMin, poolMax, ephemeralMin, ephemeralMax)
	switch {
	case shared:
		log.Printf("%s dataplane: kernel NAT ports %d-%d lie inside the host's ephemeral ports %d-%d (net.ipv4.ip_local_port_range); replies to the host's own connections from a NAT address can reach a guest instead, so move kernel_nat_port_min/kernel_nat_port_max outside that range", engine, poolMin, poolMax, ephemeralMin, ephemeralMax)
	case portMin != poolMin || portMax != poolMax:
		log.Printf("%s dataplane: kernel NAT uses ports %d-%d: the pool %d-%d less the host's ephemeral ports %d-%d", engine, portMin, portMax, poolMin, poolMax, ephemeralMin, ephemeralMax)
	}
	return portMin, portMax
}
