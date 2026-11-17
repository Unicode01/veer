package netutil

import "fmt"

const (
	KernelDefaultNATPortMin     = 20000
	KernelDefaultNATPortMax     = 65535
	KernelMinimumAllowedNATPort = 1024
	KernelMaximumAllowedNATPort = 65535
)

func NormalizeKernelNATPortRange(portMin int, portMax int) (int, int, error) {
	if portMin <= 0 {
		portMin = KernelDefaultNATPortMin
	}
	if portMax <= 0 {
		portMax = KernelDefaultNATPortMax
	}
	if portMin < KernelMinimumAllowedNATPort || portMin > KernelMaximumAllowedNATPort {
		return 0, 0, fmt.Errorf("kernel_nat_port_min must be within %d-%d", KernelMinimumAllowedNATPort, KernelMaximumAllowedNATPort)
	}
	if portMax < KernelMinimumAllowedNATPort || portMax > KernelMaximumAllowedNATPort {
		return 0, 0, fmt.Errorf("kernel_nat_port_max must be within %d-%d", KernelMinimumAllowedNATPort, KernelMaximumAllowedNATPort)
	}
	if portMin > portMax {
		return 0, 0, fmt.Errorf("kernel_nat_port_min must be less than or equal to kernel_nat_port_max")
	}
	return portMin, portMax, nil
}

func EffectiveKernelNATPortRange(portMin int, portMax int) (int, int) {
	min, max, err := NormalizeKernelNATPortRange(portMin, portMax)
	if err != nil {
		return KernelDefaultNATPortMin, KernelDefaultNATPortMax
	}
	return min, max
}

// KernelNATPortWindow returns the ports of the NAT pool [poolMin, poolMax]
// that the host's own connections do not take: the pool less the ephemeral
// range [ephemeralMin, ephemeralMax] the kernel picks local ports from. A NAT
// address is an address of the host, so a mapping on a port the host also
// uses would take the replies of the host's connection (a full-cone reply
// entry matches any remote). Of the two parts the overlap can leave, the
// larger wins, the lower one on a tie. A pool entirely inside the ephemeral
// range is kept as configured, and shared then reports that it still
// overlaps. An unknown ephemeral range (ephemeralMin <= 0) leaves the pool.
func KernelNATPortWindow(poolMin, poolMax, ephemeralMin, ephemeralMax int) (min int, max int, shared bool) {
	if ephemeralMin <= 0 || ephemeralMax < ephemeralMin || poolMax < ephemeralMin || poolMin > ephemeralMax {
		return poolMin, poolMax, false
	}
	below := ephemeralMin - poolMin // ports in [poolMin, ephemeralMin-1]
	above := poolMax - ephemeralMax // ports in [ephemeralMax+1, poolMax]
	switch {
	case below <= 0 && above <= 0:
		return poolMin, poolMax, true
	case below >= above:
		return poolMin, ephemeralMin - 1, false
	default:
		return ephemeralMax + 1, poolMax, false
	}
}
