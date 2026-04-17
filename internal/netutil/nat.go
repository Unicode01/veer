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
