package app

import "fmt"

const (
	kernelDefaultNATPortMin     = 20000
	kernelDefaultNATPortMax     = 65535
	kernelMinimumAllowedNATPort = 1024
	kernelMaximumAllowedNATPort = 65535
)

func normalizeKernelNATPortRange(portMin int, portMax int) (int, int, error) {
	if portMin <= 0 {
		portMin = kernelDefaultNATPortMin
	}
	if portMax <= 0 {
		portMax = kernelDefaultNATPortMax
	}
	if portMin < kernelMinimumAllowedNATPort || portMin > kernelMaximumAllowedNATPort {
		return 0, 0, fmt.Errorf("kernel_nat_port_min must be within %d-%d", kernelMinimumAllowedNATPort, kernelMaximumAllowedNATPort)
	}
	if portMax < kernelMinimumAllowedNATPort || portMax > kernelMaximumAllowedNATPort {
		return 0, 0, fmt.Errorf("kernel_nat_port_max must be within %d-%d", kernelMinimumAllowedNATPort, kernelMaximumAllowedNATPort)
	}
	if portMin > portMax {
		return 0, 0, fmt.Errorf("kernel_nat_port_min must be less than or equal to kernel_nat_port_max")
	}
	return portMin, portMax, nil
}

func effectiveKernelNATPortRange(portMin int, portMax int) (int, int) {
	min, max, err := normalizeKernelNATPortRange(portMin, portMax)
	if err != nil {
		return kernelDefaultNATPortMin, kernelDefaultNATPortMax
	}
	return min, max
}
