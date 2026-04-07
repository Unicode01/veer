package app

import (
	"fmt"
	"net"
	"strings"
)

func kernelFamilyLabel(family string) string {
	switch family {
	case ipFamilyIPv6:
		return "IPv6"
	default:
		return "IPv4"
	}
}

func normalizeKernelFamilyIP(ip net.IP, family string) net.IP {
	if ip == nil {
		return nil
	}
	switch family {
	case ipFamilyIPv6:
		if ip.To4() != nil {
			return nil
		}
		return ip.To16()
	default:
		return ip.To4()
	}
}

func zeroKernelFamilyIP(family string) net.IP {
	switch family {
	case ipFamilyIPv6:
		return net.IPv6zero
	default:
		return net.IPv4zero
	}
}

func parseKernelExplicitIP(text string, family string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(text))
	if ip == nil {
		return nil, fmt.Errorf("invalid %s address", kernelFamilyLabel(family))
	}
	ip = normalizeKernelFamilyIP(ip, family)
	if ip == nil {
		return nil, fmt.Errorf("invalid %s address", kernelFamilyLabel(family))
	}
	if ip.IsUnspecified() {
		return nil, fmt.Errorf("must be an explicit %s address", kernelFamilyLabel(family))
	}
	return ip, nil
}

func parseKernelInboundIP(text string, family string) (net.IP, bool, error) {
	ip := net.ParseIP(strings.TrimSpace(text))
	if ip == nil {
		return nil, false, fmt.Errorf("invalid %s address", kernelFamilyLabel(family))
	}
	ip = normalizeKernelFamilyIP(ip, family)
	if ip == nil {
		return nil, false, fmt.Errorf("invalid %s address", kernelFamilyLabel(family))
	}
	if ip.IsUnspecified() {
		return zeroKernelFamilyIP(family), true, nil
	}
	return ip, false, nil
}

func splitKernelUsableSourceIPs(addrs []net.IP, family string) ([]net.IP, []net.IP) {
	if len(addrs) == 0 {
		return nil, nil
	}
	usable := make([]net.IP, 0, len(addrs))
	linkLocal := make([]net.IP, 0, len(addrs))
	seenUsable := make(map[string]struct{}, len(addrs))
	seenLinkLocal := make(map[string]struct{}, len(addrs))
	for _, raw := range addrs {
		ip := normalizeKernelFamilyIP(raw, family)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		key := canonicalIPLiteral(ip)
		if ip.IsLinkLocalUnicast() {
			if _, ok := seenLinkLocal[key]; ok {
				continue
			}
			seenLinkLocal[key] = struct{}{}
			linkLocal = append(linkLocal, ip)
			continue
		}
		if _, ok := seenUsable[key]; ok {
			continue
		}
		seenUsable[key] = struct{}{}
		usable = append(usable, ip)
	}
	return usable, linkLocal
}

func selectKernelAutoSourceIP(ifaceName string, family string, usable []net.IP, linkLocal []net.IP) (net.IP, error) {
	label := kernelFamilyLabel(family)
	if len(usable) == 1 {
		return usable[0], nil
	}
	if len(usable) > 1 {
		return nil, fmt.Errorf("auto outbound source %s on %q is ambiguous (%d %s addresses assigned); set out_source_ip explicitly", label, ifaceName, len(usable), label)
	}
	if len(linkLocal) == 1 {
		return linkLocal[0], nil
	}
	if len(linkLocal) > 1 {
		return nil, fmt.Errorf("auto outbound source %s on %q is ambiguous (%d link-local %s addresses assigned); set out_source_ip explicitly", label, ifaceName, len(linkLocal), label)
	}
	return nil, fmt.Errorf("no %s address is assigned", label)
}
