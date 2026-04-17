//go:build linux

package app

import (
	"fmt"
	"net"
)

type kernelPreparedAddr [16]byte

type kernelPreparedRuleSpec struct {
	Family      string
	DstAddr     kernelPreparedAddr
	BackendAddr kernelPreparedAddr
	NATAddr     kernelPreparedAddr
}

func kernelPreparedAddrFromIP(ip net.IP, family string) (kernelPreparedAddr, error) {
	var out kernelPreparedAddr
	ip = normalizeKernelFamilyIP(ip, family)
	if ip == nil {
		return out, fmt.Errorf("invalid %s address", kernelFamilyLabel(family))
	}
	if family == ipFamilyIPv4 {
		copy(out[12:], ip)
		return out, nil
	}
	copy(out[:], ip)
	return out, nil
}

func kernelPreparedAddrFromIPv4Uint32(value uint32) kernelPreparedAddr {
	var out kernelPreparedAddr
	out[12] = byte(value >> 24)
	out[13] = byte(value >> 16)
	out[14] = byte(value >> 8)
	out[15] = byte(value)
	return out
}

func (addr kernelPreparedAddr) isZero() bool {
	return addr == kernelPreparedAddr{}
}

func (addr kernelPreparedAddr) ipv4Uint32() (uint32, error) {
	if addr.isZero() {
		return 0, nil
	}
	return uint32(addr[12])<<24 | uint32(addr[13])<<16 | uint32(addr[14])<<8 | uint32(addr[15]), nil
}

func buildKernelPreparedForwardRuleSpec(rule Rule, resolveNAT func(family string) (net.IP, error)) (kernelPreparedRuleSpec, error) {
	pair := analyzeIPLiteralPair(rule.InIP, rule.OutIP)
	if pair.mixedFamily() {
		return kernelPreparedRuleSpec{}, fmt.Errorf("kernel dataplane does not support mixed IPv4/IPv6 forwarding")
	}

	family := pair.firstFamily
	if family == "" {
		family = pair.secondFamily
	}
	if family == "" {
		return kernelPreparedRuleSpec{}, fmt.Errorf("kernel dataplane requires valid inbound/outbound IP addresses")
	}

	inAddr, _, err := parseKernelInboundIP(rule.InIP, family)
	if err != nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("parse inbound ip %q: %w", rule.InIP, err)
	}
	outAddr, err := parseKernelExplicitIP(rule.OutIP, family)
	if err != nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("parse outbound ip %q: %w", rule.OutIP, err)
	}

	spec := kernelPreparedRuleSpec{Family: family}
	if spec.DstAddr, err = kernelPreparedAddrFromIP(inAddr, family); err != nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("prepare inbound %s address: %w", kernelFamilyLabel(family), err)
	}
	if spec.BackendAddr, err = kernelPreparedAddrFromIP(outAddr, family); err != nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("prepare outbound %s address: %w", kernelFamilyLabel(family), err)
	}

	if rule.Transparent {
		if family == ipFamilyIPv6 {
			return kernelPreparedRuleSpec{}, fmt.Errorf("kernel dataplane currently does not support transparent IPv6 rules")
		}
		return spec, nil
	}
	if resolveNAT == nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("missing outbound nat %s resolver", kernelFamilyLabel(family))
	}
	natIP, err := resolveNAT(family)
	if err != nil {
		return kernelPreparedRuleSpec{}, err
	}
	natIP = normalizeKernelFamilyIP(natIP, family)
	if natIP == nil || natIP.IsUnspecified() {
		return kernelPreparedRuleSpec{}, fmt.Errorf("missing outbound nat %s address", kernelFamilyLabel(family))
	}
	if spec.NATAddr, err = kernelPreparedAddrFromIP(natIP, family); err != nil {
		return kernelPreparedRuleSpec{}, fmt.Errorf("prepare outbound nat %s address: %w", kernelFamilyLabel(family), err)
	}
	return spec, nil
}
