package netutil

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeIPv6Prefix validates and canonicalizes an IPv6 CIDR prefix.
func NormalizeIPv6Prefix(value string) (string, *net.IPNet, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", nil, fmt.Errorf("is required")
	}
	ip, prefix, err := net.ParseCIDR(text)
	if err != nil || ip == nil || ip.To4() != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	ip = ip.To16()
	if ip == nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	prefix = &net.IPNet{
		IP:   append(net.IP(nil), ip.Mask(prefix.Mask)...),
		Mask: append(net.IPMask(nil), prefix.Mask...),
	}
	if prefix.IP == nil || prefix.IP.To4() != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	return prefix.String(), prefix, nil
}

func IPv6PrefixContains(parent, child *net.IPNet) bool {
	if parent == nil || child == nil {
		return false
	}
	parentOnes, parentBits := parent.Mask.Size()
	childOnes, childBits := child.Mask.Size()
	if parentOnes < 0 || childOnes < 0 || parentBits != 128 || childBits != 128 || childOnes < parentOnes {
		return false
	}
	childIP := child.IP.Mask(child.Mask)
	return childIP != nil && parent.Contains(childIP)
}

func IPv6PrefixesOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	aOnes, aBits := a.Mask.Size()
	bOnes, bBits := b.Mask.Size()
	if aOnes < 0 || bOnes < 0 || aBits != 128 || bBits != 128 {
		return false
	}
	return a.Contains(b.IP.Mask(b.Mask)) || b.Contains(a.IP.Mask(a.Mask))
}

func CloneIPNet(prefix *net.IPNet) *net.IPNet {
	if prefix == nil {
		return nil
	}
	return &net.IPNet{
		IP:   append(net.IP(nil), prefix.IP...),
		Mask: append(net.IPMask(nil), prefix.Mask...),
	}
}

// RebaseIPv6PrefixWithinParent keeps the assigned subnet/host bits while
// replacing the parent bits with the current parent prefix.
func RebaseIPv6PrefixWithinParent(storedParent, currentParent, assigned *net.IPNet) (*net.IPNet, error) {
	if storedParent == nil || currentParent == nil || assigned == nil {
		return nil, fmt.Errorf("stored parent, current parent, and assigned prefix are required")
	}
	storedOnes, storedBits := storedParent.Mask.Size()
	currentOnes, currentBits := currentParent.Mask.Size()
	assignedOnes, assignedBits := assigned.Mask.Size()
	if storedOnes < 0 || currentOnes < 0 || assignedOnes < 0 || storedBits != 128 || currentBits != 128 || assignedBits != 128 {
		return nil, fmt.Errorf("all prefixes must be valid IPv6 prefixes")
	}
	if storedOnes != currentOnes {
		return nil, fmt.Errorf("parent prefix length changed from /%d to /%d", storedOnes, currentOnes)
	}
	if assignedOnes < storedOnes {
		return nil, fmt.Errorf("assigned prefix %s is shorter than parent prefix %s", assigned.String(), storedParent.String())
	}

	currentIP := currentParent.IP.Mask(currentParent.Mask).To16()
	if len(currentIP) != net.IPv6len {
		return nil, fmt.Errorf("current parent prefix %s must use a valid IPv6 address", currentParent.String())
	}
	assignedIP := assigned.IP.Mask(assigned.Mask).To16()
	if len(assignedIP) != net.IPv6len {
		return nil, fmt.Errorf("assigned prefix %s must use a valid IPv6 address", assigned.String())
	}

	ip := append(net.IP(nil), currentIP...)
	for bitPos := storedOnes; bitPos < assignedOnes; bitPos++ {
		SetIPv6Bit(ip, bitPos, IPv6BitIsSet(assignedIP, bitPos))
	}
	ip = ip.Mask(net.CIDRMask(assignedOnes, 128))
	return &net.IPNet{
		IP:   append(net.IP(nil), ip...),
		Mask: append(net.IPMask(nil), assigned.Mask...),
	}, nil
}

func IPv6BitIsSet(ip net.IP, bitPos int) bool {
	ip = ip.To16()
	if len(ip) != net.IPv6len || bitPos < 0 || bitPos >= 128 {
		return false
	}
	byteIndex := bitPos / 8
	bitIndex := 7 - (bitPos % 8)
	return ip[byteIndex]&(1<<bitIndex) != 0
}

func SetIPv6Bit(ip net.IP, bitPos int, on bool) {
	if len(ip) != net.IPv6len || bitPos < 0 || bitPos >= 128 {
		return
	}
	byteIndex := bitPos / 8
	bitIndex := 7 - (bitPos % 8)
	if on {
		ip[byteIndex] |= 1 << bitIndex
		return
	}
	ip[byteIndex] &^= 1 << bitIndex
}
