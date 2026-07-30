package managednet

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/Unicode01/veer/internal/netutil"
)

const (
	IPv6AssignmentModeSingle128 = "single_128"
	IPv6AssignmentModePrefix64  = "prefix_64"
)

var (
	ipv6FullMask     = net.CIDRMask(128, 128)
	ipv6Prefix64Mask = net.CIDRMask(64, 128)
)

type IPv6PrefixIndex struct {
	mode     string
	exact128 map[[16]byte]struct{}
	exact64  map[[16]byte]struct{}
	broader  []*net.IPNet
	narrower []*net.IPNet
	generic  []*net.IPNet
}

func NewIPv6PrefixIndex(mode string, used []*net.IPNet) *IPv6PrefixIndex {
	return NewIPv6PrefixIndexWithCapacity(mode, used, 0)
}

func NewIPv6PrefixIndexWithCapacity(mode string, used []*net.IPNet, additionalExact int) *IPv6PrefixIndex {
	index := &IPv6PrefixIndex{mode: mode}
	if additionalExact > 0 {
		exactCapacity := len(used) + additionalExact
		switch mode {
		case IPv6AssignmentModeSingle128:
			index.exact128 = make(map[[16]byte]struct{}, exactCapacity)
		case IPv6AssignmentModePrefix64:
			index.exact64 = make(map[[16]byte]struct{}, exactCapacity)
		}
	}
	for _, prefix := range used {
		index.Add(prefix)
	}
	return index
}

func (index *IPv6PrefixIndex) Add(prefix *net.IPNet) {
	if index == nil || prefix == nil {
		return
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		index.generic = append(index.generic, prefix)
		return
	}
	switch index.mode {
	case IPv6AssignmentModeSingle128:
		if ones == 128 {
			key, ok := ipv6AddressKey(prefix.IP)
			if !ok {
				index.generic = append(index.generic, prefix)
				return
			}
			if index.exact128 == nil {
				index.exact128 = make(map[[16]byte]struct{})
			}
			index.exact128[key] = struct{}{}
			return
		}
		if ones < 128 {
			index.broader = append(index.broader, prefix)
			return
		}
	case IPv6AssignmentModePrefix64:
		if ones == 64 {
			key, ok := ipv6AddressKey(prefix.IP)
			if !ok {
				index.generic = append(index.generic, prefix)
				return
			}
			if index.exact64 == nil {
				index.exact64 = make(map[[16]byte]struct{})
			}
			index.exact64[key] = struct{}{}
			return
		}
		if ones < 64 {
			index.broader = append(index.broader, prefix)
			return
		}
		if ones > 64 {
			index.narrower = append(index.narrower, prefix)
			return
		}
	}
	index.generic = append(index.generic, prefix)
}

func (index *IPv6PrefixIndex) Overlaps(prefix *net.IPNet, used []*net.IPNet) bool {
	if index == nil || prefix == nil {
		return ipv6PrefixOverlapsAny(prefix, used)
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		return ipv6PrefixOverlapsAny(prefix, used)
	}

	switch index.mode {
	case IPv6AssignmentModeSingle128:
		if ones != 128 {
			return ipv6PrefixOverlapsAny(prefix, used)
		}
		if key, ok := ipv6AddressKey(prefix.IP); ok {
			if _, exists := index.exact128[key]; exists {
				return true
			}
		}
		for _, current := range index.broader {
			if current.Contains(prefix.IP) {
				return true
			}
		}
	case IPv6AssignmentModePrefix64:
		if ones != 64 {
			return ipv6PrefixOverlapsAny(prefix, used)
		}
		if key, ok := ipv6AddressKey(prefix.IP); ok {
			if _, exists := index.exact64[key]; exists {
				return true
			}
		}
		for _, current := range index.broader {
			if current.Contains(prefix.IP) {
				return true
			}
		}
		for _, current := range index.narrower {
			if prefix.Contains(current.IP) {
				return true
			}
		}
	default:
		return ipv6PrefixOverlapsAny(prefix, used)
	}

	for _, current := range index.generic {
		if netutil.IPv6PrefixesOverlap(prefix, current) {
			return true
		}
	}
	return false
}

func AllocateIPv6Prefix(mode string, parentPrefix *net.IPNet, seed uint64, used []*net.IPNet, index *IPv6PrefixIndex) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	if index == nil {
		index = NewIPv6PrefixIndex(mode, used)
	}
	for probe := 0; probe < 4096; probe++ {
		value := seed + uint64(probe)
		var (
			prefixText string
			prefixNet  *net.IPNet
			err        error
		)
		switch mode {
		case IPv6AssignmentModeSingle128:
			prefixText, prefixNet, err = AllocateSingleIPv6(parentPrefix, value)
		case IPv6AssignmentModePrefix64:
			prefixText, prefixNet, err = AllocateDelegatedIPv6Prefix(parentPrefix, value)
		default:
			return "", nil, fmt.Errorf("unsupported ipv6 assignment mode %q", mode)
		}
		if err != nil {
			return "", nil, err
		}
		if !index.Overlaps(prefixNet, used) {
			return prefixText, prefixNet, nil
		}
	}
	return "", nil, fmt.Errorf("no free ipv6 allocation slot remains inside %s", parentPrefix.String())
}

func AllocateSingleIPv6(parentPrefix *net.IPNet, seed uint64) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	ones, bits := parentPrefix.Mask.Size()
	if ones < 0 || bits != 128 || ones >= 128 {
		return "", nil, fmt.Errorf("parent prefix must leave room for /128 assignments")
	}
	hostBits := 128 - ones
	value := seed
	if hostBits <= 64 {
		value &= bitMask(hostBits)
		if hostBits > 1 && value == 0 {
			value = 1
		}
	}
	ip := applyLowBitsIPv6(parentPrefix.IP, value, ones)
	prefix := &net.IPNet{IP: ip, Mask: ipv6FullMask}
	return prefixText(ip, "/128"), prefix, nil
}

func AllocateDelegatedIPv6Prefix(parentPrefix *net.IPNet, seed uint64) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	ones, bits := parentPrefix.Mask.Size()
	if ones < 0 || bits != 128 {
		return "", nil, fmt.Errorf("parent prefix must be a valid IPv6 prefix")
	}
	if ones >= 64 {
		return "", nil, fmt.Errorf("parent prefix must be shorter than /64 for prefix_64 mode")
	}
	value := seed & bitMask(64-ones)
	ip := applyHighBitsIPv6(parentPrefix.IP, value, ones, 64).Mask(ipv6Prefix64Mask)
	prefix := &net.IPNet{IP: ip, Mask: ipv6Prefix64Mask}
	return prefixText(ip, "/64"), prefix, nil
}

func ipv6PrefixOverlapsAny(prefix *net.IPNet, used []*net.IPNet) bool {
	for _, current := range used {
		if netutil.IPv6PrefixesOverlap(prefix, current) {
			return true
		}
	}
	return false
}

func IPv6PrefixOverlapsAny(prefix *net.IPNet, used []*net.IPNet) bool {
	return ipv6PrefixOverlapsAny(prefix, used)
}

func ipv6AddressKey(ip net.IP) ([16]byte, bool) {
	var key [16]byte
	ip = ip.To16()
	if len(ip) != net.IPv6len {
		return key, false
	}
	copy(key[:], ip)
	return key, true
}

func prefixText(ip net.IP, suffix string) string {
	if key, ok := ipv6AddressKey(ip); ok {
		var buf [48]byte
		out := netip.AddrFrom16(key).AppendTo(buf[:0])
		out = append(out, suffix...)
		return string(out)
	}
	return netutil.CanonicalIPLiteral(ip) + suffix
}

func bitMask(bits int) uint64 {
	switch {
	case bits <= 0:
		return 0
	case bits >= 64:
		return ^uint64(0)
	default:
		return (uint64(1) << bits) - 1
	}
}

func applyLowBitsIPv6(baseIP net.IP, value uint64, prefixLen int) net.IP {
	ip := baseIP.To16()
	if len(ip) != net.IPv6len {
		return nil
	}
	out := append(net.IP(nil), ip...)
	switch {
	case prefixLen <= 0:
		for i := range out {
			out[i] = 0
		}
	case prefixLen < 128:
		fullBytes := prefixLen / 8
		remBits := prefixLen % 8
		if remBits != 0 {
			out[fullBytes] &= byte(0xff << (8 - remBits))
			fullBytes++
		}
		for i := fullBytes; i < len(out); i++ {
			out[i] = 0
		}
	}
	var low [8]byte
	binary.BigEndian.PutUint64(low[:], value)
	if prefixLen <= 64 {
		copy(out[8:], low[:])
		return out
	}
	if prefixLen >= 128 {
		return out
	}
	keepBits := prefixLen - 64
	keepBytes := keepBits / 8
	keepRemainder := keepBits % 8
	target := out[8:]
	if keepRemainder == 0 {
		copy(target[keepBytes:], low[keepBytes:])
		return out
	}
	mask := byte(0xff << (8 - keepRemainder))
	target[keepBytes] = (target[keepBytes] & mask) | (low[keepBytes] &^ mask)
	copy(target[keepBytes+1:], low[keepBytes+1:])
	return out
}

func applyHighBitsIPv6(baseIP net.IP, value uint64, prefixLen, targetPrefixLen int) net.IP {
	ip := append(net.IP(nil), baseIP.Mask(net.CIDRMask(prefixLen, 128))...)
	if len(ip) != net.IPv6len {
		ip = append(net.IP(nil), baseIP.To16()...)
	}
	availableBits := targetPrefixLen - prefixLen
	for i := 0; i < availableBits && i < 64; i++ {
		bitPos := targetPrefixLen - 1 - i
		netutil.SetIPv6Bit(ip, bitPos, (value>>i)&1 == 1)
	}
	return ip
}
