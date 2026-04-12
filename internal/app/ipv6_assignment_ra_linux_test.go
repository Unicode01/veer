//go:build linux

package app

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
)

func TestIsIPv6RouterSolicitationFrame(t *testing.T) {
	t.Parallel()

	frame := make([]byte, 14+40+8)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14:]
	ipv6Header[0] = 0x60
	ipv6Header[6] = ipv6NextHeaderICMPv6
	ipv6Header[7] = ipv6RAHopLimit

	icmp := ipv6Header[40:]
	icmp[0] = icmpv6TypeRouterSolicit

	if !isIPv6RouterSolicitationFrame(frame) {
		t.Fatal("isIPv6RouterSolicitationFrame() = false, want true")
	}

	icmp[0] = 134
	if isIPv6RouterSolicitationFrame(frame) {
		t.Fatal("isIPv6RouterSolicitationFrame() = true for router advertisement, want false")
	}

	icmp[0] = icmpv6TypeRouterSolicit
	ipv6Header[7] = 64
	if isIPv6RouterSolicitationFrame(frame) {
		t.Fatal("isIPv6RouterSolicitationFrame() = true with hop limit 64, want false")
	}
}

func TestIPv6RouterSolicitationSocketFilter(t *testing.T) {
	t.Parallel()

	vm, err := bpf.NewVM(buildIPv6RouterSolicitationSocketFilter())
	if err != nil {
		t.Fatalf("bpf.NewVM() error = %v", err)
	}

	frame := make([]byte, 14+40+8)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14:]
	ipv6Header[0] = 0x60
	ipv6Header[6] = ipv6NextHeaderICMPv6
	ipv6Header[7] = ipv6RAHopLimit

	icmp := ipv6Header[40:]
	icmp[0] = icmpv6TypeRouterSolicit

	out, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run(valid RS) error = %v", err)
	}
	if out != int(packetSocketAcceptBytes) {
		t.Fatalf("vm.Run(valid RS) = %d, want %d", out, packetSocketAcceptBytes)
	}

	icmp[0] = 134
	out, err = vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run(RA frame) error = %v", err)
	}
	if out != 0 {
		t.Fatalf("vm.Run(RA frame) = %d, want 0", out)
	}
}

func TestBuildIPv6RouterAdvertisementPayloadIncludesAutonomousPrefixInfo(t *testing.T) {
	t.Parallel()

	payload, err := buildIPv6RouterAdvertisementPayload(ipv6RouterAdvertisementState{
		MTU:   1500,
		MAC:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		SrcIP: net.ParseIP("fe80::1"),
		DstIP: net.ParseIP("ff02::1"),
		Config: ipv6AssignmentRAConfig{
			TargetInterface: "tap100i0",
			Prefixes:        []string{"2402:db8:100:1::/64"},
		},
	})
	if err != nil {
		t.Fatalf("buildIPv6RouterAdvertisementPayload() error = %v", err)
	}

	body := parseIPv6RouterAdvertisementBody(t, payload)
	if body[1]&0x80 != 0 {
		t.Fatalf("managed flag = %#x, want clear for prefix-only SLAAC RA", body[1])
	}

	options := parseIPv6RouterAdvertisementOptions(t, body[12:])
	prefixInfo := findIPv6RouterAdvertisementOption(options, 3)
	if len(prefixInfo) != 1 {
		t.Fatalf("prefix info option count = %d, want 1", len(prefixInfo))
	}
	if prefixInfo[0][2] != 64 {
		t.Fatalf("prefix length = %d, want 64", prefixInfo[0][2])
	}
	if prefixInfo[0][3]&0xc0 != 0xc0 {
		t.Fatalf("prefix flags = %#x, want both on-link and autonomous bits", prefixInfo[0][3])
	}
	if got := binary.BigEndian.Uint32(prefixInfo[0][4:8]); got != uint32(ipv6RAValidLifetime/time.Second) {
		t.Fatalf("valid lifetime = %d, want %d", got, uint32(ipv6RAValidLifetime/time.Second))
	}
	if got := binary.BigEndian.Uint32(prefixInfo[0][8:12]); got != uint32(ipv6RAPreferredLifetime/time.Second) {
		t.Fatalf("preferred lifetime = %d, want %d", got, uint32(ipv6RAPreferredLifetime/time.Second))
	}
	if len(findIPv6RouterAdvertisementOption(options, 24)) != 0 {
		t.Fatal("route info option present for pure SLAAC prefix RA, want none")
	}
}

func TestBuildIPv6RouterAdvertisementPayloadManagedRouteOnly(t *testing.T) {
	t.Parallel()

	payload, err := buildIPv6RouterAdvertisementPayload(ipv6RouterAdvertisementState{
		MTU:   1500,
		MAC:   net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		SrcIP: net.ParseIP("fe80::1"),
		DstIP: net.ParseIP("ff02::1"),
		Config: ipv6AssignmentRAConfig{
			TargetInterface: "tap100i0",
			Managed:         true,
			Routes:          []string{"2402:db8::/64"},
		},
	})
	if err != nil {
		t.Fatalf("buildIPv6RouterAdvertisementPayload() error = %v", err)
	}

	body := parseIPv6RouterAdvertisementBody(t, payload)
	if body[1]&0x80 == 0 {
		t.Fatalf("managed flag = %#x, want set for DHCPv6-assisted RA", body[1])
	}

	options := parseIPv6RouterAdvertisementOptions(t, body[12:])
	if len(findIPv6RouterAdvertisementOption(options, 3)) != 0 {
		t.Fatal("prefix info option present for route-only managed RA, want none")
	}
	routeInfo := findIPv6RouterAdvertisementOption(options, 24)
	if len(routeInfo) != 1 {
		t.Fatalf("route info option count = %d, want 1", len(routeInfo))
	}
	if routeInfo[0][2] != 64 {
		t.Fatalf("route prefix length = %d, want 64", routeInfo[0][2])
	}
	if got := binary.BigEndian.Uint32(routeInfo[0][4:8]); got != uint32(ipv6RARouterLifetime/time.Second) {
		t.Fatalf("route lifetime = %d, want %d", got, uint32(ipv6RARouterLifetime/time.Second))
	}
}

func parseIPv6RouterAdvertisementBody(t *testing.T, payload []byte) []byte {
	t.Helper()
	if len(payload) < 16 {
		t.Fatalf("payload length = %d, want at least 16", len(payload))
	}
	if payload[0] != byte(ipv6.ICMPTypeRouterAdvertisement) {
		t.Fatalf("icmpv6 type = %d, want %d", payload[0], ipv6.ICMPTypeRouterAdvertisement)
	}
	return payload[4:]
}

func parseIPv6RouterAdvertisementOptions(t *testing.T, options []byte) [][]byte {
	t.Helper()
	parsed := make([][]byte, 0, 4)
	for len(options) > 0 {
		if len(options) < 2 {
			t.Fatalf("router advertisement option truncated: %d byte(s) remain", len(options))
		}
		optionLenUnits := int(options[1])
		if optionLenUnits == 0 {
			t.Fatal("router advertisement option length = 0")
		}
		optionLen := optionLenUnits * 8
		if optionLen > len(options) {
			t.Fatalf("router advertisement option length = %d exceeds remaining %d", optionLen, len(options))
		}
		parsed = append(parsed, append([]byte(nil), options[:optionLen]...))
		options = options[optionLen:]
	}
	return parsed
}

func findIPv6RouterAdvertisementOption(options [][]byte, optionType byte) [][]byte {
	matches := make([][]byte, 0, len(options))
	for _, option := range options {
		if len(option) == 0 || option[0] != optionType {
			continue
		}
		matches = append(matches, option)
	}
	return matches
}
