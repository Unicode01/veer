//go:build linux

package netservice

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
	binary.BigEndian.PutUint16(ipv6Header[4:6], 8)
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

func TestIPv6RouterAdvertiserUpdateOnlyTriggersOnChange(t *testing.T) {
	t.Parallel()

	prefixes := []string{"2001:db8:100::/64"}
	config := ipv6AssignmentRAConfig{
		TargetInterface: "br-lan",
		Prefixes:        prefixes,
		DNSServers:      []string{"2001:4860:4860::8888"},
	}
	advertiser := newIPv6RouterAdvertiser(config)
	prefixes[0] = "2001:db8:bad::/64"
	if got := advertiser.snapshot().Prefixes[0]; got != "2001:db8:100::/64" {
		t.Fatalf("new advertiser retained caller-owned prefix slice: %q", got)
	}

	if advertiser.update(advertiser.snapshot()) {
		t.Fatal("equivalent router advertisement update reported a change")
	}
	select {
	case <-advertiser.wakeCh:
		t.Fatal("equivalent router advertisement update triggered an immediate send")
	default:
	}

	changed := advertiser.snapshot()
	changed.DNSServers[0] = "2400:3200::1"
	if !advertiser.update(changed) {
		t.Fatal("changed router advertisement update was ignored")
	}
	select {
	case <-advertiser.wakeCh:
	default:
		t.Fatal("changed router advertisement update did not trigger an immediate send")
	}
	changed.DNSServers[0] = "2001:db8::bad"
	if got := advertiser.snapshot().DNSServers[0]; got != "2400:3200::1" {
		t.Fatalf("router advertisement update retained caller-owned DNS slice: %q", got)
	}
}

func TestIPv6RouterSolicitationTriggerIsCoalesced(t *testing.T) {
	t.Parallel()

	adv := newIPv6RouterAdvertiser(ipv6AssignmentRAConfig{TargetInterface: "br-lan"})
	if !adv.triggerRouterSolicitation() {
		t.Fatal("first router solicitation did not trigger an advertisement")
	}
	select {
	case <-adv.rsWakeCh:
	default:
		t.Fatal("first router solicitation did not queue an advertisement")
	}
	if adv.triggerRouterSolicitation() {
		t.Fatal("router solicitation bypassed pending-request coalescing")
	}
	select {
	case <-adv.rsWakeCh:
		t.Fatal("coalesced router solicitation queued another advertisement")
	default:
	}
	adv.clearRouterSolicitationPending()
	if !adv.triggerRouterSolicitation() {
		t.Fatal("router solicitation remained blocked after pending send completed")
	}
}

func TestIPv6RouterSolicitationDelayUsesLastSendAttempt(t *testing.T) {
	t.Parallel()

	adv := newIPv6RouterAdvertiser(ipv6AssignmentRAConfig{TargetInterface: "br-lan"})
	now := time.Now()
	if delay := adv.routerSolicitationDelay(now); delay != 0 {
		t.Fatalf("initial router solicitation delay = %s, want 0", delay)
	}
	adv.mu.Lock()
	adv.lastSendAttempt = now
	adv.mu.Unlock()
	if delay := adv.routerSolicitationDelay(now.Add(time.Second)); delay != 2*time.Second {
		t.Fatalf("rate-limited router solicitation delay = %s, want 2s", delay)
	}
	if delay := adv.routerSolicitationDelay(now.Add(ipv6RAMinSolicitedInterval)); delay != 0 {
		t.Fatalf("expired router solicitation delay = %s, want 0", delay)
	}
}

func TestIPv6RouterSolicitationLogThrottleIgnoresAlternatingText(t *testing.T) {
	t.Parallel()

	adv := newIPv6RouterAdvertiser(ipv6AssignmentRAConfig{TargetInterface: "br-lan"})
	adv.logRouterSolicitationIssue("first")
	adv.mu.Lock()
	logAt := adv.lastRSIssueLogAt
	adv.mu.Unlock()

	adv.logRouterSolicitationIssue("second")
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if !adv.lastRSIssueLogAt.Equal(logAt) {
		t.Fatal("alternating message text bypassed router solicitation log throttle")
	}
	if adv.lastRSIssue != "second" {
		t.Fatal("suppressed router solicitation log did not retain current runtime detail")
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

func TestBuildIPv6RouterAdvertisementPayloadIncludesRDNSS(t *testing.T) {
	t.Parallel()

	payload, err := buildIPv6RouterAdvertisementPayload(ipv6RouterAdvertisementState{
		MTU:   1500,
		MAC:   net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		SrcIP: net.ParseIP("fe80::1"),
		DstIP: net.ParseIP("ff02::1"),
		Config: ipv6AssignmentRAConfig{
			TargetInterface: "br-lan",
			Prefixes:        []string{"2001:db8:100::/64"},
			DNSServers:      []string{"2001:4860:4860::8888", "2400:3200::1"},
		},
	})
	if err != nil {
		t.Fatalf("buildIPv6RouterAdvertisementPayload() error = %v", err)
	}
	options := parseIPv6RouterAdvertisementOptions(t, parseIPv6RouterAdvertisementBody(t, payload)[12:])
	rdnss := findIPv6RouterAdvertisementOption(options, 25)
	if len(rdnss) != 1 || len(rdnss[0]) != 40 || rdnss[0][1] != 5 {
		t.Fatalf("RDNSS options = %v, want one 40-byte option", rdnss)
	}
	if got := binary.BigEndian.Uint32(rdnss[0][4:8]); got != uint32(ipv6RDNSSLifetime/time.Second) {
		t.Fatalf("RDNSS lifetime = %d", got)
	}
	if !net.IP(rdnss[0][8:24]).Equal(net.ParseIP("2001:4860:4860::8888")) || !net.IP(rdnss[0][24:40]).Equal(net.ParseIP("2400:3200::1")) {
		t.Fatalf("RDNSS addresses = %v, %v", net.IP(rdnss[0][8:24]), net.IP(rdnss[0][24:40]))
	}
}

func TestBuildIPv6RDNSSOptionRejectsTooManyServers(t *testing.T) {
	t.Parallel()

	servers := []string{
		"2001:db8::1", "2001:db8::2", "2001:db8::3",
		"2001:db8::4", "2001:db8::5", "2001:db8::6",
		"2001:db8::7", "2001:db8::8", "2001:db8::9",
	}
	if _, err := buildIPv6RDNSSOption(servers, ipv6RDNSSLifetime); err == nil {
		t.Fatal("buildIPv6RDNSSOption() error = nil, want DNS server limit")
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

func FuzzIsIPv6RouterSolicitationFrame(f *testing.F) {
	f.Add(make([]byte, 14+40+8))
	f.Add([]byte{0x33, 0x33, 0, 0, 0, 2})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_ = isIPv6RouterSolicitationFrame(frame)
	})
}
