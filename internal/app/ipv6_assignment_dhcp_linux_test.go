//go:build linux

package app

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

func TestIPv6DHCPv6ServerUpdateOnlyAppliesChanges(t *testing.T) {
	t.Parallel()

	addresses := []string{"2001:db8::10"}
	config := ipv6AssignmentDHCPv6Config{
		TargetInterface: "br-lan",
		Addresses:       addresses,
		DNSServers:      []string{"2001:4860:4860::8888"},
	}
	server := newIPv6DHCPv6Server(config)
	addresses[0] = "2001:db8::bad"
	if got := server.snapshot().Addresses[0]; got != "2001:db8::10" {
		t.Fatalf("new DHCPv6 server retained caller-owned address slice: %q", got)
	}

	if server.update(server.snapshot()) {
		t.Fatal("equivalent DHCPv6 update reported a change")
	}
	changed := server.snapshot()
	changed.DNSServers[0] = "2400:3200::1"
	if !server.update(changed) {
		t.Fatal("changed DHCPv6 update was ignored")
	}
	changed.DNSServers[0] = "2001:db8::bad"
	if got := server.snapshot().DNSServers[0]; got != "2400:3200::1" {
		t.Fatalf("DHCPv6 update retained caller-owned DNS slice: %q", got)
	}
}

func TestParseIPv6DHCPv6Frame(t *testing.T) {
	t.Parallel()

	srcMAC := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	srcIP := net.ParseIP("fe80::1234").To16()
	dstIP := dhcpv6AllServersAndRelays.To16()
	payload := []byte{dhcpv6MessageSolicit, 0x01, 0x02, 0x03}

	frame := make([]byte, 14+40+8+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14:]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(8+len(payload)))
	ipv6Header[6] = ipv6NextHeaderUDP
	ipv6Header[7] = 1
	copy(ipv6Header[8:24], srcIP)
	copy(ipv6Header[24:40], dstIP)

	udp := ipv6Header[40:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv6ClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	parsed, ok := parseIPv6DHCPv6Frame(frame)
	if !ok {
		t.Fatal("parseIPv6DHCPv6Frame() = false, want true")
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Fatalf("SrcIP = %v, want %v", parsed.SrcIP, srcIP)
	}
	if string(parsed.SrcMAC) != string(srcMAC) {
		t.Fatalf("SrcMAC = %v, want %v", parsed.SrcMAC, srcMAC)
	}
	if string(parsed.Payload) != string(payload) {
		t.Fatalf("Payload = %v, want %v", parsed.Payload, payload)
	}
}

func TestIPv6DHCPv6SocketFilter(t *testing.T) {
	t.Parallel()

	vm, err := bpf.NewVM(buildIPv6DHCPv6SocketFilter())
	if err != nil {
		t.Fatalf("bpf.NewVM() error = %v", err)
	}

	frame := make([]byte, 14+40+8+4)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14:]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], 12)
	ipv6Header[6] = ipv6NextHeaderUDP

	udp := ipv6Header[40:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv6ClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ServerPort)
	binary.BigEndian.PutUint16(udp[4:6], 12)

	out, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run(valid DHCPv6) error = %v", err)
	}
	if out != int(packetSocketAcceptBytes) {
		t.Fatalf("vm.Run(valid DHCPv6) = %d, want %d", out, packetSocketAcceptBytes)
	}

	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ClientPort)
	out, err = vm.Run(frame)
	if err != nil {
		t.Fatalf("vm.Run(non-server destination) error = %v", err)
	}
	if out != 0 {
		t.Fatalf("vm.Run(non-server destination) = %d, want 0", out)
	}
}

func TestBuildDHCPv6ResponseIncludesRecursiveDNSServers(t *testing.T) {
	t.Parallel()

	response, err := buildDHCPv6Response(ipv6DHCPv6State{
		DUID: []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1},
		Config: ipv6AssignmentDHCPv6Config{
			TargetInterface: "br-lan",
			Addresses:       []string{"2001:db8:100::10"},
			DNSServers:      []string{"2001:4860:4860::8888", "2400:3200::1"},
		},
	}, parsedDHCPv6Message{
		Type:     dhcpv6MessageSolicit,
		TxID:     [3]byte{1, 2, 3},
		ClientID: []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2},
		IAIDs:    [][]byte{{0, 0, 0, 7}},
	}, dhcpv6MessageAdvertise)
	if err != nil {
		t.Fatalf("buildDHCPv6Response() error = %v", err)
	}

	options := response[4:]
	var dns []byte
	for len(options) >= 4 {
		code := binary.BigEndian.Uint16(options[0:2])
		length := int(binary.BigEndian.Uint16(options[2:4]))
		if length > len(options)-4 {
			t.Fatalf("invalid option length %d", length)
		}
		if code == dhcpv6OptionDNSServers {
			dns = append([]byte(nil), options[4:4+length]...)
		}
		options = options[4+length:]
	}
	if len(dns) != 32 || !net.IP(dns[:16]).Equal(net.ParseIP("2001:4860:4860::8888")) || !net.IP(dns[16:]).Equal(net.ParseIP("2400:3200::1")) {
		t.Fatalf("DHCPv6 DNS option = %v", dns)
	}
}
