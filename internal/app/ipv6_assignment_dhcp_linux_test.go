//go:build linux

package app

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

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
