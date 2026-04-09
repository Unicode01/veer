//go:build linux

package app

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
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
