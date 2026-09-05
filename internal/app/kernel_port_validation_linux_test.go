//go:build linux

package app

import "testing"

func TestKernelPreparersRejectPortTruncation(t *testing.T) {
	for _, ports := range [][2]int{{0, 22}, {22, 0}, {65536, 22}, {22, 65536}, {-1, 22}} {
		rule := Rule{ID: 1, InIP: "127.0.0.1", OutIP: "127.0.0.1", InPort: ports[0], OutPort: ports[1], Protocol: "tcp"}
		if _, err := prepareKernelRule(nil, rule); err == nil || err.Error() != "ports must be between 1 and 65535" {
			t.Fatalf("TC ports %v: %v", ports, err)
		}
		if _, err := prepareXDPKernelRule(rule, xdpPrepareOptions{}); err == nil || err.Error() != "ports must be between 1 and 65535" {
			t.Fatalf("XDP ports %v: %v", ports, err)
		}
	}
}
