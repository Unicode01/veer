package app

import "testing"

func TestCurrentConnCountForProtocolDatagrams(t *testing.T) {
	cases := []struct {
		name      string
		protocol  string
		active    int64
		udpNat    int64
		icmpNat   int64
		wantConns int64
	}{
		{name: "tcp only", protocol: "tcp", active: 3, udpNat: 4, icmpNat: 5, wantConns: 3},
		{name: "udp only", protocol: "udp", active: 3, udpNat: 4, icmpNat: 5, wantConns: 4},
		{name: "icmp only", protocol: "icmp", active: 3, udpNat: 4, icmpNat: 5, wantConns: 5},
		{name: "udp icmp", protocol: "udp+icmp", active: 3, udpNat: 4, icmpNat: 5, wantConns: 9},
		{name: "tcp udp icmp", protocol: "tcp+udp+icmp", active: 3, udpNat: 4, icmpNat: 5, wantConns: 12},
		{name: "unknown falls back to sum", protocol: "", active: 3, udpNat: 4, icmpNat: 5, wantConns: 12},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := currentConnCountForProtocolDatagrams(tc.protocol, tc.active, tc.udpNat, tc.icmpNat); got != tc.wantConns {
				t.Fatalf("currentConnCountForProtocolDatagrams(%q, %d, %d, %d) = %d, want %d", tc.protocol, tc.active, tc.udpNat, tc.icmpNat, got, tc.wantConns)
			}
		})
	}
}
