//go:build linux

package app

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestClassifyTCBridgeRoutes(t *testing.T) {
	t.Run("direct on-link route uses bridge-direct path", func(t *testing.T) {
		matched, direct := classifyTCBridgeRoutes([]netlink.Route{
			{LinkIndex: 12},
		}, 12)
		if !matched || !direct {
			t.Fatalf("classifyTCBridgeRoutes() = matched=%v direct=%v, want matched=true direct=true", matched, direct)
		}
	})

	t.Run("gateway route keeps normal routed path", func(t *testing.T) {
		matched, direct := classifyTCBridgeRoutes([]netlink.Route{
			{LinkIndex: 12, Gw: net.ParseIP("192.0.2.1")},
		}, 12)
		if !matched || direct {
			t.Fatalf("classifyTCBridgeRoutes() = matched=%v direct=%v, want matched=true direct=false", matched, direct)
		}
	})

	t.Run("routes on other interfaces are ignored", func(t *testing.T) {
		matched, direct := classifyTCBridgeRoutes([]netlink.Route{
			{LinkIndex: 77},
		}, 12)
		if matched || direct {
			t.Fatalf("classifyTCBridgeRoutes() = matched=%v direct=%v, want matched=false direct=false", matched, direct)
		}
	})

	t.Run("link index zero is accepted as route match", func(t *testing.T) {
		matched, direct := classifyTCBridgeRoutes([]netlink.Route{
			{LinkIndex: 0},
		}, 12)
		if !matched || !direct {
			t.Fatalf("classifyTCBridgeRoutes() = matched=%v direct=%v, want matched=true direct=true", matched, direct)
		}
	})

	t.Run("bridge member route is accepted as direct match", func(t *testing.T) {
		matched, direct := classifyTCBridgeRoutesWithMembers([]netlink.Route{
			{LinkIndex: 77},
		}, 12, map[int]struct{}{77: {}})
		if !matched || !direct {
			t.Fatalf("classifyTCBridgeRoutesWithMembers() = matched=%v direct=%v, want matched=true direct=true", matched, direct)
		}
	})
}

func TestShouldFallbackTCBridgeFastPath(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "neighbor missing",
			err:  errString("no learned IPv4 neighbor entry was found; ensure the backend has recent traffic or ARP state"),
			want: true,
		},
		{
			name: "fdb missing",
			err:  errString("no forwarding database entry matched the backend MAC"),
			want: true,
		},
		{
			name: "nested bridge member",
			err:  errString("bridge forwarding database resolved nested bridge member \"tap0\", which is not supported"),
			want: true,
		},
		{
			name: "invalid ip stays hard failure",
			err:  errString("kernel dataplane bridge egress requires an explicit outbound IPv4 address"),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFallbackTCBridgeFastPath(tc.err); got != tc.want {
				t.Fatalf("shouldFallbackTCBridgeFastPath(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestMatchBridgeNeighborTarget(t *testing.T) {
	backendIP := net.ParseIP("198.51.100.20").To4()
	backendMAC := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}

	t.Run("prefers bridge slave neighbor link index", func(t *testing.T) {
		target, ok := matchBridgeNeighborTarget([]netlink.Neigh{
			{
				IP:           backendIP,
				LinkIndex:    17,
				MasterIndex:  12,
				HardwareAddr: backendMAC,
			},
		}, 12, nil, backendIP)
		if !ok {
			t.Fatal("matchBridgeNeighborTarget() = not found, want found")
		}
		if target.linkIndex != 17 {
			t.Fatalf("target.linkIndex = %d, want 17", target.linkIndex)
		}
		if target.mac.String() != backendMAC.String() {
			t.Fatalf("target.mac = %s, want %s", target.mac, backendMAC)
		}
	})

	t.Run("keeps bridge master neighbor without member index", func(t *testing.T) {
		target, ok := matchBridgeNeighborTarget([]netlink.Neigh{
			{
				IP:           backendIP,
				LinkIndex:    12,
				HardwareAddr: backendMAC,
			},
		}, 12, nil, backendIP)
		if !ok {
			t.Fatal("matchBridgeNeighborTarget() = not found, want found")
		}
		if target.linkIndex != 0 {
			t.Fatalf("target.linkIndex = %d, want 0", target.linkIndex)
		}
	})

	t.Run("accepts bridge member neighbor without master index", func(t *testing.T) {
		target, ok := matchBridgeNeighborTarget([]netlink.Neigh{
			{
				IP:           backendIP,
				LinkIndex:    17,
				HardwareAddr: backendMAC,
			},
		}, 12, map[int]struct{}{17: {}}, backendIP)
		if !ok {
			t.Fatal("matchBridgeNeighborTarget() = not found, want found")
		}
		if target.linkIndex != 17 {
			t.Fatalf("target.linkIndex = %d, want 17", target.linkIndex)
		}
	})
}
