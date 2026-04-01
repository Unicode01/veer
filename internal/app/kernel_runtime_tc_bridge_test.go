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

type errString string

func (e errString) Error() string {
	return string(e)
}
