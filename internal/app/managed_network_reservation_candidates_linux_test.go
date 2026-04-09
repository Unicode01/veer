//go:build linux

package app

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNormalizeManagedNetworkReservationCandidateMACRejectsInvalidAndNormalizesValid(t *testing.T) {
	if got := normalizeManagedNetworkReservationCandidateMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); got != "" {
		t.Fatalf("broadcast mac normalized to %q, want empty", got)
	}
	if got := normalizeManagedNetworkReservationCandidateMAC(net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); got != "" {
		t.Fatalf("zero mac normalized to %q, want empty", got)
	}
	if got := normalizeManagedNetworkReservationCandidateMAC(net.HardwareAddr{0xBC, 0x24, 0x11, 0x31, 0x53, 0xDB}); got != "bc:24:11:31:53:db" {
		t.Fatalf("normalized mac = %q, want %q", got, "bc:24:11:31:53:db")
	}
}

func TestCollectManagedNetworkObservedIPv4sForNetworkPrefersHigherQualityNeighborState(t *testing.T) {
	t.Parallel()

	macAddress := "bc:24:11:84:f5:2c"
	got := collectManagedNetworkObservedIPv4sForNetwork(
		ManagedNetwork{
			ID:          1,
			Name:        "vmbr",
			Bridge:      "vmbr0",
			IPv4Enabled: true,
			IPv4CIDR:    "192.168.4.1/24",
			Enabled:     true,
		},
		5,
		map[int]struct{}{7: {}},
		map[string]struct{}{
			"84:47:09:4c:53:f2": {},
		},
		map[string]struct{}{
			macAddress: {},
		},
		[]netlink.Neigh{
			{
				IP:           net.IPv4(192, 168, 4, 5),
				HardwareAddr: net.HardwareAddr{0xbc, 0x24, 0x11, 0x84, 0xf5, 0x2c},
				LinkIndex:    5,
				State:        unix.NUD_STALE,
			},
			{
				IP:           net.IPv4(192, 168, 4, 6),
				HardwareAddr: net.HardwareAddr{0xbc, 0x24, 0x11, 0x84, 0xf5, 0x2c},
				LinkIndex:    7,
				State:        unix.NUD_REACHABLE,
			},
			{
				IP:           net.IPv4(192, 168, 4, 1),
				HardwareAddr: net.HardwareAddr{0xbc, 0x24, 0x11, 0x84, 0xf5, 0x2c},
				LinkIndex:    5,
				State:        unix.NUD_REACHABLE,
			},
			{
				IP:           net.IPv4(192, 168, 4, 9),
				HardwareAddr: net.HardwareAddr{0x84, 0x47, 0x09, 0x4c, 0x53, 0xf2},
				LinkIndex:    5,
				State:        unix.NUD_REACHABLE,
			},
			{
				IP:           net.IPv4(192, 168, 4, 10),
				HardwareAddr: net.HardwareAddr{0xbc, 0x24, 0x11, 0x84, 0xf5, 0x2c},
				LinkIndex:    11,
				State:        unix.NUD_REACHABLE,
			},
			{
				IP:           net.IPv4(192, 168, 4, 11),
				HardwareAddr: net.HardwareAddr{0xbc, 0x24, 0x11, 0x84, 0xf5, 0x2c},
				LinkIndex:    5,
				State:        unix.NUD_FAILED,
			},
		},
	)

	ips := got[macAddress]
	if len(ips) != 2 {
		t.Fatalf("observed ips = %#v, want [192.168.4.6 192.168.4.5]", ips)
	}
	if ips[0] != "192.168.4.6" {
		t.Fatalf("ips[0] = %q, want 192.168.4.6", ips[0])
	}
	if ips[1] != "192.168.4.5" {
		t.Fatalf("ips[1] = %q, want 192.168.4.5", ips[1])
	}
}
