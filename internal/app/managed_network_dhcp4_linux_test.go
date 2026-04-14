//go:build linux

package app

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"testing"
)

func TestManagedNetworkDHCPv4AllocateLeaseHonorsReservationOutsidePool(t *testing.T) {
	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{})
	msg := parsedManagedNetworkDHCPv4Message{
		CHAddr:      net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		MessageType: dhcpv4MessageDiscover,
	}
	config := managedNetworkDHCPv4Config{
		Bridge:     "vmbr0",
		ServerCIDR: "192.0.2.1/24",
		ServerIP:   "192.0.2.1",
		Gateway:    "192.0.2.1",
		PoolStart:  "192.0.2.100",
		PoolEnd:    "192.0.2.150",
		Reservations: []managedNetworkDHCPv4Reservation{{
			MACAddress:  "aa:bb:cc:dd:ee:ff",
			IPv4Address: "192.0.2.10",
		}},
	}

	leaseIP, err := srv.allocateLease(config, msg, false)
	if err != nil {
		t.Fatalf("allocateLease(false) error = %v", err)
	}
	if leaseIP != "192.0.2.10" {
		t.Fatalf("leaseIP = %q, want %q", leaseIP, "192.0.2.10")
	}

	msg.MessageType = dhcpv4MessageRequest
	msg.RequestedIP = net.ParseIP("192.0.2.10").To4()
	leaseIP, err = srv.allocateLease(config, msg, true)
	if err != nil {
		t.Fatalf("allocateLease(true) error = %v", err)
	}
	if leaseIP != "192.0.2.10" {
		t.Fatalf("strict leaseIP = %q, want %q", leaseIP, "192.0.2.10")
	}
}

func TestManagedNetworkDHCPv4AllocateLeaseSkipsReservedPoolAddress(t *testing.T) {
	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{})
	config := managedNetworkDHCPv4Config{
		Bridge:     "vmbr0",
		ServerCIDR: "192.0.2.1/24",
		ServerIP:   "192.0.2.1",
		Gateway:    "192.0.2.1",
		PoolStart:  "192.0.2.100",
		PoolEnd:    "192.0.2.101",
		Reservations: []managedNetworkDHCPv4Reservation{{
			MACAddress:  "aa:bb:cc:dd:ee:ff",
			IPv4Address: "192.0.2.100",
		}},
	}

	leaseIP, err := srv.allocateLease(config, parsedManagedNetworkDHCPv4Message{
		CHAddr: net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
	}, false)
	if err != nil {
		t.Fatalf("allocateLease() error = %v", err)
	}
	if leaseIP != "192.0.2.101" {
		t.Fatalf("leaseIP = %q, want %q", leaseIP, "192.0.2.101")
	}
}

func TestManagedNetworkDHCPv4ConfigsEqual(t *testing.T) {
	base := managedNetworkDHCPv4Config{
		Bridge:          "vmbr1",
		UplinkInterface: "eno1",
		ServerCIDR:      "192.0.2.1/24",
		ServerIP:        "192.0.2.1",
		Gateway:         "192.0.2.1",
		PoolStart:       "192.0.2.10",
		PoolEnd:         "192.0.2.20",
		DNSServers:      []string{"1.1.1.1", "8.8.8.8"},
		Reservations: []managedNetworkDHCPv4Reservation{{
			MACAddress:  "aa:bb:cc:dd:ee:ff",
			IPv4Address: "192.0.2.11",
			Remark:      "vm100",
		}},
	}
	same := base
	same.DNSServers = append([]string(nil), base.DNSServers...)
	same.Reservations = append([]managedNetworkDHCPv4Reservation(nil), base.Reservations...)
	if !managedNetworkDHCPv4ConfigsEqual(base, same) {
		t.Fatal("managedNetworkDHCPv4ConfigsEqual() = false, want true for identical config")
	}

	changedDNS := same
	changedDNS.DNSServers = []string{"1.1.1.1"}
	if managedNetworkDHCPv4ConfigsEqual(base, changedDNS) {
		t.Fatal("managedNetworkDHCPv4ConfigsEqual() = true, want false after dns change")
	}

	changedReservation := same
	changedReservation.Reservations = []managedNetworkDHCPv4Reservation{{
		MACAddress:  "aa:bb:cc:dd:ee:ff",
		IPv4Address: "192.0.2.12",
		Remark:      "vm100",
	}}
	if managedNetworkDHCPv4ConfigsEqual(base, changedReservation) {
		t.Fatal("managedNetworkDHCPv4ConfigsEqual() = true, want false after reservation change")
	}
}

func TestBuildManagedNetworkDHCPv4ReplyFrameSetsUDPChecksum(t *testing.T) {
	state := managedNetworkDHCPv4State{
		IfName: "vmbr0",
		MAC:    net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01},
		Config: managedNetworkDHCPv4Config{
			ServerIP: "192.0.2.1",
		},
	}
	payload := []byte{
		0x02, 0x01, 0x06, 0x00,
		0xde, 0xad, 0xbe, 0xef,
	}

	frame, err := buildManagedNetworkDHCPv4ReplyFrame(
		state,
		net.IPv4bcast,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		payload,
	)
	if err != nil {
		t.Fatalf("buildManagedNetworkDHCPv4ReplyFrame() error = %v", err)
	}
	if got := binary.BigEndian.Uint16(frame[14+20+6 : 14+20+8]); got == 0 {
		t.Fatal("udp checksum = 0, want non-zero checksum in dhcpv4 reply")
	}
}

func TestManagedNetworkDHCPv4ReplyIfIndexPrefersIngressInterface(t *testing.T) {
	state := managedNetworkDHCPv4State{
		IfIndex:       11,
		BridgeIfIndex: 22,
	}
	if got := managedNetworkDHCPv4ReplyIfIndex(state); got != 11 {
		t.Fatalf("managedNetworkDHCPv4ReplyIfIndex() = %d, want 11", got)
	}

	state.IfIndex = 0
	if got := managedNetworkDHCPv4ReplyIfIndex(state); got != 22 {
		t.Fatalf("managedNetworkDHCPv4ReplyIfIndex() fallback = %d, want 22", got)
	}
}

func TestManagedNetworkDHCPv4UDPChecksumReturnsStableValue(t *testing.T) {
	udp := make([]byte, 8+4)
	binary.BigEndian.PutUint16(udp[0:2], dhcpv4ServerPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv4ClientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], []byte{0xde, 0xad, 0xbe, 0xef})

	checksum := managedNetworkDHCPv4UDPChecksum(net.IPv4(192, 0, 2, 1), net.IPv4(255, 255, 255, 255), udp)
	if checksum == 0 {
		t.Fatal("managedNetworkDHCPv4UDPChecksum() = 0, want non-zero")
	}
}

func TestBuildManagedNetworkDHCPv4ReplyPadsToBootPMinimumSize(t *testing.T) {
	reply, err := buildManagedNetworkDHCPv4Reply(
		managedNetworkDHCPv4Config{
			ServerCIDR: "192.0.2.1/24",
			ServerIP:   "192.0.2.1",
			Gateway:    "192.0.2.1",
		},
		parsedManagedNetworkDHCPv4Message{
			XID:    0x01020304,
			CHAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
		dhcpv4MessageOffer,
		"192.0.2.100",
	)
	if err != nil {
		t.Fatalf("buildManagedNetworkDHCPv4Reply() error = %v", err)
	}
	if len(reply) < dhcpv4MinMessageSize {
		t.Fatalf("len(reply) = %d, want >= %d", len(reply), dhcpv4MinMessageSize)
	}
}

func TestResolveManagedNetworkDHCPv4ListenInterfacesKeepsStickyDynamicChildWhenInventoryIsTransientlyEmpty(t *testing.T) {
	oldLoad := loadInterfaceInfosForManagedNetworkDHCPv4Tests
	oldLookup := lookupManagedNetworkDHCPv4InterfaceForTests
	loadInterfaceInfosForManagedNetworkDHCPv4Tests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "vmbr0", Kind: "bridge"},
		}, nil
	}
	lookupManagedNetworkDHCPv4InterfaceForTests = func(name string) (*net.Interface, error) {
		switch name {
		case "vmbr1":
			return &net.Interface{Name: name, Index: 10, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}}, nil
		case "tap100i0":
			return &net.Interface{Name: name, Index: 11, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x02}}, nil
		default:
			return nil, fmt.Errorf("interface %q not found", name)
		}
	}
	t.Cleanup(func() {
		loadInterfaceInfosForManagedNetworkDHCPv4Tests = oldLoad
		lookupManagedNetworkDHCPv4InterfaceForTests = oldLookup
	})

	got, err := resolveManagedNetworkDHCPv4ListenInterfaces(managedNetworkDHCPv4Config{
		Bridge:          "vmbr1",
		UplinkInterface: "vmbr0",
	}, []string{"tap100i0"})
	if err != nil {
		t.Fatalf("resolveManagedNetworkDHCPv4ListenInterfaces() error = %v", err)
	}
	if want := []string{"tap100i0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listen interfaces = %v, want %v", got, want)
	}
}

func TestResolveManagedNetworkDHCPv4ListenInterfacesDropsStickyDynamicChildAttachedElsewhere(t *testing.T) {
	got := resolveManagedNetworkDHCPv4ListenInterfacesWithInfos(
		managedNetworkDHCPv4Config{
			Bridge:          "vmbr1",
			UplinkInterface: "vmbr0",
		},
		[]InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr9", Kind: "tap"},
		},
		[]string{"tap100i0"},
		func(name string) bool { return true },
	)
	if want := []string{"vmbr1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listen interfaces = %v, want %v", got, want)
	}
}

func TestManagedNetworkDHCPv4SocketsNeedReopenKeepsStickyDynamicChildDuringTransientInventoryLoss(t *testing.T) {
	oldLoad := loadInterfaceInfosForManagedNetworkDHCPv4Tests
	oldLookup := lookupManagedNetworkDHCPv4InterfaceForTests
	loadInterfaceInfosForManagedNetworkDHCPv4Tests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "vmbr0", Kind: "bridge"},
		}, nil
	}
	lookupManagedNetworkDHCPv4InterfaceForTests = func(name string) (*net.Interface, error) {
		switch name {
		case "vmbr1":
			return &net.Interface{Name: name, Index: 10, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}}, nil
		case "tap100i0":
			return &net.Interface{Name: name, Index: 11, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x02}}, nil
		default:
			return nil, fmt.Errorf("interface %q not found", name)
		}
	}
	t.Cleanup(func() {
		loadInterfaceInfosForManagedNetworkDHCPv4Tests = oldLoad
		lookupManagedNetworkDHCPv4InterfaceForTests = oldLookup
	})

	config := managedNetworkDHCPv4Config{
		Bridge:          "vmbr1",
		UplinkInterface: "vmbr0",
	}
	sockets := []managedNetworkDHCPv4Socket{{
		state: managedNetworkDHCPv4State{
			IfIndex:       11,
			IfName:        "tap100i0",
			BridgeIfIndex: 10,
			MAC:           net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01},
			Config:        config,
		},
	}}

	if managedNetworkDHCPv4SocketsNeedReopen(config, sockets) {
		t.Fatal("managedNetworkDHCPv4SocketsNeedReopen() = true, want false while sticky child still exists")
	}
}

func TestManagedNetworkDHCPv4SocketNeedsReopenWhenBridgeIdentityChanges(t *testing.T) {
	oldLookup := lookupManagedNetworkDHCPv4InterfaceForTests
	lookupManagedNetworkDHCPv4InterfaceForTests = func(name string) (*net.Interface, error) {
		switch name {
		case "tap100i0":
			return &net.Interface{Name: name, Index: 11, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x02}}, nil
		case "vmbr1":
			return &net.Interface{Name: name, Index: 99, HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x09}}, nil
		default:
			return nil, fmt.Errorf("interface %q not found", name)
		}
	}
	t.Cleanup(func() {
		lookupManagedNetworkDHCPv4InterfaceForTests = oldLookup
	})

	if !managedNetworkDHCPv4SocketNeedsReopen(managedNetworkDHCPv4State{
		IfIndex:       11,
		IfName:        "tap100i0",
		BridgeIfIndex: 10,
		MAC:           net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01},
		Config: managedNetworkDHCPv4Config{
			Bridge: "vmbr1",
		},
	}) {
		t.Fatal("managedNetworkDHCPv4SocketNeedsReopen() = false, want true when bridge identity changes")
	}
}
