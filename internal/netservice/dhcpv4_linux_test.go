//go:build linux

package netservice

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestManagedNetworkDHCPv4OfferUsesShortHoldUntilAcknowledged(t *testing.T) {
	t.Parallel()

	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{})
	config := managedNetworkDHCPv4Config{
		PoolStart: "192.0.2.100",
		PoolEnd:   "192.0.2.110",
	}
	msg := parsedManagedNetworkDHCPv4Message{ClientID: []byte("client-a")}
	beforeOffer := time.Now()
	if _, err := srv.offerLease(config, msg); err != nil {
		t.Fatalf("offerLease() error = %v", err)
	}
	srv.mu.Lock()
	offerExpiry := srv.leases[managedNetworkDHCPv4ClientKey(msg)].ExpiresAt
	srv.mu.Unlock()
	if remaining := offerExpiry.Sub(beforeOffer); remaining < dhcpv4OfferHoldTime-time.Second || remaining > dhcpv4OfferHoldTime+time.Second {
		t.Fatalf("offer hold = %v, want about %v", remaining, dhcpv4OfferHoldTime)
	}
	invalidRequest := msg
	invalidRequest.RequestedIP = net.ParseIP("192.0.2.200").To4()
	if _, err := srv.ackLease(config, invalidRequest); err == nil {
		t.Fatal("ackLease() error = nil for out-of-pool request")
	}
	srv.mu.Lock()
	expiryAfterNAK := srv.leases[managedNetworkDHCPv4ClientKey(msg)].ExpiresAt
	srv.mu.Unlock()
	if !expiryAfterNAK.Equal(offerExpiry) {
		t.Fatal("rejected DHCPv4 request extended the pending offer")
	}

	beforeACK := time.Now()
	if _, err := srv.ackLease(config, msg); err != nil {
		t.Fatalf("ackLease() error = %v", err)
	}
	srv.mu.Lock()
	ackExpiry := srv.leases[managedNetworkDHCPv4ClientKey(msg)].ExpiresAt
	srv.mu.Unlock()
	if remaining := ackExpiry.Sub(beforeACK); remaining < dhcpv4LeaseTime-time.Second || remaining > dhcpv4LeaseTime+time.Second {
		t.Fatalf("acknowledged lease = %v, want about %v", remaining, dhcpv4LeaseTime)
	}
}

func TestManagedNetworkDHCPv4LeaseCleanupIsRateLimited(t *testing.T) {
	t.Parallel()

	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{})
	now := time.Now()
	srv.leases["expired"] = managedNetworkDHCPv4Lease{ClientKey: "expired", IP: "192.0.2.10", ExpiresAt: now.Add(-time.Second)}
	srv.ipOwners["192.0.2.10"] = "expired"
	srv.lastLeaseCleanupAt = now

	srv.cleanupExpiredLeasesLocked(now.Add(dhcpv4LeaseCleanupEvery / 2))
	if _, exists := srv.leases["expired"]; !exists {
		t.Fatal("lease cleanup ran again inside its rate limit")
	}
	srv.cleanupExpiredLeasesLocked(now.Add(dhcpv4LeaseCleanupEvery))
	if _, exists := srv.leases["expired"]; exists {
		t.Fatal("expired lease remained after the cleanup interval")
	}
	if owner := srv.ipOwners["192.0.2.10"]; owner != "" {
		t.Fatalf("expired lease owner = %q, want empty", owner)
	}
}

func TestManagedNetworkDHCPv4RejectsNewLeaseAtHardLimit(t *testing.T) {
	t.Parallel()

	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{})
	srv.leases = make(map[string]managedNetworkDHCPv4Lease, dhcpv4MaxActiveLeases)
	expiresAt := time.Now().Add(time.Hour)
	for index := 0; index < dhcpv4MaxActiveLeases; index++ {
		key := fmt.Sprintf("client-%d", index)
		srv.leases[key] = managedNetworkDHCPv4Lease{ClientKey: key, IP: "192.0.2.10", ExpiresAt: expiresAt}
	}
	srv.lastLeaseCleanupAt = time.Now()

	_, err := srv.offerLease(managedNetworkDHCPv4Config{
		PoolStart: "10.0.0.1",
		PoolEnd:   "10.0.255.254",
	}, parsedManagedNetworkDHCPv4Message{ClientID: []byte("new-client")})
	if err == nil || !strings.Contains(err.Error(), "active lease limit reached") {
		t.Fatalf("offerLease() error = %v, want active lease limit", err)
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

func TestManagedNetworkDHCPv4LogThrottleIgnoresAlternatingText(t *testing.T) {
	t.Parallel()

	srv := newManagedNetworkDHCPv4Server(managedNetworkDHCPv4Config{Bridge: "vmbr0"})
	srv.logIssue("first")
	srv.logSeenMessage("first")
	srv.mu.Lock()
	issueLogAt := srv.lastIssueLogAt
	seenLogAt := srv.lastSeenLogAt
	srv.mu.Unlock()

	srv.logIssue("second")
	srv.logSeenMessage("second")
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.lastIssueLogAt.Equal(issueLogAt) || !srv.lastSeenLogAt.Equal(seenLogAt) {
		t.Fatal("alternating message text bypassed DHCPv4 log throttle")
	}
	if srv.lastIssueText != "second" || srv.lastSeenText != "second" {
		t.Fatal("suppressed DHCPv4 log did not retain current runtime detail")
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

func TestBuildManagedNetworkDHCPv4ReplyIncludesDNSServersOption(t *testing.T) {
	reply, err := buildManagedNetworkDHCPv4Reply(
		managedNetworkDHCPv4Config{
			ServerCIDR: "192.0.2.1/24",
			ServerIP:   "192.0.2.1",
			Gateway:    "192.0.2.1",
			DNSServers: []string{"223.5.5.5", "1.1.1.1"},
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

	options := reply[240:]
	for offset := 0; offset < len(options); {
		code := options[offset]
		offset++
		if code == 0 {
			continue
		}
		if code == dhcpv4OptionEnd {
			break
		}
		if offset >= len(options) {
			t.Fatal("truncated DHCPv4 option length")
		}
		length := int(options[offset])
		offset++
		if offset+length > len(options) {
			t.Fatal("truncated DHCPv4 option payload")
		}
		if code == dhcpv4OptionDNS {
			got := options[offset : offset+length]
			want := []byte{223, 5, 5, 5, 1, 1, 1, 1}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("DHCPv4 DNS option = %v, want %v", got, want)
			}
			return
		}
		offset += length
	}
	t.Fatal("DHCPv4 reply does not contain option 6")
}

func TestParseManagedNetworkDHCPv4MessageRejectsTruncatedOptions(t *testing.T) {
	t.Parallel()

	packet := make([]byte, 240)
	packet[0] = dhcpv4BootRequest
	packet[1] = dhcpv4HWTypeEthernet
	packet[2] = 6
	binary.BigEndian.PutUint32(packet[236:240], dhcpv4MagicCookie)
	packet = append(packet, dhcpv4OptionMessageType, 1)
	if _, err := parseManagedNetworkDHCPv4Message(packet); err == nil {
		t.Fatal("parseManagedNetworkDHCPv4Message() error = nil, want truncated option rejection")
	}
	if _, err := parseManagedNetworkDHCPv4Message(make([]byte, dhcpv4MaxMessageSize+1)); err == nil {
		t.Fatal("parseManagedNetworkDHCPv4Message() error = nil, want oversized message rejection")
	}

	for length := 0; length <= len(packet); length++ {
		_, _ = parseManagedNetworkDHCPv4Message(packet[:length])
	}
}

func TestBuildManagedNetworkDHCPv4ReplyRejectsOversizedHardwareAddress(t *testing.T) {
	t.Parallel()

	_, err := buildManagedNetworkDHCPv4Reply(managedNetworkDHCPv4Config{
		ServerCIDR: "192.0.2.1/24",
		ServerIP:   "192.0.2.1",
		Gateway:    "192.0.2.1",
	}, parsedManagedNetworkDHCPv4Message{
		CHAddr: make(net.HardwareAddr, 17),
	}, dhcpv4MessageOffer, "192.0.2.100")
	if err == nil {
		t.Fatal("buildManagedNetworkDHCPv4Reply() error = nil, want hardware address bound")
	}
}

func FuzzParseManagedNetworkDHCPv4Message(f *testing.F) {
	f.Add(make([]byte, 240))
	f.Add([]byte{dhcpv4BootRequest, dhcpv4HWTypeEthernet, 6})
	valid := make([]byte, 240)
	valid[0] = dhcpv4BootRequest
	valid[1] = dhcpv4HWTypeEthernet
	valid[2] = 6
	binary.BigEndian.PutUint32(valid[236:240], dhcpv4MagicCookie)
	valid = append(valid, dhcpv4OptionMessageType, 1, dhcpv4MessageDiscover, dhcpv4OptionEnd)
	f.Add(valid)
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseManagedNetworkDHCPv4Message(packet)
	})
}

func FuzzParseManagedNetworkDHCPv4Frame(f *testing.F) {
	f.Add(make([]byte, 14+20+8+240))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = parseManagedNetworkDHCPv4Frame(frame)
	})
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
