//go:build linux

package app

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const pluginScopedNetNSTestEnv = "VEER_RUN_PLUGIN_NETNS_SCOPED_TESTS"

func TestLinuxPluginTunTapCloseWakesBlockedRead(t *testing.T) {
	data := []int{-1, -1}
	if err := unix.Pipe2(data, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(data[1])
	wake := []int{-1, -1}
	if err := unix.Pipe2(wake, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		unix.Close(data[0])
		t.Fatal(err)
	}
	handle := &linuxPluginTunTapHandle{fd: data[0], wakeRead: wake[0], wakeWrite: wake[1]}
	result := make(chan error, 1)
	go func() {
		_, err := handle.read(128, 15*time.Second)
		result <- err
	}()
	time.Sleep(25 * time.Millisecond)
	started := time.Now()
	if err := handle.close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("close waited %s for a blocked read", elapsed)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "closing") {
			t.Fatalf("blocked read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read was not awakened")
	}
}

func TestLinuxPluginScopedNamespaceNetworkAPIs(t *testing.T) {
	if os.Getenv(pluginScopedNetNSTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged namespace-scoped network test", pluginScopedNetNSTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	base, ok := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	if !ok || base == nil {
		t.Fatal("linux net.admin controller is unavailable")
	}
	namespace := fmt.Sprintf("veer-ns-%x", uint32(time.Now().UnixNano()))
	created, err := base.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: namespace, LoopbackUp: true})
	if err != nil {
		t.Skipf("create named network namespace: %v", err)
	}
	t.Cleanup(func() { _ = base.NamespaceDelete(namespace, created.Info.Identity) })

	admin, err := pluginControlNetAdminInNamespace(base, namespace)
	if err != nil {
		t.Fatal(err)
	}
	dummyName := "vnsdummy0"
	dummy, err := admin.LinkEnsureDummy(pluginControlNetDummyRequest{Namespace: namespace, Name: dummyName, MTU: 1400, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	if dummy.Link.Namespace != namespace || !dummy.Created {
		t.Fatalf("scoped dummy result = %+v", dummy)
	}
	if _, present, err := base.LinkLookup(dummyName); err != nil || present {
		t.Fatalf("scoped dummy leaked into host namespace: present=%t err=%v", present, err)
	}

	addr := pluginControlNetAddrRequest{Namespace: namespace, Interface: dummyName, CIDR: "192.0.2.1/24"}
	if err := admin.AddrReplace(addr); err != nil {
		t.Fatal(err)
	}
	link, err := admin.LinkGet(dummyName)
	if err != nil || !pluginControlNetLinkHasAddress(link, "192.0.2.1/24") {
		t.Fatalf("scoped address was not applied: link=%+v err=%v", link, err)
	}
	route := pluginControlNetRouteRequest{Namespace: namespace, Dst: "198.51.100.0/24", Dev: dummyName, Table: 100}
	if err := admin.RouteReplace(route); err != nil {
		t.Fatal(err)
	}
	if states, err := admin.RouteSnapshot(route); err != nil || len(states) != 1 || states[0].Namespace != namespace {
		t.Fatalf("scoped route snapshot = %+v err=%v", states, err)
	}
	rule := pluginControlNetRuleRequest{Namespace: namespace, Family: "ipv4", Priority: 30001, Table: 100, IIF: dummyName}
	if err := admin.RuleReplace(rule); err != nil {
		t.Fatal(err)
	}
	if states, err := admin.RuleSnapshot(rule); err != nil || len(states) != 1 {
		t.Fatalf("scoped rule snapshot = %+v err=%v", states, err)
	}
	neighbor := pluginControlNetNeighRequest{Namespace: namespace, Interface: dummyName, IP: "192.0.2.2", MAC: "02:00:00:00:00:02", State: "permanent"}
	if err := admin.NeighReplace(neighbor); err != nil {
		t.Fatal(err)
	}
	if states, err := admin.NeighSnapshot(neighbor); err != nil || len(states) != 1 {
		t.Fatalf("scoped neighbor snapshot = %+v err=%v", states, err)
	}
	reader, ok := admin.(pluginControlNetReadAdmin)
	if !ok {
		t.Fatal("scoped net.admin controller does not expose read-only inventory")
	}
	neighbors, err := reader.NeighList(pluginControlNetReadRequest{
		Namespace: namespace,
		Interface: dummyName,
		Family:    "ipv4",
	})
	if err != nil {
		t.Fatal(err)
	}
	foundNeighbor := false
	for _, item := range neighbors {
		if item.Namespace == namespace && item.Interface == dummyName && item.IP == neighbor.IP && strings.EqualFold(item.MAC, neighbor.MAC) && item.Family == "ipv4" {
			foundNeighbor = true
			break
		}
	}
	if !foundNeighbor {
		t.Fatalf("scoped neighbor inventory = %+v, want %s on %s", neighbors, neighbor.IP, dummyName)
	}

	registry := newPluginControlSocketRegistry(newPluginControlSocketTransport())
	t.Cleanup(func() { registry.CloseAll() })
	listener, err := registry.Listen("netns_test", "generation", pluginControlSocketListenRequest{
		Network: "udp4", Namespace: namespace, Interface: "lo", LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(listener.LocalAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	client, err := registry.Open("netns_test", "generation", pluginControlSocketOpenRequest{
		Network: "udp4", Namespace: namespace, Interface: "lo", RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: port,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("veer-netns-udp")
	if _, err := registry.Write("netns_test", "generation", client.Handle, pluginControlSocketWriteRequest{Payload: payload, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	read, err := registry.Read("netns_test", "generation", listener.Handle, 2048, time.Second)
	if err != nil || !bytes.Equal(read.Payload, payload) {
		t.Fatalf("scoped UDP payload = %q err=%v", read.Payload, err)
	}
	if listener.Namespace != namespace || client.Namespace != namespace {
		t.Fatalf("socket namespace metadata = listener:%q client:%q", listener.Namespace, client.Namespace)
	}
	registry.CloseAll()

	veth, err := admin.LinkEnsureVeth(pluginControlNetVethRequest{Namespace: namespace, Host: "vnsa0", Peer: "vnsb0", MTU: 1500, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	dst, err := parsePluginControlMAC(veth.Peer.MAC)
	if err != nil {
		t.Fatal(err)
	}
	l2 := newPluginControlL2Transport()
	recvCh := make(chan struct {
		frame pluginControlL2Frame
		err   error
	}, 1)
	go func() {
		frame, recvErr := l2.Recv(pluginControlL2RecvRequest{
			Namespace: namespace, Interface: "vnsb0", EtherType: 0x88b5, Timeout: 2 * time.Second, MaxBytes: 2048,
		})
		recvCh <- struct {
			frame pluginControlL2Frame
			err   error
		}{frame: frame, err: recvErr}
	}()
	time.Sleep(75 * time.Millisecond)
	l2Payload := []byte("veer-netns-l2")
	if err := l2.Send(pluginControlL2SendRequest{Namespace: namespace, Interface: "vnsa0", EtherType: 0x88b5, DstMAC: dst, Payload: l2Payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-recvCh:
		if received.err != nil || received.frame.Namespace != namespace || !bytes.Equal(received.frame.Payload, l2Payload) {
			t.Fatalf("scoped L2 frame = %+v err=%v", received.frame, received.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for scoped L2 frame")
	}

	bridgeName := "vnsbr0"
	bridge, err := admin.LinkEnsureBridge(pluginControlNetBridgeRequest{Namespace: namespace, Name: bridgeName, MTU: 1500, Up: true})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.Namespace != namespace {
		t.Fatalf("scoped bridge namespace = %q, want %q", bridge.Namespace, namespace)
	}
	if _, err := admin.LinkSetMaster(pluginControlNetMasterRequest{Namespace: namespace, Link: "vnsb0", Master: bridgeName, Up: true}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Send(pluginControlL2SendRequest{
		Namespace: namespace,
		Interface: "vnsa0",
		EtherType: 0x88b5,
		DstMAC:    [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Payload:   []byte("veer-netns-fdb"),
	}); err != nil {
		t.Fatal(err)
	}

	fdbDeadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := reader.BridgeFDBList(pluginControlNetReadRequest{Namespace: namespace, Interface: bridgeName})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, item := range entries {
			if item.Namespace == namespace && item.Interface == "vnsb0" && item.Bridge == bridgeName && strings.EqualFold(item.MAC, veth.Host.MAC) {
				found = true
				break
			}
		}
		if found {
			break
		}
		if time.Now().After(fdbDeadline) {
			t.Fatalf("scoped bridge FDB inventory = %+v, want learned %s on vnsb0", entries, veth.Host.MAC)
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := admin.NeighDelete(neighbor); err != nil {
		t.Fatal(err)
	}
	if err := admin.RuleDelete(rule); err != nil {
		t.Fatal(err)
	}
	if err := admin.RouteDelete(route); err != nil {
		t.Fatal(err)
	}
	if err := admin.AddrDelete(addr); err != nil {
		t.Fatal(err)
	}
	if err := admin.LinkDelete("vnsa0"); err != nil {
		t.Fatal(err)
	}
	if err := admin.LinkDelete(bridgeName); err != nil {
		t.Fatal(err)
	}
	if err := admin.LinkDelete(dummyName); err != nil {
		t.Fatal(err)
	}
}
