//go:build linux

package app

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/netservice"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// A plugin hook that appears on an interface while its flows are cached
// must see every later packet entering it: the reload retires the records
// made for it, and none are made while the hook stays. Once the hook goes
// away again, the cache returns. Covers a hook scoped to the interface and a
// global one, and cls_bpf filters as well as tcx links.
func TestEgressNATTCFlowCacheYieldsToHookAddedMidStream(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	for _, tc := range []struct {
		name                 string
		global, legacyAttach bool
	}{
		{name: "scoped"},
		{name: "global", global: true},
		// Kernels with tcx otherwise never detach a cls_bpf filter here.
		{name: "scoped-cls_bpf", legacyAttach: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testEgressNATTCFlowCacheYieldsToHookAddedMidStream(t, tc.global, tc.legacyAttach)
		})
	}
}

func testEgressNATTCFlowCacheYieldsToHookAddedMidStream(t *testing.T, global, legacyAttach bool) {
	// 360 cycles of 25 ms: the stream outlives both reloads.
	t.Setenv(egressNATHelperStreamCyclesEnv, "360")
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	pluginsRoot := t.TempDir()
	pluginDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	// The bridge serves no rule, so a hook there leaves the rule's
	// interfaces to the cache while keeping the plugin pipeline up.
	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.BridgeIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))
	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:    &enabled,
		PluginsDataplaneSetting:  &enabled,
		PluginsDir:               pluginsRoot,
		KernelTCFlowCacheSetting: &enabled,
		Experimental:             map[string]bool{experimentalFeatureKernelTCLegacyAttach: legacyAttach},
	}))
	defer rt.Close()
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    topology.UplinkHostIF,
		OutSourceIP:     egressNATUplinkAddr,
		Protocol:        "tcp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}, topology.ChildHostIF, 1, "tcp")
	reconcile := func(stage string) {
		t.Helper()
		results, err := rt.Reconcile([]Rule{rule})
		if err != nil {
			t.Fatalf("Reconcile(%s) error = %v", stage, err)
		}
		if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
			t.Fatalf("egress NAT result after %s = %+v, want running tc", stage, result)
		}
	}
	reconcile("initial")
	flowsMap := rt.coll.Maps[kernelFlowsMapNameV4]
	stateMap := rt.coll.Maps[kernelTCFlowCacheStateMapName]
	if flowsMap == nil || stateMap == nil {
		t.Fatal("flow map or flow cache state is unavailable")
	}
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}
	childIndex := child.Attrs().Index
	// No reload attaches a program of its own for the cache, on any hook.
	expectNoCacheProgram := func(stage string) {
		t.Helper()
		for _, att := range rt.attachments {
			if key, ok := att.key(); ok && key.isFlowCache() {
				t.Fatalf("%s: a flow cache program is attached at %+v", stage, key)
			}
		}
	}
	// childRecords counts the child's front entries whose fast-path record
	// is current: an invalidation only bumps the generation, which leaves
	// the old records in place but unusable.
	childRecords := func() int {
		t.Helper()
		var state tcFlowCacheStateV4
		if err := stateMap.Lookup(uint32(0), &state); err != nil {
			t.Fatalf("read flow cache state: %v", err)
		}
		current := 0
		iter := flowsMap.Iterate()
		var key tcFlowKeyV4
		var value tcFlowValueV4
		for iter.Next(&key, &value) {
			if int(key.IfIndex) == childIndex && key.Proto == unix.IPPROTO_TCP &&
				value.Fast.Stamp == flowFastStampForTest(value.LastSeenNS, state.Generation) {
				current++
			}
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		return current
	}
	waitForChildRecords := func(stage string, stream *egressNATTCStream) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for childRecords() == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: no current fast-path record for %s\n%s", stage, topology.ChildHostIF, stream.logs())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	expectNoCacheProgram("before the hook")

	stream := startEgressNATTCStream(t, topology)
	waitForChildRecords("before the hook", stream)

	if global {
		setControlScriptInterfacesForPipelineTest(t, pluginDir)
	} else {
		setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ChildHostIF)
	}
	reconcile("adding the hook")
	expectNoCacheProgram("after adding the hook")
	// The second invalidation runs one grace period after the reload.
	time.Sleep(2 * kernelPluginPipelineUpdateGrace)
	hookPackets := func() uint64 {
		t.Helper()
		state, ok := rt.PluginSnapshot().stateFor("packet_observer")
		if !ok {
			t.Fatal("packet_observer has no runtime state")
		}
		var total uint64
		for _, attachment := range state.Attachments {
			if attachment.Program == "packet_observer:tc_pre_forward" && attachment.Metrics != nil {
				total += attachment.Metrics.IPv4.Packets
			}
		}
		return total
	}
	hookBefore := hookPackets()
	// The counter starts after the hook's count is read, and is read before
	// the hook's count is read again, so it covers no packet the hook could
	// not have counted.
	forwarded := openIPv4TCPFlowCounter(t, topology.ChildHostIF, egressNATClientAddr, egressNATBackendAddr)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if n := childRecords(); n != 0 {
			t.Fatalf("flow cache holds %d current records for %s after a hook was added there", n, topology.ChildHostIF)
		}
		time.Sleep(20 * time.Millisecond)
	}
	received := forwarded.close(t)
	hookSeen := hookPackets() - hookBefore
	t.Logf("in one second with the hook, %s received %d forwarded IPv4 packets and the hook saw %d IPv4 packets", topology.ChildHostIF, received, hookSeen)
	// Every forwarded packet entering the interface passes the hook.
	if received < 20 || hookSeen < received {
		t.Fatalf("hook saw %d IPv4 packets while %s received %d forwarded IPv4 packets, want the hook to see all of them", hookSeen, topology.ChildHostIF, received)
	}

	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.BridgeIF)
	reconcile("removing the hook")
	expectNoCacheProgram("after removing the hook")
	waitForChildRecords("after the hook was removed", stream)
	stream.wait(t)
}

// ipv4TCPFlowCounter counts the frames of one direction of an IPv4 TCP flow
// entering an interface. The interface's rx_packets would also count ARP
// and IPv6 neighbour, router and MLD frames, which no IPv4 hook sees.
type ipv4TCPFlowCounter struct {
	fd int
}

// openIPv4TCPFlowCounter starts counting the IPv4 TCP frames from src to dst
// that enter ifName. It uses a packet socket bound to every protocol: those
// see each frame before the TC ingress hook, so they also count the frames
// that TC redirects.
func openIPv4TCPFlowCounter(t *testing.T, ifName, src, dst string) *ipv4TCPFlowCounter {
	t.Helper()
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		t.Fatalf("resolve %s: %v", ifName, err)
	}
	srcIP, dstIP := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if srcIP == nil || dstIP == nil {
		t.Fatalf("flow %s -> %s is not IPv4", src, dst)
	}
	raw, err := bpf.Assemble(netservice.BuildPacketSocketEqualityFilter([]netservice.PacketSocketEqualityCheck{
		{Offset: 12, Size: 2, Value: unix.ETH_P_IP},
		{Offset: 14 + 9, Size: 1, Value: unix.IPPROTO_TCP},
		{Offset: 14 + 12, Size: 4, Value: binary.BigEndian.Uint32(srcIP)},
		{Offset: 14 + 16, Size: 4, Value: binary.BigEndian.Uint32(dstIP)},
	}))
	if err != nil {
		t.Fatalf("assemble packet filter: %v", err)
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, inst := range raw {
		filter[i] = unix.SockFilter{Code: inst.Op, Jt: inst.Jt, Jf: inst.Jf, K: inst.K}
	}
	// Protocol 0 receives nothing, so no frame is counted before the filter
	// is attached; the bind below starts the count.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open packet socket: %v", err)
	}
	counter := &ipv4TCPFlowCounter{fd: fd}
	t.Cleanup(func() {
		if counter.fd >= 0 {
			_ = unix.Close(counter.fd)
		}
	})
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		t.Fatalf("attach packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(unix.ETH_P_ALL)}); err != nil {
		t.Fatalf("bind packet socket to %s: %v", ifName, err)
	}
	return counter
}

// close stops the count and returns the number of frames counted.
func (counter *ipv4TCPFlowCounter) close(t *testing.T) uint64 {
	t.Helper()
	// The frames the full receive queue dropped are included.
	stats, err := unix.GetsockoptTpacketStats(counter.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		t.Fatalf("read packet socket statistics: %v", err)
	}
	_ = unix.Close(counter.fd)
	counter.fd = -1
	return uint64(stats.Packets)
}
