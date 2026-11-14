//go:build linux

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// A plugin hook that appears on an interface while its flows are cached
// must see every later packet entering it: the reload drops the entries
// recorded for it and takes the cache program off it. Once the hook goes
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
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
		Experimental: map[string]bool{
			experimentalFeatureKernelTCFlowCache:    true,
			experimentalFeatureKernelTCLegacyAttach: legacyAttach,
		},
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
	cacheMap := rt.coll.Maps[kernelTCFlowCacheMapName]
	if cacheMap == nil {
		t.Fatal("flow cache map is unavailable")
	}
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}
	childIndex := child.Attrs().Index
	cacheInfo, err := rt.coll.Programs[kernelFlowCacheProgramName].Info()
	if err != nil {
		t.Fatalf("read flow cache program info: %v", err)
	}
	cacheID, ok := cacheInfo.ID()
	if !ok {
		t.Fatal("flow cache program has no ID")
	}
	// expectCache checks both the runtime's attachments and the kernel's
	// ingress hook of the child interface, as a cls_bpf filter or a tcx link.
	expectCache := func(stage string, want bool) {
		t.Helper()
		tracked := false
		for _, att := range rt.attachments {
			if key, ok := att.key(); ok && key.isFlowCache() && key.linkIndex == childIndex {
				tracked = true
			}
		}
		running := false
		filters, _ := netlink.FilterList(child, netlink.HANDLE_MIN_INGRESS)
		for _, filter := range filters {
			if bpf, ok := filter.(*netlink.BpfFilter); ok && bpf.Id == int(cacheID) {
				running = true
			}
		}
		if result, err := link.QueryPrograms(link.QueryOptions{Target: childIndex, Attach: ebpf.AttachTCXIngress}); err == nil {
			for _, prog := range result.Programs {
				if prog.ID == cacheID {
					running = true
				}
			}
		}
		if tracked != want || running != want {
			t.Fatalf("%s: flow cache on %s tracked=%t, in the kernel=%t, want %t", stage, topology.ChildHostIF, tracked, running, want)
		}
	}
	childEntries := func() int {
		t.Helper()
		counts, err := flowCacheTCPEntries(cacheMap)
		if err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		return counts[childIndex]
	}
	waitForChildEntries := func(stage string, stream *egressNATTCStream) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for childEntries() == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: no flow cache entry for %s\n%s", stage, topology.ChildHostIF, stream.logs())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	expectCache("before the hook", true)

	stream := startEgressNATTCStream(t, topology)
	waitForChildEntries("before the hook", stream)

	if global {
		setControlScriptInterfacesForPipelineTest(t, pluginDir)
	} else {
		setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ChildHostIF)
	}
	reconcile("adding the hook")
	expectCache("after adding the hook", false)
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
	hookBefore, rxBefore := hookPackets(), readInterfaceCounter(t, topology.ChildHostIF, "rx_packets")
	// Invalidation bumps the generation and leaves old entries in the map;
	// only entries of the current generation can serve packets.
	stateMap := rt.coll.Maps[kernelTCFlowCacheStateMapName]
	liveChildEntries := func() int {
		t.Helper()
		var state tcFlowCacheStateV4
		if err := stateMap.Lookup(uint32(0), &state); err != nil {
			t.Fatalf("read flow cache state: %v", err)
		}
		live := 0
		iter := cacheMap.Iterate()
		var key tcFlowKeyV4
		var value tcFlowCacheValueV4
		for iter.Next(&key, &value) {
			if int(key.IfIndex) == childIndex && value.Generation == state.Generation {
				live++
			}
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		return live
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if n := liveChildEntries(); n != 0 {
			t.Fatalf("flow cache holds %d current entries for %s after a hook was added there", n, topology.ChildHostIF)
		}
		time.Sleep(20 * time.Millisecond)
	}
	hookSeen, received := hookPackets()-hookBefore, readInterfaceCounter(t, topology.ChildHostIF, "rx_packets")-rxBefore
	t.Logf("in one second with the hook, %s received %d packets and the hook saw %d IPv4 packets", topology.ChildHostIF, received, hookSeen)
	// Every forwarded packet entering the interface passes the hook. The
	// two counters are read a moment apart, and a global hook also sees
	// the replies entering the uplink.
	if received < 20 || hookSeen+2 < received {
		t.Fatalf("hook saw %d IPv4 packets while %s received %d, want the hook to see all of them", hookSeen, topology.ChildHostIF, received)
	}

	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.BridgeIF)
	reconcile("removing the hook")
	expectCache("after removing the hook", true)
	waitForChildEntries("after the hook was removed", stream)
	stream.wait(t)
}

// readInterfaceCounter reads one of the interface's statistics counters.
func readInterfaceCounter(t *testing.T, ifName, counter string) uint64 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("/sys/class/net", ifName, "statistics", counter))
	if err != nil {
		t.Fatalf("read %s %s: %v", ifName, counter, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatalf("parse %s %s %q: %v", ifName, counter, data, err)
	}
	return value
}
