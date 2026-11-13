//go:build linux

package app

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestFlowCacheAttachmentPlansRunAheadOfTheCore(t *testing.T) {
	prog := &ebpf.Program{}
	// 6 and 7 carry only plugin hooks and 8 a rule and an ingress hook: the
	// core runs on all of them, the cache on none.
	sets := kernelAttachmentRuleSets{
		ForwardIngress:      map[int][]int64{3: {1}, 6: nil, 8: {3}},
		ReplyIngress:        map[int][]int64{3: {2}, 4: {1}, 7: nil},
		ForwardEgress:       map[int][]int64{5: {1}},
		PluginIngressHooked: map[int]struct{}{6: {}, 7: {}, 8: {}},
	}
	programs := kernelAttachmentPrograms{
		forwardProg:       prog,
		replyProg:         prog,
		forwardEgressProg: prog,
		flowCacheProg:     prog,
		tcx:               true,
	}
	plans := desiredKernelAttachmentPlansForRuleSets(sets, programs)
	var order []string
	cached := map[int]bool{}
	core := map[int]bool{}
	for _, plan := range plans {
		order = append(order, strconv.Itoa(plan.ifindex)+"/"+plan.name)
		if !plan.flowCache {
			core[plan.ifindex] = true
			continue
		}
		if plan.key.parent != netlink.HANDLE_MIN_INGRESS || !plan.key.tcx || plan.attach != kernelPluginPipelineAttachIngress {
			t.Fatalf("flow cache plan = %+v, want an ingress tcx position", plan)
		}
		cached[plan.ifindex] = true
	}
	if len(cached) != 2 || !cached[3] || !cached[4] {
		t.Fatalf("flow cache on ifindexes %v, want the rule ingress hooks 3 and 4", cached)
	}
	if !core[6] || !core[7] || !core[8] {
		t.Fatalf("core on ifindexes %v, want the hooked interfaces 6, 7 and 8 too", core)
	}
	want := "3/" + kernelFlowCacheProgramName + " 3/" + kernelReplyProgramName + " 3/" + kernelForwardProgramName
	if got := strings.Join(order[:3], " "); got != want {
		t.Fatalf("plan order on ifindex 3 = %q, want %q", got, want)
	}

	// A global ingress hook keeps the core from recording anything.
	global := sets.clone()
	global.PluginIngressHookedAll = true
	for _, plan := range desiredKernelAttachmentPlansForRuleSets(global, programs) {
		if plan.flowCache {
			t.Fatalf("flow cache plan under a global ingress hook: %+v", plan)
		}
	}

	programs.flowCacheProg = nil
	for _, plan := range desiredKernelAttachmentPlansForRuleSets(sets, programs) {
		if plan.flowCache {
			t.Fatalf("flow cache plan without the program: %+v", plan)
		}
	}
}

// The steady reconcile must notice an interface whose last rule left while
// its plugin hooks stay, which sameTargets ignores, so the cache leaves it.
func TestFlowCacheTargetsFollowRuleIDs(t *testing.T) {
	ruled := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}},
		ReplyIngress:   map[int][]int64{4: {1, 2}},
	}
	pluginOnly := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}},
		ReplyIngress:   map[int][]int64{4: nil},
	}
	if !ruled.sameTargets(pluginOnly) {
		t.Fatal("sameTargets must keep ignoring rule IDs")
	}
	if ruled.sameFlowCacheTargets(pluginOnly) || pluginOnly.sameFlowCacheTargets(ruled) {
		t.Fatal("sameFlowCacheTargets = true across an interface that lost its last rule")
	}
	renumbered := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {7}},
		ReplyIngress:   map[int][]int64{4: {8}},
	}
	if !ruled.sameFlowCacheTargets(renumbered) {
		t.Fatal("sameFlowCacheTargets = false for the same ruled interfaces")
	}
	// An interface that serves rules in either direction keeps the cache.
	mixed := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}, 4: {2}},
		ReplyIngress:   map[int][]int64{4: nil},
	}
	if !ruled.sameFlowCacheTargets(mixed) {
		t.Fatal("sameFlowCacheTargets = false although interface 4 still serves a rule")
	}
	// A rule interface that gains an ingress hook leaves the cache.
	hooked := ruled.clone()
	hooked.PluginIngressHooked = map[int]struct{}{3: {}}
	if !ruled.sameTargets(hooked) {
		t.Fatal("sameTargets must keep ignoring plugin hooks")
	}
	if ruled.sameFlowCacheTargets(hooked) || hooked.sameFlowCacheTargets(ruled) {
		t.Fatal("sameFlowCacheTargets = true across a rule interface that gained an ingress hook")
	}
	merged := ruled.clone()
	mergeKernelPluginPipelineAttachmentRuleSets(&merged, kernelAttachmentRuleSets{PluginIngressHookedAll: true})
	if !merged.PluginIngressHookedAll || len(kernelFlowCacheTargets(merged)) != 0 {
		t.Fatalf("merged sets = %+v, want a global ingress hook to clear the cache targets", merged)
	}
}

// Ingress hooks mark their interfaces, and a hook without interfaces marks
// all of them; egress hooks mark nothing.
func TestKernelPluginPipelineMarksIngressHookedInterfaces(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName(lo) error = %v", err)
	}
	resolve := func(attach string, interfaces []string) kernelAttachmentRuleSets {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "stage.o"), []byte("fake"), 0o644); err != nil {
			t.Fatalf("WriteFile(stage.o) error = %v", err)
		}
		plugin := LoadedPlugin{
			PluginManifest: PluginManifest{ID: "stage", Name: "Stage", Version: "0.1.0", Kind: "pipeline"},
			Objects: []PluginObject{{
				ID:             "stage",
				Path:           "stage.o",
				Status:         pluginObjectStatusVerified,
				ResolvedSHA256: "abc",
				Programs:       []PluginObjectProgram{{ID: "tc_forward", Section: "tc/veer/forward", Type: kernelEngineTC}},
			}},
			Hooks: []PluginHook{{
				ID:         "stage",
				Engine:     kernelEngineTC,
				Attach:     attach,
				Stage:      kernelPluginPipelineStageForward,
				Priority:   pluginPipelineCorePriority - 10,
				Program:    "stage:tc_forward",
				Mode:       "transform",
				Interfaces: interfaces,
			}},
			Status:  pluginStatusActive,
			rootDir: dir,
		}
		desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
		desired, states, targets := kernelPluginPipelineResolveExplicitAttachTargets(desired, states)
		if len(states) != 0 || len(desired) != 1 {
			t.Fatalf("desired=%+v states=%+v, want one valid plugin", desired, states)
		}
		return targets
	}
	if targets := resolve("ingress", []string{"lo"}); targets.PluginIngressHookedAll || len(targets.PluginIngressHooked) != 1 {
		t.Fatalf("ingress hook on lo: targets = %+v, want lo marked", targets)
	} else if _, ok := targets.PluginIngressHooked[lo.Index]; !ok {
		t.Fatalf("ingress hook on lo: marked %v, want lo=%d", targets.PluginIngressHooked, lo.Index)
	}
	if targets := resolve("egress", []string{"lo"}); targets.PluginIngressHookedAll || len(targets.PluginIngressHooked) != 0 {
		t.Fatalf("egress hook on lo: targets = %+v, want nothing marked", targets)
	}
	if targets := resolve("ingress", nil); !targets.PluginIngressHookedAll {
		t.Fatalf("global ingress hook: targets = %+v, want every interface marked", targets)
	}
}

// egressNATTCStream runs the streaming TCP client of the egress NAT tests
// against the backend namespace.
type egressNATTCStream struct {
	client       *exec.Cmd
	clientLogs   *bytes.Buffer
	backend      *exec.Cmd
	backendLogs  *bytes.Buffer
	observedFile string
}

func startEgressNATTCStream(t *testing.T, topology egressNATIntegrationTopology) *egressNATTCStream {
	t.Helper()
	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATProbePort))
	stream := &egressNATTCStream{observedFile: filepath.Join(t.TempDir(), "observed-stream.txt"), clientLogs: &bytes.Buffer{}}
	stream.backend, stream.backendLogs = startEgressNATBackendHelperInNamespace(t, topology.BackendNS, "tcp", targetAddr, stream.observedFile)
	t.Cleanup(func() {
		if stream.backend != nil && stream.backend.ProcessState == nil {
			stopDataplanePerfHelper(t, stream.backend)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	stream.client = exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	stream.client.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=tcp",
		egressNATHelperTargetAddrEnv+"="+targetAddr,
	)
	stream.client.Stdout = stream.clientLogs
	stream.client.Stderr = stream.clientLogs
	if err := stream.client.Start(); err != nil {
		t.Fatalf("start streaming client helper: %v", err)
	}
	t.Cleanup(func() {
		if stream.client.Process != nil && stream.client.ProcessState == nil {
			_ = stream.client.Process.Kill()
		}
	})
	return stream
}

func (stream *egressNATTCStream) logs() string {
	return "client logs:\n" + stream.clientLogs.String() + "\nbackend logs:\n" + stream.backendLogs.String()
}

// wait checks that the stream completed through the NAT address.
func (stream *egressNATTCStream) wait(t *testing.T) {
	t.Helper()
	if err := stream.client.Wait(); err != nil {
		t.Fatalf("streaming client helper failed: %v\n%s", err, stream.logs())
	}
	waitForEgressNATHelperExit(t, stream.backend, "tcp-stream", stream.backendLogs.String())
	data, err := os.ReadFile(stream.observedFile)
	if err != nil {
		t.Fatalf("read streaming observed peer: %v", err)
	}
	if observed := strings.TrimSpace(string(data)); observed != egressNATUplinkAddr {
		t.Fatalf("streaming backend observed source IP %q, want %q", observed, egressNATUplinkAddr)
	}
}

// flowCacheTCPArrivals lists the arrival ifindexes of the TCP entries
// recorded under keyIfIndex.
func flowCacheTCPArrivals(m *ebpf.Map, keyIfIndex int) ([]int, error) {
	var arrivals []int
	iter := m.Iterate()
	var key tcFlowKeyV4
	var value tcFlowCacheValueV4
	for iter.Next(&key, &value) {
		if key.Proto == syscall.IPPROTO_TCP && int(key.IfIndex) == keyIfIndex {
			arrivals = append(arrivals, int(value.InIfIndex))
		}
	}
	return arrivals, iter.Err()
}

// flowCacheTCPEntries counts the TCP entries of the flow cache per key
// ifindex.
func flowCacheTCPEntries(m *ebpf.Map) (map[int]int, error) {
	counts := map[int]int{}
	iter := m.Iterate()
	var key tcFlowKeyV4
	var value tcFlowCacheValueV4
	for iter.Next(&key, &value) {
		if key.Proto == syscall.IPPROTO_TCP {
			counts[int(key.IfIndex)]++
		}
	}
	return counts, iter.Err()
}

// With the flow cache on, established egress NAT packets in both directions
// leave through tc_flow_cache instead of the core, and a closing connection
// drops its entries. With the uplink in a bridge, replies enter a port and
// are recorded under the bridge, the ifindex of the reply flow, so a FIN or
// RST from the client finds them.
func TestEgressNATTCFlowCacheServesEstablishedTCP(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	for _, natType := range []string{egressNATTypeSymmetric, egressNATTypeFullCone} {
		for _, bridged := range []bool{false, true} {
			name := natType
			if bridged {
				name += "/bridged-uplink"
			}
			t.Run(name, func(t *testing.T) {
				testEgressNATTCFlowCacheServesEstablishedTCP(t, natType, bridged)
			})
		}
	}
}

// moveEgressNATUplinkIntoBridge makes the uplink a port of a new bridge that
// takes over its address and neighbours, and returns the bridge's name.
func moveEgressNATUplinkIntoBridge(t *testing.T, topology egressNATIntegrationTopology) string {
	t.Helper()
	bridge := truncateIfName("fwub" + strconv.Itoa(os.Getpid()%100000))
	runDataplanePerfCmd("ip", "link", "del", bridge)
	t.Cleanup(func() { runDataplanePerfCmd("ip", "link", "del", bridge) })
	backendPeerMAC := mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", bridge, "type", "bridge")
	mustRunDataplanePerfCmd(t, "ip", "addr", "del", egressNATUplinkAddr+"/24", "dev", topology.UplinkHostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.UplinkHostIF, "master", bridge)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATUplinkAddr+"/24", "dev", bridge)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", bridge, "up")
	mustRunDataplanePerfCmd(t, "ip", "route", "replace", egressNATBackendAddr+"/32", "dev", bridge, "src", egressNATUplinkAddr)
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", egressNATBackendAddr, "lladdr", backendPeerMAC, "dev", bridge, "nud", "permanent")
	bridgeMAC := mustReadHostInterfaceMAC(t, bridge)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "neigh", "replace", egressNATUplinkAddr, "lladdr", bridgeMAC, "dev", topology.BackendNSIF, "nud", "permanent")
	return bridge
}

func testEgressNATTCFlowCacheServesEstablishedTCP(t *testing.T, natType string, bridged bool) {
	t.Setenv(egressNATHelperStreamCyclesEnv, "240")
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	outInterface := topology.UplinkHostIF
	if bridged {
		outInterface = moveEgressNATUplinkIntoBridge(t, topology)
	}

	rt := newTCKernelRuleRuntime(&Config{Experimental: map[string]bool{experimentalFeatureKernelTCFlowCache: true}})
	defer rt.Close()
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    outInterface,
		OutSourceIP:     egressNATUplinkAddr,
		Protocol:        "tcp",
		NATType:         natType,
		Enabled:         true,
	}, topology.ChildHostIF, 1, "tcp")
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("egress NAT result = %+v, want running tc", result)
	}
	cacheProg := rt.coll.Programs[kernelFlowCacheProgramName]
	cacheMap := rt.coll.Maps[kernelTCFlowCacheMapName]
	forwardProg := rt.coll.Programs[kernelForwardDispatchProgramName]
	replyProg := rt.coll.Programs[kernelReplyDispatchProgramName]
	if cacheProg == nil || cacheMap == nil || forwardProg == nil || replyProg == nil {
		t.Fatal("flow cache or dispatch programs are unavailable")
	}
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}
	uplink, err := netlink.LinkByName(topology.UplinkHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.UplinkHostIF, err)
	}
	// Replies are recorded under the reply flow's ifindex: the rule's out
	// interface, also when they enter one of its ports.
	out, err := netlink.LinkByName(outInterface)
	if err != nil {
		t.Fatalf("resolve %s: %v", outInterface, err)
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Skipf("BPF run statistics are unavailable: %v", err)
	}
	defer stats.Close()

	stream := startEgressNATTCStream(t, topology)

	deadline := time.Now().Add(3 * time.Second)
	for {
		counts, err := flowCacheTCPEntries(cacheMap)
		if err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		if counts[child.Attrs().Index] > 0 && counts[out.Attrs().Index] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow cache entries per ifindex = %v, want both %s and %s\n%s", counts, topology.ChildHostIF, outInterface, stream.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	arrivals, err := flowCacheTCPArrivals(cacheMap, out.Attrs().Index)
	if err != nil {
		t.Fatalf("read flow cache: %v", err)
	}
	for _, arrival := range arrivals {
		if arrival != uplink.Attrs().Index {
			t.Fatalf("reply entries under %s record arrivals %v, want %s=%d", outInterface, arrivals, topology.UplinkHostIF, uplink.Attrs().Index)
		}
	}

	runs := func() (cache uint64, core uint64) {
		for _, item := range []struct {
			prog *ebpf.Program
			dst  *uint64
		}{{cacheProg, &cache}, {forwardProg, &core}, {replyProg, &core}} {
			s, err := item.prog.Stats()
			if err != nil {
				t.Fatalf("read program statistics: %v", err)
			}
			*item.dst += s.RunCount
		}
		return cache, core
	}
	cacheBefore, coreBefore := runs()
	time.Sleep(time.Second)
	cacheAfter, coreAfter := runs()
	cacheRuns, coreRuns := cacheAfter-cacheBefore, coreAfter-coreBefore
	// The core still takes each flow's slow path once per window and the
	// first packet after it; everything else must stay in the cache.
	if cacheRuns < 50 || coreRuns*2 > cacheRuns {
		t.Fatalf("within one second tc_flow_cache ran %d times and the core %d times, want the cache to serve most packets", cacheRuns, coreRuns)
	}
	t.Logf("within one second tc_flow_cache ran %d times, the core %d times", cacheRuns, coreRuns)

	stream.wait(t)

	// FIN and RST go through the core, which drops the connection's entries.
	deadline = time.Now().Add(3 * time.Second)
	for {
		counts, err := flowCacheTCPEntries(cacheMap)
		if err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		if len(counts) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow cache kept entries after the connection closed: %v", counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A plugin hook on an interface's ingress keeps that interface out of the
// flow cache, so the hook sees every packet: neither the cache program nor
// entries for it. The other direction, without hooks, is still cached.
func TestEgressNATTCFlowCacheSkipsPluginHookedInterface(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	t.Setenv(egressNATHelperStreamCyclesEnv, "240")
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	pluginsRoot := t.TempDir()
	pluginDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	// The bridge serves no rule: the core runs there only for the hook.
	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ChildHostIF, topology.BridgeIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))
	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
		Experimental:            map[string]bool{experimentalFeatureKernelTCFlowCache: true},
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
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("egress NAT result = %+v, want running tc", result)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q; plugin snapshot = %+v", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4, rt.PluginSnapshot())
	}
	cacheMap := rt.coll.Maps[kernelTCFlowCacheMapName]
	if cacheMap == nil {
		t.Fatal("flow cache map is unavailable")
	}
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}
	uplink, err := netlink.LinkByName(topology.UplinkHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.UplinkHostIF, err)
	}
	bridge, err := netlink.LinkByName(topology.BridgeIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.BridgeIF, err)
	}
	cacheOn := map[int]bool{}
	coreOn := map[int]bool{}
	for _, att := range rt.attachments {
		key, ok := att.key()
		if !ok || key.parent != netlink.HANDLE_MIN_INGRESS {
			continue
		}
		if key.priority == kernelFlowCacheFilterPrio {
			cacheOn[key.linkIndex] = true
		} else {
			coreOn[key.linkIndex] = true
		}
	}
	if !coreOn[bridge.Attrs().Index] || cacheOn[bridge.Attrs().Index] {
		t.Fatalf("on %s, which only a plugin hook needs: core attached %v, flow cache attached %v; want the core alone", topology.BridgeIF, coreOn[bridge.Attrs().Index], cacheOn[bridge.Attrs().Index])
	}
	if !coreOn[child.Attrs().Index] || cacheOn[child.Attrs().Index] {
		t.Fatalf("on %s, where the rule receives packets behind a plugin hook: core attached %v, flow cache attached %v; want the core alone", topology.ChildHostIF, coreOn[child.Attrs().Index], cacheOn[child.Attrs().Index])
	}
	if !cacheOn[uplink.Attrs().Index] {
		t.Fatalf("flow cache attached on ifindexes %v, want %s, where the rule receives replies without hooks", cacheOn, topology.UplinkHostIF)
	}

	stream := startEgressNATTCStream(t, topology)
	hooked := func() {
		t.Helper()
		counts, err := flowCacheTCPEntries(cacheMap)
		if err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		if counts[child.Attrs().Index] != 0 {
			t.Fatalf("flow cache recorded %d entries for %s, whose ingress runs a plugin hook", counts[child.Attrs().Index], topology.ChildHostIF)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		hooked()
		counts, err := flowCacheTCPEntries(cacheMap)
		if err != nil {
			t.Fatalf("read flow cache: %v", err)
		}
		if counts[uplink.Attrs().Index] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow cache entries per ifindex = %v, want the reply direction on %s cached\n%s", counts, topology.UplinkHostIF, stream.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Established traffic keeps entering the hooked interface without an
	// entry appearing for it.
	time.Sleep(500 * time.Millisecond)
	hooked()
	stream.wait(t)
}
