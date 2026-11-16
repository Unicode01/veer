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

// The flow cache runs inside the dispatchers: no reconcile plans a program
// of its own on any hook, the place earlier releases used included.
func TestKernelAttachmentPlansHoldNoFlowCacheProgram(t *testing.T) {
	prog := &ebpf.Program{}
	sets := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}},
		ReplyIngress:   map[int][]int64{3: {2}, 4: {1}},
		ForwardEgress:  map[int][]int64{5: {1}},
	}
	for _, tcx := range []bool{false, true} {
		programs := kernelAttachmentPrograms{forwardProg: prog, replyProg: prog, forwardEgressProg: prog, tcx: tcx}
		plans := desiredKernelAttachmentPlansForRuleSets(sets, programs)
		if len(plans) == 0 {
			t.Fatal("no attachment plans for the rule sets")
		}
		for _, plan := range plans {
			if plan.key.isFlowCache() {
				t.Fatalf("plan %+v takes the flow cache position", plan)
			}
		}
	}
}

// The flow cache, configured or on by default, stays off beside the options
// it cannot serve, and the runtime names the option that keeps it off.
func TestTCRuntimeKeepsFlowCacheOffBesideOptionsItCannotServe(t *testing.T) {
	enabled := true
	for _, tc := range []struct {
		feature string
		want    string
	}{
		{feature: "", want: ""},
		// Packets sent from records count into their rules.
		{feature: experimentalFeatureKernelTraffic, want: ""},
		{feature: experimentalFeatureKernelTCReplyL2Cache, want: experimentalFeatureKernelTCReplyL2Cache},
		{feature: experimentalFeatureKernelTCRedirectNeighFast, want: experimentalFeatureKernelTCRedirectNeighFast},
		// Prepared L2 only affects its own rules; the others still record.
		{feature: experimentalFeatureKernelTCPreparedL2, want: ""},
	} {
		cfg := &Config{KernelTCFlowCacheSetting: &enabled, Experimental: map[string]bool{}}
		if tc.feature != "" {
			cfg.Experimental[tc.feature] = true
		}
		rt := newTCKernelRuleRuntime(cfg)
		if rt.flowCacheDisabledBy != tc.want || rt.enableFlowCache != (tc.want == "") {
			t.Fatalf("with %q: enableFlowCache = %t, flowCacheDisabledBy = %q; want %t, %q",
				tc.feature, rt.enableFlowCache, rt.flowCacheDisabledBy, tc.want == "", tc.want)
		}
	}
	// Unconfigured, the cache is on by default and yields the same way.
	for _, cfg := range []*Config{nil, {}} {
		if rt := newTCKernelRuleRuntime(cfg); !rt.enableFlowCache || rt.flowCacheDisabledBy != "" {
			t.Fatalf("unconfigured cache (config %v): enableFlowCache = %t, flowCacheDisabledBy = %q; want on", cfg, rt.enableFlowCache, rt.flowCacheDisabledBy)
		}
	}
	rt := newTCKernelRuleRuntime(&Config{Experimental: map[string]bool{experimentalFeatureKernelTCReplyL2Cache: true}})
	if rt.enableFlowCache || rt.flowCacheDisabledBy != experimentalFeatureKernelTCReplyL2Cache {
		t.Fatalf("unconfigured cache beside the reply L2 cache: enableFlowCache = %t, flowCacheDisabledBy = %q; want off for %s",
			rt.enableFlowCache, rt.flowCacheDisabledBy, experimentalFeatureKernelTCReplyL2Cache)
	}
	// Switched off, it stays off without a reason, whatever else is on.
	disabled := false
	rt = newTCKernelRuleRuntime(&Config{KernelTCFlowCacheSetting: &disabled, Experimental: map[string]bool{experimentalFeatureKernelTCReplyL2Cache: true}})
	if rt.enableFlowCache || rt.flowCacheDisabledBy != "" {
		t.Fatalf("disabled cache: enableFlowCache = %t, flowCacheDisabledBy = %q; want off without a reason", rt.enableFlowCache, rt.flowCacheDisabledBy)
	}
}

// An in-place reconcile keeps the core attachments it no longer plans but
// drops a flow cache program an earlier release attached, on cls_bpf and tcx
// alike.
func TestWithoutUnplannedFlowCacheKeepsOnlyPlannedCaches(t *testing.T) {
	filterAt := func(ifindex int, priority uint16, minor uint16) kernelAttachment {
		return kernelAttachment{filter: &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  priority,
			Handle:    netlink.MakeHandle(0, minor),
		}}}
	}
	tcxAt := func(ifindex int, priority uint16, minor uint16) kernelAttachment {
		key, _ := filterAt(ifindex, priority, minor).key()
		key.tcx = true
		return kernelAttachment{tcx: &kernelTCXAttachment{key: key}}
	}
	for _, at := range []func(int, uint16, uint16) kernelAttachment{filterAt, tcxAt} {
		leftover := at(3, kernelFlowCacheFilterPrio, kernelFlowCacheFilterHandle)
		staleCore := at(4, kernelForwardFilterPrio, kernelForwardFilterHandle)
		planned := []kernelAttachment{at(3, kernelForwardFilterPrio, kernelForwardFilterHandle)}
		old := []kernelAttachment{leftover, staleCore}

		got := withoutUnplannedFlowCache(mergeKernelAttachments(old, planned), planned)
		keys := kernelAttachmentKeySet(got)
		for _, want := range append(planned, staleCore) {
			key, _ := want.key()
			if _, ok := keys[key]; !ok {
				t.Fatalf("attachments %v miss %+v", keys, key)
			}
		}
		leftoverKey, _ := leftover.key()
		if _, ok := keys[leftoverKey]; ok || len(got) != 2 {
			t.Fatalf("attachments = %v, want the flow cache at %+v dropped", keys, leftoverKey)
		}
		if got := kernelAttachmentDeleteCount(old, got); got != 1 {
			t.Fatalf("delete count = %d, want 1", got)
		}
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

// flowFastTCPRecords lists, per key ifindex of the TCP flow entries that
// hold a fast-path record, the arrival ifindex each record was made for.
// Retired records carry no stamp.
func flowFastTCPRecords(m *ebpf.Map) (map[int][]int, error) {
	records := map[int][]int{}
	iter := m.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		if key.Proto == syscall.IPPROTO_TCP && value.Fast.Stamp != 0 {
			records[int(key.IfIndex)] = append(records[int(key.IfIndex)], int(value.Fast.InIfIndex))
		}
	}
	return records, iter.Err()
}

// With the flow cache on, established egress NAT packets in both directions
// leave straight from their flow entries' fast-path records, and a closing
// connection retires the records. With the uplink in a bridge, replies enter
// a port and their entry is keyed by the bridge, so the record names the
// port the packets arrive on.
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

	enabled := true
	rt := newTCKernelRuleRuntime(&Config{KernelTCFlowCacheSetting: &enabled})
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
	flowsMap := rt.coll.Maps[kernelFlowsMapNameV4]
	diagMap := rt.coll.Maps[kernelDiagMapName]
	forwardProg := rt.coll.Programs[kernelForwardDispatchProgramName]
	replyProg := rt.coll.Programs[kernelReplyDispatchProgramName]
	if flowsMap == nil || diagMap == nil || forwardProg == nil || replyProg == nil {
		t.Fatal("flow map, diag map or dispatch programs are unavailable")
	}
	child, err := netlink.LinkByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.ChildHostIF, err)
	}
	uplink, err := netlink.LinkByName(topology.UplinkHostIF)
	if err != nil {
		t.Fatalf("resolve %s: %v", topology.UplinkHostIF, err)
	}
	// The reply entry is keyed by the rule's out interface, also when
	// replies enter one of its ports.
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
		records, err := flowFastTCPRecords(flowsMap)
		if err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		if len(records[child.Attrs().Index]) > 0 && len(records[out.Attrs().Index]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast-path records per key ifindex = %v, want both %s and %s\n%s", records, topology.ChildHostIF, outInterface, stream.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	records, err := flowFastTCPRecords(flowsMap)
	if err != nil {
		t.Fatalf("read flow entries: %v", err)
	}
	for _, arrival := range records[out.Attrs().Index] {
		if arrival != uplink.Attrs().Index {
			t.Fatalf("reply records under %s name arrivals %v, want %s=%d", outInterface, records[out.Attrs().Index], topology.UplinkHostIF, uplink.Attrs().Index)
		}
	}

	runs := func() (hits, forward, reply uint64) {
		for _, item := range []struct {
			prog *ebpf.Program
			dst  *uint64
		}{{forwardProg, &forward}, {replyProg, &reply}} {
			s, err := item.prog.Stats()
			if err != nil {
				t.Fatalf("read program statistics: %v", err)
			}
			*item.dst = s.RunCount
		}
		return flowCacheHitsForTest(t, diagMap), forward, reply
	}
	// The stream's packets in both directions, counted where they enter the
	// router: the client's at the child, the backend's at the uplink port.
	sent := openIPv4TCPFlowCounter(t, topology.ChildHostIF, egressNATClientAddr, egressNATBackendAddr)
	replied := openIPv4TCPFlowCounter(t, topology.UplinkHostIF, egressNATBackendAddr, egressNATUplinkAddr)
	hitsBefore, forwardBefore, replyBefore := runs()
	time.Sleep(time.Second)
	hitsAfter, forwardAfter, replyAfter := runs()
	packets := sent.close(t) + replied.close(t)
	hits := hitsAfter - hitsBefore
	t.Logf("within one second the stream sent %d packets, %d left from fast-path records; the forward dispatcher ran %d times, the reply dispatcher %d",
		packets, hits, forwardAfter-forwardBefore, replyAfter-replyBefore)
	// Each direction still takes the full path for the first packet of a
	// window and the next one, which records; everything else must leave
	// from the records.
	if packets < 50 || hits > packets || hits*3 < packets*2 {
		t.Fatalf("%d of %d stream packets left from fast-path records, want most of them", hits, packets)
	}

	stream.wait(t)

	// FIN and RST go through the full path, which retires both records.
	deadline = time.Now().Add(3 * time.Second)
	for {
		records, err := flowFastTCPRecords(flowsMap)
		if err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		if len(records) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast-path records outlived the connection: %v", records)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A plugin hook on an interface's ingress keeps that interface out of the
// flow cache, so the hook sees every packet: no record for packets entering
// it. The other direction, without hooks, is still recorded.
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
		PluginsEnabledSetting:    &enabled,
		PluginsDataplaneSetting:  &enabled,
		PluginsDir:               pluginsRoot,
		KernelTCFlowCacheSetting: &enabled,
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
	flowsMap := rt.coll.Maps[kernelFlowsMapNameV4]
	if flowsMap == nil {
		t.Fatal("flow map is unavailable")
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
	coreOn := map[int]bool{}
	for _, att := range rt.attachments {
		key, ok := att.key()
		if !ok || key.parent != netlink.HANDLE_MIN_INGRESS {
			continue
		}
		if key.isFlowCache() {
			t.Fatalf("a flow cache program is attached: %+v", key)
		}
		coreOn[key.linkIndex] = true
	}
	for _, link := range []netlink.Link{bridge, child, uplink} {
		if !coreOn[link.Attrs().Index] {
			t.Fatalf("core attached on ingress of ifindexes %v, want %s too", coreOn, link.Attrs().Name)
		}
	}

	stream := startEgressNATTCStream(t, topology)
	hooked := func() {
		t.Helper()
		records, err := flowFastTCPRecords(flowsMap)
		if err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		if n := len(records[child.Attrs().Index]); n != 0 {
			t.Fatalf("flow cache recorded %d entries for %s, whose ingress runs a plugin hook", n, topology.ChildHostIF)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		hooked()
		records, err := flowFastTCPRecords(flowsMap)
		if err != nil {
			t.Fatalf("read flow entries: %v", err)
		}
		if len(records[uplink.Attrs().Index]) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast-path records per key ifindex = %v, want the reply direction on %s recorded\n%s", records, topology.UplinkHostIF, stream.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Established traffic keeps entering the hooked interface without a
	// record appearing for it.
	time.Sleep(500 * time.Millisecond)
	hooked()
	stream.wait(t)
}
