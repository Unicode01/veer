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
	sets := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{3: {1}},
		ReplyIngress:   map[int][]int64{3: {2}, 4: {1}},
		ForwardEgress:  map[int][]int64{5: {1}},
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
	for _, plan := range plans {
		order = append(order, strconv.Itoa(plan.ifindex)+"/"+plan.name)
		if !plan.flowCache {
			continue
		}
		if plan.key.parent != netlink.HANDLE_MIN_INGRESS || !plan.key.tcx || plan.attach != kernelPluginPipelineAttachIngress {
			t.Fatalf("flow cache plan = %+v, want an ingress tcx position", plan)
		}
		cached[plan.ifindex] = true
	}
	if len(cached) != 2 || !cached[3] || !cached[4] {
		t.Fatalf("flow cache on ifindexes %v, want the ingress hooks 3 and 4", cached)
	}
	want := "3/" + kernelFlowCacheProgramName + " 3/" + kernelReplyProgramName + " 3/" + kernelForwardProgramName
	if got := strings.Join(order[:3], " "); got != want {
		t.Fatalf("plan order on ifindex 3 = %q, want %q", got, want)
	}

	programs.flowCacheProg = nil
	for _, plan := range desiredKernelAttachmentPlansForRuleSets(sets, programs) {
		if plan.flowCache {
			t.Fatalf("flow cache plan without the program: %+v", plan)
		}
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

// flowCacheTCPEntries counts the TCP entries of the flow cache per ingress
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
// drops its entries.
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
		t.Run(natType, func(t *testing.T) {
			testEgressNATTCFlowCacheServesEstablishedTCP(t, natType)
		})
	}
}

func testEgressNATTCFlowCacheServesEstablishedTCP(t *testing.T, natType string) {
	t.Setenv(egressNATHelperStreamCyclesEnv, "240")
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	rt := newTCKernelRuleRuntime(&Config{Experimental: map[string]bool{experimentalFeatureKernelTCFlowCache: true}})
	defer rt.Close()
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    topology.UplinkHostIF,
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
		if counts[child.Attrs().Index] > 0 && counts[uplink.Attrs().Index] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow cache entries per ifindex = %v, want both %s and %s\n%s", counts, topology.ChildHostIF, topology.UplinkHostIF, stream.logs())
		}
		time.Sleep(10 * time.Millisecond)
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
// flow cache, so the hook sees every packet. The other direction, without
// hooks, is still cached.
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
	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ChildHostIF)
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
