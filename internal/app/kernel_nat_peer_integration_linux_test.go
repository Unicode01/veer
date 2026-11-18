//go:build linux

package app

// Shared NAT ports: symmetric egress NAT and full NAT port forwards hold a
// NAT port per peer (nat_peers_v4/v6), so one port serves every destination
// once, while full cone keeps its ports to itself. The pools here hold a
// single port, so every mapping is on it.
//
// Linux usage, as root with the embedded eBPF objects built:
//   FORWARD_RUN_EGRESS_NAT_TEST=1 go test ./internal/app -run 'TestEgressNATTCSharedNATPort' -count=1 -v
//   FORWARD_RUN_EGRESS_NAT_XDP_TEST=1 go test ./internal/app -run 'TestEgressNATXDPSharedNATPort' -count=1 -v
//   FORWARD_RUN_TC_IPV6_TEST=1 go test ./internal/app -run 'TestTCKernelIPv6SharedNATPort' -count=1 -v
//   FORWARD_RUN_XDP_FULLNAT_TEST=1 go test ./internal/app -run 'TestXDPKernelIPv6SharedNATPort' -count=1 -v

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// sharedNATTestPort lies in the default pool and outside the host's
// ephemeral ports.
const sharedNATTestPort = 24600

type sharedNATTestCounts struct {
	peers     int
	shared    int
	draining  int
	exclusive int
}

func requireSharedNATIntegration(t *testing.T, enableEnv string) {
	t.Helper()
	if os.Getenv(enableEnv) != "1" {
		t.Skipf("set %s=1 to run this Linux kernel NAT integration test", enableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
}

func newSharedNATTestRuntime(t *testing.T, engine string) kernelRuleRuntime {
	t.Helper()
	cfg := &Config{KernelNATPortMin: sharedNATTestPort, KernelNATPortMax: sharedNATTestPort}
	var rt kernelRuleRuntime
	if engine == kernelEngineXDP {
		rt = newXDPKernelRuleRuntime(cfg)
	} else {
		rt = newTCKernelRuleRuntime(cfg)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

func reconcileSharedNATTestRules(t *testing.T, rt kernelRuleRuntime, engine string, rules ...Rule) {
	t.Helper()
	results, err := rt.Reconcile(rules)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for _, rule := range rules {
		if result := results[rule.ID]; !result.Running || result.Engine != engine || result.Error != "" {
			t.Fatalf("rule %d result = %+v, want running %s", rule.ID, result, engine)
		}
	}
}

func sharedNATTestRefs(rt kernelRuleRuntime) kernelRuntimeMapRefs {
	switch r := rt.(type) {
	case *linuxKernelRuleRuntime:
		r.mu.Lock()
		defer r.mu.Unlock()
		return kernelRuntimeMapRefsFromCollection(r.coll)
	case *xdpKernelRuleRuntime:
		r.mu.Lock()
		defer r.mu.Unlock()
		return kernelRuntimeMapRefsFromCollection(r.coll)
	}
	return kernelRuntimeMapRefs{}
}

// runSharedNATTestMaintenance runs one full maintenance pass, which prunes
// orphan NAT entries and reclaims shared ports.
func runSharedNATTestMaintenance(t *testing.T, rt kernelRuleRuntime) {
	t.Helper()
	var err error
	switch r := rt.(type) {
	case *linuxKernelRuleRuntime:
		r.mu.Lock()
		r.maintenanceState.requestFull()
		r.mu.Unlock()
		err = r.Maintain()
	case *xdpKernelRuleRuntime:
		r.mu.Lock()
		r.maintenanceState.requestFull()
		r.mu.Unlock()
		err = r.Maintain()
	default:
		t.Fatalf("runtime %T has no maintenance", rt)
	}
	if err != nil {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func countSharedNATTestEntries[K any, PK any](t *testing.T, ports []*ebpf.Map, peers []*ebpf.Map) sharedNATTestCounts {
	t.Helper()
	var out sharedNATTestCounts
	for _, m := range ports {
		if m == nil {
			continue
		}
		iter := m.Iterate()
		var key K
		var value tcNATPortValue
		for iter.Next(&key, &value) {
			switch value.Mode {
			case kernelNATPortShared:
				out.shared++
			case kernelNATPortDraining:
				out.draining++
			default:
				out.exclusive++
			}
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("iterate nat ports: %v", err)
		}
	}
	for _, m := range peers {
		if m == nil {
			continue
		}
		iter := m.Iterate()
		var key PK
		var value tcNATPeerValue
		for iter.Next(&key, &value) {
			out.peers++
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("iterate nat peers: %v", err)
		}
	}
	return out
}

// sharedNATTestState counts the NAT entries of both banks, since a reconcile
// may rebuild the collection and move the live ones to the old bank.
func sharedNATTestState(t *testing.T, rt kernelRuleRuntime) sharedNATTestCounts {
	t.Helper()
	refs := sharedNATTestRefs(rt)
	return countSharedNATTestEntries[tcNATPortKeyV4, tcNATPeerKeyV4](t,
		[]*ebpf.Map{refs.natV4, refs.natOldV4},
		[]*ebpf.Map{refs.natPeersV4, refs.natPeersOldV4})
}

func sharedNATTestStateV6(t *testing.T, rt kernelRuleRuntime) sharedNATTestCounts {
	t.Helper()
	refs := sharedNATTestRefs(rt)
	return countSharedNATTestEntries[tcNATPortKeyV6, tcNATPeerKeyV6](t,
		[]*ebpf.Map{refs.natV6, refs.natOldV6},
		[]*ebpf.Map{refs.natPeersV6, refs.natPeersOldV6})
}

// expectEgressNATUDPProbeDropped sends a datagram the NAT has no port for:
// neither the backend nor, through it, the client may see it.
func expectEgressNATUDPProbeDropped(t *testing.T, topology egressNATIntegrationTopology, targetPort int, localPort int) {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), fmt.Sprintf("dropped-udp-%d-%d.txt", targetPort, localPort))
	listenAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(targetPort))
	backendCmd, backendLogs := startEgressNATBackendHelperInNamespaceWithObservedFormat(t, topology.BackendNS, "udp", listenAddr, observedFile, egressNATObservedFmtHostPort)
	defer stopDataplanePerfHelper(t, backendCmd)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=udp",
		egressNATHelperTargetAddrEnv+"="+listenAddr,
		egressNATHelperLocalAddrEnv+"="+net.JoinHostPort(egressNATClientAddr, strconv.Itoa(localPort)),
	)
	if output, err := clientCmd.CombinedOutput(); err == nil {
		t.Fatalf("a datagram from client port %d to port %d got through without a free NAT mapping\nclient output:\n%s\nbackend logs:\n%s", localPort, targetPort, output, backendLogs.String())
	}
	if data, err := os.ReadFile(observedFile); err == nil {
		t.Fatalf("the backend saw %q from client port %d, which the NAT had no mapping for", data, localPort)
	}
}

func TestEgressNATTCSharedNATPortServesManyPeers(t *testing.T) {
	testEgressNATSharedNATPort(t, kernelEngineTC, egressNATTestEnableEnv)
}

func TestEgressNATXDPSharedNATPortServesManyPeers(t *testing.T) {
	testEgressNATSharedNATPort(t, kernelEngineXDP, egressNATXDPTestEnableEnv)
}

func testEgressNATSharedNATPort(t *testing.T, engine string, enableEnv string) {
	requireSharedNATIntegration(t, enableEnv)
	var topology egressNATIntegrationTopology
	if engine == kernelEngineXDP {
		if reason := xdpVethNATRedirectGuardReasonForRelease(kernelRelease()); reason != "" {
			t.Skip(reason)
		}
		topology = setupEgressNATIntegrationDirectTopology(t)
	} else {
		topology = setupEgressNATIntegrationTopology(t)
	}
	seedEgressNATIntegrationNeighbor(t, topology)
	// The direct topology has no bridge: guests sit behind the parent itself.
	child := topology.ChildHostIF
	if child == "" {
		child = topology.BridgeIF
	}

	rt := newSharedNATTestRuntime(t, engine)
	item := EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    topology.UplinkHostIF,
		OutSourceIP:     egressNATUplinkAddr,
		Protocol:        "udp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}
	reconcileSharedNATTestRules(t, rt, engine, buildEgressNATSyntheticRule(item, child, 1, "udp"))

	want := net.JoinHostPort(egressNATUplinkAddr, strconv.Itoa(sharedNATTestPort))
	for i, port := range []int{egressNATProbePort, egressNATProbePortAlt1, egressNATProbePortAlt2} {
		if got := runEgressNATUDPMappingProbe(t, topology, port, egressNATMappingLocalPort+i); got != want {
			t.Fatalf("flow to port %d left as %s, want %s: every destination shares the pool's only port", port, got, want)
		}
	}
	if state := sharedNATTestState(t, rt); state.peers != 3 || state.shared != 1 || state.exclusive != 0 {
		t.Fatalf("NAT entries after three destinations = %+v, want three peers on one shared port", state)
	}

	// The port's mapping to a destination belongs to the flow that made it.
	expectEgressNATUDPProbeDropped(t, topology, egressNATProbePort, egressNATMappingLocalPort+3)

	// The switch to full cone purges the symmetric flows and their mappings;
	// the port stays shared, so the full cone mapping cannot take it yet.
	item.NATType = egressNATTypeFullCone
	reconcileSharedNATTestRules(t, rt, engine, buildEgressNATSyntheticRule(item, child, 1, "udp"))
	if state := sharedNATTestState(t, rt); state.peers != 0 || state.shared != 1 {
		t.Fatalf("NAT entries after the purge = %+v, want no peers and the port still shared", state)
	}
	expectEgressNATUDPProbeDropped(t, topology, egressNATProbePort, egressNATMappingLocalPort+4)

	// Maintenance drains the unused port, then deletes it a pass later.
	runSharedNATTestMaintenance(t, rt)
	if state := sharedNATTestState(t, rt); state.draining != 1 || state.shared != 0 {
		t.Fatalf("NAT entries after one maintenance pass = %+v, want the port draining", state)
	}
	expectEgressNATUDPProbeDropped(t, topology, egressNATProbePort, egressNATMappingLocalPort+5)
	runSharedNATTestMaintenance(t, rt)
	if state := sharedNATTestState(t, rt); state.draining != 0 || state.shared != 0 {
		t.Fatalf("NAT entries after two maintenance passes = %+v, want the port reclaimed", state)
	}

	if got := runEgressNATUDPMappingProbe(t, topology, egressNATProbePort, egressNATMappingLocalPort+6); got != want {
		t.Fatalf("full cone mapping left as %s, want %s", got, want)
	}
	if state := sharedNATTestState(t, rt); state.exclusive != 1 || state.peers != 0 {
		t.Fatalf("NAT entries after the full cone mapping = %+v, want one exclusive port", state)
	}
}

func TestTCKernelIPv6SharedNATPortServesManyBackends(t *testing.T) {
	testIPv6SharedNATPort(t, kernelEngineTC, tcIPv6IntegrationEnableEnv)
}

func TestXDPKernelIPv6SharedNATPortServesManyBackends(t *testing.T) {
	testIPv6SharedNATPort(t, kernelEngineXDP, xdpFullNATIntegrationEnableEnv)
}

func testIPv6SharedNATPort(t *testing.T, engine string, enableEnv string) {
	requireSharedNATIntegration(t, enableEnv)
	if engine == kernelEngineXDP {
		if reason := xdpVethNATRedirectGuardReasonForRelease(kernelRelease()); reason != "" {
			t.Skip(reason)
		}
	}
	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)
	seedTCIPv6IntegrationNeighbors(t, topology)

	rt := newSharedNATTestRuntime(t, engine)
	forward := func(id int64, frontPort int, backendPort int) Rule {
		return Rule{
			ID:               id,
			InInterface:      topology.ClientHostIF,
			InIP:             tcIPv6IntegrationFrontAddr,
			InPort:           frontPort,
			OutInterface:     topology.BackendHostIF,
			OutIP:            tcIPv6IntegrationBackendAddr,
			OutSourceIP:      tcIPv6IntegrationBackendHost,
			OutPort:          backendPort,
			Protocol:         "udp",
			Enabled:          true,
			EnginePreference: ruleEngineKernel,
		}
	}
	rules := []Rule{
		forward(1, tcIPv6IntegrationFrontPort+20, tcIPv6IntegrationBackendPort+20),
		forward(2, tcIPv6IntegrationFrontPort+21, tcIPv6IntegrationBackendPort+21),
	}
	reconcileSharedNATTestRules(t, rt, engine, rules...)

	for _, rule := range rules {
		if err := runTCIPv6IntegrationProbePorts(t, topology, "udp", rule.InPort, rule.OutPort); err != nil {
			t.Fatalf("rule %d: %v", rule.ID, err)
		}
	}
	natPorts := make(map[uint32]uint16)
	refs := sharedNATTestRefs(rt)
	for _, flows := range []*ebpf.Map{refs.flowsV6, refs.flowsOldV6} {
		if flows == nil {
			continue
		}
		iter := flows.Iterate()
		var key tcFlowKeyV6
		var value tcFlowValueV6
		var xdpValue xdpFlowValueV6
		for {
			var ok bool
			if engine == kernelEngineXDP {
				ok = iter.Next(&key, &xdpValue)
				value.RuleID, value.NATPort, value.Flags = xdpValue.RuleID, xdpValue.NATPort, xdpValue.Flags
			} else {
				ok = iter.Next(&key, &value)
			}
			if !ok {
				break
			}
			if value.Flags&kernelFlowFlagFullNAT != 0 && value.Flags&kernelFlowFlagFrontEntry == 0 {
				if value.Flags&kernelFlowFlagNATPeer == 0 {
					t.Fatalf("rule %d flow %+v holds an exclusive NAT port, want a shared one", value.RuleID, key)
				}
				natPorts[value.RuleID] = value.NATPort
			}
		}
		if err := iter.Err(); err != nil {
			t.Fatalf("iterate IPv6 flows: %v", err)
		}
	}
	for _, rule := range rules {
		if got := natPorts[uint32(rule.ID)]; got != sharedNATTestPort {
			t.Fatalf("rule %d NAT port = %d, want %d for both backends (all: %v)", rule.ID, got, sharedNATTestPort, natPorts)
		}
	}
	if state := sharedNATTestStateV6(t, rt); state.peers != 2 || state.shared != 1 || state.exclusive != 0 {
		t.Fatalf("IPv6 NAT entries = %+v, want two peers on one shared port", state)
	}

	// A port forward's peer is its backend: while one flow holds the pool's
	// only port towards it, a second flow through the same rule finds none.
	err := runTCIPv6IntegrationProbePorts(t, topology, "udp", rules[0].InPort, rules[0].OutPort)
	if err == nil {
		t.Fatal("a second flow to one backend got through without a free NAT mapping")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("second flow to one backend failed for another reason: %v", err)
	}
	if state := sharedNATTestStateV6(t, rt); state.peers != 2 {
		t.Fatalf("IPv6 NAT entries after the refused flow = %+v, want the two mappings only", state)
	}
}

// sharedNATTestStream is a TCP stream from the client namespace to one
// backend port, which the backend records the source of.
type sharedNATTestStream struct {
	port         int
	client       *exec.Cmd
	clientLogs   bytes.Buffer
	done         chan error
	backend      *exec.Cmd
	backendLogs  *bytes.Buffer
	observedFile string
}

func startSharedNATTestStream(t *testing.T, topology egressNATIntegrationTopology, port int) *sharedNATTestStream {
	t.Helper()
	stream := &sharedNATTestStream{
		port:         port,
		done:         make(chan error, 1),
		observedFile: filepath.Join(t.TempDir(), fmt.Sprintf("stream-%d.txt", port)),
	}
	listenAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(port))
	stream.backend, stream.backendLogs = startEgressNATBackendHelperInNamespaceWithObservedFormat(t, topology.BackendNS, "tcp", listenAddr, stream.observedFile, egressNATObservedFmtHostPort)
	stream.client = exec.Command("ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	stream.client.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=tcp",
		egressNATHelperTargetAddrEnv+"="+listenAddr,
	)
	stream.client.Stdout = &stream.clientLogs
	stream.client.Stderr = &stream.clientLogs
	if err := stream.client.Start(); err != nil {
		stopDataplanePerfHelper(t, stream.backend)
		t.Fatalf("start stream client to port %d: %v", port, err)
	}
	go func() { stream.done <- stream.client.Wait() }()
	t.Cleanup(func() {
		if stream.client.ProcessState == nil && stream.client.Process != nil {
			_ = stream.client.Process.Kill()
		}
		if stream.backend.ProcessState == nil {
			stopDataplanePerfHelper(t, stream.backend)
		}
	})
	return stream
}

// wait returns the source the backend saw once the stream completed.
func (stream *sharedNATTestStream) wait(t *testing.T, harness egressNATIntegrationHarness) string {
	t.Helper()
	select {
	case err := <-stream.done:
		if err != nil {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("stream to port %d broke: %v\nclient logs:\n%s\nbackend logs:\n%s", stream.port, err, stream.clientLogs.String(), stream.backendLogs.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("stream to port %d did not finish", stream.port)
	}
	waitForEgressNATHelperExit(t, stream.backend, "tcp-stream", stream.backendLogs.String())
	data, err := os.ReadFile(stream.observedFile)
	if err != nil {
		t.Fatalf("read the source the backend on port %d saw: %v", stream.port, err)
	}
	return strings.TrimSpace(string(data))
}

func setSharedNATTestPortPool(t *testing.T, configPath string) {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg["kernel_nat_port_min"] = sharedNATTestPort
	cfg["kernel_nat_port_max"] = sharedNATTestPort
	if data, err = json.MarshalIndent(cfg, "", "  "); err != nil {
		t.Fatalf("encode config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// Mappings on a shared port outlive a hot restart: the successor adopts the
// NAT peer maps as its old bank along with the flows that hold them, and new
// mappings share the port with them meanwhile.
func TestEgressNATTCSharedNATPortSurvivesHotRestart(t *testing.T) {
	requireSharedNATIntegration(t, egressNATTestEnableEnv)
	// Each stream runs about eight seconds, which a hot restart fits in.
	t.Setenv(egressNATHelperStreamCyclesEnv, "320")

	harness := startEgressNATIntegrationHarnessWithConfig(t, "shared-hr", func(t *testing.T, _ string, _ string, configPath string) {
		setSharedNATTestPortPool(t, configPath)
	})
	createEgressNATIntegrationEntryForScopeWithOptions(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF, "tcp", egressNATTypeSymmetric)
	waitForEgressNATIntegrationStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)

	streams := []*sharedNATTestStream{
		startSharedNATTestStream(t, harness.Topology, egressNATProbePort),
		startSharedNATTestStream(t, harness.Topology, egressNATProbePortAlt1),
	}
	time.Sleep(time.Second)

	offset := hotRestartIntegrationLogSize(t, harness.LogPath)
	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		t.Fatalf("write hot restart marker: %v", err)
	}
	restartManagedNetworkIntegrationForward(t, &harness)
	waitForHotRestartIntegrationLog(t, harness.LogPath, offset, "kernel dataplane hot restart: adopting pinned tc maps=")
	adopted := hotRestartIntegrationLogSince(t, harness.LogPath, offset)
	if strings.Contains(adopted, "(cold restart)") || !strings.Contains(adopted, kernelTCNatPeersOldMapNameV4) {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("the successor did not adopt the NAT peer map as its old bank:\n%s", adopted)
	}
	waitForEgressNATIntegrationStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)

	// While the old bank's streams run, a new destination shares their port.
	t.Setenv(egressNATHelperStreamCyclesEnv, "1")
	want := net.JoinHostPort(egressNATUplinkAddr, strconv.Itoa(sharedNATTestPort))
	probe := startSharedNATTestStream(t, harness.Topology, egressNATProbePortAlt2)
	if got := probe.wait(t, harness); got != want {
		t.Fatalf("new mapping after the hot restart left as %s, want %s beside the old bank's", got, want)
	}
	for _, stream := range streams {
		if got := stream.wait(t, harness); got != want {
			t.Fatalf("stream to port %d left as %s, want %s", stream.port, got, want)
		}
	}
}

// A port forward's connection opened on a shared port survives a hot restart
// into a build from before ports were shared, which knows nothing of the NAT
// peer maps, and the hot restart back. FORWARD_TC_RULE_MUTATION_PEER_BINARY
// names that build.
//
//	FORWARD_RUN_TC_RULE_MUTATION_TEST=1 FORWARD_TC_RULE_MUTATION_PEER_BINARY=/path/to/older/veer go test ./internal/app -run TestTCKernelRuleMutationHotRestartAcrossBuildsKeepsSharedNATPortConnection -count=1 -v
func TestTCKernelRuleMutationHotRestartAcrossBuildsKeepsSharedNATPortConnection(t *testing.T) {
	baseBinary := requireTCRuleMutationIntegrationBinary(t)
	peerBinary := strings.TrimSpace(os.Getenv("FORWARD_TC_RULE_MUTATION_PEER_BINARY"))
	if peerBinary == "" {
		t.Skip("set FORWARD_TC_RULE_MUTATION_PEER_BINARY to the build to hot restart to and from")
	}

	harness := startTCRuleMutationHarness(t, baseBinary, "hot-restart-shared-nat-across-builds")
	rule := createTCRuleMutationRule(t, harness.APIBase, harness.Topology, Rule{
		InInterface:      harness.Topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     harness.Topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Remark:           "tc-rule-mutation-hot-restart-shared-nat-across-builds",
		Tag:              "tc-rule-mutation",
		Transparent:      false,
		EnginePreference: ruleEngineKernel,
	})
	target := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))
	if err := runTCRuleMutationProbe(harness.Topology.ClientNS, target); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("baseline probe failed: %v", err)
	}

	// This build opens the connection on a shared port.
	client := startTCRuleMutationSteadyClientWithDuration(t, harness.Topology.ClientNS, target, 3*tcRuleMutationRestartSteadyDuration)
	waitForTCRuleMutationSteadyClientReady(t, client)

	for _, binary := range []string{peerBinary, baseBinary} {
		if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
			stopTCRuleMutationSteadyClient(t, client)
			t.Fatalf("write hot restart marker: %v", err)
		}
		harness.ForwardBinary = binary
		restartTCRuleMutationForward(t, &harness)
		waitForTCRuleMutationRuleRunning(t, harness.APIBase, rule.ID)
		if err := runTCRuleMutationProbe(harness.Topology.ClientNS, target); err != nil {
			stopTCRuleMutationSteadyClient(t, client)
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("probe after the hot restart into %s failed: %v", binary, err)
		}
	}

	stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
	if err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("connection on a shared port broke across the builds: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
}
