//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

const (
	tcRuleScaleDefaultCount   = 2048
	tcRuleScaleDefaultBatch   = 256
	managedNetworkRuleCount   = 2048
	managedNetworkRuleBatch   = 256
	xdpRuleScaleDefaultCount  = 512
	xdpRuleScaleDefaultBatch  = 128
	kernelRuleScalePollDelay  = 250 * time.Millisecond
	kernelRuleScaleWaitPeriod = 90 * time.Second
)

func TestTCKernelRuleScaleSelectiveMutationAndHotRestart(t *testing.T) {
	baseBinary := requireTCRuleMutationIntegrationBinary(t)

	harness := startTCRuleMutationHarness(t, baseBinary, "scale-hot-restart")
	ruleCount := envInt("FORWARD_TC_RULE_SCALE_RULES", tcRuleScaleDefaultCount)
	batchSize := envInt("FORWARD_TC_RULE_SCALE_BATCH", tcRuleScaleDefaultBatch)
	if ruleCount < 8 {
		t.Fatalf("FORWARD_TC_RULE_SCALE_RULES=%d, want >= 8", ruleCount)
	}

	created := createKernelScaleRulesBatch(t, harness.APIBase, buildTCRuleScaleRules(harness.Topology, ruleCount), batchSize)
	if len(created) != ruleCount {
		t.Fatalf("created rules = %d, want %d", len(created), ruleCount)
	}

	statusByID := waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount)

	sampleRules := selectKernelScaleSampleRules(t, created, statusByID)
	probeTCRuleScaleSampleRules(t, harness.Topology.ClientNS, sampleRules)

	middleRule := sampleRules[len(sampleRules)/2]
	updated := middleRule.Rule
	updated.Remark = middleRule.Remark + "-updated"
	updated.Tag = "tc-scale-updated"
	updateTCRuleMutationRule(t, harness.APIBase, updated)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount)
	probeTCRuleScaleSampleRules(t, harness.Topology.ClientNS, sampleRules)

	toggledRule := sampleRules[0]
	toggleTCRuleScaleRule(t, harness.APIBase, toggledRule.ID)
	waitForTCRuleScaleRuleStopped(t, harness.APIBase, toggledRule.ID)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount-1)
	expectTCRuleScaleProbeFailure(t, harness.Topology.ClientNS, toggledRule.InPort)
	probeTCRuleScaleSampleRules(t, harness.Topology.ClientNS, sampleRules[1:])

	toggleTCRuleScaleRule(t, harness.APIBase, toggledRule.ID)
	waitForTCRuleMutationRuleRunning(t, harness.APIBase, toggledRule.ID)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount)
	probeTCRuleScaleSampleRules(t, harness.Topology.ClientNS, sampleRules)

	steadyClients := make([]*tcRuleMutationSteadyClient, 0, len(sampleRules))
	for _, rule := range sampleRules {
		target := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))
		client := startTCRuleMutationSteadyClientWithDuration(t, harness.Topology.ClientNS, target, tcRuleMutationRestartSteadyDuration)
		waitForTCRuleMutationSteadyClientReady(t, client)
		steadyClients = append(steadyClients, client)
	}

	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		for _, client := range steadyClients {
			stopTCRuleMutationSteadyClient(t, client)
		}
		t.Fatalf("write hot restart marker: %v", err)
	}

	restartTCRuleMutationForward(t, &harness)
	waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount)

	for _, client := range steadyClients {
		stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
		if err != nil {
			logKernelRuntimeOnFailure(t, harness.APIBase)
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("steady client failed across scaled hot restart: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
		}
	}
	probeTCRuleScaleSampleRules(t, harness.Topology.ClientNS, sampleRules)
}

func TestXDPKernelIPv4FullNATScaleSelectiveToggle(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)

	harness := startXDPFullNATIntegrationHarness(t, baseBinary, "scale-toggle")
	ruleCount := envInt("FORWARD_XDP_RULE_SCALE_RULES", xdpRuleScaleDefaultCount)
	batchSize := envInt("FORWARD_XDP_RULE_SCALE_BATCH", xdpRuleScaleDefaultBatch)
	if ruleCount < 8 {
		t.Fatalf("FORWARD_XDP_RULE_SCALE_RULES=%d, want >= 8", ruleCount)
	}

	created := createKernelScaleRulesBatch(t, harness.APIBase, buildXDPRuleScaleRules(harness.Topology, ruleCount), batchSize)
	if len(created) != ruleCount {
		t.Fatalf("created rules = %d, want %d", len(created), ruleCount)
	}

	statusByID := waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listXDPFullNATIntegrationRules,
		ruleEngineKernel,
		kernelEngineXDP,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineXDP, ruleCount)

	sampleRules := selectKernelScaleSampleRules(t, created, statusByID)
	probeXDPRuleScaleSampleRules(t, harness.Topology, sampleRules)

	toggledRule := sampleRules[len(sampleRules)/2]
	toggleXDPFullNATIntegrationRule(t, harness.APIBase, toggledRule.ID)
	waitForXDPFullNATIntegrationRuleStopped(t, harness.APIBase, toggledRule.Remark)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineXDP, ruleCount-1)
	expectXDPFullNATIntegrationProbeFailure(t, harness.Topology, "tcp", toggledRule.InPort, toggledRule.OutPort)
	for _, rule := range sampleRules {
		if rule.ID == toggledRule.ID {
			continue
		}
		if observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, "tcp", rule.InPort, rule.OutPort); observedIP != dataplanePerfBackendHost {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("xdp scale probe on rule %d observed source IP %q, want %q", rule.ID, observedIP, dataplanePerfBackendHost)
		}
	}

	toggleXDPFullNATIntegrationRule(t, harness.APIBase, toggledRule.ID)
	waitForXDPFullNATIntegrationRuleRunning(t, harness.APIBase, toggledRule.Remark, xdpFullNATIntegrationMode("xdp-fullnat-scale-toggle"))
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineXDP, ruleCount)
	probeXDPRuleScaleSampleRules(t, harness.Topology, sampleRules)
}

func TestManagedNetworkTCKernelRuleScaleCoexistsWithHotRestart(t *testing.T) {
	requireManagedNetworkKernelRuleScalePrereqs(t)

	harness := startEgressNATIntegrationHarness(t, "managed-network-tc-scale")
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}

	backendCmd, backendLogs := startDataplanePerfBackend(t, perfTopology)
	t.Cleanup(func() {
		stopDataplanePerfHelper(t, backendCmd)
	})
	defer func() {
		if !t.Failed() {
			return
		}
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		if backendLogs != nil {
			t.Logf("backend logs:\n%s", backendLogs.String())
		}
	}()

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	network := createManagedNetworkIntegrationNetwork(t, harness.APIBase, topology)
	managedIPv6 := mustBuildManagedNetworkIntegrationIPv6Assignment(t, network, topology.ChildHostIF)
	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	createManagedNetworkIntegrationReservation(t, harness.APIBase, network.ID, clientMAC, managedNetworkIntegrationIPv4Lease)
	waitForManagedNetworkKernelRuleScaleReady(t, harness, topology, perfTopology, network.ID, managedIPv6.AssignedPrefix, "initial apply")
	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)

	baselineEngine := waitForKernelScaleEngineActiveEntriesAtLeast(t, harness.APIBase, kernelEngineTC, 1)
	ruleCount := envInt("FORWARD_MANAGED_NETWORK_TC_RULE_SCALE_RULES", managedNetworkRuleCount)
	batchSize := envInt("FORWARD_MANAGED_NETWORK_TC_RULE_SCALE_BATCH", managedNetworkRuleBatch)
	if ruleCount < 8 {
		t.Fatalf("FORWARD_MANAGED_NETWORK_TC_RULE_SCALE_RULES=%d, want >= 8", ruleCount)
	}

	created := createKernelScaleRulesBatch(t, harness.APIBase, buildTCRuleScaleRules(perfTopology, ruleCount), batchSize)
	if len(created) != ruleCount {
		t.Fatalf("created rules = %d, want %d", len(created), ruleCount)
	}

	statusByID := waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, baselineEngine.ActiveEntries+ruleCount)

	sampleRules := selectKernelScaleSampleRules(t, created, statusByID)
	probeTCRuleScaleSampleRules(t, topology.ClientNS, sampleRules)
	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)

	middleRule := sampleRules[len(sampleRules)/2]
	updated := middleRule.Rule
	updated.Remark = middleRule.Remark + "-updated"
	updated.Tag = "managed-network-tc-scale-updated"
	updateTCRuleMutationRule(t, harness.APIBase, updated)
	waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, baselineEngine.ActiveEntries+ruleCount)
	probeTCRuleScaleSampleRules(t, topology.ClientNS, sampleRules)
	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)

	toggledRule := sampleRules[0]
	toggleTCRuleScaleRule(t, harness.APIBase, toggledRule.ID)
	waitForTCRuleScaleRuleStopped(t, harness.APIBase, toggledRule.ID)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, baselineEngine.ActiveEntries+ruleCount-1)
	expectTCRuleScaleProbeFailure(t, topology.ClientNS, toggledRule.InPort)
	probeTCRuleScaleSampleRules(t, topology.ClientNS, sampleRules[1:])
	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)

	toggleTCRuleScaleRule(t, harness.APIBase, toggledRule.ID)
	waitForTCRuleMutationRuleRunning(t, harness.APIBase, toggledRule.ID)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, baselineEngine.ActiveEntries+ruleCount)
	probeTCRuleScaleSampleRules(t, topology.ClientNS, sampleRules)
	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)

	restartClients := make([]*tcRuleMutationSteadyClient, 0, 3)
	for _, rule := range []RuleStatus{sampleRules[0], sampleRules[len(sampleRules)-1]} {
		target := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))
		client := startTCRuleMutationSteadyClientWithDuration(t, topology.ClientNS, target, tcRuleMutationRestartSteadyDuration)
		waitForTCRuleMutationSteadyClientReady(t, client)
		restartClients = append(restartClients, client)
	}
	egressClient := startTCRuleMutationSteadyClientWithDuration(
		t,
		topology.ClientNS,
		net.JoinHostPort(dataplanePerfBackendAddr, strconv.Itoa(dataplanePerfBackendPort)),
		tcRuleMutationRestartSteadyDuration,
	)
	waitForTCRuleMutationSteadyClientReady(t, egressClient)
	restartClients = append(restartClients, egressClient)

	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		for _, client := range restartClients {
			stopTCRuleMutationSteadyClient(t, client)
		}
		t.Fatalf("write hot restart marker: %v", err)
	}

	restartManagedNetworkIntegrationForward(t, &harness)
	waitForManagedNetworkKernelRuleScaleReady(t, harness, topology, perfTopology, network.ID, managedIPv6.AssignedPrefix, "post-hot-restart apply")
	waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, baselineEngine.ActiveEntries+ruleCount)

	for _, client := range restartClients {
		stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
		if err != nil {
			t.Fatalf("steady client failed across managed-network scale hot restart: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
		}
	}

	assertManagedNetworkKernelRuleScaleManagedConnectivity(t, harness, topology, perfTopology)
	probeTCRuleScaleSampleRules(t, topology.ClientNS, sampleRules)
}

func buildTCRuleScaleRules(topology dataplanePerfTopology, count int) []Rule {
	rules := make([]Rule, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, Rule{
			InInterface:      topology.ClientHostIF,
			InIP:             dataplanePerfFrontAddr,
			InPort:           dataplanePerfFrontPort + i,
			OutInterface:     topology.BackendHostIF,
			OutIP:            dataplanePerfBackendAddr,
			OutPort:          dataplanePerfBackendPort,
			Protocol:         "tcp",
			Remark:           fmt.Sprintf("tc-scale-%04d", i),
			Tag:              "tc-scale",
			Transparent:      false,
			EnginePreference: ruleEngineKernel,
		})
	}
	return rules
}

func buildXDPRuleScaleRules(topology dataplanePerfTopology, count int) []Rule {
	rules := make([]Rule, 0, count)
	for i := 0; i < count; i++ {
		rules = append(rules, Rule{
			InInterface:      topology.ClientHostIF,
			InIP:             dataplanePerfFrontAddr,
			InPort:           dataplanePerfFrontPort + i,
			OutInterface:     topology.BackendHostIF,
			OutIP:            dataplanePerfBackendAddr,
			OutSourceIP:      dataplanePerfBackendHost,
			OutPort:          dataplanePerfBackendPort + i,
			Protocol:         "tcp",
			Remark:           fmt.Sprintf("xdp-scale-%04d", i),
			Tag:              "xdp-scale",
			Transparent:      false,
			EnginePreference: ruleEngineKernel,
		})
	}
	return rules
}

func createKernelScaleRulesBatch(t *testing.T, apiBase string, rules []Rule, batchSize int) []Rule {
	t.Helper()

	if batchSize <= 0 {
		batchSize = len(rules)
	}
	created := make([]Rule, 0, len(rules))
	for start := 0; start < len(rules); start += batchSize {
		end := start + batchSize
		if end > len(rules) {
			end = len(rules)
		}
		payload := ruleBatchRequest{Create: append([]Rule(nil), rules[start:end]...)}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal rule batch [%d:%d): %v", start, end, err)
		}
		req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules/batch", bytes.NewReader(data))
		if err != nil {
			t.Fatalf("build create rule batch request [%d:%d): %v", start, end, err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create rule batch [%d:%d): %v", start, end, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("create rule batch [%d:%d) unexpected status %d: %s", start, end, resp.StatusCode, string(body))
		}
		var result ruleBatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			t.Fatalf("decode create rule batch response [%d:%d): %v", start, end, err)
		}
		resp.Body.Close()
		if len(result.Created) != end-start {
			t.Fatalf("create rule batch [%d:%d) created=%d, want %d", start, end, len(result.Created), end-start)
		}
		created = append(created, result.Created...)
	}
	return created
}

func waitForKernelScaleRulesRunning(t *testing.T, apiBase string, ids []int64, list func(*testing.T, string) []RuleStatus, expectedEngine string, expectedKernelEngine string) map[int64]RuleStatus {
	t.Helper()

	want := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	deadline := time.Now().Add(kernelRuleScaleWaitPeriod)
	for time.Now().Before(deadline) {
		items := list(t, apiBase)
		statusByID := make(map[int64]RuleStatus, len(items))
		for _, item := range items {
			statusByID[item.ID] = item
		}

		allReady := len(statusByID) >= len(want)
		if allReady {
			for id := range want {
				item, ok := statusByID[id]
				if !ok || item.Status != "running" || item.EffectiveEngine != expectedEngine || item.EffectiveKernelEngine != expectedKernelEngine {
					allReady = false
					break
				}
			}
		}
		if allReady {
			return statusByID
		}
		time.Sleep(kernelRuleScalePollDelay)
	}
	t.Fatalf("rule set did not enter running/%s with kernel=%s in time", expectedEngine, expectedKernelEngine)
	return nil
}

func waitForKernelScaleEngineActiveEntries(t *testing.T, apiBase string, engineName string, expectedEntries int) KernelEngineRuntimeView {
	t.Helper()

	deadline := time.Now().Add(kernelRuleScaleWaitPeriod)
	for time.Now().Before(deadline) {
		runtimeResp := fetchKernelScaleRuntime(t, apiBase)
		engine, ok := dataplanePerfFindKernelEngine(runtimeResp.Engines, engineName)
		if ok && engine.ActiveEntries == expectedEntries && engine.Loaded {
			return engine
		}
		time.Sleep(kernelRuleScalePollDelay)
	}
	logDataplanePerfKernelRuntime(t, apiBase, "kernel scale runtime timeout for "+engineName)
	t.Fatalf("%s active entries did not reach %d in time", engineName, expectedEntries)
	return KernelEngineRuntimeView{}
}

func waitForKernelScaleEngineActiveEntriesAtLeast(t *testing.T, apiBase string, engineName string, minimumEntries int) KernelEngineRuntimeView {
	t.Helper()

	deadline := time.Now().Add(kernelRuleScaleWaitPeriod)
	for time.Now().Before(deadline) {
		runtimeResp := fetchKernelScaleRuntime(t, apiBase)
		engine, ok := dataplanePerfFindKernelEngine(runtimeResp.Engines, engineName)
		if ok && engine.Loaded && engine.ActiveEntries >= minimumEntries {
			return engine
		}
		time.Sleep(kernelRuleScalePollDelay)
	}
	logDataplanePerfKernelRuntime(t, apiBase, "kernel scale runtime timeout for "+engineName)
	t.Fatalf("%s active entries did not reach >= %d in time", engineName, minimumEntries)
	return KernelEngineRuntimeView{}
}

func fetchKernelScaleRuntime(t *testing.T, apiBase string) KernelRuntimeResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime", nil)
	if err != nil {
		t.Fatalf("build kernel runtime request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch kernel runtime: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetch kernel runtime unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var runtimeResp KernelRuntimeResponse
	if err := json.NewDecoder(resp.Body).Decode(&runtimeResp); err != nil {
		t.Fatalf("decode kernel runtime: %v", err)
	}
	return runtimeResp
}

func collectKernelScaleRuleIDs(rules []Rule) []int64 {
	out := make([]int64, 0, len(rules))
	for _, rule := range rules {
		if rule.ID <= 0 {
			continue
		}
		out = append(out, rule.ID)
	}
	return out
}

func selectKernelScaleSampleRules(t *testing.T, created []Rule, statusByID map[int64]RuleStatus) []RuleStatus {
	t.Helper()

	indexes := kernelScaleSampleIndexes(len(created))
	out := make([]RuleStatus, 0, len(indexes))
	for _, idx := range indexes {
		rule, ok := statusByID[created[idx].ID]
		if !ok {
			t.Fatalf("missing rule status for created rule id=%d", created[idx].ID)
		}
		out = append(out, rule)
	}
	return out
}

func kernelScaleSampleIndexes(total int) []int {
	if total <= 0 {
		return nil
	}
	candidates := []int{0, total / 3, (2 * total) / 3, total - 1}
	seen := make(map[int]struct{}, len(candidates))
	out := make([]int, 0, len(candidates))
	for _, idx := range candidates {
		if idx < 0 || idx >= total {
			continue
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}

func probeTCRuleScaleSampleRules(t *testing.T, clientNS string, rules []RuleStatus) {
	t.Helper()

	for _, rule := range rules {
		target := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))
		if err := runTCRuleMutationProbe(clientNS, target); err != nil {
			t.Fatalf("tc scale probe for rule %d on port %d failed: %v", rule.ID, rule.InPort, err)
		}
	}
}

func expectTCRuleScaleProbeFailure(t *testing.T, clientNS string, port int) {
	t.Helper()

	target := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(port))
	if err := runTCRuleMutationProbe(clientNS, target); err == nil {
		t.Fatalf("tc scale probe on disabled port %d unexpectedly succeeded", port)
	}
}

func probeXDPRuleScaleSampleRules(t *testing.T, topology dataplanePerfTopology, rules []RuleStatus) {
	t.Helper()

	for _, rule := range rules {
		if observedIP := runXDPFullNATIntegrationProbe(t, topology, "tcp", rule.InPort, rule.OutPort); observedIP != dataplanePerfBackendHost {
			t.Fatalf("xdp scale probe for rule %d observed source IP %q, want %q", rule.ID, observedIP, dataplanePerfBackendHost)
		}
	}
}

func toggleTCRuleScaleRule(t *testing.T, apiBase string, id int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules/toggle?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		t.Fatalf("build tc scale toggle rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("toggle tc scale rule %d: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("toggle tc scale rule %d unexpected status %d: %s", id, resp.StatusCode, string(body))
	}
}

func waitForTCRuleScaleRuleStopped(t *testing.T, apiBase string, id int64) RuleStatus {
	t.Helper()

	deadline := time.Now().Add(kernelRuleScaleWaitPeriod)
	for time.Now().Before(deadline) {
		for _, rule := range listTCRuleMutationRules(t, apiBase) {
			if rule.ID != id {
				continue
			}
			if !rule.Enabled && rule.Status == "stopped" {
				return rule
			}
			break
		}
		time.Sleep(kernelRuleScalePollDelay)
	}
	t.Fatalf("tc scale rule %d did not enter stopped state in time", id)
	return RuleStatus{}
}

func requireManagedNetworkKernelRuleScalePrereqs(t *testing.T) {
	t.Helper()

	if os.Getenv(managedNetworkIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux managed network integration test", managedNetworkIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
}

func waitForManagedNetworkKernelRuleScaleReady(t *testing.T, harness egressNATIntegrationHarness, topology egressNATIntegrationTopology, perfTopology dataplanePerfTopology, networkID int64, assignedPrefix string, phase string) {
	t.Helper()

	waitForManagedNetworkIntegrationReady(t, harness.APIBase, networkID, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	waitForManagedNetworkIntegrationAutoEgressNATReady(t, harness.APIBase, harness.LogPath, phase)
	if err := waitForManagedNetworkIntegrationIPv4Address(topology.BridgeIF, managedNetworkIntegrationIPv4CIDR, 15*time.Second); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	if err := waitForIPv6AssignmentRouteForPrefix(perfTopology, assignedPrefix); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
}

func assertManagedNetworkKernelRuleScaleManagedConnectivity(t *testing.T, harness egressNATIntegrationHarness, topology egressNATIntegrationTopology, perfTopology dataplanePerfTopology) {
	t.Helper()

	if err := runManagedNetworkDHCPv4Client(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4LeaseCIDR, managedNetworkIntegrationIPv4Gateway); err != nil {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatal(err)
	}
	seedManagedNetworkIntegrationIPv4Neighbors(t, topology, managedNetworkIntegrationIPv4Lease, managedNetworkIntegrationIPv4Gateway)
	if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		logManagedNetworkIntegrationStateOnFailure(t, perfTopology)
		t.Fatalf("managed network tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}
}
