//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	controlplaneStressDiagEnableEnv       = "FORWARD_RUN_CONTROLPLANE_STRESS_DIAG"
	controlplaneStressRuleCount           = 2048
	controlplaneStressRulesMapLimit       = 65536
	controlplaneStressFlowsMapLimit       = 8192
	controlplaneStressNATMapLimit         = 8192
	controlplaneStressLoadConnections     = 3500
	controlplaneStressLoadConcurrency     = 1024
	controlplaneStressLoadBytesPerConn    = 128
	controlplaneStressLoadIOChunkBytes    = 128
	controlplaneStressLoadSteadySeconds   = 40
	controlplaneStressMinFlowUtilization  = 0.80
	controlplaneStressMinNATUtilization   = 0.40
	controlplaneStressPollInterval        = 200 * time.Millisecond
	controlplaneStressWaitTimeout         = 45 * time.Second
	controlplaneStressManagedLease        = managedNetworkIntegrationIPv4Lease
	controlplaneStressManagedLeaseCIDR    = managedNetworkIntegrationIPv4LeaseCIDR
	controlplaneStressManagedLeaseGateway = managedNetworkIntegrationIPv4Gateway
)

type controlplaneStressRuntimeSample struct {
	ActiveEntries      int       `json:"active_entries"`
	RulesEntries       int       `json:"rules_entries"`
	RulesCapacity      int       `json:"rules_capacity"`
	FlowsEntries       int       `json:"flows_entries"`
	FlowsCapacity      int       `json:"flows_capacity"`
	NATEntries         int       `json:"nat_entries"`
	NATCapacity        int       `json:"nat_capacity"`
	FlowUtilization    float64   `json:"flow_utilization"`
	NATUtilization     float64   `json:"nat_utilization"`
	PressureActive     bool      `json:"pressure_active"`
	PressureLevel      string    `json:"pressure_level,omitempty"`
	PressureReason     string    `json:"pressure_reason,omitempty"`
	Loaded             bool      `json:"loaded"`
	AttachmentsHealthy bool      `json:"attachments_healthy"`
	LastReconcileAt    time.Time `json:"last_reconcile_at,omitempty"`
	LastReconcileMs    int64     `json:"last_reconcile_ms,omitempty"`
	LastReconcileMode  string    `json:"last_reconcile_mode,omitempty"`
	LastReconcileError string    `json:"last_reconcile_error,omitempty"`
	LastReconcileApply int       `json:"last_reconcile_applied_entries,omitempty"`
	LastReconcileUps   int       `json:"last_reconcile_upserts,omitempty"`
	LastReconcileDel   int       `json:"last_reconcile_deletes,omitempty"`
	LastReconcileAtt   int       `json:"last_reconcile_attaches,omitempty"`
	LastReconcileDet   int       `json:"last_reconcile_detaches,omitempty"`
	LastReconcileKeep  int       `json:"last_reconcile_preserved,omitempty"`
}

type controlplaneStressMeasurement struct {
	Name             string                          `json:"name"`
	APIMs            int64                           `json:"api_ms"`
	SettleMs         int64                           `json:"settle_ms"`
	EngineAfter      controlplaneStressRuntimeSample `json:"engine_after"`
	RuleAfter        *RuleStatus                     `json:"rule_after,omitempty"`
	ManagedAfter     *ManagedNetworkStatus           `json:"managed_after,omitempty"`
	ManagedEgressNAT *egressNATIntegrationStatus     `json:"managed_egress_nat,omitempty"`
	Notes            []string                        `json:"notes,omitempty"`
}

type controlplaneStressLoadResult struct {
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Connections    int     `json:"connections"`
	PayloadBytes   int64   `json:"payload_bytes"`
}

type controlplaneStressReport struct {
	RuleCount         int                             `json:"rule_count"`
	RulesMapLimit     int                             `json:"rules_map_limit"`
	FlowsMapLimit     int                             `json:"flows_map_limit"`
	NATMapLimit       int                             `json:"nat_map_limit"`
	LoadConnections   int                             `json:"load_connections"`
	LoadConcurrency   int                             `json:"load_concurrency"`
	InitialRuntime    controlplaneStressRuntimeSample `json:"initial_runtime"`
	UnderLoadRuntime  controlplaneStressRuntimeSample `json:"under_load_runtime"`
	Operations        []controlplaneStressMeasurement `json:"operations"`
	LoadSurvived      bool                            `json:"load_survived"`
	LoadResult        *controlplaneStressLoadResult   `json:"load_result,omitempty"`
	LoadStdout        string                          `json:"load_stdout,omitempty"`
	LoadStderr        string                          `json:"load_stderr,omitempty"`
	ManagedProbeOK    bool                            `json:"managed_probe_ok"`
	ManagedProbeError string                          `json:"managed_probe_error,omitempty"`
	FinalRuntime      controlplaneStressRuntimeSample `json:"final_runtime"`
}

type controlplaneStressLoadClient struct {
	cmd      *exec.Cmd
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	waitDone chan error
}

func TestKernelControlplaneLatencyUnderHighRuleAndMapPressure(t *testing.T) {
	if os.Getenv(controlplaneStressDiagEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux control-plane stress diagnostic", controlplaneStressDiagEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	ruleCount := envInt("FORWARD_STRESS_RULE_COUNT", controlplaneStressRuleCount)
	rulesMapLimit := envInt("FORWARD_STRESS_RULES_MAP_LIMIT", controlplaneStressRulesMapLimit)
	flowsMapLimit := envInt("FORWARD_STRESS_FLOWS_MAP_LIMIT", controlplaneStressFlowsMapLimit)
	natMapLimit := envInt("FORWARD_STRESS_NAT_MAP_LIMIT", controlplaneStressNATMapLimit)
	loadConnections := envInt("FORWARD_STRESS_LOAD_CONNECTIONS", controlplaneStressLoadConnections)
	loadConcurrency := envInt("FORWARD_STRESS_LOAD_CONCURRENCY", controlplaneStressLoadConcurrency)
	loadSteadySeconds := envInt("FORWARD_STRESS_LOAD_STEADY_SECONDS", controlplaneStressLoadSteadySeconds)
	minFlowUtilization := envFloat("FORWARD_STRESS_MIN_FLOW_UTILIZATION", controlplaneStressMinFlowUtilization)
	minNATUtilization := envFloat("FORWARD_STRESS_MIN_NAT_UTILIZATION", controlplaneStressMinNATUtilization)

	harness := startControlplaneStressHarness(t, "controlplane-stress", rulesMapLimit, flowsMapLimit, natMapLimit)
	topology := harness.Topology
	perfTopology := dataplanePerfTopology{
		ClientNS:      topology.ClientNS,
		BackendNS:     topology.BackendNS,
		ClientHostIF:  topology.ChildHostIF,
		ClientNSIF:    topology.ClientNSIF,
		BackendHostIF: topology.UplinkHostIF,
		BackendNSIF:   topology.BackendNSIF,
	}
	report := controlplaneStressReport{
		RuleCount:       ruleCount,
		RulesMapLimit:   rulesMapLimit,
		FlowsMapLimit:   flowsMapLimit,
		NATMapLimit:     natMapLimit,
		LoadConnections: loadConnections,
		LoadConcurrency: loadConcurrency,
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
		t.Logf("backend logs:\n%s", backendLogs.String())
	}()

	mustEnsureIPv6AssignmentAddress(t, perfTopology.BackendHostIF, ipv6AssignmentIntegrationParentAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6AddressInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationBackendAddr+"/64")
	mustEnsureManagedNetworkIntegrationIPv6DefaultRouteInNamespace(t, perfTopology.BackendNS, perfTopology.BackendNSIF, ipv6AssignmentIntegrationParentAddr)
	seedIPv6AssignmentIntegrationBackendNeighbors(t, perfTopology)

	created := createKernelScaleRulesBatch(t, harness.APIBase, buildTCRuleScaleRules(perfTopology, ruleCount), 256)
	statusByID := waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	waitForKernelScaleEngineActiveEntries(t, harness.APIBase, kernelEngineTC, ruleCount)
	report.InitialRuntime = captureControlplaneStressRuntime(t, harness.APIBase)

	loadRule := statusByID[created[0].ID]
	updateRule := statusByID[created[len(created)/2].ID]
	toggleRule := statusByID[created[len(created)-1].ID]

	if err := runTCRuleMutationProbe(topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(loadRule.InPort))); err != nil {
		t.Fatalf("baseline load-rule probe failed: %v", err)
	}

	loadClient := startControlplaneStressLoadClient(
		t,
		topology.ClientNS,
		net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(loadRule.InPort)),
		loadConnections,
		loadConcurrency,
		controlplaneStressLoadBytesPerConn,
		controlplaneStressLoadIOChunkBytes,
		loadSteadySeconds,
	)
	t.Cleanup(func() {
		stopControlplaneStressLoadClient(loadClient)
	})
	underLoad := waitForControlplaneStressUtilization(t, harness.APIBase, minFlowUtilization, minNATUtilization, loadClient)
	report.UnderLoadRuntime = underLoad

	report.Operations = append(report.Operations, measureControlplaneStressRuleUpdate(t, harness.APIBase, updateRule.ID))
	report.Operations = append(report.Operations, measureControlplaneStressRuleToggle(t, harness.APIBase, toggleRule.ID, ruleCount-1))
	report.Operations = append(report.Operations, measureControlplaneStressRuleToggle(t, harness.APIBase, toggleRule.ID, ruleCount))

	clientMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	report.Operations = append(report.Operations, measureControlplaneStressManagedNetworkCreate(t, harness.APIBase, topology, clientMAC))

	report.Operations = append(report.Operations, measureControlplaneStressHotRestart(t, &harness, topology, created, ruleCount))

	loadResult, loadStdout, loadStderr, err := waitForControlplaneStressLoadClient(loadClient)
	report.LoadStdout = strings.TrimSpace(loadStdout)
	report.LoadStderr = strings.TrimSpace(loadStderr)
	if err != nil {
		payload, _ := json.MarshalIndent(report, "", "  ")
		t.Fatalf("steady load failed under stress diagnostic: %v\nreport=%s", err, string(payload))
	}
	report.LoadSurvived = true
	report.LoadResult = &controlplaneStressLoadResult{
		ElapsedSeconds: loadResult.ElapsedSeconds,
		Connections:    loadResult.Connections,
		PayloadBytes:   loadResult.PayloadBytes,
	}

	prepareManagedNetworkIntegrationClientNamespace(t, topology)
	seedEgressNATIntegrationNeighbor(t, topology)
	err = runManagedNetworkDHCPv4Client(t, topology, controlplaneStressManagedLease, controlplaneStressManagedLeaseCIDR, controlplaneStressManagedLeaseGateway)
	if err == nil {
		seedManagedNetworkIntegrationIPv4Neighbors(t, topology, controlplaneStressManagedLease, controlplaneStressManagedLeaseGateway)
		if observedIP := runEgressNATIntegrationProbe(t, topology, "tcp"); observedIP == egressNATUplinkAddr {
			report.ManagedProbeOK = true
		} else {
			report.ManagedProbeError = fmt.Sprintf("managed egress probe observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
		}
	} else {
		report.ManagedProbeError = err.Error()
	}

	report.FinalRuntime = captureControlplaneStressRuntime(t, harness.APIBase)
	payload, _ := json.MarshalIndent(report, "", "  ")
	t.Logf("controlplane stress report:\n%s", string(payload))
	if report.ManagedProbeError != "" {
		t.Fatalf("managed network probe failed after stress: %s", report.ManagedProbeError)
	}
}

func startControlplaneStressHarness(t *testing.T, name string, rulesLimit int, flowsLimit int, natLimit int) egressNATIntegrationHarness {
	t.Helper()

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-"+name)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	runtimeStateRoot := filepath.Join(runtimeDir, "runtime-state")
	if err := os.MkdirAll(runtimeStateRoot, 0o755); err != nil {
		t.Fatalf("create runtime state dir: %v", err)
	}
	bpfStateRoot := requireKernelHotRestartBPFStateRoot(t)
	hotRestartMarkerPath := filepath.Join(runtimeDir, ".hot-restart-kernel")
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeControlplaneStressConfig(t, configPath, webPort, rulesLimit, flowsLimit, natLimit)

	logPath := filepath.Join(workDir, "forward-"+name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	t.Cleanup(func() {
		_ = logFile.Close()
	})

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)),
		forwardHotRestartMarkerEnv+"="+hotRestartMarkerPath,
		forwardBPFStateDirEnv+"="+bpfStateRoot,
		forwardRuntimeStateDirEnv+"="+runtimeStateRoot,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	t.Cleanup(func() {
		stopForwardProcessTree(t, cmd)
	})

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	return egressNATIntegrationHarness{
		Topology:             topology,
		APIBase:              apiBase,
		LogPath:              logPath,
		Cmd:                  cmd,
		WorkDir:              workDir,
		ForwardBinary:        forwardBinary,
		ConfigPath:           configPath,
		HotRestartMarkerPath: hotRestartMarkerPath,
		BPFStateRoot:         bpfStateRoot,
		RuntimeStateRoot:     runtimeStateRoot,
	}
}

func writeControlplaneStressConfig(t *testing.T, path string, webPort int, rulesLimit int, flowsLimit int, natLimit int) {
	t.Helper()

	cfg := Config{
		WebPort:             webPort,
		WebToken:            dataplanePerfToken,
		MaxWorkers:          1,
		DrainTimeoutHours:   1,
		DefaultEngine:       ruleEngineKernel,
		KernelEngineOrder:   []string{kernelEngineTC},
		KernelRulesMapLimit: rulesLimit,
		KernelFlowsMapLimit: flowsLimit,
		KernelNATMapLimit:   natLimit,
		Experimental: map[string]bool{
			experimentalFeatureBridgeXDP:     false,
			experimentalFeatureKernelTraffic: true,
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func captureControlplaneStressRuntime(t *testing.T, apiBase string) controlplaneStressRuntimeSample {
	t.Helper()

	runtimeResp := fetchControlplaneStressRuntime(t, apiBase)
	engine, ok := dataplanePerfFindKernelEngine(runtimeResp.Engines, kernelEngineTC)
	if !ok {
		t.Fatalf("tc engine missing from kernel runtime")
	}
	return controlplaneStressRuntimeFromEngine(engine)
}

func controlplaneStressRuntimeFromEngine(engine KernelEngineRuntimeView) controlplaneStressRuntimeSample {
	return controlplaneStressRuntimeSample{
		ActiveEntries:      engine.ActiveEntries,
		RulesEntries:       engine.RulesMapEntries,
		RulesCapacity:      engine.RulesMapCapacity,
		FlowsEntries:       engine.FlowsMapEntries,
		FlowsCapacity:      engine.FlowsMapCapacity,
		NATEntries:         engine.NATMapEntries,
		NATCapacity:        engine.NATMapCapacity,
		FlowUtilization:    controlplaneStressUtilization(engine.FlowsMapEntries, engine.FlowsMapCapacity),
		NATUtilization:     controlplaneStressUtilization(engine.NATMapEntries, engine.NATMapCapacity),
		PressureActive:     engine.PressureActive,
		PressureLevel:      engine.PressureLevel,
		PressureReason:     engine.PressureReason,
		Loaded:             engine.Loaded,
		AttachmentsHealthy: engine.AttachmentsHealthy,
		LastReconcileAt:    engine.LastReconcileAt,
		LastReconcileMs:    engine.LastReconcileMs,
		LastReconcileMode:  engine.LastReconcileMode,
		LastReconcileError: engine.LastReconcileError,
		LastReconcileApply: engine.LastReconcileAppliedEntries,
		LastReconcileUps:   engine.LastReconcileUpserts,
		LastReconcileDel:   engine.LastReconcileDeletes,
		LastReconcileAtt:   engine.LastReconcileAttaches,
		LastReconcileDet:   engine.LastReconcileDetaches,
		LastReconcileKeep:  engine.LastReconcilePreserved,
	}
}

func controlplaneStressUtilization(entries int, capacity int) float64 {
	if capacity <= 0 {
		return 0
	}
	return float64(entries) / float64(capacity)
}

func fetchControlplaneStressRuntime(t *testing.T, apiBase string) KernelRuntimeResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime?refresh=1", nil)
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
		t.Fatalf("fetch kernel runtime unexpected status %d", resp.StatusCode)
	}

	var runtimeResp KernelRuntimeResponse
	if err := json.NewDecoder(resp.Body).Decode(&runtimeResp); err != nil {
		t.Fatalf("decode kernel runtime: %v", err)
	}
	return runtimeResp
}

func startControlplaneStressLoadClient(t *testing.T, clientNS string, targetAddr string, connections int, concurrency int, bytesPerConn int64, ioChunkBytes int64, steadySeconds int) *controlplaneStressLoadClient {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", clientNS, os.Args[0], "-test.run", "TestDataplanePerfHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		dataplanePerfHelperEnv+"=1",
		dataplanePerfHelperRoleEnv+"=client",
		dataplanePerfTargetEnv+"="+targetAddr,
		dataplanePerfConnEnv+"="+strconv.Itoa(connections),
		dataplanePerfConcurrencyEnv+"="+strconv.Itoa(concurrency),
		dataplanePerfBytesEnv+"="+strconv.FormatInt(bytesPerConn, 10),
		dataplanePerfIOChunkEnv+"="+strconv.FormatInt(ioChunkBytes, 10),
		dataplanePerfSteadyEnv+"="+strconv.Itoa(steadySeconds),
	)

	client := &controlplaneStressLoadClient{
		cmd:      cmd,
		waitDone: make(chan error, 1),
	}
	cmd.Stdout = &client.stdout
	cmd.Stderr = &client.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stress load client: %v", err)
	}
	go func() {
		client.waitDone <- cmd.Wait()
	}()
	return client
}

func waitForControlplaneStressUtilization(t *testing.T, apiBase string, minFlowUtilization float64, minNATUtilization float64, client *controlplaneStressLoadClient) controlplaneStressRuntimeSample {
	t.Helper()

	deadline := time.Now().Add(controlplaneStressWaitTimeout)
	for time.Now().Before(deadline) {
		sample := captureControlplaneStressRuntime(t, apiBase)
		if sample.FlowUtilization >= minFlowUtilization && sample.NATUtilization >= minNATUtilization {
			return sample
		}

		select {
		case err := <-client.waitDone:
			stdout := strings.TrimSpace(client.stdout.String())
			stderr := strings.TrimSpace(client.stderr.String())
			t.Fatalf("stress load client exited before target utilization: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
		default:
		}
		time.Sleep(controlplaneStressPollInterval)
	}
	t.Fatalf("timed out waiting for flow/nat utilization target %.2f/%.2f", minFlowUtilization, minNATUtilization)
	return controlplaneStressRuntimeSample{}
}

func waitForControlplaneStressLoadClient(client *controlplaneStressLoadClient) (dataplanePerfClientResult, string, string, error) {
	if client == nil {
		return dataplanePerfClientResult{}, "", "", nil
	}
	err := <-client.waitDone
	stdout := strings.TrimSpace(client.stdout.String())
	stderr := strings.TrimSpace(client.stderr.String())
	if err != nil {
		return dataplanePerfClientResult{}, stdout, stderr, err
	}
	var result dataplanePerfClientResult
	if stdout != "" {
		if decodeErr := json.Unmarshal([]byte(stdout), &result); decodeErr != nil {
			return dataplanePerfClientResult{}, stdout, stderr, fmt.Errorf("decode stress load result: %w", decodeErr)
		}
	}
	return result, stdout, stderr, nil
}

func stopControlplaneStressLoadClient(client *controlplaneStressLoadClient) {
	if client == nil || client.cmd == nil || client.cmd.Process == nil {
		return
	}
	if client.cmd.ProcessState != nil && client.cmd.ProcessState.Exited() {
		return
	}
	_ = client.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-client.waitDone:
	case <-time.After(3 * time.Second):
		_ = client.cmd.Process.Kill()
		<-client.waitDone
	}
}

func measureControlplaneStressRuleUpdate(t *testing.T, apiBase string, id int64) controlplaneStressMeasurement {
	t.Helper()

	before := captureControlplaneStressRuntime(t, apiBase)
	target := findControlplaneStressRule(t, apiBase, id)
	updated := target.Rule
	updated.Remark = target.Remark + "-diag"
	updated.Tag = "controlplane-stress-update"

	start := time.Now()
	putControlplaneStressRule(t, apiBase, updated)
	apiMs := time.Since(start).Milliseconds()

	ruleAfter := waitForControlplaneStressRule(t, apiBase, id, func(item RuleStatus) bool {
		return item.Remark == updated.Remark && item.Status == "running" && item.EffectiveEngine == ruleEngineKernel && item.EffectiveKernelEngine == kernelEngineTC
	})
	engineAfter := waitForControlplaneStressRuntimeAfter(t, apiBase, before.LastReconcileAt, func(sample controlplaneStressRuntimeSample) bool {
		return sample.ActiveEntries == before.ActiveEntries
	})

	return controlplaneStressMeasurement{
		Name:        "rule_metadata_update",
		APIMs:       apiMs,
		SettleMs:    time.Since(start).Milliseconds(),
		EngineAfter: engineAfter,
		RuleAfter:   &ruleAfter,
	}
}

func measureControlplaneStressRuleToggle(t *testing.T, apiBase string, id int64, expectedEntries int) controlplaneStressMeasurement {
	t.Helper()

	before := captureControlplaneStressRuntime(t, apiBase)
	current := findControlplaneStressRule(t, apiBase, id)
	start := time.Now()
	postControlplaneStressRuleToggle(t, apiBase, id)
	apiMs := time.Since(start).Milliseconds()

	wantEnabled := !current.Enabled
	wantStatus := "stopped"
	if wantEnabled {
		wantStatus = "running"
	}
	ruleAfter := waitForControlplaneStressRule(t, apiBase, id, func(item RuleStatus) bool {
		if item.Enabled != wantEnabled || item.Status != wantStatus {
			return false
		}
		if wantEnabled {
			return item.EffectiveEngine == ruleEngineKernel && item.EffectiveKernelEngine == kernelEngineTC
		}
		return true
	})
	engineAfter := waitForControlplaneStressRuntimeAfter(t, apiBase, before.LastReconcileAt, func(sample controlplaneStressRuntimeSample) bool {
		return sample.ActiveEntries == expectedEntries
	})

	name := "rule_toggle_disable"
	if wantEnabled {
		name = "rule_toggle_enable"
	}
	return controlplaneStressMeasurement{
		Name:        name,
		APIMs:       apiMs,
		SettleMs:    time.Since(start).Milliseconds(),
		EngineAfter: engineAfter,
		RuleAfter:   &ruleAfter,
	}
}

func measureControlplaneStressManagedNetworkCreate(t *testing.T, apiBase string, topology egressNATIntegrationTopology, clientMAC string) controlplaneStressMeasurement {
	t.Helper()

	before := captureControlplaneStressRuntime(t, apiBase)
	requestedAfter := time.Now()
	start := time.Now()
	network := createManagedNetworkIntegrationNetwork(t, apiBase, topology)
	createManagedNetworkIntegrationReservation(t, apiBase, network.ID, clientMAC, controlplaneStressManagedLease)
	apiMs := time.Since(start).Milliseconds()

	if err := waitForManagedNetworkRuntimeReload(t, apiBase, requestedAfter, "manual"); err != nil {
		t.Fatalf("managed network runtime reload after create: %v", err)
	}
	managedAfter := waitForManagedNetworkIntegrationReady(t, apiBase, network.ID, topology)
	egressAfter, _ := findControlplaneStressManagedEgressNAT(t, apiBase, topology)
	engineAfter := waitForControlplaneStressRuntimeAfter(t, apiBase, before.LastReconcileAt, func(sample controlplaneStressRuntimeSample) bool {
		return sample.ActiveEntries >= before.ActiveEntries
	})

	notes := []string{fmt.Sprintf("managed_network_id=%d", network.ID)}
	if egressAfter != nil && egressAfter.EffectiveEngine != ruleEngineKernel {
		notes = append(notes, "managed network egress nat left kernel")
	}

	return controlplaneStressMeasurement{
		Name:             "managed_network_create",
		APIMs:            apiMs,
		SettleMs:         time.Since(start).Milliseconds(),
		EngineAfter:      engineAfter,
		ManagedAfter:     &managedAfter,
		ManagedEgressNAT: egressAfter,
		Notes:            notes,
	}
}

func measureControlplaneStressHotRestart(t *testing.T, harness *egressNATIntegrationHarness, topology egressNATIntegrationTopology, created []Rule, minimumEntries int) controlplaneStressMeasurement {
	t.Helper()

	start := time.Now()
	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		t.Fatalf("write hot restart marker: %v", err)
	}
	restartManagedNetworkIntegrationForward(t, harness)
	apiMs := time.Since(start).Milliseconds()

	waitForKernelScaleRulesRunning(
		t,
		harness.APIBase,
		collectKernelScaleRuleIDs(created),
		listTCRuleMutationRules,
		ruleEngineKernel,
		kernelEngineTC,
	)
	engineAfter := waitForControlplaneStressRuntimeAtLeast(t, harness.APIBase, minimumEntries)
	managedAfter, managedOK := findControlplaneStressManagedNetworkStatus(t, harness.APIBase, topology)
	egressAfter, _ := findControlplaneStressManagedEgressNAT(t, harness.APIBase, topology)

	var notes []string
	if managedOK && strings.TrimSpace(managedAfter.IPv4RuntimeStatus) != "" {
		notes = append(notes, fmt.Sprintf("managed_ipv4=%s", managedAfter.IPv4RuntimeStatus))
	}
	if managedOK && strings.TrimSpace(managedAfter.IPv6RuntimeStatus) != "" {
		notes = append(notes, fmt.Sprintf("managed_ipv6=%s", managedAfter.IPv6RuntimeStatus))
	}

	measurement := controlplaneStressMeasurement{
		Name:             "hot_restart",
		APIMs:            apiMs,
		SettleMs:         time.Since(start).Milliseconds(),
		EngineAfter:      engineAfter,
		ManagedEgressNAT: egressAfter,
		Notes:            notes,
	}
	if managedOK {
		measurement.ManagedAfter = &managedAfter
	}
	return measurement
}

func findControlplaneStressRule(t *testing.T, apiBase string, id int64) RuleStatus {
	t.Helper()

	for _, item := range listTCRuleMutationRules(t, apiBase) {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("rule %d not found", id)
	return RuleStatus{}
}

func waitForControlplaneStressRule(t *testing.T, apiBase string, id int64, predicate func(RuleStatus) bool) RuleStatus {
	t.Helper()

	deadline := time.Now().Add(controlplaneStressWaitTimeout)
	for time.Now().Before(deadline) {
		for _, item := range listTCRuleMutationRules(t, apiBase) {
			if item.ID != id {
				continue
			}
			if predicate(item) {
				return item
			}
			break
		}
		time.Sleep(controlplaneStressPollInterval)
	}
	t.Fatalf("rule %d did not reach expected state in time", id)
	return RuleStatus{}
}

func waitForControlplaneStressRuntimeAfter(t *testing.T, apiBase string, after time.Time, predicate func(controlplaneStressRuntimeSample) bool) controlplaneStressRuntimeSample {
	t.Helper()

	deadline := time.Now().Add(controlplaneStressWaitTimeout)
	for time.Now().Before(deadline) {
		sample := captureControlplaneStressRuntime(t, apiBase)
		if !after.IsZero() && !sample.LastReconcileAt.After(after) {
			time.Sleep(controlplaneStressPollInterval)
			continue
		}
		if predicate(sample) {
			return sample
		}
		time.Sleep(controlplaneStressPollInterval)
	}
	t.Fatalf("kernel runtime did not settle after %s in time", after.Format(time.RFC3339Nano))
	return controlplaneStressRuntimeSample{}
}

func waitForControlplaneStressRuntimeAtLeast(t *testing.T, apiBase string, minimumEntries int) controlplaneStressRuntimeSample {
	t.Helper()

	deadline := time.Now().Add(controlplaneStressWaitTimeout)
	for time.Now().Before(deadline) {
		sample := captureControlplaneStressRuntime(t, apiBase)
		if sample.ActiveEntries >= minimumEntries {
			return sample
		}
		time.Sleep(controlplaneStressPollInterval)
	}
	t.Fatalf("kernel runtime active entries did not reach >= %d in time", minimumEntries)
	return controlplaneStressRuntimeSample{}
}

func putControlplaneStressRule(t *testing.T, apiBase string, rule Rule) {
	t.Helper()

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule update: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build rule update request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update rule %d: %v", rule.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update rule %d unexpected status %d", rule.ID, resp.StatusCode)
	}
}

func postControlplaneStressRuleToggle(t *testing.T, apiBase string, id int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules/toggle?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		t.Fatalf("build toggle rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("toggle rule %d: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("toggle rule %d unexpected status %d", id, resp.StatusCode)
	}
}

func findControlplaneStressManagedNetworkStatus(t *testing.T, apiBase string, topology egressNATIntegrationTopology) (ManagedNetworkStatus, bool) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/managed-networks", nil)
	if err != nil {
		t.Fatalf("build list managed networks request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list managed networks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list managed networks unexpected status %d", resp.StatusCode)
	}
	var items []ManagedNetworkStatus
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode managed networks: %v", err)
	}
	for _, item := range items {
		if item.ChildInterfaceCount == 1 &&
			len(item.ChildInterfaces) == 1 &&
			item.ChildInterfaces[0] == topology.ChildHostIF &&
			item.GeneratedEgressNAT {
			return item, true
		}
	}
	return ManagedNetworkStatus{}, false
}

func findControlplaneStressManagedEgressNAT(t *testing.T, apiBase string, topology egressNATIntegrationTopology) (*egressNATIntegrationStatus, bool) {
	t.Helper()

	for _, item := range listEgressNATIntegrationStatuses(t, apiBase) {
		if item.ParentInterface == topology.BridgeIF && item.ChildInterface == topology.ChildHostIF && item.OutInterface == topology.UplinkHostIF {
			copyItem := item
			return &copyItem, true
		}
	}
	return nil, false
}

func envFloat(name string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return value
}
