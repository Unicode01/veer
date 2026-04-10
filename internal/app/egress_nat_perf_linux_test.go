//go:build linux

package app

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the benchmark test as root:
//      FORWARD_RUN_EGRESS_NAT_PERF_TEST=1 go test ./internal/app -run TestEgressNATPerfMatrix -count=1 -v
//
// Optional environment variables:
//   FORWARD_EGRESS_NAT_PERF_MODES
//   FORWARD_PERF_CONNECTIONS
//   FORWARD_PERF_CONNECTION_SERIES
//   FORWARD_PERF_CONCURRENCY
//   FORWARD_PERF_CONCURRENCY_SERIES
//   FORWARD_PERF_PROTOCOL
//   FORWARD_PERF_TCP_MODE
//   FORWARD_PERF_BYTES_PER_CONN
//   FORWARD_PERF_IO_CHUNK_BYTES
//   FORWARD_PERF_TOTAL_PAYLOAD_BYTES
//   FORWARD_PERF_STEADY_SECONDS
//   FORWARD_PERF_WARMUP_CONNECTIONS
//   FORWARD_PERF_WARMUP_BYTES_PER_CONN
//   FORWARD_PERF_BACKEND_WORKERS
//   FORWARD_PERF_DISABLE_OFFLOADS  (default: keep veth offloads enabled)
//   FORWARD_PERF_TXQLEN            (default: 10000)

import (
	"encoding/json"
	"fmt"
	"net"
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
	egressNATPerfEnableEnv = "FORWARD_RUN_EGRESS_NAT_PERF_TEST"
	egressNATPerfModesEnv  = "FORWARD_EGRESS_NAT_PERF_MODES"
)

func TestEgressNATPerfMatrix(t *testing.T) {
	if os.Getenv(egressNATPerfEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT performance test", egressNATPerfEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)

	connections := envInt(dataplanePerfConnEnv, 256)
	concurrency := envInt(dataplanePerfConcurrencyEnv, 32)
	bytesPerConn := envInt64(dataplanePerfBytesEnv, 1<<20)
	ioChunkBytes := envInt64(dataplanePerfIOChunkEnv, 16<<10)
	warmupConnections := envInt(dataplanePerfWarmupConnEnv, 8)
	warmupBytesPerConn := envInt64(dataplanePerfWarmupBytesEnv, 64<<10)
	scenarios := dataplanePerfScenarios(connections, concurrency, bytesPerConn, ioChunkBytes, warmupConnections, warmupBytesPerConn)

	modes := []dataplanePerfMode{
		{Name: "iptables", Expected: "iptables"},
		{Name: "nftables", Expected: "nftables"},
		{Name: "tc", Default: ruleEngineKernel, Order: []string{kernelEngineTC}, Expected: ruleEngineKernel, ExpectedKern: egressNATExpectedKernelEngine},
	}
	modes = selectEgressNATPerfModes(t, modes)

	results := make([]dataplanePerfResult, 0, len(modes)*len(scenarios))
	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.Label, func(t *testing.T) {
			for _, mode := range modes {
				mode := mode
				t.Run(mode.Name, func(t *testing.T) {
					result := runEgressNATPerfMode(t, baseBinary, mode, scenario)
					results = append(results, result)
					t.Logf("%s payload=%.2f MiB/s wire=%.2f MiB/s payload_pps=%.0f wire_pps=%.0f conn=%.2f/s cpu=%.2fs payload/cpu=%.2f MiB/s host=%.2f cores engine=%s/%s",
						mode.Name,
						result.PayloadMiBPerSec,
						result.WireMiBPerSec,
						result.PayloadPPS,
						result.WirePPS,
						result.ConnPerSec,
						result.ForwardCPUSeconds,
						result.PayloadMiBPerCPU,
						result.HostBusyCores,
						result.EffectiveEngine,
						result.KernelEngine,
					)
				})
			}
		})
	}

	if data, err := json.MarshalIndent(results, "", "  "); err == nil {
		t.Logf("egress nat perf results:\n%s", string(data))
	}
}

func runEgressNATPerfMode(t *testing.T, baseBinary string, mode dataplanePerfMode, scenario dataplanePerfScenario) dataplanePerfResult {
	t.Helper()

	if mode.Name == "iptables" {
		return runEgressNATPerfIptablesMode(t, scenario)
	}
	if mode.Name == "nftables" {
		return runEgressNATPerfNFTablesMode(t, scenario)
	}

	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	backendCmd, backendLogs := startDataplanePerfBackend(t, dataplanePerfTopology{BackendNS: topology.BackendNS})
	defer stopDataplanePerfHelper(t, backendCmd)

	modeDir := t.TempDir()
	forwardBinary := filepath.Join(modeDir, "forward-egress-nat-perf")
	copyFile(t, baseBinary, forwardBinary)
	workDir := filepath.Join(modeDir, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}

	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, mode, webPort)

	forwardLogs := filepath.Join(workDir, "forward.log")
	logFile, err := os.Create(forwardLogs)
	if err != nil {
		t.Fatalf("create forward log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.Command(forwardBinary, "--config", configPath)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)))
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start forward: %v", err)
	}
	defer stopForwardProcessTree(t, cmd)

	apiBase := fmt.Sprintf("http://127.0.0.1:%d", webPort)
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, forwardLogs)
	createEgressNATIntegrationEntryForScopeWithProtocol(t, apiBase, topology, topology.ChildHostIF, dataplanePerfProtocol())
	status := waitForEgressNATIntegrationRunningStatusWithKernelEngine(t, apiBase, topology, topology.ChildHostIF, mode.ExpectedKern)

	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(dataplanePerfBackendPort))
	if _, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.WarmupConnections, minInt(scenario.Concurrency, maxInt(1, scenario.WarmupConnections)), scenario.WarmupBytesPerConn, scenario.IOChunkBytes, 0); err != nil {
		logEgressNATPerfFailureArtifacts(t, mode.Name, forwardLogs, backendLogs.String())
		t.Fatalf("warmup client benchmark failed: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	hz := procClockTicks(t)
	hostCPUStart := readDataplanePerfCPUStat(t)
	startCPU := sampleProcessTreeJiffies(t, cmd.Process.Pid)
	clientResult, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.Connections, scenario.Concurrency, scenario.BytesPerConnection, scenario.IOChunkBytes, envInt(dataplanePerfSteadyEnv, 0))
	if err != nil {
		logEgressNATPerfFailureArtifacts(t, mode.Name, forwardLogs, backendLogs.String())
		t.Fatalf("client benchmark failed: %v", err)
	}
	endCPU := sampleProcessTreeJiffies(t, cmd.Process.Pid)
	hostCPUEnd := readDataplanePerfCPUStat(t)

	cpuSeconds := float64(endCPU-startCPU) / float64(hz)
	if cpuSeconds < 0 {
		cpuSeconds = 0
	}

	result := dataplanePerfBuildResult(mode.Name, scenario, clientResult, cpuSeconds, status.EffectiveEngine, status.EffectiveKernelEngine)
	result.HostBusyCores = dataplanePerfBusyCores(hostCPUStart, hostCPUEnd, hz, clientResult.Elapsed)
	runtimeResp := fetchDataplanePerfKernelRuntime(t, apiBase)
	if engineView, ok := dataplanePerfFindKernelEngine(runtimeResp.Engines, status.EffectiveKernelEngine); ok {
		result.TCDiagnostics = runtimeResp.TCDiagnostics
		result.TCDiagnosticsVerbose = runtimeResp.TCDiagnosticsVerbose
		result.DiagFIBNonSuccess = engineView.DiagFIBNonSuccess
		result.DiagRedirectNeighUsed = engineView.DiagRedirectNeighUsed
		result.DiagRedirectDrop = engineView.DiagRedirectDrop
	}
	if t.Failed() {
		logEgressNATPerfFailureArtifacts(t, mode.Name, forwardLogs, backendLogs.String())
	}
	return result
}

func runEgressNATPerfIptablesMode(t *testing.T, scenario dataplanePerfScenario) dataplanePerfResult {
	t.Helper()

	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	backendCmd, backendLogs := startDataplanePerfBackend(t, dataplanePerfTopology{BackendNS: topology.BackendNS})
	defer stopDataplanePerfHelper(t, backendCmd)

	backend := setupEgressNATPerfIptablesSNAT(t, topology)
	defer cleanupEgressNATPerfIptablesSNAT(topology)

	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(dataplanePerfBackendPort))
	if _, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.WarmupConnections, minInt(scenario.Concurrency, maxInt(1, scenario.WarmupConnections)), scenario.WarmupBytesPerConn, scenario.IOChunkBytes, 0); err != nil {
		t.Logf("iptables egress nat backend logs before warmup failure:\n%s", backendLogs.String())
		t.Fatalf("iptables warmup client benchmark failed: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	hz := procClockTicks(t)
	hostCPUStart := readDataplanePerfCPUStat(t)
	clientResult, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.Connections, scenario.Concurrency, scenario.BytesPerConnection, scenario.IOChunkBytes, envInt(dataplanePerfSteadyEnv, 0))
	if err != nil {
		t.Logf("iptables egress nat backend logs before client failure:\n%s", backendLogs.String())
		t.Fatalf("iptables client benchmark failed: %v", err)
	}
	hostCPUEnd := readDataplanePerfCPUStat(t)

	result := dataplanePerfBuildResult("iptables", scenario, clientResult, 0, "iptables", backend)
	result.HostBusyCores = dataplanePerfBusyCores(hostCPUStart, hostCPUEnd, hz, clientResult.Elapsed)
	return result
}

func runEgressNATPerfNFTablesMode(t *testing.T, scenario dataplanePerfScenario) dataplanePerfResult {
	t.Helper()

	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)
	backendCmd, backendLogs := startDataplanePerfBackend(t, dataplanePerfTopology{BackendNS: topology.BackendNS})
	defer stopDataplanePerfHelper(t, backendCmd)

	backend := setupEgressNATPerfNFTablesSNAT(t, topology)
	defer cleanupEgressNATPerfNFTablesSNAT(topology)

	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(dataplanePerfBackendPort))
	if _, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.WarmupConnections, minInt(scenario.Concurrency, maxInt(1, scenario.WarmupConnections)), scenario.WarmupBytesPerConn, scenario.IOChunkBytes, 0); err != nil {
		t.Logf("nftables egress nat backend logs before warmup failure:\n%s", backendLogs.String())
		t.Fatalf("nftables warmup client benchmark failed: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	hz := procClockTicks(t)
	hostCPUStart := readDataplanePerfCPUStat(t)
	clientResult, err := runDataplanePerfClientBenchmarkRawToTarget(topology.ClientNS, targetAddr, scenario.Connections, scenario.Concurrency, scenario.BytesPerConnection, scenario.IOChunkBytes, envInt(dataplanePerfSteadyEnv, 0))
	if err != nil {
		t.Logf("nftables egress nat backend logs before client failure:\n%s", backendLogs.String())
		t.Fatalf("nftables client benchmark failed: %v", err)
	}
	hostCPUEnd := readDataplanePerfCPUStat(t)

	result := dataplanePerfBuildResult("nftables", scenario, clientResult, 0, "nftables", backend)
	result.HostBusyCores = dataplanePerfBusyCores(hostCPUStart, hostCPUEnd, hz, clientResult.Elapsed)
	return result
}

func setupEgressNATPerfIptablesSNAT(t *testing.T, topology egressNATIntegrationTopology) string {
	t.Helper()

	const natChain = "FORWARD_EGRESS_PERF_SNAT"
	const fwdChain = "FORWARD_EGRESS_PERF_FWD"

	proto := dataplanePerfProtocol()
	backend := dataplanePerfIptablesBackend(t)
	originalIPForward := strings.TrimSpace(readDataplanePerfProcFile(t, "/proc/sys/net/ipv4/ip_forward"))
	cleanupEgressNATPerfIptablesSNAT(topology)
	t.Cleanup(func() {
		if originalIPForward != "" {
			if output, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+originalIPForward).CombinedOutput(); err != nil {
				t.Logf("egress nat perf: restore net.ipv4.ip_forward=%s failed: %v (%s)", originalIPForward, err, strings.TrimSpace(string(output)))
			}
		}
		cleanupEgressNATPerfIptablesSNAT(topology)
	})

	mustRunDataplanePerfCmd(t, "sysctl", "-w", "net.ipv4.ip_forward=1")

	mustRunDataplanePerfCmd(t, "iptables", "-t", "nat", "-N", natChain)
	mustRunDataplanePerfCmd(t, "iptables", "-t", "nat", "-F", natChain)
	mustRunDataplanePerfCmd(t, "iptables", "-t", "nat", "-A", natChain,
		"-s", egressNATClientAddr,
		"-d", egressNATBackendAddr,
		"-o", topology.UplinkHostIF,
		"-p", proto,
		"--dport", strconv.Itoa(dataplanePerfBackendPort),
		"-j", "SNAT",
		"--to-source", egressNATUplinkAddr,
	)
	mustRunDataplanePerfCmd(t, "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-j", natChain)

	mustRunDataplanePerfCmd(t, "iptables", "-N", fwdChain)
	mustRunDataplanePerfCmd(t, "iptables", "-F", fwdChain)
	mustRunDataplanePerfCmd(t, "iptables", "-A", fwdChain,
		"-p", proto,
		"-s", egressNATClientAddr,
		"-d", egressNATBackendAddr,
		"--dport", strconv.Itoa(dataplanePerfBackendPort),
		"-j", "ACCEPT",
	)
	mustRunDataplanePerfCmd(t, "iptables", "-A", fwdChain,
		"-p", proto,
		"-s", egressNATBackendAddr,
		"-d", egressNATClientAddr,
		"--sport", strconv.Itoa(dataplanePerfBackendPort),
		"-j", "ACCEPT",
	)
	mustRunDataplanePerfCmd(t, "iptables", "-I", "FORWARD", "1", "-j", fwdChain)

	return backend
}

func setupEgressNATPerfNFTablesSNAT(t *testing.T, topology egressNATIntegrationTopology) string {
	t.Helper()

	const (
		natTable    = "forward_egress_perf_nat_nft"
		filterTable = "forward_egress_perf_filter_nft"
	)

	dataplanePerfRequireNFTables(t)
	proto := dataplanePerfProtocol()
	originalIPForward := strings.TrimSpace(readDataplanePerfProcFile(t, "/proc/sys/net/ipv4/ip_forward"))
	cleanupEgressNATPerfNFTablesSNAT(topology)
	t.Cleanup(func() {
		if originalIPForward != "" {
			if output, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+originalIPForward).CombinedOutput(); err != nil {
				t.Logf("egress nat perf: restore net.ipv4.ip_forward=%s failed: %v (%s)", originalIPForward, err, strings.TrimSpace(string(output)))
			}
		}
		cleanupEgressNATPerfNFTablesSNAT(topology)
	})

	mustRunDataplanePerfCmd(t, "sysctl", "-w", "net.ipv4.ip_forward=1")

	mustRunDataplanePerfCmd(t, "nft", "add", "table", "ip", natTable)
	mustRunDataplanePerfCmd(t, "nft", "add", "chain", "ip", natTable, "postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }")
	mustRunDataplanePerfCmd(t, "nft", "add", "rule", "ip", natTable, "postrouting",
		"ip", "saddr", egressNATClientAddr,
		"ip", "daddr", egressNATBackendAddr,
		"oifname", topology.UplinkHostIF,
		proto, "dport", strconv.Itoa(dataplanePerfBackendPort),
		"masquerade",
	)

	mustRunDataplanePerfCmd(t, "nft", "add", "table", "ip", filterTable)
	mustRunDataplanePerfCmd(t, "nft", "add", "chain", "ip", filterTable, "forward", "{ type filter hook forward priority filter; policy accept; }")
	mustRunDataplanePerfCmd(t, "nft", "add", "rule", "ip", filterTable, "forward",
		"iifname", topology.BridgeIF,
		"oifname", topology.UplinkHostIF,
		"ip", "saddr", egressNATClientAddr,
		"ip", "daddr", egressNATBackendAddr,
		proto, "dport", strconv.Itoa(dataplanePerfBackendPort),
		"accept",
	)
	mustRunDataplanePerfCmd(t, "nft", "add", "rule", "ip", filterTable, "forward",
		"iifname", topology.UplinkHostIF,
		"oifname", topology.BridgeIF,
		"ip", "saddr", egressNATBackendAddr,
		"ip", "daddr", egressNATClientAddr,
		proto, "sport", strconv.Itoa(dataplanePerfBackendPort),
		"ct", "state", "established,related",
		"accept",
	)

	return "native"
}

func cleanupEgressNATPerfIptablesSNAT(topology egressNATIntegrationTopology) {
	const natChain = "FORWARD_EGRESS_PERF_SNAT"
	const fwdChain = "FORWARD_EGRESS_PERF_FWD"

	runDataplanePerfCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", natChain)
	runDataplanePerfCmd("iptables", "-D", "FORWARD", "-j", fwdChain)
	runDataplanePerfCmd("iptables", "-t", "nat", "-F", natChain)
	runDataplanePerfCmd("iptables", "-t", "nat", "-X", natChain)
	runDataplanePerfCmd("iptables", "-F", fwdChain)
	runDataplanePerfCmd("iptables", "-X", fwdChain)
}

func cleanupEgressNATPerfNFTablesSNAT(topology egressNATIntegrationTopology) {
	runDataplanePerfCmd("nft", "delete", "table", "ip", "forward_egress_perf_nat_nft")
	runDataplanePerfCmd("nft", "delete", "table", "ip", "forward_egress_perf_filter_nft")
}

func selectEgressNATPerfModes(t *testing.T, modes []dataplanePerfMode) []dataplanePerfMode {
	t.Helper()

	raw := strings.TrimSpace(os.Getenv(egressNATPerfModesEnv))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(dataplanePerfModesEnv))
	}
	if raw == "" {
		return modes
	}

	byName := make(map[string]dataplanePerfMode, len(modes))
	for _, mode := range modes {
		byName[strings.ToLower(strings.TrimSpace(mode.Name))] = mode
	}

	selected := make([]dataplanePerfMode, 0, len(modes))
	seen := make(map[string]struct{}, len(modes))
	for _, item := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		mode, ok := byName[name]
		if !ok {
			t.Fatalf("unknown egress nat perf mode %q (supported: tc, iptables, nftables)", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		selected = append(selected, mode)
	}
	if len(selected) == 0 {
		t.Fatalf("no egress nat perf modes selected from %q", raw)
	}
	return selected
}

func logEgressNATPerfFailureArtifacts(t *testing.T, modeName string, forwardLogPath string, backendLogs string) {
	t.Helper()

	if strings.TrimSpace(forwardLogPath) != "" {
		if data, err := os.ReadFile(forwardLogPath); err == nil {
			t.Logf("%s egress nat forward logs:\n%s", modeName, string(data))
		}
	}
	if strings.TrimSpace(backendLogs) != "" {
		t.Logf("%s egress nat backend logs:\n%s", modeName, backendLogs)
	}
}
