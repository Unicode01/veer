//go:build linux

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	tcpSessionGuardIntegrationEnableEnv = "FORWARD_RUN_TCP_SESSION_GUARD_TEST"

	tcpSessionGuardPacketCount              = 64
	tcpSessionGuardObserveWindow            = 4 * time.Second
	tcpSessionGuardPollInterval             = 250 * time.Millisecond
	tcpSessionGuardBackendPacketThresholdRX = 8
)

type tcpSessionGuardHarness struct {
	Topology dataplanePerfTopology
	APIBase  string
	LogPath  string
}

type tcpSessionGuardPacketCounters struct {
	RX uint64
	TX uint64
}

type tcpSessionGuardObservation struct {
	Stats    RuleStatsListItem
	Engine   KernelEngineRuntimeView
	Counters tcpSessionGuardPacketCounters
}

func TestTCKernelTransparentRejectsACKOnlyNewSession(t *testing.T) {
	baseBinary := requireTCPSessionGuardIntegrationBinary(t, false)
	mode := dataplanePerfMode{
		Name:         "tc-tcp-session-guard",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineTC,
	}

	harness := startTCPSessionGuardHarness(t, baseBinary, "tc", mode)
	rule := createTCPSessionGuardRule(t, harness.APIBase, mode, Rule{
		InInterface:      harness.Topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     harness.Topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Remark:           "tc-transparent-ack-guard",
		Tag:              "tcp-guard",
		Transparent:      true,
		EnginePreference: ruleEngineKernel,
	})

	assertTransparentTCPInitialPacketGuard(t, harness, mode.ExpectedKern, rule.ID, dataplanePerfFrontPort)
}

func TestXDPKernelTransparentRejectsACKOnlyNewSession(t *testing.T) {
	baseBinary := requireTCPSessionGuardIntegrationBinary(t, true)
	mode := dataplanePerfMode{
		Name:         "xdp-tcp-session-guard",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineXDP},
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineXDP,
		Experimental: map[string]bool{
			experimentalFeatureXDPGeneric: true,
		},
	}

	harness := startTCPSessionGuardHarness(t, baseBinary, "xdp", mode)
	rule := createTCPSessionGuardRule(t, harness.APIBase, mode, Rule{
		InInterface:      harness.Topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     harness.Topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Remark:           "xdp-transparent-ack-guard",
		Tag:              "tcp-guard",
		Transparent:      true,
		EnginePreference: ruleEngineKernel,
	})
	waitForDataplanePerfModeSettle(t, harness.APIBase, mode)

	assertTransparentTCPInitialPacketGuard(t, harness, mode.ExpectedKern, rule.ID, dataplanePerfFrontPort)
}

func requireTCPSessionGuardIntegrationBinary(t *testing.T, xdp bool) string {
	t.Helper()

	if os.Getenv(tcpSessionGuardIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux TCP session guard integration tests", tcpSessionGuardIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is required")
	}
	if xdp {
		if reason := xdpVethNATRedirectGuardReasonForRelease(kernelRelease()); reason != "" {
			t.Skip(reason)
		}
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	return buildDataplanePerfBinary(t, repoRoot)
}

func startTCPSessionGuardHarness(t *testing.T, baseBinary string, name string, mode dataplanePerfMode) tcpSessionGuardHarness {
	t.Helper()

	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	runtimeDir, err := os.MkdirTemp("", "fwtcpguard-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(runtimeDir)
	})
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-"+name)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, mode, webPort)

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
	cmd.Env = append(os.Environ(), forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)))
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
	waitForDataplanePerfAPI(t, apiBase)
	t.Cleanup(func() {
		if t.Failed() {
			logKernelRuntimeOnFailure(t, apiBase)
			logForwardLogOnFailure(t, logPath)
			logDataplanePerfInterfaceStats(t, topology, "tcp session guard interface stats")
		}
	})

	return tcpSessionGuardHarness{
		Topology: topology,
		APIBase:  apiBase,
		LogPath:  logPath,
	}
}

func createTCPSessionGuardRule(t *testing.T, apiBase string, mode dataplanePerfMode, rule Rule) RuleStatus {
	t.Helper()

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal tcp session guard rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("build create rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create rule unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var created Rule
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	return waitForTCPSessionGuardRuleRunning(t, apiBase, created.ID, mode)
}

func waitForTCPSessionGuardRuleRunning(t *testing.T, apiBase string, id int64, mode dataplanePerfMode) RuleStatus {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, rule := range listTCPSessionGuardRules(t, apiBase) {
			if rule.ID != id {
				continue
			}
			if !rule.Enabled || rule.Status != "running" {
				break
			}
			if rule.EffectiveEngine != mode.Expected {
				t.Fatalf("%s requested %s but effective engine is %s (kernel=%s kernel_reason=%q fallback=%q)",
					mode.Name,
					mode.Expected,
					rule.EffectiveEngine,
					rule.EffectiveKernelEngine,
					rule.KernelReason,
					rule.FallbackReason,
				)
			}
			if mode.ExpectedKern != "" && rule.EffectiveKernelEngine != mode.ExpectedKern {
				t.Fatalf("%s requested kernel engine %s but effective kernel engine is %s (kernel_reason=%q fallback=%q)",
					mode.Name,
					mode.ExpectedKern,
					rule.EffectiveKernelEngine,
					rule.KernelReason,
					rule.FallbackReason,
				)
			}
			return rule
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("rule %d did not enter running/%s state in time", id, mode.Expected)
	return RuleStatus{}
}

func listTCPSessionGuardRules(t *testing.T, apiBase string) []RuleStatus {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/rules", nil)
	if err != nil {
		t.Fatalf("build list rules request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read list rules response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list rules unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var rules []RuleStatus
	if err := json.Unmarshal(body, &rules); err != nil {
		t.Fatalf("decode list rules response: %v", err)
	}
	return rules
}

func assertTransparentTCPInitialPacketGuard(t *testing.T, harness tcpSessionGuardHarness, engineName string, ruleID int64, frontPort int) {
	t.Helper()

	before := captureTCPSessionGuardObservation(t, harness, engineName, ruleID)

	sendTCPSessionGuardPackets(t, harness.Topology.ClientNS, dataplanePerfClientAddr, dataplanePerfFrontAddr, frontPort, "ack", tcpSessionGuardPacketCount)
	afterACK, ackMatched := watchTCPSessionGuardObservation(t, harness, engineName, ruleID, tcpSessionGuardObserveWindow, func(obs tcpSessionGuardObservation) bool {
		return obs.Stats.TotalConns > before.Stats.TotalConns ||
			obs.Engine.FlowsMapEntries > before.Engine.FlowsMapEntries ||
			obs.Counters.RX >= before.Counters.RX+tcpSessionGuardBackendPacketThresholdRX
	})
	if ackMatched {
		t.Fatalf(
			"ACK-only traffic created a new session or reached backend: before={stats:%+v engine:%+v counters:%+v} after={stats:%+v engine:%+v counters:%+v}",
			before.Stats,
			before.Engine,
			before.Counters,
			afterACK.Stats,
			afterACK.Engine,
			afterACK.Counters,
		)
	}

	sendTCPSessionGuardPackets(t, harness.Topology.ClientNS, dataplanePerfClientAddr, dataplanePerfFrontAddr, frontPort, "syn", tcpSessionGuardPacketCount)
	afterSYN, synMatched := watchTCPSessionGuardObservation(t, harness, engineName, ruleID, tcpSessionGuardObserveWindow, func(obs tcpSessionGuardObservation) bool {
		return obs.Stats.TotalConns > afterACK.Stats.TotalConns ||
			obs.Engine.FlowsMapEntries > afterACK.Engine.FlowsMapEntries ||
			obs.Counters.RX >= afterACK.Counters.RX+tcpSessionGuardBackendPacketThresholdRX
	})
	if !synMatched {
		t.Fatalf(
			"SYN-only traffic did not create sessions or reach backend: after_ack={stats:%+v engine:%+v counters:%+v} after_syn={stats:%+v engine:%+v counters:%+v}",
			afterACK.Stats,
			afterACK.Engine,
			afterACK.Counters,
			afterSYN.Stats,
			afterSYN.Engine,
			afterSYN.Counters,
		)
	}
	if afterSYN.Engine.ActiveEntries == 0 {
		t.Fatalf("SYN-only traffic did not leave active %s entries: engine=%+v", engineName, afterSYN.Engine)
	}
}

func captureTCPSessionGuardObservation(t *testing.T, harness tcpSessionGuardHarness, engineName string, ruleID int64) tcpSessionGuardObservation {
	t.Helper()

	stats := fetchTCPSessionGuardRuleStats(t, harness.APIBase, ruleID)
	runtime := fetchTCPSessionGuardKernelRuntime(t, harness.APIBase)
	engine := mustFindTCPSessionGuardEngine(t, runtime, engineName)
	counters := readTCPSessionGuardPacketCounters(t, harness.Topology.BackendNS, harness.Topology.BackendNSIF)
	return tcpSessionGuardObservation{
		Stats:    stats,
		Engine:   engine,
		Counters: counters,
	}
}

func watchTCPSessionGuardObservation(t *testing.T, harness tcpSessionGuardHarness, engineName string, ruleID int64, timeout time.Duration, match func(tcpSessionGuardObservation) bool) (tcpSessionGuardObservation, bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last tcpSessionGuardObservation
	for {
		last = captureTCPSessionGuardObservation(t, harness, engineName, ruleID)
		if match != nil && match(last) {
			return last, true
		}
		if !time.Now().Before(deadline) {
			return last, false
		}
		time.Sleep(tcpSessionGuardPollInterval)
	}
}

func sendTCPSessionGuardPackets(t *testing.T, netns string, sourceIP string, targetIP string, targetPort int, flags string, count int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	script := strings.Join([]string{
		"import os, socket, struct, sys",
		"src_ip, dst_ip, dst_port, flags, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4].lower(), int(sys.argv[5])",
		"flag_map = {'ack': 0x10, 'syn': 0x02}",
		"if flags not in flag_map:",
		"    raise SystemExit(f'unsupported flags: {flags}')",
		"tcp_flags = flag_map[flags]",
		"def checksum(data):",
		"    if len(data) & 1:",
		"        data += b'\\x00'",
		"    total = 0",
		"    for i in range(0, len(data), 2):",
		"        total += (data[i] << 8) + data[i + 1]",
		"    while total >> 16:",
		"        total = (total & 0xffff) + (total >> 16)",
		"    return (~total) & 0xffff",
		"src_addr = socket.inet_aton(src_ip)",
		"dst_addr = socket.inet_aton(dst_ip)",
		"sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)",
		"sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)",
		"ident = 1",
		"seq = 1",
		"for i in range(count):",
		"    src_port = 10000 + (i % 50000)",
		"    tcp_wo = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, 0, 5 << 4, tcp_flags, 64240, 0, 0)",
		"    pseudo = src_addr + dst_addr + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp_wo))",
		"    tcp_sum = checksum(pseudo + tcp_wo)",
		"    tcp = struct.pack('!HHLLBBH', src_port, dst_port, seq, 0, 5 << 4, tcp_flags, 64240) + struct.pack('!H', tcp_sum) + struct.pack('!H', 0)",
		"    total_len = 20 + len(tcp)",
		"    ip_wo = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident, 0, 64, socket.IPPROTO_TCP, 0, src_addr, dst_addr)",
		"    ip_sum = checksum(ip_wo)",
		"    iphdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ident, 0, 64, socket.IPPROTO_TCP, ip_sum, src_addr, dst_addr)",
		"    sock.sendto(iphdr + tcp, (dst_ip, 0))",
		"    ident = (ident + 1) & 0xffff",
		"    seq = (seq + 1) & 0xffffffff",
	}, "\n")
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", netns, "python3", "-c", script, sourceIP, targetIP, strconv.Itoa(targetPort), flags, strconv.Itoa(count))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("send %s packets via %s: %v\n%s", flags, netns, err, string(output))
	}
}

func fetchTCPSessionGuardRuleStats(t *testing.T, apiBase string, ruleID int64) RuleStatsListItem {
	t.Helper()

	_ = fetchTCPSessionGuardKernelRuntime(t, apiBase)

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/rules/stats?page=1&page_size=200", nil)
	if err != nil {
		t.Fatalf("build rule stats request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request rule stats: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rule stats response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rule stats unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var payload RuleStatsListResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode rule stats response: %v", err)
	}
	for _, item := range payload.Items {
		if item.RuleID == ruleID {
			return item
		}
	}
	t.Fatalf("rule stats missing rule %d", ruleID)
	return RuleStatsListItem{}
}

func fetchTCPSessionGuardKernelRuntime(t *testing.T, apiBase string) KernelRuntimeResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime?refresh=1", nil)
	if err != nil {
		t.Fatalf("build kernel runtime request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request kernel runtime: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read kernel runtime response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kernel runtime unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var payload KernelRuntimeResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode kernel runtime response: %v", err)
	}
	return payload
}

func mustFindTCPSessionGuardEngine(t *testing.T, runtime KernelRuntimeResponse, name string) KernelEngineRuntimeView {
	t.Helper()

	for _, engine := range runtime.Engines {
		if engine.Name == name {
			return engine
		}
	}
	t.Fatalf("kernel runtime missing engine %q", name)
	return KernelEngineRuntimeView{}
}

func readTCPSessionGuardPacketCounters(t *testing.T, netns string, ifName string) tcpSessionGuardPacketCounters {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", netns, "sh", "-c", "cat /sys/class/net/"+ifName+"/statistics/rx_packets /sys/class/net/"+ifName+"/statistics/tx_packets")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read packet counters for %s/%s: %v\n%s", netns, ifName, err, string(output))
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 {
		t.Fatalf("unexpected packet counter output for %s/%s: %q", netns, ifName, string(output))
	}
	rx, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatalf("parse rx packet counter %q: %v", fields[0], err)
	}
	tx, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		t.Fatalf("parse tx packet counter %q: %v", fields[1], err)
	}
	return tcpSessionGuardPacketCounters{RX: rx, TX: tx}
}
