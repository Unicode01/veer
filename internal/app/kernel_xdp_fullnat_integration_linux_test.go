//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the integration test as root:
//      FORWARD_RUN_XDP_FULLNAT_TEST=1 go test ./internal/app -run TestXDPKernelIPv4FullNATIntegration -count=1 -v

const xdpFullNATIntegrationEnableEnv = "FORWARD_RUN_XDP_FULLNAT_TEST"

const (
	xdpFullNATTransparentFrontPort   = dataplanePerfFrontPort + 1
	xdpFullNATTransparentBackendPort = dataplanePerfBackendPort + 1
)

type xdpFullNATIntegrationHarness struct {
	Topology dataplanePerfTopology
	APIBase  string
	LogPath  string
}

func TestXDPKernelIPv4FullNATIntegration(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)

	cases := []struct {
		name  string
		proto string
	}{
		{name: "tcp", proto: "tcp"},
		{name: "udp", proto: "udp"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := startXDPFullNATIntegrationHarness(t, baseBinary, "integration-"+tc.proto)
			createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        "xdp-fullnat-integration-" + tc.proto,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-" + tc.proto),
			})

			observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s backend observed source IP %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}
		})
	}
}

func TestXDPKernelIPv4FullNATTransparentCoexists(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)
	harness := startXDPFullNATIntegrationHarness(t, baseBinary, "coexist-tcp")

	createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
		Remark:        "xdp-fullnat-coexist",
		Protocol:      "tcp",
		FrontPort:     dataplanePerfFrontPort,
		BackendPort:   dataplanePerfBackendPort,
		Transparent:   false,
		OutSourceIP:   dataplanePerfBackendHost,
		Tag:           "xdp-fullnat",
		ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-coexist"),
	})
	createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
		Remark:        "xdp-transparent-coexist",
		Protocol:      "tcp",
		FrontPort:     xdpFullNATTransparentFrontPort,
		BackendPort:   xdpFullNATTransparentBackendPort,
		Transparent:   true,
		OutSourceIP:   "",
		Tag:           "xdp-transparent",
		ExpectRunning: xdpFullNATIntegrationMode("xdp-transparent-coexist"),
	})
	waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after coexist enable", func(entries int) bool {
		return entries >= 2
	})

	observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort)
	if observedIP != dataplanePerfBackendHost {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("full-nat backend observed source IP %q, want %q", observedIP, dataplanePerfBackendHost)
	}

	observedIP = runXDPFullNATIntegrationProbe(t, harness.Topology, "tcp", xdpFullNATTransparentFrontPort, xdpFullNATTransparentBackendPort)
	if observedIP != dataplanePerfClientAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("transparent backend observed source IP %q, want %q", observedIP, dataplanePerfClientAddr)
	}
}

func TestXDPKernelIPv4FullNATToggleDisableReenableRestoresConnectivity(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)
	for _, tc := range []struct {
		name  string
		proto string
	}{
		{name: "tcp", proto: "tcp"},
		{name: "udp", proto: "udp"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := startXDPFullNATIntegrationHarness(t, baseBinary, "toggle-"+tc.proto)
			rule := createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        "xdp-fullnat-toggle-" + tc.proto,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-toggle-" + tc.proto),
			})
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after enable", func(entries int) bool {
				return entries > 0
			})

			observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s backend observed source IP %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}

			toggleXDPFullNATIntegrationRule(t, harness.APIBase, rule.ID)
			waitForXDPFullNATIntegrationRuleStopped(t, harness.APIBase, rule.Remark)
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after disable", func(entries int) bool {
				return entries == 0
			})
			expectXDPFullNATIntegrationProbeFailure(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)

			toggleXDPFullNATIntegrationRule(t, harness.APIBase, rule.ID)
			waitForXDPFullNATIntegrationRuleRunning(t, harness.APIBase, rule.Remark, xdpFullNATIntegrationMode("xdp-fullnat-toggle-"+tc.proto))
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after re-enable", func(entries int) bool {
				return entries > 0
			})

			observedIP = runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s backend observed source IP after re-enable %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}
		})
	}
}

func TestXDPKernelIPv4FullNATDeleteRecreateRestoresConnectivity(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)
	for _, tc := range []struct {
		name  string
		proto string
	}{
		{name: "tcp", proto: "tcp"},
		{name: "udp", proto: "udp"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := startXDPFullNATIntegrationHarness(t, baseBinary, "delete-recreate-"+tc.proto)
			rule := createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        "xdp-fullnat-delete-recreate-" + tc.proto,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-delete-recreate-" + tc.proto),
			})
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after create", func(entries int) bool {
				return entries > 0
			})

			observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s backend observed source IP %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}

			deleteXDPFullNATIntegrationRule(t, harness.APIBase, rule.ID)
			waitForXDPFullNATIntegrationRuleAbsent(t, harness.APIBase, rule.Remark)
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after delete", func(entries int) bool {
				return entries == 0
			})
			expectXDPFullNATIntegrationProbeFailure(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)

			createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        rule.Remark,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-delete-recreate-" + tc.proto),
			})
			waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, "after recreate", func(entries int) bool {
				return entries > 0
			})

			observedIP = runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s backend observed source IP after recreate %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}
		})
	}
}

func TestXDPKernelIPv4FullNATSteadyTraffic(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)
	for _, tc := range []struct {
		name         string
		proto        string
		connections  int
		concurrency  int
		bytesPerConn int64
		ioChunkBytes int64
		steadySecond int
	}{
		{name: "tcp", proto: "tcp", connections: 24, concurrency: 8, bytesPerConn: 128 << 10, ioChunkBytes: 16 << 10, steadySecond: 2},
		{name: "udp", proto: "udp", connections: 48, concurrency: 16, bytesPerConn: 96 << 10, ioChunkBytes: 1200, steadySecond: 2},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(dataplanePerfProtocolEnv, tc.proto)
			if tc.proto == "tcp" {
				t.Setenv(dataplanePerfTCPModeEnv, dataplanePerfTCPEchoMode)
			}

			harness := startXDPFullNATIntegrationHarness(t, baseBinary, "steady-"+tc.proto)
			createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        "xdp-fullnat-steady-" + tc.proto,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-steady-" + tc.proto),
			})

			backendCmd, backendLogs := startDataplanePerfBackend(t, harness.Topology)
			t.Cleanup(func() {
				if backendCmd != nil && backendCmd.ProcessState == nil {
					stopDataplanePerfHelper(t, backendCmd)
				}
			})

			result, err := runDataplanePerfClientBenchmarkRaw(harness.Topology.ClientNS, tc.connections, tc.concurrency, tc.bytesPerConn, tc.ioChunkBytes, tc.steadySecond)
			if err != nil {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s steady full-NAT benchmark failed: %v\nbackend logs:\n%s", tc.proto, err, backendLogs.String())
			}
			if result.PayloadBytes <= 0 {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s steady full-NAT benchmark payload bytes = %d, want > 0", tc.proto, result.PayloadBytes)
			}
			if result.Connections != tc.connections {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s steady full-NAT benchmark connections = %d, want %d", tc.proto, result.Connections, tc.connections)
			}

			rule := waitForXDPFullNATIntegrationRuleRunning(t, harness.APIBase, "xdp-fullnat-steady-"+tc.proto, xdpFullNATIntegrationMode("xdp-fullnat-steady-"+tc.proto))
			if rule.EffectiveEngine != ruleEngineKernel || rule.EffectiveKernelEngine != kernelEngineXDP {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s steady full-NAT rule runtime = engine %q kernel %q, want kernel/xdp", tc.proto, rule.EffectiveEngine, rule.EffectiveKernelEngine)
			}
		})
	}
}

func TestXDPKernelIPv4FullNATRepeatedToggleCycles(t *testing.T) {
	baseBinary := requireXDPFullNATIntegrationBinary(t)
	for _, tc := range []struct {
		name  string
		proto string
		cycle int
	}{
		{name: "tcp", proto: "tcp", cycle: 4},
		{name: "udp", proto: "udp", cycle: 4},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := startXDPFullNATIntegrationHarness(t, baseBinary, "toggle-cycles-"+tc.proto)
			rule := createXDPFullNATIntegrationRule(t, harness.APIBase, harness.Topology, xdpIntegrationRuleConfig{
				Remark:        "xdp-fullnat-toggle-cycles-" + tc.proto,
				Protocol:      tc.proto,
				FrontPort:     dataplanePerfFrontPort,
				BackendPort:   dataplanePerfBackendPort,
				Transparent:   false,
				OutSourceIP:   dataplanePerfBackendHost,
				Tag:           "xdp-fullnat",
				ExpectRunning: xdpFullNATIntegrationMode("xdp-fullnat-toggle-cycles-" + tc.proto),
			})

			for i := 0; i < tc.cycle; i++ {
				observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
				if observedIP != dataplanePerfBackendHost {
					logForwardLogOnFailure(t, harness.LogPath)
					t.Fatalf("%s cycle %d backend observed source IP %q, want %q", tc.proto, i+1, observedIP, dataplanePerfBackendHost)
				}

				toggleXDPFullNATIntegrationRule(t, harness.APIBase, rule.ID)
				waitForXDPFullNATIntegrationRuleStopped(t, harness.APIBase, rule.Remark)
				waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, fmt.Sprintf("cycle %d disable", i+1), func(entries int) bool {
					return entries == 0
				})
				expectXDPFullNATIntegrationProbeFailure(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)

				toggleXDPFullNATIntegrationRule(t, harness.APIBase, rule.ID)
				waitForXDPFullNATIntegrationRuleRunning(t, harness.APIBase, rule.Remark, xdpFullNATIntegrationMode("xdp-fullnat-toggle-cycles-"+tc.proto))
				waitForXDPFullNATIntegrationActiveEntries(t, harness.APIBase, harness.LogPath, fmt.Sprintf("cycle %d re-enable", i+1), func(entries int) bool {
					return entries > 0
				})
			}

			observedIP := runXDPFullNATIntegrationProbe(t, harness.Topology, tc.proto, dataplanePerfFrontPort, dataplanePerfBackendPort)
			if observedIP != dataplanePerfBackendHost {
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("%s final backend observed source IP %q, want %q", tc.proto, observedIP, dataplanePerfBackendHost)
			}
		})
	}
}

type xdpIntegrationRuleConfig struct {
	Remark        string
	Protocol      string
	FrontPort     int
	BackendPort   int
	Transparent   bool
	OutSourceIP   string
	Tag           string
	ExpectRunning dataplanePerfMode
}

func createXDPFullNATIntegrationRule(t *testing.T, apiBase string, topology dataplanePerfTopology, cfg xdpIntegrationRuleConfig) RuleStatus {
	t.Helper()

	payload := map[string]any{
		"in_interface":      topology.ClientHostIF,
		"in_ip":             dataplanePerfFrontAddr,
		"in_port":           cfg.FrontPort,
		"out_interface":     topology.BackendHostIF,
		"out_ip":            dataplanePerfBackendAddr,
		"out_source_ip":     cfg.OutSourceIP,
		"out_port":          cfg.BackendPort,
		"protocol":          cfg.Protocol,
		"transparent":       cfg.Transparent,
		"engine_preference": ruleEngineKernel,
		"remark":            cfg.Remark,
		"tag":               cfg.Tag,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal XDP full-NAT rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create XDP full-NAT rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create XDP full-NAT rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create XDP full-NAT rule unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return waitForXDPFullNATIntegrationRuleRunning(t, apiBase, cfg.Remark, cfg.ExpectRunning)
}

func runXDPFullNATIntegrationProbe(t *testing.T, topology dataplanePerfTopology, proto string, frontPort int, backendPort int) string {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), "observed-"+proto+".txt")
	backendTarget := net.JoinHostPort(dataplanePerfBackendAddr, strconv.Itoa(backendPort))
	clientTarget := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(frontPort))

	backendCmd, backendLogs := startEgressNATBackendHelperInNamespace(t, topology.BackendNS, proto, backendTarget, observedFile)
	t.Cleanup(func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+clientTarget,
	)
	output, err := clientCmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s XDP full-NAT client helper timed out\nclient output:\n%s\nbackend logs:\n%s", proto, string(output), backendLogs.String())
		}
		t.Fatalf("%s XDP full-NAT client helper failed: %v\nclient output:\n%s\nbackend logs:\n%s", proto, err, string(output), backendLogs.String())
	}

	waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
	data, err := os.ReadFile(observedFile)
	if err != nil {
		t.Fatalf("%s read observed peer file: %v\n%s", proto, err, backendLogs.String())
	}
	return strings.TrimSpace(string(data))
}

func expectXDPFullNATIntegrationProbeFailure(t *testing.T, topology dataplanePerfTopology, proto string, frontPort int, backendPort int) {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), "observed-failure-"+proto+".txt")
	backendTarget := net.JoinHostPort(dataplanePerfBackendAddr, strconv.Itoa(backendPort))
	if proto == "icmp" {
		backendTarget = dataplanePerfBackendAddr
	}
	backendCmd, backendLogs := startEgressNATBackendHelperInNamespace(t, topology.BackendNS, proto, backendTarget, observedFile)
	t.Cleanup(func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientTarget := net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(frontPort))
	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+clientTarget,
	)
	output, err := clientCmd.CombinedOutput()
	if err == nil {
		waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
		t.Fatalf("%s XDP full-NAT client unexpectedly succeeded\nclient output:\n%s\nbackend logs:\n%s", proto, string(output), backendLogs.String())
	}
	if backendCmd != nil && backendCmd.ProcessState == nil {
		stopDataplanePerfHelper(t, backendCmd)
	}
	if data, readErr := os.ReadFile(observedFile); readErr == nil && strings.TrimSpace(string(data)) != "" {
		t.Fatalf("%s XDP full-NAT backend unexpectedly observed traffic %q while failure was expected\nclient output:\n%s\nbackend logs:\n%s", proto, strings.TrimSpace(string(data)), string(output), backendLogs.String())
	}
}

func waitForXDPFullNATIntegrationAPI(t *testing.T, apiBase string, cmd *exec.Cmd, logPath string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cmd != nil && cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				logForwardLogOnFailure(t, logPath)
				t.Fatalf("forward process exited before api became ready: %v", err)
			}
		}
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/tags", nil)
		if err != nil {
			t.Fatalf("build api request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	logForwardLogOnFailure(t, logPath)
	t.Fatalf("api %s not ready in time", apiBase)
}

func requireXDPFullNATIntegrationBinary(t *testing.T) string {
	t.Helper()

	if os.Getenv(xdpFullNATIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux XDP full-NAT integration test", xdpFullNATIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	return buildDataplanePerfBinary(t, repoRoot)
}

func startXDPFullNATIntegrationHarness(t *testing.T, baseBinary string, name string) xdpFullNATIntegrationHarness {
	t.Helper()

	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	runtimeDir := makeShortXDPFullNATIntegrationDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-"+name)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, xdpFullNATIntegrationMode("xdp-fullnat-"+name), webPort)

	logPath := filepath.Join(workDir, "forward-xdp-fullnat-"+name+".log")
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
	waitForXDPFullNATIntegrationAPI(t, apiBase, cmd, logPath)
	return xdpFullNATIntegrationHarness{
		Topology: topology,
		APIBase:  apiBase,
		LogPath:  logPath,
	}
}

func xdpFullNATIntegrationMode(name string) dataplanePerfMode {
	return dataplanePerfMode{
		Name:         name,
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineXDP},
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineXDP,
	}
}

func listXDPFullNATIntegrationRules(t *testing.T, apiBase string) []RuleStatus {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/rules", nil)
	if err != nil {
		t.Fatalf("build list rules request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list rules unexpected status %d: %s", resp.StatusCode, string(body))
	}
	var rules []RuleStatus
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	return rules
}

func waitForXDPFullNATIntegrationRuleRunning(t *testing.T, apiBase string, remark string, mode dataplanePerfMode) RuleStatus {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, rule := range listXDPFullNATIntegrationRules(t, apiBase) {
			if rule.Remark != remark {
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
	t.Fatalf("rule %q did not enter running/%s state in time", remark, mode.Expected)
	return RuleStatus{}
}

func waitForXDPFullNATIntegrationRuleStopped(t *testing.T, apiBase string, remark string) RuleStatus {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, rule := range listXDPFullNATIntegrationRules(t, apiBase) {
			if rule.Remark != remark {
				continue
			}
			if rule.Enabled || rule.Status != "stopped" {
				break
			}
			return rule
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("rule %q did not enter stopped state in time", remark)
	return RuleStatus{}
}

func waitForXDPFullNATIntegrationRuleAbsent(t *testing.T, apiBase string, remark string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, rule := range listXDPFullNATIntegrationRules(t, apiBase) {
			if rule.Remark == remark {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("rule %q still present after delete", remark)
}

func toggleXDPFullNATIntegrationRule(t *testing.T, apiBase string, id int64) {
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
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("toggle rule %d unexpected status %d: %s", id, resp.StatusCode, string(body))
	}
}

func deleteXDPFullNATIntegrationRule(t *testing.T, apiBase string, id int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, apiBase+"/api/rules?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		t.Fatalf("build delete rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete rule %d: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete rule %d unexpected status %d: %s", id, resp.StatusCode, string(body))
	}
}

func waitForXDPFullNATIntegrationActiveEntries(t *testing.T, apiBase string, logPath string, phase string, predicate func(int) bool) int {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	lastEntries := -1
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime", nil)
		if err != nil {
			t.Fatalf("build kernel runtime request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var runtime KernelRuntimeResponse
		err = json.NewDecoder(resp.Body).Decode(&runtime)
		resp.Body.Close()
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		for _, engine := range runtime.Engines {
			if engine.Name != kernelEngineXDP {
				continue
			}
			lastEntries = engine.ActiveEntries
			if predicate(engine.ActiveEntries) {
				return engine.ActiveEntries
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	logForwardLogOnFailure(t, logPath)
	t.Fatalf("xdp active entries %s did not reach expected state; last=%d", phase, lastEntries)
	return 0
}

func makeShortXDPFullNATIntegrationDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fwxdp-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
