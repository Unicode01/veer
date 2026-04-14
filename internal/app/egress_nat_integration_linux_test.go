//go:build linux

package app

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the TC integration test as root:
//      FORWARD_RUN_EGRESS_NAT_TEST=1 go test ./internal/app -run TestEgressNATTCIntegration -count=1 -v
//   3. Run the XDP integration test as root:
//      FORWARD_RUN_EGRESS_NAT_XDP_TEST=1 go test ./internal/app -run TestEgressNATXDPIntegration -count=1 -v

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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

const (
	egressNATTestEnableEnv        = "FORWARD_RUN_EGRESS_NAT_TEST"
	egressNATXDPTestEnableEnv     = "FORWARD_RUN_EGRESS_NAT_XDP_TEST"
	egressNATHelperEnv            = "FORWARD_EGRESS_NAT_HELPER"
	egressNATHelperRoleEnv        = "FORWARD_EGRESS_NAT_HELPER_ROLE"
	egressNATHelperProtocolEnv    = "FORWARD_EGRESS_NAT_PROTOCOL"
	egressNATHelperListenAddrEnv  = "FORWARD_EGRESS_NAT_LISTEN_ADDR"
	egressNATHelperTargetAddrEnv  = "FORWARD_EGRESS_NAT_TARGET_ADDR"
	egressNATHelperLocalAddrEnv   = "FORWARD_EGRESS_NAT_LOCAL_ADDR"
	egressNATHelperObservedEnv    = "FORWARD_EGRESS_NAT_OBSERVED_FILE"
	egressNATHelperObservedFmtEnv = "FORWARD_EGRESS_NAT_OBSERVED_FORMAT"
	egressNATTestToken            = dataplanePerfToken
	egressNATBridgeAddr           = "198.18.0.1"
	egressNATClientAddr           = "198.18.0.2"
	egressNATUplinkAddr           = "198.19.0.1"
	egressNATBackendAddr          = "198.19.0.2"
	egressNATProbePort            = 24001
	egressNATProbePortAlt1        = 24003
	egressNATProbePortAlt2        = 24005
	egressNATForwardProbePort     = 24002
	egressNATMappingLocalPort     = 35001
	egressNATHelperReadyLine      = "READY"
	egressNATHelperRoleBackend    = "backend"
	egressNATHelperRoleClient     = "client"
	egressNATObservedFmtHost      = "host"
	egressNATObservedFmtHostPort  = "hostport"
	egressNATExpectedKernelEngine = kernelEngineTC
	egressNATExpectedXDPKernel    = kernelEngineXDP
)

type egressNATIntegrationTopology struct {
	ClientNS     string
	BackendNS    string
	BridgeIF     string
	ChildHostIF  string
	ClientNSIF   string
	UplinkHostIF string
	BackendNSIF  string
}

type egressNATIntegrationStatus struct {
	ID                    int64  `json:"id"`
	ParentInterface       string `json:"parent_interface"`
	ChildInterface        string `json:"child_interface"`
	OutInterface          string `json:"out_interface"`
	OutSourceIP           string `json:"out_source_ip"`
	Enabled               bool   `json:"enabled"`
	Status                string `json:"status"`
	EffectiveEngine       string `json:"effective_engine"`
	EffectiveKernelEngine string `json:"effective_kernel_engine"`
	KernelReason          string `json:"kernel_reason"`
	FallbackReason        string `json:"fallback_reason"`
}

type egressNATIntegrationHarness struct {
	Topology             egressNATIntegrationTopology
	APIBase              string
	LogPath              string
	Cmd                  *exec.Cmd
	WorkDir              string
	ForwardBinary        string
	ConfigPath           string
	HotRestartMarkerPath string
	BPFStateRoot         string
	RuntimeStateRoot     string
}

type egressNATPacketCapture struct {
	Label   string
	cancel  context.CancelFunc
	cmd     *exec.Cmd
	output  bytes.Buffer
	stopped bool
}

func ensureEgressNATIntegrationIPForwarding(t *testing.T) {
	t.Helper()

	originalIPForward := strings.TrimSpace(readDataplanePerfProcFile(t, "/proc/sys/net/ipv4/ip_forward"))
	t.Cleanup(func() {
		if originalIPForward == "" {
			return
		}
		if output, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+originalIPForward).CombinedOutput(); err != nil {
			t.Logf("egress nat integration: restore net.ipv4.ip_forward=%s failed: %v (%s)", originalIPForward, err, strings.TrimSpace(string(output)))
		}
	})

	mustRunDataplanePerfCmd(t, "sysctl", "-w", "net.ipv4.ip_forward=1")
}

func TestEgressNATIntegrationHelperProcess(t *testing.T) {
	if os.Getenv(egressNATHelperEnv) != "1" {
		return
	}

	var err error
	switch strings.TrimSpace(os.Getenv(egressNATHelperRoleEnv)) {
	case egressNATHelperRoleBackend:
		err = runEgressNATBackendHelper()
	case egressNATHelperRoleClient:
		err = runEgressNATClientHelper()
	default:
		err = fmt.Errorf("unknown egress nat helper role %q", os.Getenv(egressNATHelperRoleEnv))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestEgressNATTCIntegration(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
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
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "tc-egress-nat",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat.log")
	logFile, err := os.Create(logPath)
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
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	createEgressNATIntegrationEntry(t, apiBase, topology)
	waitForEgressNATIntegrationStatus(t, apiBase, topology, topology.ChildHostIF)

	for _, proto := range []string{"tcp", "udp", "icmp"} {
		proto := proto
		t.Run(proto, func(t *testing.T) {
			observedIP := runEgressNATIntegrationProbe(t, topology, proto)
			if observedIP != egressNATUplinkAddr {
				logForwardLogOnFailure(t, logPath)
				t.Fatalf("%s backend observed source IP %q, want %q", proto, observedIP, egressNATUplinkAddr)
			}
		})
	}
}

func TestEgressNATXDPIntegration(t *testing.T) {
	if os.Getenv(egressNATXDPTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux xdp egress NAT integration test", egressNATXDPTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}
	if reason := xdpVethNATRedirectGuardReasonForRelease(kernelRelease()); reason != "" {
		t.Skip(reason)
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)
	topology := setupEgressNATIntegrationDirectTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-xdp")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "xdp-egress-nat",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineXDP, kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedXDPKernel,
		Experimental: map[string]bool{
			experimentalFeatureXDPGeneric: true,
		},
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat-xdp.log")
	logFile, err := os.Create(logPath)
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
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	createEgressNATIntegrationEntryForScopeWithProtocol(t, apiBase, topology, topology.ChildHostIF, "tcp+udp")
	waitForEgressNATIntegrationStatusWithKernelEngine(t, apiBase, topology, topology.ChildHostIF, egressNATExpectedXDPKernel)

	for _, proto := range []string{"tcp", "udp"} {
		proto := proto
		t.Run(proto, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					logKernelRuntimeOnFailure(t, apiBase)
					logForwardLogOnFailure(t, logPath)
				}
			}()
			observedIP := runEgressNATIntegrationProbe(t, topology, proto)
			if observedIP != egressNATUplinkAddr {
				logForwardLogOnFailure(t, logPath)
				t.Fatalf("%s backend observed source IP %q, want %q", proto, observedIP, egressNATUplinkAddr)
			}
		})
	}
}

func TestEgressNATTraditionalSNATIntegration(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	t.Setenv(dataplanePerfProtocolEnv, "tcp")

	cases := []struct {
		name  string
		setup func(*testing.T, egressNATIntegrationTopology) string
	}{
		{name: "iptables", setup: setupEgressNATPerfIptablesSNAT},
		{name: "nftables", setup: setupEgressNATPerfNFTablesSNAT},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			topology := setupEgressNATIntegrationTopology(t)
			seedEgressNATIntegrationNeighbor(t, topology)
			tc.setup(t, topology)

			observedIP := runEgressNATIntegrationProbeToAddr(t, topology, "tcp", net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(dataplanePerfBackendPort)))
			if observedIP != egressNATUplinkAddr {
				t.Fatalf("%s backend observed source IP %q, want %q", tc.name, observedIP, egressNATUplinkAddr)
			}
		})
	}
}

func TestEgressNATUDPMappingRespectsNATType(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	cases := []struct {
		name            string
		natType         string
		wantUniquePorts int
	}{
		{name: "symmetric", natType: egressNATTypeSymmetric, wantUniquePorts: 2},
		{name: "full_cone", natType: egressNATTypeFullCone, wantUniquePorts: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := findRepoRoot(t)
			requireEmbeddedEBPFObjects(t, repoRoot)
			baseBinary := buildDataplanePerfBinary(t, repoRoot)
			topology := setupEgressNATIntegrationTopology(t)
			seedEgressNATIntegrationNeighbor(t, topology)

			runtimeDir := makeShortEgressNATTestDir(t)
			forwardBinary := filepath.Join(runtimeDir, "forward")
			copyFile(t, baseBinary, forwardBinary)

			workDir := filepath.Join(runtimeDir, "work-mapping-"+tc.natType)
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatalf("create work dir: %v", err)
			}
			webPort := freeTCPPort(t)
			configPath := filepath.Join(workDir, "config.json")
			writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
				Name:         "tc-egress-nat-mapping-" + tc.natType,
				Default:      ruleEngineKernel,
				Order:        []string{kernelEngineTC},
				Expected:     ruleEngineKernel,
				ExpectedKern: egressNATExpectedKernelEngine,
			}, webPort)

			logPath := filepath.Join(workDir, "forward-egress-nat-mapping-"+tc.natType+".log")
			logFile, err := os.Create(logPath)
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
			waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
			createEgressNATIntegrationEntryForScopeWithOptions(t, apiBase, topology, topology.ChildHostIF, "udp", tc.natType)
			waitForEgressNATIntegrationStatus(t, apiBase, topology, topology.ChildHostIF)

			observed := []string{
				runEgressNATUDPMappingProbe(t, topology, egressNATProbePort, egressNATMappingLocalPort),
				runEgressNATUDPMappingProbe(t, topology, egressNATProbePortAlt1, egressNATMappingLocalPort),
				runEgressNATUDPMappingProbe(t, topology, egressNATProbePortAlt2, egressNATMappingLocalPort),
			}

			ports := make(map[string]struct{}, len(observed))
			for _, endpoint := range observed {
				host, port, err := net.SplitHostPort(endpoint)
				if err != nil {
					logForwardLogOnFailure(t, logPath)
					t.Fatalf("%s mapping observed invalid endpoint %q: %v", tc.natType, endpoint, err)
				}
				if host != egressNATUplinkAddr {
					logForwardLogOnFailure(t, logPath)
					t.Fatalf("%s mapping observed host %q, want %q (all=%v)", tc.natType, host, egressNATUplinkAddr, observed)
				}
				ports[port] = struct{}{}
			}

			if len(ports) < tc.wantUniquePorts {
				logForwardLogOnFailure(t, logPath)
				t.Fatalf("%s mapping unique port count = %d, want >= %d (all=%v)", tc.natType, len(ports), tc.wantUniquePorts, observed)
			}
			if tc.natType == egressNATTypeFullCone && len(ports) != 1 {
				logForwardLogOnFailure(t, logPath)
				t.Fatalf("%s mapping ports = %v, want single reused port", tc.natType, observed)
			}
		})
	}
}

func TestEgressNATUserspaceForwardCoexists(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
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
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-userspace-forward")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "tc-egress-nat-userspace-forward",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat-userspace-forward.log")
	logFile, err := os.Create(logPath)
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
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	createEgressNATIntegrationEntryForScope(t, apiBase, topology, "")
	waitForEgressNATIntegrationStatus(t, apiBase, topology, "")
	createEgressNATForwardRule(t, apiBase, topology, ruleEngineUserspace, "tcp", false, "egress-nat-userspace-forward")
	waitForDataplanePerfRule(t, apiBase, dataplanePerfMode{
		Name:     "egress-nat-userspace-forward",
		Expected: ruleEngineUserspace,
	})

	if err := runForwardThroughEgressNATProbe(t, topology, "tcp"); err != nil {
		logForwardLogOnFailure(t, logPath)
		t.Fatal(err)
	}
}

func TestEgressNATKernelForwardCoexists(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
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
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-kernel-forward")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "tc-egress-nat-kernel-forward",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat-kernel-forward.log")
	logFile, err := os.Create(logPath)
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
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	createEgressNATIntegrationEntryForScope(t, apiBase, topology, "")
	waitForEgressNATIntegrationStatus(t, apiBase, topology, "")
	createEgressNATForwardRule(t, apiBase, topology, ruleEngineKernel, "tcp", true, "egress-nat-kernel-forward")
	waitForDataplanePerfRule(t, apiBase, dataplanePerfMode{
		Name:         "egress-nat-kernel-forward",
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	})

	if err := runForwardThroughEgressNATProbe(t, topology, "tcp"); err != nil {
		logForwardLogOnFailure(t, logPath)
		t.Fatal(err)
	}
}

func TestEgressNATKernelWildcardForwardCoexists(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
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
	topology := setupEgressNATIntegrationTopology(t)
	seedEgressNATIntegrationNeighbor(t, topology)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)

	workDir := filepath.Join(runtimeDir, "work-kernel-wildcard-forward")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "tc-egress-nat-kernel-wildcard-forward",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat-kernel-wildcard-forward.log")
	logFile, err := os.Create(logPath)
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
	waitForEgressNATIntegrationAPI(t, apiBase, cmd, logPath)
	createEgressNATIntegrationEntryForScope(t, apiBase, topology, "")
	waitForEgressNATIntegrationStatus(t, apiBase, topology, "")
	createEgressNATForwardRuleWithInboundIP(t, apiBase, topology, ruleEngineKernel, "0.0.0.0", "tcp", true, "egress-nat-kernel-wildcard-forward")
	waitForDataplanePerfRule(t, apiBase, dataplanePerfMode{
		Name:         "egress-nat-kernel-wildcard-forward",
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	})

	if err := runForwardThroughEgressNATProbe(t, topology, "tcp"); err != nil {
		logForwardLogOnFailure(t, logPath)
		t.Fatal(err)
	}
}

func TestEgressNATToggleDisableReenableRestoresConnectivity(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "toggle-cycle")
	createEgressNATIntegrationEntry(t, harness.APIBase, harness.Topology)
	item := waitForEgressNATIntegrationRunningStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after enable", func(entries int) bool {
		return entries > 0
	})

	for _, proto := range []string{"tcp", "udp", "icmp"} {
		observedIP := runEgressNATIntegrationProbe(t, harness.Topology, proto)
		if observedIP != egressNATUplinkAddr {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("%s backend observed source IP %q, want %q", proto, observedIP, egressNATUplinkAddr)
		}
	}

	toggleEgressNATIntegrationEntry(t, harness.APIBase, item.ID)
	waitForEgressNATIntegrationStoppedStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after disable", func(entries int) bool {
		return entries == 0
	})
	observedIP := runEgressNATIntegrationProbe(t, harness.Topology, "tcp")
	if observedIP != egressNATClientAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("tcp backend observed source IP after disable %q, want %q", observedIP, egressNATClientAddr)
	}

	toggleEgressNATIntegrationEntry(t, harness.APIBase, item.ID)
	waitForEgressNATIntegrationRunningStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after re-enable", func(entries int) bool {
		return entries > 0
	})

	for _, proto := range []string{"tcp", "udp", "icmp"} {
		observedIP := runEgressNATIntegrationProbe(t, harness.Topology, proto)
		if observedIP != egressNATUplinkAddr {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("%s backend observed source IP after re-enable %q, want %q", proto, observedIP, egressNATUplinkAddr)
		}
	}
}

func TestEgressNATDeleteRecreateWildcardRestoresConnectivity(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "delete-recreate-wildcard")
	createEgressNATIntegrationEntryForScope(t, harness.APIBase, harness.Topology, "")
	item := waitForEgressNATIntegrationRunningStatus(t, harness.APIBase, harness.Topology, "")
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after wildcard enable", func(entries int) bool {
		return entries > 0
	})

	observedIP := runEgressNATIntegrationProbe(t, harness.Topology, "tcp")
	if observedIP != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("tcp backend observed source IP %q, want %q", observedIP, egressNATUplinkAddr)
	}

	deleteEgressNATIntegrationEntry(t, harness.APIBase, item.ID)
	waitForEgressNATIntegrationAbsent(t, harness.APIBase, harness.Topology, "")
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after wildcard delete", func(entries int) bool {
		return entries == 0
	})
	observedIP = runEgressNATIntegrationProbe(t, harness.Topology, "tcp")
	if observedIP != egressNATClientAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("tcp backend observed source IP after wildcard delete %q, want %q", observedIP, egressNATClientAddr)
	}

	createEgressNATIntegrationEntryForScope(t, harness.APIBase, harness.Topology, "")
	waitForEgressNATIntegrationRunningStatus(t, harness.APIBase, harness.Topology, "")
	waitForEgressNATIntegrationTCActiveEntries(t, harness.APIBase, harness.LogPath, "after wildcard recreate", func(entries int) bool {
		return entries > 0
	})

	for _, proto := range []string{"tcp", "udp"} {
		observedIP = runEgressNATIntegrationProbe(t, harness.Topology, proto)
		if observedIP != egressNATUplinkAddr {
			logForwardLogOnFailure(t, harness.LogPath)
			t.Fatalf("%s backend observed source IP after recreate %q, want %q", proto, observedIP, egressNATUplinkAddr)
		}
	}
}

func runEgressNATBackendHelper() error {
	proto := strings.ToLower(strings.TrimSpace(os.Getenv(egressNATHelperProtocolEnv)))
	listenAddr := strings.TrimSpace(os.Getenv(egressNATHelperListenAddrEnv))
	observedFile := strings.TrimSpace(os.Getenv(egressNATHelperObservedEnv))
	observedFormat := strings.TrimSpace(os.Getenv(egressNATHelperObservedFmtEnv))
	if listenAddr == "" {
		return errors.New("missing backend listen address")
	}
	if observedFile == "" {
		return errors.New("missing observed peer file")
	}

	switch proto {
	case "icmp":
		pc, err := net.ListenPacket("ip4:icmp", listenAddr)
		if err != nil {
			return err
		}
		defer pc.Close()

		fmt.Println(egressNATHelperReadyLine)
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 1500)
		_, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		return writeEgressNATObservedPeer(observedFile, peer, observedFormat)
	case "udp":
		pc, err := net.ListenPacket("udp4", listenAddr)
		if err != nil {
			return err
		}
		defer pc.Close()

		fmt.Println(egressNATHelperReadyLine)
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 128)
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if err := writeEgressNATObservedPeer(observedFile, peer, observedFormat); err != nil {
			return err
		}
		_, err = pc.WriteTo(buf[:n], peer)
		return err
	default:
		ln, err := net.Listen("tcp4", listenAddr)
		if err != nil {
			return err
		}
		defer ln.Close()

		fmt.Println(egressNATHelperReadyLine)
		tcpLn, _ := ln.(*net.TCPListener)
		if tcpLn != nil {
			_ = tcpLn.SetDeadline(time.Now().Add(10 * time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := writeEgressNATObservedPeer(observedFile, conn.RemoteAddr(), observedFormat); err != nil {
			return err
		}
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		_, err = conn.Write(buf[:n])
		return err
	}
}

func runEgressNATClientHelper() error {
	proto := strings.ToLower(strings.TrimSpace(os.Getenv(egressNATHelperProtocolEnv)))
	targetAddr := strings.TrimSpace(os.Getenv(egressNATHelperTargetAddrEnv))
	localAddr := strings.TrimSpace(os.Getenv(egressNATHelperLocalAddrEnv))
	if targetAddr == "" {
		return errors.New("missing client target address")
	}

	payload := []byte("egress-nat-probe")
	dialer := net.Dialer{Timeout: 10 * time.Second}
	switch proto {
	case "icmp":
		pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))

		targetIP := net.ParseIP(targetAddr)
		if targetIP == nil {
			return fmt.Errorf("invalid icmp target address %q", targetAddr)
		}
		targetIP = targetIP.To4()
		if targetIP == nil {
			return fmt.Errorf("invalid IPv4 icmp target address %q", targetAddr)
		}
		echoID := uint16(os.Getpid() & 0xffff)
		echoSeq := uint16(1)
		msg := buildICMPEchoMessage(8, echoID, echoSeq, payload)
		if _, err := pc.WriteTo(msg, &net.IPAddr{IP: targetIP}); err != nil {
			return err
		}

		buf := make([]byte, 1500)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return err
			}
			icmpType, replyID, replySeq, replyPayload, ok := parseICMPEchoMessage(buf[:n])
			if !ok {
				continue
			}
			if icmpType != 0 || replyID != echoID || replySeq != echoSeq {
				continue
			}
			if !bytes.Equal(replyPayload, payload) {
				return fmt.Errorf("icmp echo mismatch: got %q want %q", string(replyPayload), string(payload))
			}
			return nil
		}
	case "udp":
		if localAddr != "" {
			laddr, err := net.ResolveUDPAddr("udp4", localAddr)
			if err != nil {
				return err
			}
			raddr, err := net.ResolveUDPAddr("udp4", targetAddr)
			if err != nil {
				return err
			}
			conn, err := net.DialUDP("udp4", laddr, raddr)
			if err != nil {
				return err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				return err
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return err
			}
			if !bytes.Equal(buf, payload) {
				return fmt.Errorf("udp echo mismatch: got %q want %q", string(buf), string(payload))
			}
			return nil
		}
		conn, err := dialer.Dial("udp4", targetAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if !bytes.Equal(buf, payload) {
			return fmt.Errorf("udp echo mismatch: got %q want %q", string(buf), string(payload))
		}
		return nil
	default:
		conn, err := dialer.Dial("tcp4", targetAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if !bytes.Equal(buf, payload) {
			return fmt.Errorf("tcp echo mismatch: got %q want %q", string(buf), string(payload))
		}
		return nil
	}
}

func setupEgressNATIntegrationTopology(t *testing.T) egressNATIntegrationTopology {
	t.Helper()
	ensureEgressNATIntegrationIPForwarding(t)

	suffix := strconv.Itoa(os.Getpid() % 100000)
	topology := egressNATIntegrationTopology{
		ClientNS:     "fwec" + suffix,
		BackendNS:    "fweb" + suffix,
		BridgeIF:     truncateIfName("vmbr" + suffix),
		ChildHostIF:  truncateIfName("tap" + suffix),
		ClientNSIF:   truncateIfName("fwcn" + suffix),
		UplinkHostIF: truncateIfName("fwup" + suffix),
		BackendNSIF:  truncateIfName("fwbn" + suffix),
	}

	cleanup := func() {
		runDataplanePerfCmd("ip", "link", "del", topology.ChildHostIF)
		runDataplanePerfCmd("ip", "link", "del", topology.UplinkHostIF)
		runDataplanePerfCmd("ip", "link", "del", topology.BridgeIF)
		runDataplanePerfCmd("ip", "netns", "del", topology.ClientNS)
		runDataplanePerfCmd("ip", "netns", "del", topology.BackendNS)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.BackendNS)

	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.BridgeIF, "type", "bridge")
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATBridgeAddr+"/24", "dev", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BridgeIF, "up")

	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.ChildHostIF, "type", "veth", "peer", "name", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ChildHostIF, "master", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ChildHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ClientNSIF, "netns", topology.ClientNS)

	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.UplinkHostIF, "type", "veth", "peer", "name", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATUplinkAddr+"/24", "dev", topology.UplinkHostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.UplinkHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BackendNSIF, "netns", topology.BackendNS)

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "addr", "add", egressNATClientAddr+"/24", "dev", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", topology.ClientNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "route", "replace", "default", "via", egressNATBridgeAddr, "dev", topology.ClientNSIF)

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "addr", "add", egressNATBackendAddr+"/24", "dev", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", topology.BackendNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "route", "replace", "default", "via", egressNATUplinkAddr, "dev", topology.BackendNSIF)

	if dataplanePerfDisableOffloads() {
		bestEffortDisableDataplanePerfOffloads(t, dataplanePerfTopology{
			ClientNS:      topology.ClientNS,
			BackendNS:     topology.BackendNS,
			ClientHostIF:  topology.ChildHostIF,
			ClientNSIF:    topology.ClientNSIF,
			BackendHostIF: topology.UplinkHostIF,
			BackendNSIF:   topology.BackendNSIF,
		})
	}

	return topology
}

func setupEgressNATIntegrationDirectTopology(t *testing.T) egressNATIntegrationTopology {
	t.Helper()
	ensureEgressNATIntegrationIPForwarding(t)

	suffix := strconv.Itoa(os.Getpid() % 100000)
	topology := egressNATIntegrationTopology{
		ClientNS:     "fwec" + suffix,
		BackendNS:    "fweb" + suffix,
		BridgeIF:     truncateIfName("fwfr" + suffix),
		ChildHostIF:  "",
		ClientNSIF:   truncateIfName("fwcn" + suffix),
		UplinkHostIF: truncateIfName("fwup" + suffix),
		BackendNSIF:  truncateIfName("fwbn" + suffix),
	}

	cleanup := func() {
		runDataplanePerfCmd("ip", "link", "del", topology.BridgeIF)
		runDataplanePerfCmd("ip", "link", "del", topology.UplinkHostIF)
		runDataplanePerfCmd("ip", "netns", "del", topology.ClientNS)
		runDataplanePerfCmd("ip", "netns", "del", topology.BackendNS)
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.ClientNS)
	mustRunDataplanePerfCmd(t, "ip", "netns", "add", topology.BackendNS)

	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.BridgeIF, "type", "veth", "peer", "name", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATBridgeAddr+"/24", "dev", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BridgeIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.ClientNSIF, "netns", topology.ClientNS)

	mustRunDataplanePerfCmd(t, "ip", "link", "add", topology.UplinkHostIF, "type", "veth", "peer", "name", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", egressNATUplinkAddr+"/24", "dev", topology.UplinkHostIF)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.UplinkHostIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "link", "set", topology.BackendNSIF, "netns", topology.BackendNS)

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "addr", "add", egressNATClientAddr+"/24", "dev", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "link", "set", topology.ClientNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "route", "replace", "default", "via", egressNATBridgeAddr, "dev", topology.ClientNSIF)

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", "lo", "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "addr", "add", egressNATBackendAddr+"/24", "dev", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "link", "set", topology.BackendNSIF, "up")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "route", "replace", "default", "via", egressNATUplinkAddr, "dev", topology.BackendNSIF)

	if dataplanePerfDisableOffloads() {
		bestEffortDisableDataplanePerfOffloads(t, dataplanePerfTopology{
			ClientNS:      topology.ClientNS,
			BackendNS:     topology.BackendNS,
			ClientHostIF:  topology.BridgeIF,
			ClientNSIF:    topology.ClientNSIF,
			BackendHostIF: topology.UplinkHostIF,
			BackendNSIF:   topology.BackendNSIF,
		})
		restoreEgressNATDirectTopologyGRO(t, topology)
	} else {
		t.Log("dataplane perf: keeping veth offloads enabled")
	}

	return topology
}

func restoreEgressNATDirectTopologyGRO(t *testing.T, topology egressNATIntegrationTopology) {
	t.Helper()

	// XDP redirect between veth peers can stall in this direct test topology if
	// the namespace-side peer has GRO disabled, so restore GRO after the broad
	// perf-style offload disable pass.
	restore := func(netns string, ifName string) {
		if strings.TrimSpace(netns) == "" || strings.TrimSpace(ifName) == "" {
			return
		}
		if _, err := exec.LookPath("ethtool"); err != nil {
			return
		}
		args := []string{"ip", "netns", "exec", netns, "ethtool", "-K", ifName, "gro", "on"}
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			text := strings.TrimSpace(string(output))
			if text == "" {
				text = err.Error()
			}
			t.Logf("xdp egress nat: ethtool %s/%s gro on skipped: %s", netns, ifName, text)
			return
		}
		t.Logf("xdp egress nat: restored gro on for %s/%s", netns, ifName)
	}

	restore(topology.ClientNS, topology.ClientNSIF)
	restore(topology.BackendNS, topology.BackendNSIF)
}

func startEgressNATIntegrationHarness(t *testing.T, name string) egressNATIntegrationHarness {
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
		t.Fatalf("create hot restart runtime state dir: %v", err)
	}
	bpfStateRoot := requireKernelHotRestartBPFStateRoot(t)
	hotRestartMarkerPath := filepath.Join(runtimeDir, ".hot-restart-kernel")
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "tc-egress-nat-" + name,
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedKernelEngine,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-egress-nat-"+name+".log")
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

func seedEgressNATIntegrationNeighbor(t *testing.T, topology egressNATIntegrationTopology) {
	t.Helper()

	bridgeMAC := mustReadHostInterfaceMAC(t, topology.BridgeIF)
	uplinkMAC := mustReadHostInterfaceMAC(t, topology.UplinkHostIF)
	clientPeerMAC := mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF)
	backendPeerMAC := mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF)

	mustRunDataplanePerfCmd(t, "ip", "route", "replace", egressNATBackendAddr+"/32", "dev", topology.UplinkHostIF, "src", egressNATUplinkAddr)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "neigh", "replace", egressNATBridgeAddr, "lladdr", bridgeMAC, "dev", topology.ClientNSIF, "nud", "permanent")
	// Classic routed SNAT returns through the bridge master, while the kernel
	// dataplane fast path may redirect straight to the child port.
	runDataplanePerfCmd("ip", "neigh", "del", egressNATClientAddr, "dev", topology.BridgeIF)
	mustRunDataplanePerfCmd(t, "ip", "route", "replace", egressNATClientAddr+"/32", "dev", topology.BridgeIF, "src", egressNATBridgeAddr)
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", egressNATClientAddr, "lladdr", clientPeerMAC, "dev", topology.BridgeIF, "nud", "permanent")
	if strings.TrimSpace(topology.ChildHostIF) != "" {
		runDataplanePerfCmd("ip", "neigh", "del", egressNATClientAddr, "dev", topology.ChildHostIF)
		mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", egressNATClientAddr, "lladdr", clientPeerMAC, "dev", topology.ChildHostIF, "nud", "permanent")
	}
	runDataplanePerfCmd("ip", "neigh", "del", egressNATBackendAddr, "dev", topology.UplinkHostIF)
	mustRunDataplanePerfCmd(t, "ip", "neigh", "replace", egressNATBackendAddr, "lladdr", backendPeerMAC, "dev", topology.UplinkHostIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "neigh", "replace", egressNATUplinkAddr, "lladdr", uplinkMAC, "dev", topology.BackendNSIF, "nud", "permanent")
}

func waitForEgressNATIntegrationAPI(t *testing.T, apiBase string, cmd *exec.Cmd, logPath string) {
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
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
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

func makeShortEgressNATTestDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fwenat-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func createEgressNATIntegrationEntry(t *testing.T, apiBase string, topology egressNATIntegrationTopology) {
	createEgressNATIntegrationEntryForScopeWithProtocol(t, apiBase, topology, topology.ChildHostIF, "tcp+udp+icmp")
}

func createEgressNATIntegrationEntryForScope(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string) {
	createEgressNATIntegrationEntryForScopeWithProtocol(t, apiBase, topology, childInterface, "")
}

func createEgressNATIntegrationEntryForScopeWithProtocol(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string, protocol string) {
	createEgressNATIntegrationEntryForScopeWithOptions(t, apiBase, topology, childInterface, protocol, "")
}

func createEgressNATIntegrationEntryForScopeWithOptions(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string, protocol string, natType string) {
	t.Helper()

	payload := map[string]any{
		"parent_interface": topology.BridgeIF,
		"child_interface":  childInterface,
		"out_interface":    topology.UplinkHostIF,
		"out_source_ip":    egressNATUplinkAddr,
	}
	if strings.TrimSpace(protocol) != "" {
		payload["protocol"] = protocol
	}
	if strings.TrimSpace(natType) != "" {
		payload["nat_type"] = natType
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal egress nat payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/egress-nats", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create egress nat request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create egress nat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create egress nat unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func waitForEgressNATIntegrationStatus(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string) {
	t.Helper()
	_ = waitForEgressNATIntegrationRunningStatusWithKernelEngine(t, apiBase, topology, childInterface, egressNATExpectedKernelEngine)
}

func listEgressNATIntegrationStatuses(t *testing.T, apiBase string) []egressNATIntegrationStatus {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/egress-nats", nil)
	if err != nil {
		t.Fatalf("build list egress nat request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list egress nat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list egress nat unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var items []egressNATIntegrationStatus
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode list egress nat response: %v", err)
	}
	return items
}

func waitForEgressNATIntegrationRunningStatus(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string) egressNATIntegrationStatus {
	return waitForEgressNATIntegrationRunningStatusWithKernelEngine(t, apiBase, topology, childInterface, egressNATExpectedKernelEngine)
}

func waitForEgressNATIntegrationStatusWithKernelEngine(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string, expectedKernelEngine string) {
	t.Helper()
	_ = waitForEgressNATIntegrationRunningStatusWithKernelEngine(t, apiBase, topology, childInterface, expectedKernelEngine)
}

func waitForEgressNATIntegrationRunningStatusWithKernelEngine(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string, expectedKernelEngine string) egressNATIntegrationStatus {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/egress-nats", nil)
		if err != nil {
			t.Fatalf("build list egress nat request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var items []egressNATIntegrationStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil || len(items) == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		for _, item := range items {
			if item.ParentInterface != topology.BridgeIF || item.ChildInterface != childInterface || item.OutInterface != topology.UplinkHostIF {
				continue
			}
			if item.Status != "running" || !item.Enabled {
				continue
			}
			if item.EffectiveEngine != ruleEngineKernel {
				t.Fatalf("egress nat effective engine = %q, want %q (kernel_reason=%q fallback=%q)", item.EffectiveEngine, ruleEngineKernel, item.KernelReason, item.FallbackReason)
			}
			if item.EffectiveKernelEngine != expectedKernelEngine {
				t.Fatalf("egress nat kernel engine = %q, want %q (kernel_reason=%q fallback=%q)", item.EffectiveKernelEngine, expectedKernelEngine, item.KernelReason, item.FallbackReason)
			}
			if item.OutSourceIP != egressNATUplinkAddr {
				t.Fatalf("egress nat out_source_ip = %q, want %q", item.OutSourceIP, egressNATUplinkAddr)
			}
			return item
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("egress nat did not enter running/kernel %s state in time", expectedKernelEngine)
	return egressNATIntegrationStatus{}
}

func waitForEgressNATIntegrationStoppedStatus(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string) egressNATIntegrationStatus {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/egress-nats", nil)
		if err != nil {
			t.Fatalf("build list egress nat request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var items []egressNATIntegrationStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil || len(items) == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		for _, item := range items {
			if item.ParentInterface != topology.BridgeIF || item.ChildInterface != childInterface || item.OutInterface != topology.UplinkHostIF {
				continue
			}
			if item.Enabled || item.Status != "stopped" {
				continue
			}
			return item
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("egress nat did not enter stopped state in time")
	return egressNATIntegrationStatus{}
}

func waitForEgressNATIntegrationAbsent(t *testing.T, apiBase string, topology egressNATIntegrationTopology, childInterface string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		items := listEgressNATIntegrationStatuses(t, apiBase)
		found := false
		for _, item := range items {
			if item.ParentInterface == topology.BridgeIF && item.ChildInterface == childInterface && item.OutInterface == topology.UplinkHostIF {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("egress nat entry still present after delete")
}

func toggleEgressNATIntegrationEntry(t *testing.T, apiBase string, id int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/egress-nats/toggle?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		t.Fatalf("build toggle egress nat request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("toggle egress nat %d: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("toggle egress nat %d unexpected status %d: %s", id, resp.StatusCode, string(body))
	}
}

func deleteEgressNATIntegrationEntry(t *testing.T, apiBase string, id int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, apiBase+"/api/egress-nats?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		t.Fatalf("build delete egress nat request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete egress nat %d: %v", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete egress nat %d unexpected status %d: %s", id, resp.StatusCode, string(body))
	}
}

func waitForEgressNATIntegrationTCActiveEntries(t *testing.T, apiBase string, logPath string, phase string, predicate func(int) bool) int {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	lastEntries := -1
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime", nil)
		if err != nil {
			t.Fatalf("build kernel runtime request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
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
			if engine.Name != kernelEngineTC {
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
	t.Fatalf("tc active entries %s did not reach expected state; last=%d", phase, lastEntries)
	return 0
}

func createEgressNATForwardRule(t *testing.T, apiBase string, topology egressNATIntegrationTopology, engine string, proto string, transparent bool, remark string) {
	createEgressNATForwardRuleWithInboundIP(t, apiBase, topology, engine, egressNATUplinkAddr, proto, transparent, remark)
}

func createEgressNATForwardRuleWithInboundIP(t *testing.T, apiBase string, topology egressNATIntegrationTopology, engine string, inIP string, proto string, transparent bool, remark string) {
	t.Helper()

	payload := map[string]any{
		"in_interface":      topology.UplinkHostIF,
		"in_ip":             inIP,
		"in_port":           egressNATForwardProbePort,
		"out_interface":     topology.BridgeIF,
		"out_ip":            egressNATClientAddr,
		"out_port":          egressNATProbePort,
		"protocol":          proto,
		"transparent":       transparent,
		"engine_preference": engine,
		"remark":            remark,
		"tag":               "egress-nat",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal coexist rule payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build coexist rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create coexist rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create coexist rule unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func runEgressNATIntegrationProbe(t *testing.T, topology egressNATIntegrationTopology, proto string) string {
	t.Helper()

	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATProbePort))
	if proto == "icmp" {
		targetAddr = egressNATBackendAddr
	}
	return runEgressNATIntegrationProbeToAddr(t, topology, proto, targetAddr)
}

func runEgressNATIntegrationProbeToAddr(t *testing.T, topology egressNATIntegrationTopology, proto string, targetAddr string) string {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), "observed-"+proto+".txt")

	backendCmd, backendLogs := startEgressNATBackendHelperInNamespace(t, topology.BackendNS, proto, targetAddr, observedFile)
	t.Cleanup(func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	})

	captures := startEgressNATPacketCaptures(t, topology, proto)
	defer stopEgressNATPacketCaptures(captures)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+targetAddr,
	)
	if output, err := clientCmd.CombinedOutput(); err != nil {
		captureLogs := stopAndCollectEgressNATPacketCaptures(captures)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s client helper timed out\nclient output:\n%s\nbackend logs:\n%s\npacket capture:\n%s", proto, string(output), backendLogs.String(), captureLogs)
		}
		t.Fatalf("%s client helper failed: %v\nclient output:\n%s\nbackend logs:\n%s\npacket capture:\n%s", proto, err, string(output), backendLogs.String(), captureLogs)
	} else if len(output) > 0 {
		t.Logf("%s client helper output:\n%s", proto, string(output))
	}

	waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
	data, err := os.ReadFile(observedFile)
	if err != nil {
		t.Fatalf("%s read observed peer file: %v\n%s\npacket capture:\n%s", proto, err, backendLogs.String(), stopAndCollectEgressNATPacketCaptures(captures))
	}
	return strings.TrimSpace(string(data))
}

func startEgressNATPacketCaptures(t *testing.T, topology egressNATIntegrationTopology, proto string) []*egressNATPacketCapture {
	t.Helper()

	if strings.TrimSpace(topology.ChildHostIF) != "" {
		return nil
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return nil
	}

	captures := []*egressNATPacketCapture{
		startEgressNATPacketCapture(t, "host "+topology.UplinkHostIF, "", topology.UplinkHostIF, proto),
		startEgressNATPacketCapture(t, "netns "+topology.BackendNS+"/"+topology.BackendNSIF, topology.BackendNS, topology.BackendNSIF, proto),
	}
	anyStarted := false
	for _, capture := range captures {
		if capture != nil {
			anyStarted = true
			break
		}
	}
	if anyStarted {
		time.Sleep(300 * time.Millisecond)
	}
	return captures
}

func startEgressNATPacketCapture(t *testing.T, label string, namespace string, ifName string, proto string) *egressNATPacketCapture {
	t.Helper()

	if strings.TrimSpace(ifName) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	args := []string{"tcpdump", "-l", "-nn", "-e", "-vvv", "-c", "8", "-i", ifName}
	args = append(args, egressNATPacketCaptureFilter(proto)...)

	var cmd *exec.Cmd
	if strings.TrimSpace(namespace) == "" {
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	} else {
		nsArgs := append([]string{"netns", "exec", namespace}, args...)
		cmd = exec.CommandContext(ctx, "ip", nsArgs...)
	}

	capture := &egressNATPacketCapture{
		Label:  label,
		cancel: cancel,
		cmd:    cmd,
	}
	cmd.Stdout = &capture.output
	cmd.Stderr = &capture.output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Logf("start packet capture %s failed: %v", label, err)
		return nil
	}
	return capture
}

func egressNATPacketCaptureFilter(proto string) []string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp":
		return []string{"tcp", "and", "port", strconv.Itoa(egressNATProbePort)}
	case "udp":
		return []string{"udp", "and", "port", strconv.Itoa(egressNATProbePort)}
	case "icmp":
		return []string{"icmp"}
	default:
		return nil
	}
}

func stopEgressNATPacketCaptures(captures []*egressNATPacketCapture) {
	for _, capture := range captures {
		if capture == nil || capture.stopped {
			continue
		}
		capture.stopped = true
		capture.cancel()
		if capture.cmd == nil {
			continue
		}
		done := make(chan error, 1)
		go func(cmd *exec.Cmd) {
			done <- cmd.Wait()
		}(capture.cmd)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if capture.cmd.Process != nil {
				_ = capture.cmd.Process.Kill()
			}
			<-done
		}
	}
}

func stopAndCollectEgressNATPacketCaptures(captures []*egressNATPacketCapture) string {
	stopEgressNATPacketCaptures(captures)
	return collectEgressNATPacketCaptures(captures)
}

func collectEgressNATPacketCaptures(captures []*egressNATPacketCapture) string {
	parts := make([]string, 0, len(captures))
	for _, capture := range captures {
		if capture == nil {
			continue
		}
		text := strings.TrimSpace(capture.output.String())
		if text == "" {
			text = "(no packets captured)"
		}
		parts = append(parts, fmt.Sprintf("[%s]\n%s", capture.Label, text))
	}
	if len(parts) == 0 {
		return "(packet capture unavailable)"
	}
	return strings.Join(parts, "\n")
}

func expectEgressNATIntegrationProbeFailure(t *testing.T, topology egressNATIntegrationTopology, proto string) {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), "observed-fail-"+proto+".txt")
	targetAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(egressNATProbePort))
	if proto == "icmp" {
		targetAddr = egressNATBackendAddr
	}

	backendCmd, backendLogs := startEgressNATBackendHelperInNamespace(t, topology.BackendNS, proto, targetAddr, observedFile)
	defer func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+targetAddr,
	)
	output, err := clientCmd.CombinedOutput()
	if err == nil {
		waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
		t.Fatalf("%s client helper unexpectedly succeeded while failure was expected\nclient output:\n%s\nbackend logs:\n%s", proto, string(output), backendLogs.String())
	}
	if _, statErr := os.Stat(observedFile); statErr == nil {
		waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
		t.Fatalf("%s probe unexpectedly reached backend while failure was expected\nclient output:\n%s\nbackend logs:\n%s", proto, string(output), backendLogs.String())
	}
}

func runEgressNATUDPMappingProbe(t *testing.T, topology egressNATIntegrationTopology, targetPort int, localPort int) string {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), fmt.Sprintf("observed-udp-%d.txt", targetPort))
	listenAddr := net.JoinHostPort(egressNATBackendAddr, strconv.Itoa(targetPort))
	localAddr := net.JoinHostPort(egressNATClientAddr, strconv.Itoa(localPort))

	backendCmd, backendLogs := startEgressNATBackendHelperInNamespaceWithObservedFormat(t, topology.BackendNS, "udp", listenAddr, observedFile, egressNATObservedFmtHostPort)
	defer func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"=udp",
		egressNATHelperTargetAddrEnv+"="+listenAddr,
		egressNATHelperLocalAddrEnv+"="+localAddr,
	)
	output, err := clientCmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("udp mapping client timed out\nclient output:\n%s\nbackend logs:\n%s", string(output), backendLogs.String())
		}
		t.Fatalf("udp mapping client failed: %v\nclient output:\n%s\nbackend logs:\n%s", err, string(output), backendLogs.String())
	}

	waitForEgressNATHelperExit(t, backendCmd, "udp", backendLogs.String())
	data, err := os.ReadFile(observedFile)
	if err != nil {
		t.Fatalf("udp mapping read observed peer file: %v\n%s", err, backendLogs.String())
	}
	return strings.TrimSpace(string(data))
}

func startEgressNATBackendHelper(t *testing.T, topology egressNATIntegrationTopology, proto string, listenAddr string, observedFile string) (*exec.Cmd, *bytes.Buffer) {
	return startEgressNATBackendHelperInNamespace(t, topology.BackendNS, proto, listenAddr, observedFile)
}

func startEgressNATBackendHelperInNamespace(t *testing.T, namespace string, proto string, listenAddr string, observedFile string) (*exec.Cmd, *bytes.Buffer) {
	return startEgressNATBackendHelperInNamespaceWithObservedFormat(t, namespace, proto, listenAddr, observedFile, egressNATObservedFmtHost)
}

func startEgressNATBackendHelperInNamespaceWithObservedFormat(t *testing.T, namespace string, proto string, listenAddr string, observedFile string, observedFormat string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", namespace, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleBackend,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperListenAddrEnv+"="+listenAddr,
		egressNATHelperObservedEnv+"="+observedFile,
		egressNATHelperObservedFmtEnv+"="+observedFormat,
	)

	var stderr bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("%s backend stdout pipe: %v", proto, err)
	}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s start backend helper: %v", proto, err)
	}

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == egressNATHelperReadyLine {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("backend helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			stopDataplanePerfHelper(t, cmd)
			t.Fatalf("%s backend helper ready: %v\n%s", proto, err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		stopDataplanePerfHelper(t, cmd)
		t.Fatalf("%s backend helper ready timeout\n%s", proto, stderr.String())
	}

	return cmd, &stderr
}

func runForwardThroughEgressNATProbe(t *testing.T, topology egressNATIntegrationTopology, proto string) error {
	t.Helper()

	observedFile := filepath.Join(t.TempDir(), "observed-forward-"+proto+".txt")
	listenAddr := net.JoinHostPort(egressNATClientAddr, strconv.Itoa(egressNATProbePort))
	targetAddr := net.JoinHostPort(egressNATUplinkAddr, strconv.Itoa(egressNATForwardProbePort))

	backendCmd, backendLogs := startEgressNATBackendHelperInNamespace(t, topology.ClientNS, proto, listenAddr, observedFile)
	defer func() {
		if backendCmd != nil && backendCmd.ProcessState == nil {
			stopDataplanePerfHelper(t, backendCmd)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientCmd := exec.CommandContext(ctx, "ip", "netns", "exec", topology.BackendNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	clientCmd.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+targetAddr,
	)
	output, err := clientCmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s forward probe client timed out\nclient output:\n%s\nbackend logs:\n%s", proto, string(output), backendLogs.String())
		}
		return fmt.Errorf("%s forward probe client failed: %v\nclient output:\n%s\nbackend logs:\n%s", proto, err, string(output), backendLogs.String())
	}

	waitForEgressNATHelperExit(t, backendCmd, proto, backendLogs.String())
	return nil
}

func waitForEgressNATHelperExit(t *testing.T, cmd *exec.Cmd, proto string, logs string) {
	t.Helper()
	if cmd == nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s backend helper failed: %v\n%s", proto, err, logs)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("%s backend helper timed out\n%s", proto, logs)
	}
}

func writeEgressNATObservedPeer(path string, addr net.Addr, format string) error {
	var observed string
	var err error

	switch strings.ToLower(strings.TrimSpace(format)) {
	case egressNATObservedFmtHostPort:
		observed, err = peerHostPort(addr)
	default:
		observed, err = peerHost(addr)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(observed), 0o644)
}

func buildICMPEchoMessage(icmpType byte, id uint16, seq uint16, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = icmpType
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	binary.BigEndian.PutUint16(msg[2:4], icmpChecksum(msg))
	return msg
}

func parseICMPEchoMessage(msg []byte) (icmpType byte, id uint16, seq uint16, payload []byte, ok bool) {
	if len(msg) < 8 {
		return 0, 0, 0, nil, false
	}
	return msg[0], binary.BigEndian.Uint16(msg[4:6]), binary.BigEndian.Uint16(msg[6:8]), msg[8:], true
}

func icmpChecksum(msg []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if len(msg)%2 != 0 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func mustReadHostInterfaceMAC(t *testing.T, ifName string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("/sys/class/net", ifName, "address"))
	if err != nil {
		t.Fatalf("read host MAC for %s: %v", ifName, err)
	}
	mac := strings.TrimSpace(string(data))
	if mac == "" {
		t.Fatalf("read host MAC for %s: empty address", ifName)
	}
	return mac
}

func peerHost(addr net.Addr) (string, error) {
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.IP.String(), nil
	case *net.UDPAddr:
		return value.IP.String(), nil
	case *net.IPAddr:
		return value.IP.String(), nil
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", err
		}
		return host, nil
	}
}

func peerHostPort(addr net.Addr) (string, error) {
	switch value := addr.(type) {
	case *net.TCPAddr:
		return net.JoinHostPort(value.IP.String(), strconv.Itoa(value.Port)), nil
	case *net.UDPAddr:
		return net.JoinHostPort(value.IP.String(), strconv.Itoa(value.Port)), nil
	default:
		return addr.String(), nil
	}
}

func logForwardLogOnFailure(t *testing.T, logPath string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Logf("read forward log %s: %v", logPath, err)
		return
	}
	t.Logf("forward log:\n%s", string(data))
}

func logKernelRuntimeOnFailure(t *testing.T, apiBase string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/kernel/runtime", nil)
	if err != nil {
		t.Logf("build kernel runtime request: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Logf("request kernel runtime: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Logf("read kernel runtime response: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Logf("kernel runtime unexpected status %d:\n%s", resp.StatusCode, string(body))
		return
	}

	var runtime KernelRuntimeResponse
	if err := json.Unmarshal(body, &runtime); err != nil {
		t.Logf("decode kernel runtime response: %v\n%s", err, string(body))
		return
	}
	pretty, err := json.MarshalIndent(runtime, "", "  ")
	if err != nil {
		t.Logf("marshal kernel runtime response: %v\n%s", err, string(body))
		return
	}
	t.Logf("kernel runtime:\n%s", string(pretty))
}
