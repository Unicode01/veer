//go:build linux

package app

import (
	"context"
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

// TestEgressNATLeavesLocalNetworksToKernel checks guest-to-guest traffic
// beside TC egress NAT: two guests on one bridge, one leaving by the
// bridge's default exit and one by a child override to another exit (as a
// VPN exit is chosen for one VM), plus a guest on a second bridge with its
// own egress NAT. Traffic between them, on one bridge or routed between the
// bridges, must reach the peer with the guest's own address, while traffic
// for an uplink's network is still translated.
func TestEgressNATLeavesLocalNetworksToKernel(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	h := startEgressNATIntegrationHarness(t, "lateral")
	top := h.Topology
	suffix := strconv.Itoa(os.Getpid() % 100000)
	nsB, nsC, nsV := "ltb"+suffix, "ltc"+suffix, "ltv"+suffix
	tapB, peerB := truncateIfName("ltpb"+suffix), truncateIfName("ltnb"+suffix)
	br2, tapC, peerC := truncateIfName("ltbr"+suffix), truncateIfName("ltpc"+suffix), truncateIfName("ltnc"+suffix)
	exitV, peerV := truncateIfName("ltvx"+suffix), truncateIfName("ltvn"+suffix)
	const (
		addrA     = egressNATClientAddr // 198.18.0.2 on the first bridge
		addrB     = "198.18.0.3"
		br2Addr   = "198.21.0.1"
		addrC     = "198.21.0.2"
		exitVAddr = "198.20.0.1"
		addrV     = "198.20.0.2"
	)
	cleanupLateralLinks(t, []string{tapB, tapC, exitV, br2}, []string{nsB, nsC, nsV})
	addLateralGuest(t, nsB, tapB, peerB, top.BridgeIF, addrB, egressNATBridgeAddr)
	mustRunDataplanePerfCmd(t, "ip", "link", "add", br2, "type", "bridge")
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", br2Addr+"/24", "dev", br2)
	mustRunDataplanePerfCmd(t, "ip", "link", "set", br2, "up")
	addLateralGuest(t, nsC, tapC, peerC, br2, addrC, br2Addr)
	addLateralGuest(t, nsV, exitV, peerV, "", addrV, exitVAddr)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", exitVAddr+"/24", "dev", exitV)

	all := []string{"tcp", "udp", "icmp"}
	lateral := []lateralPath{
		{"A_to_B_same_bridge", top.ClientNS, nsB, addrB, addrA, all},
		{"B_to_A_same_bridge", nsB, top.ClientNS, addrA, addrB, all},
		{"A_to_C_other_bridge", top.ClientNS, nsC, addrC, addrA, all},
		{"B_to_C_other_bridge", nsB, nsC, addrC, addrB, all},
		{"C_to_A_other_bridge", nsC, top.ClientNS, addrA, addrC, all},
		{"C_to_B_other_bridge", nsC, nsB, addrB, addrC, all},
	}
	// Plain kernel routing first, so a failure later is Veer's.
	runLateralPaths(t, "baseline", lateral)

	createEgressNATIntegrationEntryForScopeWithOptions(t, h.APIBase, top, "", "tcp+udp+icmp", egressNATTypeFullCone)
	postLateralEgressNAT(t, h.APIBase, `{"parent_interface":"`+top.BridgeIF+`","child_interface":"`+tapB+`","out_interface":"`+exitV+`","out_source_ip":"`+exitVAddr+`","protocol":"tcp+udp","nat_type":"full_cone"}`)
	postLateralEgressNAT(t, h.APIBase, `{"parent_interface":"`+br2+`","out_interface":"`+top.UplinkHostIF+`","out_source_ip":"`+egressNATUplinkAddr+`","protocol":"tcp+udp+icmp","nat_type":"full_cone"}`)
	waitForLateralEgressNATs(t, h.APIBase, h.LogPath, 3, kernelEngineTC)

	// The exits still translate, also for a peer on the exit's own network:
	// the backend shares the uplink's network, the far end B's exit's.
	runLateralPaths(t, "veer", []lateralPath{
		{"A_to_uplink_network", top.ClientNS, top.BackendNS, egressNATBackendAddr, egressNATUplinkAddr, all},
		{"C_to_uplink_network", nsC, top.BackendNS, egressNATBackendAddr, egressNATUplinkAddr, all},
		{"B_to_its_exit", nsB, nsV, addrV, exitVAddr, []string{"tcp", "udp"}},
	})
	runLateralPaths(t, "veer", lateral)
	if t.Failed() {
		logKernelRuntimeOnFailure(t, h.APIBase)
		logForwardLogOnFailure(t, h.LogPath)
	}
}

// TestEgressNATXDPLeavesLocalNetworksToKernel is the XDP engine's check:
// a guest reaches a guest of another egress NAT network untranslated, and
// the uplink's network still sees the NAT address.
func TestEgressNATXDPLeavesLocalNetworksToKernel(t *testing.T) {
	if os.Getenv(egressNATXDPTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux xdp egress NAT integration test", egressNATXDPTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if reason := xdpVethNATRedirectGuardReasonForRelease(kernelRelease()); reason != "" {
		t.Skip(reason)
	}

	repoRoot := findRepoRoot(t)
	requireEmbeddedEBPFObjects(t, repoRoot)
	baseBinary := buildDataplanePerfBinary(t, repoRoot)
	top := setupEgressNATIntegrationDirectTopology(t)
	seedEgressNATIntegrationNeighbor(t, top)
	suffix := strconv.Itoa(os.Getpid() % 100000)
	nsC, hostC, peerC := "lxc"+suffix, truncateIfName("lxpc"+suffix), truncateIfName("lxnc"+suffix)
	const (
		hostCAddr = "198.21.0.1"
		addrC     = "198.21.0.2"
	)
	cleanupLateralLinks(t, []string{hostC}, []string{nsC})
	addLateralGuest(t, nsC, hostC, peerC, "", addrC, hostCAddr)
	mustRunDataplanePerfCmd(t, "ip", "addr", "add", hostCAddr+"/24", "dev", hostC)

	runtimeDir := makeShortEgressNATTestDir(t)
	forwardBinary := filepath.Join(runtimeDir, "forward")
	copyFile(t, baseBinary, forwardBinary)
	workDir := filepath.Join(runtimeDir, "work-xdp-lateral")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	webPort := freeTCPPort(t)
	configPath := filepath.Join(workDir, "config.json")
	writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
		Name:         "xdp-egress-nat-lateral",
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineXDP, kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: egressNATExpectedXDPKernel,
		Experimental: map[string]bool{experimentalFeatureXDPGeneric: true},
	}, webPort)
	logPath := filepath.Join(workDir, "forward.log")
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

	lateral := []lateralPath{
		{"A_to_C", top.ClientNS, nsC, addrC, egressNATClientAddr, []string{"tcp", "udp"}},
		{"C_to_A", nsC, top.ClientNS, egressNATClientAddr, addrC, []string{"tcp", "udp"}},
	}
	runLateralPaths(t, "baseline", lateral)

	createEgressNATIntegrationEntryForScopeWithProtocol(t, apiBase, top, "", "tcp+udp")
	postLateralEgressNAT(t, apiBase, `{"parent_interface":"`+hostC+`","out_interface":"`+top.UplinkHostIF+`","out_source_ip":"`+egressNATUplinkAddr+`","protocol":"tcp+udp"}`)
	waitForLateralEgressNATs(t, apiBase, logPath, 2, kernelEngineXDP)

	runLateralPaths(t, "veer", []lateralPath{
		{"A_to_uplink_network", top.ClientNS, top.BackendNS, egressNATBackendAddr, egressNATUplinkAddr, []string{"tcp", "udp"}},
	})
	runLateralPaths(t, "veer", lateral)
	if t.Failed() {
		logKernelRuntimeOnFailure(t, apiBase)
		logForwardLogOnFailure(t, logPath)
	}
}

type lateralPath struct {
	name, fromNS, toNS, toAddr, wantSrc string
	protos                              []string
}

func cleanupLateralLinks(t *testing.T, links []string, namespaces []string) {
	t.Helper()
	cleanup := func() {
		for _, link := range links {
			runDataplanePerfCmd("ip", "link", "del", link)
		}
		for _, ns := range namespaces {
			runDataplanePerfCmd("ip", "netns", "del", ns)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
}

// addLateralGuest puts a guest in namespace ns behind a veth whose host end
// joins master (when given) and routes everything by gw.
func addLateralGuest(t *testing.T, ns, host, peer, master, addr, gw string) {
	t.Helper()
	ip := func(args ...string) { mustRunDataplanePerfCmd(t, "ip", args...) }
	ip("netns", "add", ns)
	ip("link", "add", host, "type", "veth", "peer", "name", peer)
	if master != "" {
		ip("link", "set", host, "master", master)
	}
	ip("link", "set", host, "up")
	ip("link", "set", peer, "netns", ns)
	ip("-n", ns, "link", "set", "lo", "up")
	ip("-n", ns, "addr", "add", addr+"/24", "dev", peer)
	ip("-n", ns, "link", "set", peer, "up")
	ip("-n", ns, "route", "replace", "default", "via", gw, "dev", peer)
}

// runLateralPaths sends each protocol of each path and checks the source
// address the far end saw; it reports every failure, not just the first.
func runLateralPaths(t *testing.T, phase string, paths []lateralPath) {
	t.Helper()
	for _, path := range paths {
		for _, proto := range path.protos {
			got, err := probeLateralPath(t, path.fromNS, path.toNS, proto, path.toAddr)
			switch {
			case err != nil:
				t.Errorf("%s %s %s: no answer: %v", phase, path.name, proto, err)
			case got != path.wantSrc:
				t.Errorf("%s %s %s: peer saw source %s, want %s", phase, path.name, proto, got, path.wantSrc)
			default:
				t.Logf("%s %s %s: ok, peer saw %s", phase, path.name, proto, got)
			}
		}
	}
}

func probeLateralPath(t *testing.T, fromNS, toNS, proto, toAddr string) (string, error) {
	t.Helper()
	target := toAddr
	if proto != "icmp" {
		target = net.JoinHostPort(toAddr, strconv.Itoa(egressNATProbePort))
	}
	observed := filepath.Join(t.TempDir(), "observed")
	backend, logs := startEgressNATBackendHelperInNamespace(t, toNS, proto, target, observed)
	defer func() {
		if backend.ProcessState == nil {
			stopDataplanePerfHelper(t, backend)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, "ip", "netns", "exec", fromNS, os.Args[0], "-test.run", "TestEgressNATIntegrationHelperProcess", "-test.v=false")
	client.Env = append(os.Environ(),
		egressNATHelperEnv+"=1",
		egressNATHelperRoleEnv+"="+egressNATHelperRoleClient,
		egressNATHelperProtocolEnv+"="+proto,
		egressNATHelperTargetAddrEnv+"="+target,
	)
	if out, err := client.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w: %s %s", err, strings.TrimSpace(string(out)), strings.TrimSpace(logs.String()))
	}
	waitForEgressNATHelperExit(t, backend, proto, logs.String())
	data, err := os.ReadFile(observed)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func waitForLateralEgressNATs(t *testing.T, apiBase, logPath string, want int, kernelEngine string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		statuses := listEgressNATIntegrationStatuses(t, apiBase)
		running := 0
		for _, s := range statuses {
			if s.Status == "running" && s.EffectiveEngine == ruleEngineKernel && s.EffectiveKernelEngine == kernelEngine {
				running++
			}
		}
		if running == want {
			return
		}
		if time.Now().After(deadline) {
			logForwardLogOnFailure(t, logPath)
			t.Fatalf("want %d egress NATs running on %s, have %+v", want, kernelEngine, statuses)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func postLateralEgressNAT(t *testing.T, apiBase, payload string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/egress-nats", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+egressNATTestToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create egress nat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create egress nat %s: status %d", payload, resp.StatusCode)
	}
}
