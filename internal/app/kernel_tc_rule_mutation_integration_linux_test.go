//go:build linux

package app

import (
	"bufio"
	"bytes"
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
//      FORWARD_RUN_TC_RULE_MUTATION_TEST=1 go test ./internal/app -run TestTCKernelRuleMutationEstablishedTCPConnection -count=1 -v

const (
	tcRuleMutationIntegrationEnableEnv      = "FORWARD_RUN_TC_RULE_MUTATION_TEST"
	tcRuleMutationHelperEnv                 = "FORWARD_TC_RULE_MUTATION_HELPER"
	tcRuleMutationHelperTargetEnv           = "FORWARD_TC_RULE_MUTATION_TARGET_ADDR"
	tcRuleMutationHelperDurationMsEnv       = "FORWARD_TC_RULE_MUTATION_DURATION_MS"
	tcRuleMutationHelperReadyLine           = "READY"
	tcRuleMutationProbePayloadBytes         = 1024
	tcRuleMutationProbeChunkBytes           = 512
	tcRuleMutationProbeDeadlineMs           = 3000
	tcRuleMutationProbeIdleMs               = 1000
	tcRuleMutationSteadyDuration            = 4 * time.Second
	tcRuleMutationRestartSteadyDuration     = 8 * time.Second
	tcRuleMutationSteadyStepDeadline        = 1500 * time.Millisecond
	tcRuleMutationSteadyPayload             = "forward-tc-rule-mutation"
	tcRuleMutationExtraRuleFrontPortOffset  = 17
	tcRuleMutationExtraRuleBackendPortDelta = 17
	tcRuleMutationBrokenBackendPortDelta    = 1
)

type tcRuleMutationHarness struct {
	Topology             dataplanePerfTopology
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

type tcRuleMutationSteadyClient struct {
	cmd      *exec.Cmd
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	readyCh  chan error
	scanDone chan struct{}
}

func TestTCKernelRuleMutationIntegrationHelperProcess(t *testing.T) {
	if os.Getenv(tcRuleMutationHelperEnv) != "1" {
		return
	}

	if err := runTCRuleMutationSteadyClientHelper(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestTCKernelRuleMutationEstablishedTCPConnection(t *testing.T) {
	baseBinary := requireTCRuleMutationIntegrationBinary(t)

	cases := []struct {
		name             string
		mutate           func(t *testing.T, harness tcRuleMutationHarness, rule RuleStatus)
		expectClientFail bool
		expectProbeFail  bool
	}{
		{
			name: "add_unrelated_rule_keeps_connection",
			mutate: func(t *testing.T, harness tcRuleMutationHarness, rule RuleStatus) {
				createTCRuleMutationRule(t, harness.APIBase, harness.Topology, Rule{
					InInterface:      harness.Topology.ClientHostIF,
					InIP:             dataplanePerfFrontAddr,
					InPort:           dataplanePerfFrontPort + tcRuleMutationExtraRuleFrontPortOffset,
					OutInterface:     harness.Topology.BackendHostIF,
					OutIP:            dataplanePerfBackendAddr,
					OutPort:          dataplanePerfBackendPort + tcRuleMutationExtraRuleBackendPortDelta,
					Protocol:         "tcp",
					Remark:           "tc-rule-mutation-extra",
					Tag:              "tc-rule-mutation",
					Transparent:      true,
					EnginePreference: ruleEngineKernel,
				})
			},
		},
		{
			name: "metadata_update_keeps_connection",
			mutate: func(t *testing.T, harness tcRuleMutationHarness, rule RuleStatus) {
				updated := rule.Rule
				updated.Remark = rule.Remark + "-updated"
				updated.Tag = "tc-rule-mutation-updated"
				updateTCRuleMutationRule(t, harness.APIBase, updated)
			},
		},
		{
			name: "backend_port_update_breaks_connection",
			mutate: func(t *testing.T, harness tcRuleMutationHarness, rule RuleStatus) {
				updated := rule.Rule
				updated.OutPort = dataplanePerfBackendPort + tcRuleMutationBrokenBackendPortDelta
				updateTCRuleMutationRule(t, harness.APIBase, updated)
			},
			expectClientFail: true,
			expectProbeFail:  true,
		},
		{
			name: "delete_rule_breaks_connection",
			mutate: func(t *testing.T, harness tcRuleMutationHarness, rule RuleStatus) {
				deleteTCRuleMutationRule(t, harness.APIBase, rule.ID)
				waitForTCRuleMutationRuleAbsent(t, harness.APIBase, rule.ID)
			},
			expectClientFail: true,
			expectProbeFail:  true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := startTCRuleMutationHarness(t, baseBinary, tc.name)
			rule := createTCRuleMutationRule(t, harness.APIBase, harness.Topology, Rule{
				InInterface:      harness.Topology.ClientHostIF,
				InIP:             dataplanePerfFrontAddr,
				InPort:           dataplanePerfFrontPort,
				OutInterface:     harness.Topology.BackendHostIF,
				OutIP:            dataplanePerfBackendAddr,
				OutPort:          dataplanePerfBackendPort,
				Protocol:         "tcp",
				Remark:           "tc-rule-mutation-primary",
				Tag:              "tc-rule-mutation",
				Transparent:      true,
				EnginePreference: ruleEngineKernel,
			})

			if err := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))); err != nil {
				logKernelRuntimeOnFailure(t, harness.APIBase)
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("baseline probe failed: %v", err)
			}

			client := startTCRuleMutationSteadyClient(t, harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort)))
			waitForTCRuleMutationSteadyClientReady(t, client)

			tc.mutate(t, harness, rule)

			stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
			if tc.expectClientFail {
				if err == nil {
					logKernelRuntimeOnFailure(t, harness.APIBase)
					logForwardLogOnFailure(t, harness.LogPath)
					t.Fatalf("steady client unexpectedly survived mutation\nstdout=%s\nstderr=%s", stdout, stderr)
				}
			} else if err != nil {
				logKernelRuntimeOnFailure(t, harness.APIBase)
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("steady client failed unexpectedly: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
			}

			probeErr := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort)))
			if tc.expectProbeFail {
				if probeErr == nil {
					logKernelRuntimeOnFailure(t, harness.APIBase)
					logForwardLogOnFailure(t, harness.LogPath)
					t.Fatal("probe unexpectedly succeeded after breaking mutation")
				}
			} else if probeErr != nil {
				logKernelRuntimeOnFailure(t, harness.APIBase)
				logForwardLogOnFailure(t, harness.LogPath)
				t.Fatalf("probe failed unexpectedly after non-breaking mutation: %v", probeErr)
			}
		})
	}
}

func TestTCKernelRuleMutationHotRestartKeepsEstablishedTCPConnection(t *testing.T) {
	baseBinary := requireTCRuleMutationIntegrationBinary(t)

	harness := startTCRuleMutationHarness(t, baseBinary, "hot-restart-established")
	rule := createTCRuleMutationRule(t, harness.APIBase, harness.Topology, Rule{
		InInterface:      harness.Topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     harness.Topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Remark:           "tc-rule-mutation-hot-restart",
		Tag:              "tc-rule-mutation",
		Transparent:      true,
		EnginePreference: ruleEngineKernel,
	})

	if err := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))); err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("baseline probe failed: %v", err)
	}

	client := startTCRuleMutationSteadyClientWithDuration(
		t,
		harness.Topology.ClientNS,
		net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort)),
		tcRuleMutationRestartSteadyDuration,
	)
	waitForTCRuleMutationSteadyClientReady(t, client)

	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		stopTCRuleMutationSteadyClient(t, client)
		t.Fatalf("write hot restart marker: %v", err)
	}

	restartTCRuleMutationForward(t, &harness)
	waitForTCRuleMutationRuleRunning(t, harness.APIBase, rule.ID)

	stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
	if err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("steady client failed across hot restart: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	if err := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))); err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("post-restart probe failed: %v", err)
	}
}

func TestTCKernelRuleMutationHotRestartKeepsEstablishedFullNATTCPConnection(t *testing.T) {
	baseBinary := requireTCRuleMutationIntegrationBinary(t)

	harness := startTCRuleMutationHarness(t, baseBinary, "hot-restart-fullnat")
	rule := createTCRuleMutationRule(t, harness.APIBase, harness.Topology, Rule{
		InInterface:      harness.Topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     harness.Topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Remark:           "tc-rule-mutation-hot-restart-fullnat",
		Tag:              "tc-rule-mutation",
		Transparent:      false,
		EnginePreference: ruleEngineKernel,
	})

	if err := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))); err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("baseline probe failed: %v", err)
	}

	client := startTCRuleMutationSteadyClientWithDuration(
		t,
		harness.Topology.ClientNS,
		net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort)),
		tcRuleMutationRestartSteadyDuration,
	)
	waitForTCRuleMutationSteadyClientReady(t, client)

	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		stopTCRuleMutationSteadyClient(t, client)
		t.Fatalf("write hot restart marker: %v", err)
	}

	restartTCRuleMutationForward(t, &harness)
	waitForTCRuleMutationRuleRunning(t, harness.APIBase, rule.ID)
	postRestartProbeErr := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort)))

	stdout, stderr, err := waitForTCRuleMutationSteadyClient(client)
	if err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("steady client failed across fullnat hot restart: %v\npost_restart_probe_err=%v\nstdout=%s\nstderr=%s", err, postRestartProbeErr, stdout, stderr)
	}

	if postRestartProbeErr != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("post-restart probe failed: %v", postRestartProbeErr)
	}
	if err := runTCRuleMutationProbe(harness.Topology.ClientNS, net.JoinHostPort(dataplanePerfFrontAddr, strconv.Itoa(rule.InPort))); err != nil {
		logKernelRuntimeOnFailure(t, harness.APIBase)
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("post-restart probe failed: %v", err)
	}
}

func runTCRuleMutationSteadyClientHelper() error {
	target := strings.TrimSpace(os.Getenv(tcRuleMutationHelperTargetEnv))
	if target == "" {
		return errors.New("missing steady client target")
	}

	durationMs := envInt(tcRuleMutationHelperDurationMsEnv, int(tcRuleMutationSteadyDuration/time.Millisecond))
	if durationMs <= 0 {
		durationMs = int(tcRuleMutationSteadyDuration / time.Millisecond)
	}

	conn, err := net.DialTimeout("tcp4", target, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		configureDataplanePerfTCPConn(tcpConn)
	}

	payload := []byte(tcRuleMutationSteadyPayload)
	reply := make([]byte, len(payload))
	deadline := time.Now().Add(time.Duration(durationMs) * time.Millisecond)
	totalBytes := 0

	exchange := func() error {
		if err := conn.SetDeadline(time.Now().Add(tcRuleMutationSteadyStepDeadline)); err != nil {
			return fmt.Errorf("%s set deadline: %w", time.Now().Format(time.RFC3339Nano), err)
		}
		if err := writeAll(conn, payload); err != nil {
			return fmt.Errorf("%s write: %w", time.Now().Format(time.RFC3339Nano), err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return fmt.Errorf("%s read: %w", time.Now().Format(time.RFC3339Nano), err)
		}
		if !bytes.Equal(reply, payload) {
			return fmt.Errorf("%s echo payload mismatch: got %q want %q", time.Now().Format(time.RFC3339Nano), string(reply), string(payload))
		}
		totalBytes += len(payload)
		return nil
	}

	if err := exchange(); err != nil {
		return err
	}
	fmt.Println(tcRuleMutationHelperReadyLine)

	for time.Now().Before(deadline) {
		if err := exchange(); err != nil {
			return err
		}
	}

	fmt.Printf("DONE payload_bytes=%d elapsed_ms=%d\n", totalBytes, (time.Duration(durationMs) * time.Millisecond).Milliseconds())
	return nil
}

func requireTCRuleMutationIntegrationBinary(t *testing.T) string {
	t.Helper()

	if os.Getenv(tcRuleMutationIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux tc rule mutation integration test", tcRuleMutationIntegrationEnableEnv)
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

func startTCRuleMutationHarness(t *testing.T, baseBinary string, name string) tcRuleMutationHarness {
	t.Helper()

	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	backendCmd, backendLogs := startDataplanePerfBackend(t, topology)
	t.Cleanup(func() {
		stopDataplanePerfHelper(t, backendCmd)
	})

	runtimeDir := makeShortTCRuleMutationDir(t)
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
		Name:         "tc-rule-mutation-" + name,
		Default:      ruleEngineKernel,
		Order:        []string{kernelEngineTC},
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineTC,
	}, webPort)

	logPath := filepath.Join(workDir, "forward-tc-rule-mutation-"+name+".log")
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
	waitForDataplanePerfAPI(t, apiBase)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("backend helper logs:\n%s", backendLogs.String())
			logKernelRuntimeOnFailure(t, apiBase)
			logForwardLogOnFailure(t, logPath)
		}
	})
	return tcRuleMutationHarness{
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

func createTCRuleMutationRule(t *testing.T, apiBase string, topology dataplanePerfTopology, rule Rule) RuleStatus {
	t.Helper()

	if strings.TrimSpace(rule.InIP) == "" {
		rule.InIP = dataplanePerfFrontAddr
	}
	if strings.TrimSpace(rule.OutIP) == "" {
		rule.OutIP = dataplanePerfBackendAddr
	}
	if strings.TrimSpace(rule.InInterface) == "" {
		rule.InInterface = topology.ClientHostIF
	}
	if strings.TrimSpace(rule.OutInterface) == "" {
		rule.OutInterface = topology.BackendHostIF
	}
	if strings.TrimSpace(rule.Protocol) == "" {
		rule.Protocol = "tcp"
	}
	if strings.TrimSpace(rule.EnginePreference) == "" {
		rule.EnginePreference = ruleEngineKernel
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
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
	status := waitForTCRuleMutationRuleRunning(t, apiBase, created.ID)
	waitForDataplanePerfModeSettle(t, apiBase, dataplanePerfMode{
		Name:         "tc-rule-mutation",
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineTC,
	})
	return status
}

func updateTCRuleMutationRule(t *testing.T, apiBase string, rule Rule) RuleStatus {
	t.Helper()

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal updated rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build update rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dataplanePerfToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update rule %d: %v", rule.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("update rule %d unexpected status %d: %s", rule.ID, resp.StatusCode, string(body))
	}

	status := waitForTCRuleMutationRuleRunning(t, apiBase, rule.ID)
	waitForDataplanePerfModeSettle(t, apiBase, dataplanePerfMode{
		Name:         "tc-rule-mutation",
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineTC,
	})
	return status
}

func deleteTCRuleMutationRule(t *testing.T, apiBase string, id int64) {
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

func listTCRuleMutationRules(t *testing.T, apiBase string) []RuleStatus {
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

func waitForTCRuleMutationRuleRunning(t *testing.T, apiBase string, id int64) RuleStatus {
	t.Helper()

	mode := dataplanePerfMode{
		Name:         "tc-rule-mutation",
		Expected:     ruleEngineKernel,
		ExpectedKern: kernelEngineTC,
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, rule := range listTCRuleMutationRules(t, apiBase) {
			if rule.ID != id {
				continue
			}
			if rule.Status != "running" {
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
			if rule.EffectiveKernelEngine != mode.ExpectedKern {
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

func waitForTCRuleMutationRuleAbsent(t *testing.T, apiBase string, id int64) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, rule := range listTCRuleMutationRules(t, apiBase) {
			if rule.ID == id {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("rule %d still present after delete", id)
}

func startTCRuleMutationSteadyClient(t *testing.T, clientNS string, targetAddr string) *tcRuleMutationSteadyClient {
	return startTCRuleMutationSteadyClientWithDuration(t, clientNS, targetAddr, tcRuleMutationSteadyDuration)
}

func startTCRuleMutationSteadyClientWithDuration(t *testing.T, clientNS string, targetAddr string, duration time.Duration) *tcRuleMutationSteadyClient {
	t.Helper()

	client := &tcRuleMutationSteadyClient{
		readyCh:  make(chan error, 1),
		scanDone: make(chan struct{}),
	}

	cmd := exec.Command("ip", "netns", "exec", clientNS, os.Args[0], "-test.run", "TestTCKernelRuleMutationIntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		tcRuleMutationHelperEnv+"=1",
		tcRuleMutationHelperTargetEnv+"="+targetAddr,
		tcRuleMutationHelperDurationMsEnv+"="+strconv.Itoa(int(duration/time.Millisecond)),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("steady client stdout pipe: %v", err)
	}
	cmd.Stderr = &client.stderr
	client.cmd = cmd

	if err := client.cmd.Start(); err != nil {
		t.Fatalf("start steady client: %v", err)
	}

	go func() {
		defer close(client.scanDone)

		readySent := false
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			client.stdout.WriteString(line)
			client.stdout.WriteByte('\n')
			if line == tcRuleMutationHelperReadyLine && !readySent {
				client.readyCh <- nil
				readySent = true
			}
		}
		if readySent {
			return
		}
		if err := scanner.Err(); err != nil {
			client.readyCh <- err
			return
		}
		client.readyCh <- errors.New("steady client exited before ready")
	}()

	return client
}

func restartTCRuleMutationForward(t *testing.T, harness *tcRuleMutationHarness) {
	t.Helper()

	if harness == nil {
		t.Fatal("tc rule mutation harness is nil")
	}

	stopForwardProcessTree(t, harness.Cmd)
	if delayMs := envInt("FORWARD_HOT_RESTART_DELAY_MS", 0); delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	logFile, err := os.OpenFile(harness.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open forward log file for restart: %v", err)
	}

	cmd := exec.Command(harness.ForwardBinary, "--config", harness.ConfigPath)
	cmd.Dir = harness.WorkDir
	cmd.Env = append(os.Environ(),
		forwardKernelMaintenanceIntervalEnv+"="+strconv.Itoa(envInt(forwardKernelMaintenanceIntervalEnv, 600000)),
		forwardHotRestartMarkerEnv+"="+harness.HotRestartMarkerPath,
		forwardBPFStateDirEnv+"="+harness.BPFStateRoot,
		forwardRuntimeStateDirEnv+"="+harness.RuntimeStateRoot,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("restart forward: %v", err)
	}
	_ = logFile.Close()

	harness.Cmd = cmd
	t.Cleanup(func() {
		stopForwardProcessTree(t, cmd)
	})
	waitForDataplanePerfAPI(t, harness.APIBase)
}

func waitForTCRuleMutationSteadyClientReady(t *testing.T, client *tcRuleMutationSteadyClient) {
	t.Helper()

	select {
	case err := <-client.readyCh:
		if err != nil {
			stopTCRuleMutationSteadyClient(t, client)
			t.Fatalf("steady client ready failed: %v\nstderr=%s", err, client.stderr.String())
		}
	case <-time.After(10 * time.Second):
		stopTCRuleMutationSteadyClient(t, client)
		t.Fatalf("steady client ready timeout\nstderr=%s", client.stderr.String())
	}
}

func waitForTCRuleMutationSteadyClient(client *tcRuleMutationSteadyClient) (string, string, error) {
	if client == nil || client.cmd == nil {
		return "", "", nil
	}
	err := client.cmd.Wait()
	<-client.scanDone
	return client.stdout.String(), client.stderr.String(), err
}

func stopTCRuleMutationSteadyClient(t *testing.T, client *tcRuleMutationSteadyClient) {
	t.Helper()

	if client == nil || client.cmd == nil || client.cmd.Process == nil {
		return
	}
	if client.cmd.ProcessState != nil && client.cmd.ProcessState.Exited() {
		return
	}
	_ = client.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- client.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = client.cmd.Process.Kill()
		<-done
	}
	<-client.scanDone
}

func runTCRuleMutationProbe(clientNS string, targetAddr string) error {
	cmd := exec.Command("ip", "netns", "exec", clientNS, os.Args[0], "-test.run", "TestDataplanePerfHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		dataplanePerfHelperEnv+"=1",
		dataplanePerfHelperRoleEnv+"=client",
		dataplanePerfTargetEnv+"="+targetAddr,
		dataplanePerfConnEnv+"=1",
		dataplanePerfConcurrencyEnv+"=1",
		dataplanePerfBytesEnv+"="+strconv.Itoa(tcRuleMutationProbePayloadBytes),
		dataplanePerfIOChunkEnv+"="+strconv.Itoa(tcRuleMutationProbeChunkBytes),
		dataplanePerfDeadlineEnv+"="+strconv.Itoa(tcRuleMutationProbeDeadlineMs),
		dataplanePerfIdleEnv+"="+strconv.Itoa(tcRuleMutationProbeIdleMs),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(stderr.String()))
	}

	var result dataplanePerfClientResult
	if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
		return fmt.Errorf("decode probe output: %w\nstdout=%s\nstderr=%s", err, string(output), stderr.String())
	}
	if result.PayloadBytes <= 0 {
		return errors.New("probe completed without payload")
	}
	return nil
}

func makeShortTCRuleMutationDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fwtcmut-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
