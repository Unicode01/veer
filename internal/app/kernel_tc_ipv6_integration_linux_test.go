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
//      FORWARD_RUN_TC_IPV6_TEST=1 go test ./internal/app -run 'TestTCKernelIPv6(Integration|RangeIntegration)' -count=1 -v

const (
	tcIPv6IntegrationEnableEnv        = "FORWARD_RUN_TC_IPV6_TEST"
	tcIPv6IntegrationHelperEnv        = "FORWARD_TC_IPV6_HELPER"
	tcIPv6IntegrationHelperRoleEnv    = "FORWARD_TC_IPV6_HELPER_ROLE"
	tcIPv6IntegrationHelperProtoEnv   = "FORWARD_TC_IPV6_PROTOCOL"
	tcIPv6IntegrationHelperListenEnv  = "FORWARD_TC_IPV6_LISTEN_ADDR"
	tcIPv6IntegrationHelperTargetEnv  = "FORWARD_TC_IPV6_TARGET_ADDR"
	tcIPv6IntegrationToken            = dataplanePerfToken
	tcIPv6IntegrationReadyLine        = "READY"
	tcIPv6IntegrationFrontAddr        = "2001:db8:1::1"
	tcIPv6IntegrationClientAddr       = "2001:db8:1::2"
	tcIPv6IntegrationBackendHost      = "2001:db8:2::1"
	tcIPv6IntegrationBackendAddr      = "2001:db8:2::2"
	tcIPv6IntegrationFrontPort        = 16000
	tcIPv6IntegrationBackendPort      = 26000
	tcIPv6IntegrationRangeFrontPort   = 16010
	tcIPv6IntegrationRangeBackendPort = 26010
)

var tcIPv6IntegrationPayload = []byte("forward-tc-ipv6")

func TestTCKernelIPv6IntegrationHelperProcess(t *testing.T) {
	if os.Getenv(tcIPv6IntegrationHelperEnv) != "1" {
		return
	}

	var err error
	switch strings.TrimSpace(os.Getenv(tcIPv6IntegrationHelperRoleEnv)) {
	case "backend":
		err = runTCIPv6IntegrationBackendHelper()
	case "client":
		err = runTCIPv6IntegrationClientHelper()
	default:
		err = fmt.Errorf("unknown tc ipv6 helper role %q", os.Getenv(tcIPv6IntegrationHelperRoleEnv))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestTCKernelIPv6Integration(t *testing.T) {
	if os.Getenv(tcIPv6IntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux tc IPv6 integration test", tcIPv6IntegrationEnableEnv)
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
			topology := setupDataplanePerfTopology(t)
			seedDataplanePerfNeighbors(t, topology)
			seedTCIPv6IntegrationNeighbors(t, topology)

			runtimeDir := makeShortTCIPv6IntegrationDir(t)
			forwardBinary := filepath.Join(runtimeDir, "forward")
			copyFile(t, baseBinary, forwardBinary)

			workDir := filepath.Join(runtimeDir, "work-"+tc.proto)
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatalf("create work dir: %v", err)
			}
			webPort := freeTCPPort(t)
			configPath := filepath.Join(workDir, "config.json")
			writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
				Name:         "tc-ipv6-" + tc.proto,
				Default:      ruleEngineKernel,
				Order:        []string{kernelEngineTC},
				Expected:     ruleEngineKernel,
				ExpectedKern: kernelEngineTC,
			}, webPort)

			logPath := filepath.Join(workDir, "forward-tc-ipv6-"+tc.proto+".log")
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
			waitForTCIPv6IntegrationAPI(t, apiBase, cmd, logPath)
			createTCIPv6IntegrationRule(t, apiBase, topology, tc.proto)
			waitForDataplanePerfRule(t, apiBase, dataplanePerfMode{
				Name:         "tc-ipv6-" + tc.proto,
				Expected:     ruleEngineKernel,
				ExpectedKern: kernelEngineTC,
			})

			if err := runTCIPv6IntegrationProbePorts(t, topology, tc.proto, tcIPv6IntegrationFrontPort, tcIPv6IntegrationBackendPort); err != nil {
				logForwardLogOnFailure(t, logPath)
				t.Fatal(err)
			}
		})
	}
}

func TestTCKernelIPv6RangeIntegration(t *testing.T) {
	if os.Getenv(tcIPv6IntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux tc IPv6 range integration test", tcIPv6IntegrationEnableEnv)
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
			topology := setupDataplanePerfTopology(t)
			seedDataplanePerfNeighbors(t, topology)
			seedTCIPv6IntegrationNeighbors(t, topology)

			runtimeDir := makeShortTCIPv6IntegrationDir(t)
			forwardBinary := filepath.Join(runtimeDir, "forward")
			copyFile(t, baseBinary, forwardBinary)

			workDir := filepath.Join(runtimeDir, "work-range-"+tc.proto)
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatalf("create work dir: %v", err)
			}
			webPort := freeTCPPort(t)
			configPath := filepath.Join(workDir, "config.json")
			writeDataplanePerfConfig(t, configPath, dataplanePerfMode{
				Name:         "tc-ipv6-range-" + tc.proto,
				Default:      ruleEngineKernel,
				Order:        []string{kernelEngineTC},
				Expected:     ruleEngineKernel,
				ExpectedKern: kernelEngineTC,
			}, webPort)

			logPath := filepath.Join(workDir, "forward-tc-ipv6-range-"+tc.proto+".log")
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
			waitForTCIPv6IntegrationAPI(t, apiBase, cmd, logPath)
			createTCIPv6IntegrationRange(t, apiBase, topology, tc.proto)
			waitForTCIPv6IntegrationRange(t, apiBase, tc.proto)

			if err := runTCIPv6IntegrationProbePorts(t, topology, tc.proto, tcIPv6IntegrationRangeFrontPort, tcIPv6IntegrationRangeBackendPort); err != nil {
				logForwardLogOnFailure(t, logPath)
				t.Fatal(err)
			}
		})
	}
}

func runTCIPv6IntegrationBackendHelper() error {
	proto := strings.ToLower(strings.TrimSpace(os.Getenv(tcIPv6IntegrationHelperProtoEnv)))
	listenAddr := strings.TrimSpace(os.Getenv(tcIPv6IntegrationHelperListenEnv))
	if listenAddr == "" {
		return errors.New("missing backend listen address")
	}

	switch proto {
	case "udp":
		pc, err := net.ListenPacket("udp6", listenAddr)
		if err != nil {
			return err
		}
		defer pc.Close()

		fmt.Println(tcIPv6IntegrationReadyLine)
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, len(tcIPv6IntegrationPayload))
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], tcIPv6IntegrationPayload) {
			return fmt.Errorf("udp backend payload mismatch: got %q want %q", string(buf[:n]), string(tcIPv6IntegrationPayload))
		}
		_, err = pc.WriteTo(buf[:n], peer)
		return err
	default:
		ln, err := net.Listen("tcp6", listenAddr)
		if err != nil {
			return err
		}
		defer ln.Close()

		fmt.Println(tcIPv6IntegrationReadyLine)
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, len(tcIPv6IntegrationPayload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if !bytes.Equal(buf, tcIPv6IntegrationPayload) {
			return fmt.Errorf("tcp backend payload mismatch: got %q want %q", string(buf), string(tcIPv6IntegrationPayload))
		}
		return writeAll(conn, buf)
	}
}

func runTCIPv6IntegrationClientHelper() error {
	proto := strings.ToLower(strings.TrimSpace(os.Getenv(tcIPv6IntegrationHelperProtoEnv)))
	targetAddr := strings.TrimSpace(os.Getenv(tcIPv6IntegrationHelperTargetEnv))
	if targetAddr == "" {
		return errors.New("missing client target address")
	}

	switch proto {
	case "udp":
		conn, err := net.DialTimeout("udp6", targetAddr, 5*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := writeAll(conn, tcIPv6IntegrationPayload); err != nil {
			return err
		}
		buf := make([]byte, len(tcIPv6IntegrationPayload))
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:n], tcIPv6IntegrationPayload) {
			return fmt.Errorf("udp client payload mismatch: got %q want %q", string(buf[:n]), string(tcIPv6IntegrationPayload))
		}
		return nil
	default:
		conn, err := net.DialTimeout("tcp6", targetAddr, 5*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := writeAll(conn, tcIPv6IntegrationPayload); err != nil {
			return err
		}
		buf := make([]byte, len(tcIPv6IntegrationPayload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if !bytes.Equal(buf, tcIPv6IntegrationPayload) {
			return fmt.Errorf("tcp client payload mismatch: got %q want %q", string(buf), string(tcIPv6IntegrationPayload))
		}
		return nil
	}
}

func createTCIPv6IntegrationRule(t *testing.T, apiBase string, topology dataplanePerfTopology, proto string) {
	t.Helper()

	payload := map[string]any{
		"in_interface":      topology.ClientHostIF,
		"in_ip":             tcIPv6IntegrationFrontAddr,
		"in_port":           tcIPv6IntegrationFrontPort,
		"out_interface":     topology.BackendHostIF,
		"out_ip":            tcIPv6IntegrationBackendAddr,
		"out_source_ip":     tcIPv6IntegrationBackendHost,
		"out_port":          tcIPv6IntegrationBackendPort,
		"protocol":          proto,
		"transparent":       false,
		"engine_preference": ruleEngineKernel,
		"remark":            "tc-ipv6-integration-" + proto,
		"tag":               "ipv6",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal IPv6 rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create IPv6 rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tcIPv6IntegrationToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create IPv6 rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create IPv6 rule unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func createTCIPv6IntegrationRange(t *testing.T, apiBase string, topology dataplanePerfTopology, proto string) {
	t.Helper()

	payload := map[string]any{
		"in_interface":   topology.ClientHostIF,
		"in_ip":          tcIPv6IntegrationFrontAddr,
		"start_port":     tcIPv6IntegrationRangeFrontPort,
		"end_port":       tcIPv6IntegrationRangeFrontPort,
		"out_interface":  topology.BackendHostIF,
		"out_ip":         tcIPv6IntegrationBackendAddr,
		"out_source_ip":  tcIPv6IntegrationBackendHost,
		"out_start_port": tcIPv6IntegrationRangeBackendPort,
		"protocol":       proto,
		"transparent":    false,
		"remark":         "tc-ipv6-range-integration-" + proto,
		"tag":            "ipv6",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal IPv6 range: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/ranges", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create IPv6 range request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tcIPv6IntegrationToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create IPv6 range: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create IPv6 range unexpected status %d: %s", resp.StatusCode, string(body))
	}
}

func waitForTCIPv6IntegrationRange(t *testing.T, apiBase string, proto string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, apiBase+"/api/ranges", nil)
		if err != nil {
			t.Fatalf("build list IPv6 ranges request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tcIPv6IntegrationToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		var items []PortRangeStatus
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil || len(items) == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		item := items[0]
		if item.InIP != tcIPv6IntegrationFrontAddr || item.OutIP != tcIPv6IntegrationBackendAddr || item.Protocol != proto {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if item.StartPort != tcIPv6IntegrationRangeFrontPort || item.EndPort != tcIPv6IntegrationRangeFrontPort || item.OutStartPort != tcIPv6IntegrationRangeBackendPort {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if item.Status != "running" {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if item.EffectiveEngine != ruleEngineKernel {
			t.Fatalf("IPv6 range effective engine = %q, want %q (kernel_reason=%q fallback=%q)", item.EffectiveEngine, ruleEngineKernel, item.KernelReason, item.FallbackReason)
		}
		if item.EffectiveKernelEngine != kernelEngineTC {
			t.Fatalf("IPv6 range kernel engine = %q, want %q (kernel_reason=%q fallback=%q)", item.EffectiveKernelEngine, kernelEngineTC, item.KernelReason, item.FallbackReason)
		}
		if item.OutSourceIP != tcIPv6IntegrationBackendHost {
			t.Fatalf("IPv6 range out_source_ip = %q, want %q", item.OutSourceIP, tcIPv6IntegrationBackendHost)
		}
		return
	}
	t.Fatalf("IPv6 range %s did not enter running/%s state in time", proto, ruleEngineKernel)
}

func runTCIPv6IntegrationProbePorts(t *testing.T, topology dataplanePerfTopology, proto string, frontPort int, backendPort int) error {
	t.Helper()

	backendCmd, backendLogs := startTCIPv6IntegrationBackendHelper(t, topology, proto, backendPort)
	defer stopDataplanePerfHelper(t, backendCmd)

	cmd := exec.Command("ip", "netns", "exec", topology.ClientNS, os.Args[0], "-test.run", "TestTCKernelIPv6IntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		tcIPv6IntegrationHelperEnv+"=1",
		tcIPv6IntegrationHelperRoleEnv+"=client",
		tcIPv6IntegrationHelperProtoEnv+"="+proto,
		tcIPv6IntegrationHelperTargetEnv+"="+net.JoinHostPort(tcIPv6IntegrationFrontAddr, strconv.Itoa(frontPort)),
	)
	var stderr bytes.Buffer
	output, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			text = strings.TrimSpace(stderr.String())
		}
		return fmt.Errorf("%s client helper failed: %w\nclient output:\n%s\n\nbackend logs:\n%s", proto, err, text, backendLogs.String())
	}
	return nil
}

func startTCIPv6IntegrationBackendHelper(t *testing.T, topology dataplanePerfTopology, proto string, backendPort int) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()

	cmd := exec.Command("ip", "netns", "exec", topology.BackendNS, os.Args[0], "-test.run", "TestTCKernelIPv6IntegrationHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(),
		tcIPv6IntegrationHelperEnv+"=1",
		tcIPv6IntegrationHelperRoleEnv+"=backend",
		tcIPv6IntegrationHelperProtoEnv+"="+proto,
		tcIPv6IntegrationHelperListenEnv+"="+net.JoinHostPort(tcIPv6IntegrationBackendAddr, strconv.Itoa(backendPort)),
	)
	var stderr bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("backend stdout pipe: %v", err)
	}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start IPv6 backend helper: %v", err)
	}

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == tcIPv6IntegrationReadyLine {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
			return
		}
		ready <- errors.New("IPv6 backend helper exited before ready")
	}()

	select {
	case err := <-ready:
		if err != nil {
			stopDataplanePerfHelper(t, cmd)
			t.Fatalf("IPv6 backend helper ready: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		stopDataplanePerfHelper(t, cmd)
		t.Fatalf("IPv6 backend helper ready timeout\n%s", stderr.String())
	}

	return cmd, &stderr
}

func seedTCIPv6IntegrationNeighbors(t *testing.T, topology dataplanePerfTopology) {
	t.Helper()

	mustRunDataplanePerfCmd(t, "ip", "-6", "addr", "replace", tcIPv6IntegrationFrontAddr+"/64", "dev", topology.ClientHostIF, "nodad")
	mustRunDataplanePerfCmd(t, "ip", "-6", "addr", "replace", tcIPv6IntegrationBackendHost+"/64", "dev", topology.BackendHostIF, "nodad")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "addr", "replace", tcIPv6IntegrationClientAddr+"/64", "dev", topology.ClientNSIF, "nodad")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "addr", "replace", tcIPv6IntegrationBackendAddr+"/64", "dev", topology.BackendNSIF, "nodad")

	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "route", "replace", "default", "via", tcIPv6IntegrationFrontAddr, "dev", topology.ClientNSIF)
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "route", "replace", "default", "via", tcIPv6IntegrationBackendHost, "dev", topology.BackendNSIF)
	mustRunDataplanePerfCmd(t, "ip", "-6", "route", "replace", tcIPv6IntegrationBackendAddr+"/128", "dev", topology.BackendHostIF)
	mustRunDataplanePerfCmd(t, "ip", "-6", "route", "replace", tcIPv6IntegrationClientAddr+"/128", "dev", topology.ClientHostIF)

	runDataplanePerfCmd("ip", "-6", "neigh", "del", tcIPv6IntegrationBackendAddr, "dev", topology.BackendHostIF)
	runDataplanePerfCmd("ip", "-6", "neigh", "del", tcIPv6IntegrationClientAddr, "dev", topology.ClientHostIF)
	runDataplanePerfCmd("ip", "netns", "exec", topology.ClientNS, "ip", "-6", "neigh", "del", tcIPv6IntegrationFrontAddr, "dev", topology.ClientNSIF)
	runDataplanePerfCmd("ip", "netns", "exec", topology.BackendNS, "ip", "-6", "neigh", "del", tcIPv6IntegrationBackendHost, "dev", topology.BackendNSIF)

	mustRunDataplanePerfCmd(t, "ip", "-6", "neigh", "replace", tcIPv6IntegrationBackendAddr, "lladdr", mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF), "dev", topology.BackendHostIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "-6", "neigh", "replace", tcIPv6IntegrationClientAddr, "lladdr", mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF), "dev", topology.ClientHostIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.ClientNS, "ip", "-6", "neigh", "replace", tcIPv6IntegrationFrontAddr, "lladdr", mustReadHostInterfaceMAC(t, topology.ClientHostIF), "dev", topology.ClientNSIF, "nud", "permanent")
	mustRunDataplanePerfCmd(t, "ip", "netns", "exec", topology.BackendNS, "ip", "-6", "neigh", "replace", tcIPv6IntegrationBackendHost, "lladdr", mustReadHostInterfaceMAC(t, topology.BackendHostIF), "dev", topology.BackendNSIF, "nud", "permanent")
}

func waitForTCIPv6IntegrationAPI(t *testing.T, apiBase string, cmd *exec.Cmd, logPath string) {
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
		req.Header.Set("Authorization", "Bearer "+tcIPv6IntegrationToken)
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

func makeShortTCIPv6IntegrationDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "fwtc6-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}
