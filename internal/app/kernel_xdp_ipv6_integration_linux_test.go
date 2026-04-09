//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// Linux usage:
//   1. Prepare embedded eBPF objects first:
//      bash release.sh
//   2. Run the integration test as root:
//      FORWARD_RUN_XDP_IPV6_TEST=1 go test ./internal/app -run TestXDPKernelIPv6Integration -count=1 -v

const xdpIPv6IntegrationEnableEnv = "FORWARD_RUN_XDP_IPV6_TEST"

func TestXDPKernelIPv6Integration(t *testing.T) {
	if os.Getenv(xdpIPv6IntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux xdp IPv6 integration test", xdpIPv6IntegrationEnableEnv)
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

	for _, tc := range []struct {
		name  string
		proto string
	}{
		{name: "tcp", proto: "tcp"},
		{name: "udp", proto: "udp"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			topology := setupDataplanePerfTopology(t)
			seedDataplanePerfNeighbors(t, topology)
			seedTCIPv6IntegrationNeighbors(t, topology)

			runtimeDir := makeShortXDPFullNATIntegrationDir(t)
			forwardBinary := filepath.Join(runtimeDir, "forward")
			copyFile(t, baseBinary, forwardBinary)

			workDir := filepath.Join(runtimeDir, "work-ipv6-"+tc.proto)
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				t.Fatalf("create work dir: %v", err)
			}
			webPort := freeTCPPort(t)
			mode := dataplanePerfMode{
				Name:         "xdp-ipv6-" + tc.proto,
				Default:      ruleEngineKernel,
				Order:        []string{kernelEngineXDP},
				Expected:     ruleEngineKernel,
				ExpectedKern: kernelEngineXDP,
			}
			configPath := filepath.Join(workDir, "config.json")
			writeDataplanePerfConfig(t, configPath, mode, webPort)

			logPath := filepath.Join(workDir, "forward-xdp-ipv6-"+tc.proto+".log")
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
			createXDPIPv6IntegrationRule(t, apiBase, topology, tc.proto)
			waitForDataplanePerfRule(t, apiBase, mode)

			if err := runTCIPv6IntegrationProbePorts(t, topology, tc.proto, tcIPv6IntegrationFrontPort, tcIPv6IntegrationBackendPort); err != nil {
				logForwardLogOnFailure(t, logPath)
				t.Fatal(err)
			}
		})
	}
}

func createXDPIPv6IntegrationRule(t *testing.T, apiBase string, topology dataplanePerfTopology, proto string) {
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
		"remark":            "xdp-ipv6-integration-" + proto,
		"tag":               "ipv6",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal xdp IPv6 rule: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/rules", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("build create xdp IPv6 rule request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tcIPv6IntegrationToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create xdp IPv6 rule: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create xdp IPv6 rule unexpected status %d: %s", resp.StatusCode, string(body))
	}
}
