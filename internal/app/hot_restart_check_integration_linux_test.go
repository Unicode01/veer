//go:build linux

package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHotRestartCheckPredictsTCHandoffIntegration runs `hot-restart check`
// against a daemon carrying egress NAT state, then hot-restarts it and checks
// that the daemon did what the check said: adopt the maps, and fall back to a
// cold restart once kernel_traffic_stats is toggled.
func TestHotRestartCheckPredictsTCHandoffIntegration(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	harness := startEgressNATIntegrationHarness(t, "hrcheck")
	createEgressNATIntegrationEntry(t, harness.APIBase, harness.Topology)
	waitForEgressNATIntegrationStatus(t, harness.APIBase, harness.Topology, harness.Topology.ChildHostIF)
	if observed := runEgressNATIntegrationProbe(t, harness.Topology, "udp"); observed != egressNATUplinkAddr {
		logForwardLogOnFailure(t, harness.LogPath)
		t.Fatalf("backend observed source IP %q, want %q", observed, egressNATUplinkAddr)
	}

	report := runHotRestartCheckForHarness(t, &harness)
	tc := hotRestartReportEngine(t, report, kernelEngineTC)
	if report.Verdict != hotRestartVerdictHot || tc.Source != hotRestartSourceRunning || tc.PID != harness.Cmd.Process.Pid {
		t.Fatalf("check before an unchanged restart = %+v, want hot from the running daemon pid %d", report, harness.Cmd.Process.Pid)
	}
	adopted := make(map[string]bool, len(tc.Maps))
	for _, item := range tc.Maps {
		if !item.Compatible {
			t.Fatalf("map %+v incompatible with the same binary", item)
		}
		adopted[item.Name] = true
	}
	// Without a draining migration the active NAT bank becomes the old bank.
	if !adopted[kernelStatsMapName] || !(adopted[kernelTCNatPortsOldMapNameV4] || adopted[kernelNatPortsMapName]) {
		t.Fatalf("checked maps = %+v, want the stats map and the IPv4 NAT bank", tc.Maps)
	}

	offset := hotRestartIntegrationLogSize(t, harness.LogPath)
	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		t.Fatalf("write hot restart marker: %v", err)
	}
	restartManagedNetworkIntegrationForward(t, &harness)
	waitForHotRestartIntegrationLog(t, harness.LogPath, offset, "kernel dataplane hot restart: adopting pinned tc maps=")
	if text := hotRestartIntegrationLogSince(t, harness.LogPath, offset); strings.Contains(text, "(cold restart)") {
		t.Fatalf("hot restart fell back although the check said hot:\n%s", text)
	}

	// The successor adopted the old active banks as its old banks, which keep
	// their names: the check must still tell the banks apart.
	report = runHotRestartCheckForHarness(t, &harness)
	if tc = hotRestartReportEngine(t, report, kernelEngineTC); report.Verdict != hotRestartVerdictHot {
		t.Fatalf("check after a hot restart = %+v, want hot", report)
	}
	text, err := hotRestartCheckCommand(&harness).CombinedOutput()
	if err != nil {
		t.Fatalf("hot-restart check text output: %v\n%s", err, text)
	}
	t.Logf("hot-restart check after a hot restart:\n%s", text)

	setHotRestartIntegrationTrafficStats(t, harness.ConfigPath, true)
	report = runHotRestartCheckForHarness(t, &harness)
	tc = hotRestartReportEngine(t, report, kernelEngineTC)
	if report.Verdict != hotRestartVerdictCold || !strings.Contains(tc.Reason, "compat token") {
		t.Fatalf("check after toggling kernel_traffic_stats = %+v, want cold on the compat token", report)
	}

	offset = hotRestartIntegrationLogSize(t, harness.LogPath)
	if err := os.WriteFile(harness.HotRestartMarkerPath, []byte("1"), 0o644); err != nil {
		t.Fatalf("write hot restart marker: %v", err)
	}
	restartManagedNetworkIntegrationForward(t, &harness)
	waitForHotRestartIntegrationLog(t, harness.LogPath, offset, "preserved tc handoff is incompatible, abandoning handoff and falling back to fresh maps (cold restart)")
}

func hotRestartCheckCommand(harness *egressNATIntegrationHarness, extra ...string) *exec.Cmd {
	args := append([]string{"hot-restart", "check", "--install-dir", harness.WorkDir, "--config", harness.ConfigPath}, extra...)
	cmd := exec.Command(harness.ForwardBinary, args...)
	cmd.Env = append(os.Environ(),
		forwardBPFStateDirEnv+"="+harness.BPFStateRoot,
		forwardRuntimeStateDirEnv+"="+harness.RuntimeStateRoot,
	)
	return cmd
}

func runHotRestartCheckForHarness(t *testing.T, harness *egressNATIntegrationHarness) hotRestartCheckReport {
	t.Helper()
	cmd := hotRestartCheckCommand(harness, "--json")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hot-restart check: %v\n%s", err, stderr.String())
	}
	var report hotRestartCheckReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("parse hot-restart check output: %v\n%s", err, out)
	}
	t.Logf("hot-restart check: %s", strings.TrimSpace(string(out)))
	return report
}

func hotRestartReportEngine(t *testing.T, report hotRestartCheckReport, engine string) hotRestartEngineReport {
	t.Helper()
	for _, item := range report.Engines {
		if item.Engine == engine {
			return item
		}
	}
	t.Fatalf("report %+v has no %s engine", report, engine)
	return hotRestartEngineReport{}
}

func setHotRestartIntegrationTrafficStats(t *testing.T, configPath string, enabled bool) {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	features, _ := cfg["experimental_features"].(map[string]any)
	if features == nil {
		features = map[string]any{}
	}
	features[experimentalFeatureKernelTraffic] = enabled
	cfg["experimental_features"] = features
	if data, err = json.MarshalIndent(cfg, "", "  "); err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func hotRestartIntegrationLogSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat forward log: %v", err)
	}
	return info.Size()
}

func hotRestartIntegrationLogSince(t *testing.T, path string, offset int64) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read forward log: %v", err)
	}
	if offset > int64(len(data)) {
		return ""
	}
	return string(data[offset:])
}

func waitForHotRestartIntegrationLog(t *testing.T, path string, offset int64, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		text := hotRestartIntegrationLogSince(t, path, offset)
		if strings.Contains(text, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward log after the restart lacks %q:\n%s", want, text)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
