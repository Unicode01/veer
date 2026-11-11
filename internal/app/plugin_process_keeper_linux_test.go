package app

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func init() { pluginProcessKeeperTestMode = true }

// TestPluginProcessKeeperEntrypoint is the keeper subprocess used by managed
// process tests. os.Exit keeps test runner output off the keeper's stdio.
func TestPluginProcessKeeperEntrypoint(t *testing.T) {
	if os.Getenv(pluginProcessKeeperTestEnv) != "1" {
		return
	}
	if err := runPluginProcessKeeper(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "plugin process keeper: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func managedProcessAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	stat := string(data)
	if i := strings.LastIndex(stat, ") "); i >= 0 && i+3 <= len(stat) {
		state := stat[i+2 : i+3]
		return state != "Z" && state != "X"
	}
	return true
}

func waitManagedProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for managedProcessAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d is still alive", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitManagedOutput(t *testing.T, p *pluginManagedProcess, text string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for {
		if out, _ := p.stdout.snapshot(); strings.Contains(out, text) {
			return
		}
		if time.Now().After(deadline) {
			out, _ := p.stdout.snapshot()
			t.Fatalf("output %q never contained %q", out, text)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// handOffManagedForTest plays the old daemon's side of a hot restart.
func handOffManagedForTest(t *testing.T, r *pluginProcessRegistry) []pluginProcessHandoffRecord {
	t.Helper()
	records := r.handOff(5 * time.Second)
	if len(records) == 0 {
		t.Fatal("nothing was handed off")
	}
	if err := writePluginProcessHandoff(records); err != nil {
		t.Fatal(err)
	}
	r.CloseAll()
	return records
}

func TestPluginManagedProcessSurvivesHandOffAndIsClaimedWithoutRestart(t *testing.T) {
	t.Setenv("VEER_RUNTIME_STATE_DIR", t.TempDir())
	req := managedTestRequest(t, "graceful")
	req.StopTimeoutMS = 2500
	old := &pluginProcessRegistry{}
	if _, err := old.Start("one", "v1", req, nil); err != nil {
		t.Fatal(err)
	}
	waitManagedOutput(t, old.get("one", "core"), "ready")
	before := old.get("one", "core").snapshot()
	records := handOffManagedForTest(t, old)
	if !managedProcessAlive(before.PID) {
		t.Fatal("closing the old registry stopped a handed-off process")
	}
	if _, _, _, err := dialPluginKeeper(records[0].Socket, strings.Repeat("0", 64), records[0].KeeperPID, records[0].KeeperStartTicks); err == nil {
		t.Fatal("keeper accepted a wrong token")
	}

	successor := newPluginProcessRegistry(nil)
	defer successor.CloseAll()
	p := successor.get("one", "core")
	if p == nil {
		t.Fatal("process was not adopted")
	}
	if _, err := os.Stat(pluginProcessHandoffPath()); !os.IsNotExist(err) {
		t.Fatal("handoff file was not consumed", err)
	}
	adopted := p.snapshot()
	if adopted.State != "running" || adopted.PID != before.PID || adopted.StartedAt != before.StartedAt || adopted.Starts != before.Starts {
		t.Fatalf("adopted status %+v, want %+v", adopted, before)
	}
	if _, err := p.requestRestart(); err == nil {
		t.Fatal("an unclaimed process accepted a restart")
	}
	claimed, err := successor.Start("one", "v2", req, nil)
	if err != nil || claimed.PID != before.PID || claimed.StartedAt != before.StartedAt {
		t.Fatalf("claim restarted the process: %+v, %v", claimed, err)
	}
	if again, err := successor.Start("one", "v2", req, nil); err != nil || again.PID != before.PID {
		t.Fatalf("repeated start by the claiming generation: %+v, %v", again, err)
	}
	if _, err := successor.Start("one", "v3", req, nil); err == nil {
		t.Fatal("another generation took over a claimed process")
	}
	status := successor.Stop("one", "core")
	if status.State != "stopped" || status.ExitCode != 0 {
		t.Fatalf("stop after adoption: %+v", status)
	}
	waitManagedProcessGone(t, before.PID)
	// Output written before the handoff and after the adoption both reach the successor.
	out, _ := p.stdout.snapshot()
	if !strings.Contains(out, "ready") || !strings.Contains(out, "terminated") {
		t.Fatalf("logs across the handoff: %q", out)
	}
}

func TestPluginManagedProcessAdoptedWithAnotherSpecificationIsReplaced(t *testing.T) {
	t.Setenv("VEER_RUNTIME_STATE_DIR", t.TempDir())
	old := &pluginProcessRegistry{}
	if _, err := old.Start("one", "v1", managedTestRequest(t, "sleep"), nil); err != nil {
		t.Fatal(err)
	}
	before := old.get("one", "core").snapshot()
	handOffManagedForTest(t, old)
	successor := newPluginProcessRegistry(nil)
	defer successor.CloseAll()
	changed := managedTestRequest(t, "graceful")
	status, err := successor.Start("one", "v2", changed, nil)
	if err != nil || status.PID == before.PID || status.Starts != 1 {
		t.Fatalf("changed specification: %+v, %v", status, err)
	}
	waitManagedProcessGone(t, before.PID)
}

func TestPluginManagedProcessUnclaimedAdoptionIsStopped(t *testing.T) {
	t.Setenv("VEER_RUNTIME_STATE_DIR", t.TempDir())
	previous := pluginProcessClaimDeadline
	pluginProcessClaimDeadline = 200 * time.Millisecond
	defer func() { pluginProcessClaimDeadline = previous }()
	old := &pluginProcessRegistry{}
	if _, err := old.Start("one", "v1", managedTestRequest(t, "sleep"), nil); err != nil {
		t.Fatal(err)
	}
	before := old.get("one", "core").snapshot()
	handOffManagedForTest(t, old)
	successor := newPluginProcessRegistry(nil)
	defer successor.CloseAll()
	if successor.get("one", "core") == nil {
		t.Fatal("process was not adopted")
	}
	waitManagedProcessGone(t, before.PID)
	deadline := time.Now().Add(3 * time.Second)
	for successor.get("one", "core") != nil {
		if time.Now().After(deadline) {
			t.Fatal("expired adoption remains registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginManagedProcessKeeperStopsWhenTheDaemonVanishes(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	if _, err := r.Start("one", "v1", managedTestRequest(t, "ignore"), nil); err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	waitManagedOutput(t, p, "ready")
	pid := p.snapshot().PID
	// A crashed daemon closes its end without arming a handoff.
	p.mu.Lock()
	conn := p.run.conn
	p.mu.Unlock()
	_ = conn.Close()
	waitManagedProcessGone(t, pid)
}

func TestPluginManagedProcessHandOffIsCancelledWhenTheFileCannotBeWritten(t *testing.T) {
	r := &pluginProcessRegistry{}
	if _, err := r.Start("one", "v1", managedTestRequest(t, "sleep"), nil); err != nil {
		t.Fatal(err)
	}
	pid := r.get("one", "core").snapshot().PID
	records := r.handOff(5 * time.Second)
	if len(records) != 1 {
		t.Fatal(records)
	}
	r.cancelHandOff(records)
	r.CloseAll()
	waitManagedProcessGone(t, pid)
	waitManagedProcessGone(t, records[0].KeeperPID)
}

func TestPluginManagedProcessHandOffReleasesDelegatedControllers(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_PROCESS_LIMITS_TEST") != "1" {
		t.Skip("requires a delegated cgroup containing only this test process")
	}
	t.Setenv("VEER_RUNTIME_STATE_DIR", t.TempDir())
	cfg := &Config{PluginsMinSandboxLevel: pluginSandboxLevelFull}
	old := &pluginProcessRegistry{cfg: cfg}
	if _, err := old.Start("one", "v1", managedTestRequest(t, "sleep"), nil); err != nil {
		t.Fatal(err)
	}
	before := old.get("one", "core").snapshot()
	limitOwner := old.get("one", "core").limitOwner
	root, err := pluginHostCgroupRootPath()
	if err != nil {
		t.Fatal(err)
	}
	records := handOffManagedForTest(t, old)
	if err := (&pluginProcessHandoff{registry: old, records: records}).finalize(); err != nil {
		t.Fatal(err)
	}
	// systemd can only place the successor in the delegated root once it has
	// no controllers enabled for children.
	if enabled, err := os.ReadFile(root + "/cgroup.subtree_control"); err != nil || strings.TrimSpace(string(enabled)) != "" {
		t.Fatalf("delegated controllers after handoff: %q, %v", enabled, err)
	}
	leaf := root + "/" + pluginProcessHandoffLeaf + "/" + limitOwner
	for _, pid := range []int{records[0].KeeperPID, before.PID} {
		if path, err := pluginProcessCgroupPath(pid); err != nil || path != leaf {
			t.Fatalf("process %d is in %q, want %q: %v", pid, path, leaf, err)
		}
	}
	if !managedProcessAlive(before.PID) {
		t.Fatal("handoff stopped the process")
	}

	successor := newPluginProcessRegistry(cfg)
	defer successor.CloseAll()
	if successor.get("one", "core") == nil {
		t.Fatal("process was not adopted")
	}
	group := fmt.Sprintf("%s/veer-plugins-%d/%s", root, os.Getpid(), limitOwner)
	for _, pid := range []int{records[0].KeeperPID, before.PID} {
		if path, err := pluginProcessCgroupPath(pid); err != nil || path != group {
			t.Fatalf("adopted process %d is in %q, want %q: %v", pid, path, group, err)
		}
	}
	if _, err := os.Stat(root + "/" + pluginProcessHandoffLeaf); !os.IsNotExist(err) {
		t.Fatal("handoff cgroup remains", err)
	}
	if value, err := os.ReadFile(group + "/memory.max"); err != nil || strings.TrimSpace(string(value)) == "max" {
		t.Fatal("adopted process has no memory limit", string(value), err)
	}
	if status, err := successor.Start("one", "v2", managedTestRequest(t, "sleep"), nil); err != nil || status.PID != before.PID {
		t.Fatalf("claim: %+v, %v", status, err)
	}
	successor.Stop("one", "core")
	waitManagedProcessGone(t, before.PID)
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatal("managed cgroup remains", err)
	}
}
