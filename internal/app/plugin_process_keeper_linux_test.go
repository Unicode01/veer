package app

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// requirePluginProcessKeeper skips a managed process test where no plugin
// worker is built (scripts/build-native-plugins.sh): the keeper is the worker
// binary. CI sets VEER_REQUIRE_NATIVE_PLUGINS=1 so a missing build fails.
func requirePluginProcessKeeper(t *testing.T) {
	t.Helper()
	if _, err := pluginProcessKeeperExecutable(); err != nil {
		if os.Getenv("VEER_REQUIRE_NATIVE_PLUGINS") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
}

// requireWorkerKeeper checks that pid is the worker binary's keeper.
func requireWorkerKeeper(t *testing.T, pid int) {
	t.Helper()
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		t.Fatal(err)
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(comm)) != "veer-keeper" || string(cmdline) != pluginProcessKeeperArgv0+"\x00" {
		t.Fatalf("keeper %d runs as %q with command line %q", pid, comm, cmdline)
	}
}

const pluginProcessKeeperLegacyTestEnv = "VEER_PLUGIN_PROCESS_KEEPER_TEST"

// TestPluginProcessKeeperLegacyEntrypoint plays "veer --plugin-process-keeper"
// for TestPluginProcessKeeperLegacyCommandBecomesTheWorkerKeeper.
func TestPluginProcessKeeperLegacyEntrypoint(t *testing.T) {
	if os.Getenv(pluginProcessKeeperLegacyTestEnv) != "1" {
		return
	}
	err := runPluginProcessKeeper()
	_, _ = fmt.Fprintf(os.Stderr, "plugin process keeper: %v\n", err)
	os.Exit(2)
}

// A daemon from before the worker keeper still starts keepers as
// "veer --plugin-process-keeper" from its executable path, which names the
// new binary once an upgrade has replaced the file. That process becomes the
// worker keeper under the same PID, which the daemon has already placed in
// the resource cgroup, and serves the old daemon.
func TestPluginProcessKeeperLegacyCommandBecomesTheWorkerKeeper(t *testing.T) {
	requirePluginProcessKeeper(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	local, remote := os.NewFile(uintptr(pair[0]), "daemon"), os.NewFile(uintptr(pair[1]), "keeper")
	conn, err := net.FileConn(local)
	_ = local.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keeper := exec.Command(executable, "-test.run=^TestPluginProcessKeeperLegacyEntrypoint$")
	keeper.Env = append(os.Environ(), pluginProcessKeeperLegacyTestEnv+"=1")
	keeper.ExtraFiles = []*os.File{remote}
	keeper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := keeper.Start(); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	defer func() {
		_ = syscall.Kill(-keeper.Process.Pid, syscall.SIGKILL)
		_ = keeper.Wait()
	}()
	run := newPluginKeeperRun(conn, keeper.Process.Pid)
	var stdout, stderr pluginProcessLog
	go run.read(newPluginKeeperScanner(conn), &stdout, &stderr)
	req := managedTestRequest(t, "graceful")
	if err := run.send(pluginKeeperMessage{Op: "start", Command: req.Command, Args: req.Args, Env: pluginExecEnvironment(), Dir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := run.awaitStart(); err != nil {
		t.Fatal(err)
	}
	requireWorkerKeeper(t, keeper.Process.Pid)
	deadline := time.Now().Add(6 * time.Second)
	for out, _ := stdout.snapshot(); !strings.Contains(out, "ready"); out, _ = stdout.snapshot() {
		if time.Now().After(deadline) {
			t.Fatalf("output %q", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	run.stop(2 * time.Second)
	if code := run.code(); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if out, _ := stdout.snapshot(); !strings.Contains(out, "terminated") {
		t.Fatalf("output %q", out)
	}
	corePID, _ := run.core()
	waitManagedProcessGone(t, corePID)
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
	// Restarts used in the current crash streak travel with the process.
	handedOff := old.get("one", "core")
	handedOff.mu.Lock()
	handedOff.restarts = 2
	handedOff.mu.Unlock()
	records := handOffManagedForTest(t, old)
	if records[0].Restarts != 2 {
		t.Fatalf("handoff record restarts = %d, want 2", records[0].Restarts)
	}
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
	p.mu.Lock()
	restarts := p.restarts
	p.mu.Unlock()
	if restarts != 2 {
		t.Fatalf("adopted restarts = %d, want 2", restarts)
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
	p.mu.Lock()
	conn, keeperPID := p.run.conn, p.run.keeperPID
	p.mu.Unlock()
	requireWorkerKeeper(t, keeperPID)
	// A crashed daemon closes its end without arming a handoff.
	_ = conn.Close()
	waitManagedProcessGone(t, pid)
	waitManagedProcessGone(t, keeperPID)
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

// A keeper run signals its executable's group only while the recorded PID
// still names the executable, or names nothing: a process that started later
// under that PID means the group is gone and the number is someone else's.
func TestPluginKeeperRunLeavesAReusedPIDAlone(t *testing.T) {
	pid := os.Getpid()
	ticks, err := kernelProcessStartTicks(pid)
	if err != nil {
		t.Fatal(err)
	}
	run := &pluginKeeperRun{corePID: pid}
	run.noteCoreStart()
	if run.coreTicks != ticks {
		t.Fatalf("recorded start ticks = %d, want %d", run.coreTicks, ticks)
	}
	if group := run.coreGroup(); group != pid {
		t.Fatalf("group of the live executable = %d, want %d", group, pid)
	}
	run.coreTicks = ticks + 1 // as if this PID had been handed out again
	if group := run.coreGroup(); group != 0 {
		t.Fatalf("group of a reused PID = %d, want 0", group)
	}

	child := exec.Command("true")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if pluginPIDInUse(child.Process.Pid) {
		t.Skip("the reaped child's PID was handed out again at once")
	}
	gone := &pluginKeeperRun{corePID: child.Process.Pid, coreTicks: ticks}
	if group := gone.coreGroup(); group != child.Process.Pid {
		t.Fatalf("group of an executable that is gone = %d, want %d: its children may live on", group, child.Process.Pid)
	}
}

func TestPluginPIDInUse(t *testing.T) {
	if !pluginPIDInUse(os.Getpid()) {
		t.Fatal("this process is not in use")
	}
	child := exec.Command("true")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if pluginPIDInUse(child.Process.Pid) {
		t.Skip("the reaped child's PID was handed out again at once")
	}
}
