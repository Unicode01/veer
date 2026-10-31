package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

func TestPluginManagedProcessHelper(t *testing.T) {
	if len(os.Args) < 5 || os.Args[3] != "--veer-process-test" {
		return
	}
	switch os.Args[4] {
	case "config":
		data, err := os.ReadFile(os.Args[5])
		if err != nil {
			os.Exit(3)
		}
		info, _ := os.Stat(os.Args[5])
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"config": string(data), "path": os.Args[5], "mode": info.Mode().Perm(), "secret": os.Getenv("VEER_PROCESS_SECRET")})
	case "output":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 200000))
	case "fail":
		os.Exit(9)
	case "tree":
		child := exec.Command("/bin/sleep", "60")
		if child.Start() != nil {
			os.Exit(2)
		}
		fmt.Println(child.Process.Pid)
		time.Sleep(time.Minute)
	case "sleep":
		time.Sleep(time.Minute)
	case "graceful":
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGTERM)
		fmt.Println("ready")
		<-term
		fmt.Println("terminated")
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
		fmt.Println("ready")
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func managedTestRequest(t *testing.T, mode string) pluginProcessRequest {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return pluginProcessRequest{ID: "core", Command: binary, Args: []string{"-test.run=^TestPluginManagedProcessHelper$", "--", "--veer-process-test", mode}, StopTimeoutMS: 100}
}

func waitManaged(t *testing.T, p *pluginManagedProcess, predicate func(pluginProcessStatus) bool) pluginProcessStatus {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		status := p.snapshot()
		if predicate(status) {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process status: %+v", p.snapshot())
	return pluginProcessStatus{}
}

func TestPluginManagedProcessConfigOwnershipAndCleanup(t *testing.T) {
	t.Setenv("VEER_PROCESS_SECRET", "not-inherited")
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	req := managedTestRequest(t, "config")
	req.Args = append(req.Args, "{config}")
	req.Config = "private\nconfig"
	if _, err := r.Start("one", "generation", req, nil); err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	<-p.done
	output, _ := p.stdout.snapshot()
	var got struct {
		Config, Path, Secret string
		Mode                 uint32
	}
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err, output)
	}
	if got.Config != req.Config || got.Secret != "" || got.Mode != 0600 {
		t.Fatalf("config transport: %+v", got)
	}
	if _, err := os.Stat(filepath.Dir(got.Path)); !os.IsNotExist(err) {
		t.Fatalf("private directory remains: %v", err)
	}
	if r.get("two", "core") != nil {
		t.Fatal("cross-plugin ownership leak")
	}
	if _, err := r.Start("one", "different", req, nil); err == nil {
		t.Fatal("generation collision accepted")
	}
}

func TestPluginManagedProcessOrphanDirectoryCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "processes")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	dead := exec.Command("/bin/true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, fmt.Sprintf("%d-old", dead.Process.Pid))
	live := filepath.Join(root, fmt.Sprintf("%d-live", os.Getpid()))
	for _, dir := range []string{orphan, live} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(orphan, "config"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(root, fmt.Sprintf("%d-link", dead.Process.Pid))
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPluginManagedProcessDirectories(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan remains", err)
	}
	for _, dir := range []string{live, outside, link} {
		if _, err := os.Lstat(dir); err != nil {
			t.Fatal("live or unrelated path removed", dir, err)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPluginManagedProcessDirectories(alias); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestPluginManagedProcessIdempotenceStopAndOwnerShutdown(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	stop := make(chan struct{})
	req := managedTestRequest(t, "sleep")
	a, err := r.Start("one", "v1", req, stop)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Start("one", "v1", req, stop)
	if err != nil || a.PID != b.PID {
		t.Fatal("duplicate process", a, b, err)
	}
	changed := req
	changed.Stdin = "changed"
	if _, err := r.Start("one", "v1", changed, stop); err == nil {
		t.Fatal("changed process replaced silently")
	}
	close(stop)
	p := r.get("one", "core")
	<-p.done
	if p.snapshot().State != "stopped" {
		t.Fatal(p.snapshot())
	}
	r.Stop("one", "core")
	if err := syscall.Kill(a.PID, 0); err == nil {
		t.Fatal("leader remains alive")
	}
}

func TestPluginManagedProcessRestartBudgetAndBoundedLogs(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	req := managedTestRequest(t, "fail")
	req.Restart = "on-failure"
	req.MaxRestarts = 1
	if _, err := r.Start("one", "v1", req, nil); err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	<-p.done
	if status := p.snapshot(); status.Starts != 2 || status.ExitCode != 9 || status.State != "exited" {
		t.Fatal(status)
	}
	// Reconciliation of an identical specification cannot bypass its restart budget.
	status, err := r.Start("one", "v1", req, nil)
	if err != nil || status.Starts != 2 {
		t.Fatal(status, err)
	}
	r.Stop("one", "core")
	req = managedTestRequest(t, "output")
	if _, err := r.Start("one", "v1", req, nil); err != nil {
		t.Fatal(err)
	}
	p = r.get("one", "core")
	<-p.done
	output, truncated := p.stdout.snapshot()
	if !truncated || len(output) != pluginExecMaxOutputBytes {
		t.Fatal("unbounded logs", len(output), truncated)
	}
}

func TestPluginManagedProcessStopKillsDescendants(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	if _, err := r.Start("one", "v1", managedTestRequest(t, "tree"), nil); err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	var child int
	deadline := time.Now().Add(3 * time.Second)
	for child == 0 && time.Now().Before(deadline) {
		output, _ := p.stdout.snapshot()
		_, _ = fmt.Sscan(output, &child)
		time.Sleep(10 * time.Millisecond)
	}
	if child == 0 {
		t.Fatal("child did not start")
	}
	r.Stop("one", "core")
	// A descendant can briefly remain as a zombie until PID 1 reaps it.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
	if err == nil && !strings.Contains(string(data), ") Z ") {
		t.Fatal("descendant still alive", string(data))
	}
}

func TestPluginManagedProcessBrokerPolicy(t *testing.T) {
	for _, mode := range []string{"remote", "permission", "registration", "worker", "upgrade"} {
		t.Run(mode, func(t *testing.T) {
			r := newPluginControlRuntime(openTestDB(t), pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
			defer r.Close()
			h := &pluginControlHost{vm: goja.New(), cfg: &Config{}, runtime: r}
			h.plugin.ID = "one"
			h.plugin.Control = &PluginControl{Permissions: []string{"exec"}}
			switch mode {
			case "remote":
				h.cfg.PluginsRemoteInstallEnabled = true
			case "permission":
				h.plugin.Control.Permissions = nil
			case "registration":
				h.registrationPhase = true
			case "worker":
				h.workerVM = true
			case "upgrade":
				h.upgradePhase = true
			}
			if err := h.install(); err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"process.start", "process.status", "process.stop", "process.restart", "process.list", "process.logs"} {
				if _, _, err := h.callPluginHostMethod(method, []any{map[string]any{"id": "core", "command": "/bin/sleep"}}); err == nil {
					t.Fatal(method, "accepted", mode)
				}
			}
		})
	}
}

func TestPluginManagedProcessGracefulAndForcedStop(t *testing.T) {
	for _, mode := range []string{"graceful", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			r := &pluginProcessRegistry{}
			defer r.CloseAll()
			if _, err := r.Start("one", "v1", managedTestRequest(t, mode), nil); err != nil {
				t.Fatal(err)
			}
			p := r.get("one", "core")
			end := time.Now().Add(3 * time.Second)
			for {
				out, _ := p.stdout.snapshot()
				if strings.Contains(out, "ready") {
					break
				}
				if time.Now().After(end) {
					t.Fatal("helper not ready")
				}
				time.Sleep(10 * time.Millisecond)
			}
			start := time.Now()
			status := r.Stop("one", "core")
			if status.State != "stopped" || time.Since(start) > 2*time.Second {
				t.Fatal(status, time.Since(start))
			}
			out, _ := p.stdout.snapshot()
			if mode == "graceful" && (!strings.Contains(out, "terminated") || status.ExitCode != 0) {
				t.Fatal(status, out)
			}
			if mode == "ignore" && status.ExitCode != -1 {
				t.Fatal("TERM-resistant process not killed", status)
			}
		})
	}
}

func TestPluginManagedProcessHealthRestartSharesBudget(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	req := managedTestRequest(t, "sleep")
	req.MaxRestarts = 1
	first, err := r.Start("one", "v1", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	if _, err := p.requestRestart(); err != nil {
		t.Fatal(err)
	}
	next := waitManaged(t, p, func(s pluginProcessStatus) bool { return s.State == "running" && s.Starts == 2 })
	if first.PID == next.PID {
		t.Fatal("leader not replaced")
	}
	if _, err := p.requestRestart(); err == nil {
		t.Fatal("health recovery bypassed budget")
	}
	r.Stop("one", "core")
	// Cancellation during backoff must not launch a new generation.
	req = managedTestRequest(t, "fail")
	req.Restart = "on-failure"
	req.MaxRestarts = 10
	if _, err := r.Start("one", "v1", req, nil); err != nil {
		t.Fatal(err)
	}
	p = r.get("one", "core")
	waitManaged(t, p, func(s pluginProcessStatus) bool { return s.State == "backoff" })
	status := r.Stop("one", "core")
	if status.Starts != 1 || status.State != "stopped" {
		t.Fatal(status)
	}
}

func TestPluginManagedProcessRegistryLimitsAndShutdown(t *testing.T) {
	r := &pluginProcessRegistry{}
	defer r.CloseAll()
	for i := 0; i < 8; i++ {
		req := managedTestRequest(t, "sleep")
		req.ID = fmt.Sprintf("core%d", i)
		if _, err := r.Start("one", "v1", req, nil); err != nil {
			t.Fatal(err)
		}
	}
	req := managedTestRequest(t, "sleep")
	req.ID = "ninth"
	if _, err := r.Start("one", "v1", req, nil); err == nil {
		t.Fatal("per-plugin limit bypassed")
	}
	r.ClosePlugin("one")
	if len(r.entries) != 0 {
		t.Fatal("owner entries remain")
	}
	r.CloseAll()
	if _, err := r.Start("two", "v1", req, nil); err == nil {
		t.Fatal("closed registry restarted")
	}
}

func TestPluginManagedProcessThroughIsolatedAndInProcessRuntime(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		t.Run(fmt.Sprint(isolated), func(t *testing.T) {
			dir := t.TempDir()
			writeTestPlugin(t, dir, "process_runtime", `{"api_version":"v1","id":"process_runtime","name":"Process Runtime","version":"1.0.0","kind":"control","stability":"lab","actions":[{"id":"run","runtime_update":"runtime_apply"}],"control":{"main":"control.js","permissions":["exec","kv"]}}`)
			req := managedTestRequest(t, "sleep")
			data, _ := json.Marshal(req)
			writePluginControlScript(t, dir, "process_runtime", `exports.onAction=function(){ var first=process.start(`+string(data)+`); var again=process.start(`+string(data)+`); if(first.pid!==again.pid) throw new Error('duplicate'); kv.set('result',process.status('core')); };`)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			if isolated {
				cfg = isolatedPluginsTestConfig(cfg)
			}
			plugin := loadTestPluginByID(t, cfg, "process_runtime")
			db := openTestDB(t)
			r := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			defer r.Close()
			if err := r.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
				t.Fatal(err)
			}
			record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "result")
			if err != nil {
				t.Fatal(err)
			}
			var status pluginProcessStatus
			if err := json.Unmarshal([]byte(record.DataJSON), &status); err != nil || status.State != "running" || status.PID == 0 {
				t.Fatal(record, err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(status.PID, 0); err == nil {
				t.Fatal("core survived runtime close", status)
			}
		})
	}
}

func TestPluginManagedProcessFullResourceLimits(t *testing.T) {
	if os.Getenv("VEER_RUN_VPN_PROCESS_LIMITS_TEST") != "1" {
		t.Skip("requires a delegated cgroup containing only this test process")
	}
	r := &pluginProcessRegistry{cfg: &Config{PluginsMinSandboxLevel: pluginSandboxLevelFull}}
	defer r.CloseAll()
	status, err := r.Start("one", "v1", managedTestRequest(t, "sleep"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := r.get("one", "core")
	root, err := pluginHostCgroupRootPath()
	if err != nil {
		t.Fatal(err)
	}
	group := filepath.Join(root, fmt.Sprintf("veer-plugins-%d", os.Getpid()), p.limitOwner)
	for _, name := range []string{"memory.max", "pids.max", "cpu.max"} {
		value, err := os.ReadFile(filepath.Join(group, name))
		if err != nil || strings.TrimSpace(string(value)) == "max" {
			t.Fatal(name, string(value), err)
		}
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", status.PID))
	if err != nil || !strings.Contains(string(data), p.limitOwner) {
		t.Fatal("core is not in its cgroup", string(data), err)
	}
	r.Stop("one", "core")
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatal("managed cgroup remains", err)
	}
}
