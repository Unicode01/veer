//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPluginNativeWorkerServiceLaunch starts the plugin worker built into this
// binary the way the daemon does, from a memory file where the kernel allows
// executing one, and checks its handshake, its cgroup and limits, and that
// stopping it removes the cgroup. scripts/verify-service-platform.sh and
// verify-openrc-platform.sh run it inside the real systemd and OpenRC services
// (SELinux enforcing on Rocky), where a skip counts as a failure.
func TestPluginNativeWorkerServiceLaunch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to attach the plugin worker cgroup")
	}
	if os.Getenv(pluginNativeWorkerEnv) != "" {
		t.Skip("VEER_PLUGIN_WORKER replaces the embedded worker")
	}
	executable, err := extractEmbeddedPluginNativeWorker()
	if err != nil {
		t.Skipf("this binary carries no plugin worker for %q (run scripts/build-native-plugins.sh before building it): %v", pluginNativeHostTriple(), err)
	}
	cfg := &Config{}
	pool := newPluginNativeWorkerPool(cfg)
	defer pool.Close()
	worker, err := pool.worker(pluginNativeWorkerShared, time.Now().Add(pluginNativeWorkerStartTimeout))
	if err != nil {
		t.Fatalf("start plugin worker from %s: %v", executable, err)
	}
	pid := worker.command.Process.Pid
	t.Logf("plugin worker %d started from %s", pid, executable)

	// Run from a memory file, the worker would otherwise show up in ps and
	// top as the descriptor number. PROCESS_NAME in sdk/native/worker sets
	// the kernel name.
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	if comm, err := os.ReadFile(filepath.Join(procDir, "comm")); err != nil || strings.TrimSpace(string(comm)) != "veer-plugins" {
		t.Fatalf("plugin worker comm = %q (err %v), want veer-plugins", strings.TrimSpace(string(comm)), err)
	}
	wantCmdline := pluginNativeWorkerArgv0 + "\x00" + pluginNativeWorkerShared + "\x00"
	if cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err != nil || string(cmdline) != wantCmdline {
		t.Fatalf("plugin worker cmdline = %q (err %v), want %q", cmdline, err, wantCmdline)
	}

	name := "worker-" + pluginNativeWorkerShared
	cgroupData, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	member := fmt.Sprintf("/veer-plugins-%d/%s", os.Getpid(), name)
	if !strings.Contains(string(cgroupData), member) {
		if pool.limitWarned.Load() {
			t.Skipf("cgroup controllers are not delegated to this environment; worker cgroup %q", strings.TrimSpace(string(cgroupData)))
		}
		t.Fatalf("plugin worker cgroup = %q, want %s", strings.TrimSpace(string(cgroupData)), member)
	}
	cgroupRoot, err := pluginHostCgroupRootPath()
	if err != nil {
		t.Fatal(err)
	}
	group := filepath.Join(cgroupRoot, fmt.Sprintf("veer-plugins-%d", os.Getpid()), name)
	limits := pluginHostResourceLimitsFromConfig(cfg)
	for file, want := range map[string]string{
		"memory.max": strconv.FormatInt(limits.MemoryBytes, 10),
		"pids.max":   strconv.Itoa(limits.PIDs),
		"cpu.max":    fmt.Sprintf("%d 100000", int64(limits.CPUPercent)*1000),
	} {
		data, err := os.ReadFile(filepath.Join(group, file))
		if err != nil || strings.TrimSpace(string(data)) != want {
			t.Fatalf("%s = %q (err %v), want %q", file, strings.TrimSpace(string(data)), err, want)
		}
	}

	pool.Close()
	select {
	case <-worker.done:
	case <-time.After(3 * time.Second):
		t.Fatal("plugin worker did not stop")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(group); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin worker cgroup %s was not removed", group)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
