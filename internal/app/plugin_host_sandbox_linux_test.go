//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPluginHostCgroupControllerChanges(t *testing.T) {
	required := []string{"memory", "pids", "cpu"}
	tests := []struct {
		name      string
		available string
		enabled   string
		want      []string
		wantError string
	}{
		{name: "all disabled", available: "cpu io memory pids", want: []string{"+memory", "+pids", "+cpu"}},
		{name: "partially enabled", available: "cpu memory pids", enabled: "cpu memory", want: []string{"+pids"}},
		{name: "all enabled", available: "cpu memory pids", enabled: "cpu memory pids", want: []string{}},
		{name: "controller unavailable", available: "cpu pids", wantError: "controller memory is unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := pluginHostCgroupControllerChanges([]byte(test.available), []byte(test.enabled), required)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("changes = %v, want %v", got, test.want)
			}
		})
	}
}

func TestResolvePluginHostCgroupRoot(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		want      string
		wantError string
	}{
		{name: "host root", data: "0::/\n", want: "/sys/fs/cgroup"},
		{name: "systemd delegated unit", data: "0::/system.slice/veer.service\n", want: "/sys/fs/cgroup/system.slice/veer.service"},
		{name: "mixed hierarchy", data: "2:cpu:/legacy\n0::/system.slice/veer.service\n", want: "/sys/fs/cgroup/system.slice/veer.service"},
		{name: "missing unified hierarchy", data: "2:cpu:/legacy\n", wantError: "unified hierarchy is unavailable"},
		{name: "relative unified path", data: "0::relative\n", wantError: "must be absolute"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolvePluginHostCgroupRoot("/sys/fs/cgroup", []byte(test.data))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("root = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPluginHostProcessParent(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		want      int
		wantError string
	}{
		{name: "valid", status: "Name:\tveer\nPPid:\t42\n", want: 42},
		{name: "init", status: "PPid:\t0\n", want: 0},
		{name: "missing", status: "Name:\tveer\n", wantError: "PPid is unavailable"},
		{name: "invalid", status: "PPid:\tunknown\n", wantError: "invalid PPid value"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := pluginHostProcessParent([]byte(test.status))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parent = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPluginHostProcessUnavailable(t *testing.T) {
	for _, err := range []error{
		os.ErrNotExist,
		fmt.Errorf("wrapped: %w", syscall.ESRCH),
	} {
		if !pluginHostProcessUnavailable(err) {
			t.Fatalf("pluginHostProcessUnavailable(%v) = false", err)
		}
	}
	if pluginHostProcessUnavailable(syscall.EPERM) {
		t.Fatal("permission errors must not be ignored")
	}
}

func TestPluginHostLinuxSandboxIdentityAndCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to verify UID/GID drop and cgroup attachment")
	}
	cfg := isolatedPluginsTestConfig(&Config{})
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "linux_sandbox", Control: &PluginControl{Main: "control.js"}}}
	client, err := startPluginHostClient(cfg, plugin, "control", "", `exports.onAction = function () {};`, nil)
	if err != nil {
		t.Fatal(err)
	}
	pid := client.PID()
	statusData, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	status := string(statusData)
	for _, want := range []string{"Uid:\t65534\t65534\t65534\t65534", "Gid:\t65534\t65534\t65534\t65534", "NoNewPrivs:\t1"} {
		if !strings.Contains(status, want) {
			client.Close()
			t.Fatalf("plugin host status does not contain %q:\n%s", want, status)
		}
	}
	limitsData, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "limits"))
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	if line := pluginHostProcLine(string(limitsData), "Max open files"); !strings.Contains(line, "64") {
		client.Close()
		t.Fatalf("Max open files limit = %q, want 64", line)
	}
	cgroupRoot, err := pluginHostCgroupRootPath()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	cgroupPath := filepath.Join(cgroupRoot, "veer-plugins-"+strconv.Itoa(os.Getpid()), plugin.ID)
	if degraded := client.ResourceError(); degraded != "" {
		if !strings.Contains(degraded, "memory.oom.group") {
			client.Close()
			t.Skipf("cgroup controllers are not delegated to this test environment: %s", degraded)
		}
		t.Logf("optional cgroup OOM grouping unavailable: %s", degraded)
	}
	cgroupData, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	if !strings.Contains(string(cgroupData), "/veer-plugins-"+strconv.Itoa(os.Getpid())+"/"+plugin.ID) {
		client.Close()
		t.Fatalf("plugin host cgroup = %q", strings.TrimSpace(string(cgroupData)))
	}
	for name, want := range map[string]string{
		"memory.max": strconv.FormatInt(pluginHostCgroupMemoryMax, 10),
		"pids.max":   "64",
		"cpu.max":    "200000 100000",
	} {
		data, err := os.ReadFile(filepath.Join(cgroupPath, name))
		if err != nil || strings.TrimSpace(string(data)) != want {
			client.Close()
			t.Fatalf("%s = %q, err=%v, want %q", name, strings.TrimSpace(string(data)), err, want)
		}
	}
	client.Close()
	select {
	case <-client.done:
	case <-time.After(3 * time.Second):
		t.Fatal("plugin host did not stop")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := os.Stat(cgroupPath)
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("plugin host cgroup was not cleaned: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPluginHostLinuxSandboxSupportsConcurrentHosts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to verify concurrent isolated plugin hosts")
	}
	cfg := isolatedPluginsTestConfig(&Config{})
	clients := make([]*pluginHostClient, 0, 12)
	t.Cleanup(func() {
		for _, client := range clients {
			client.Close()
		}
	})

	for i := 0; i < cap(clients); i++ {
		plugin := LoadedPlugin{PluginManifest: PluginManifest{
			ID:      fmt.Sprintf("concurrent_host_%02d", i),
			Control: &PluginControl{Main: "control.js"},
		}}
		client, err := startPluginHostClient(cfg, plugin, "control", "", `exports.onAction = function () { return {ok: true}; };`, nil)
		if err != nil {
			t.Fatalf("start concurrent plugin host %d: %v", i, err)
		}
		clients = append(clients, client)
	}

	for i, client := range clients {
		if client.PID() <= 0 {
			t.Fatalf("concurrent plugin host %d has no process", i)
		}
		select {
		case <-client.done:
			t.Fatalf("concurrent plugin host %d exited during startup", i)
		default:
		}
	}
}

func TestCleanupOrphanPluginHostCgroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to create a cgroup fixture")
	}
	pid := 2000000000 + os.Getpid()%1000000
	cgroupRoot, err := pluginHostCgroupRootPath()
	if err != nil {
		t.Skipf("cgroup v2 root is unavailable in this test environment: %v", err)
	}
	base := filepath.Join(cgroupRoot, "veer-plugins-"+strconv.Itoa(pid))
	group := filepath.Join(base, "orphan_test")
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil {
		t.Skipf("fixture pid %d unexpectedly exists", pid)
	}
	if err := os.MkdirAll(group, 0o755); err != nil {
		t.Skipf("cgroup root is not writable in this test environment: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(group)
		_ = os.Remove(base)
	})
	if err := cleanupOrphanPluginHostCgroups(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("orphan cgroup still exists: %v", err)
	}
}

func TestCleanupOrphanPluginHostFilesystemRoots(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to create a root-owned filesystem sandbox fixture")
	}
	pid := 2000000000 + os.Getpid()%1000000
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil {
		t.Skipf("fixture pid %d unexpectedly exists", pid)
	}
	root, err := os.MkdirTemp(pluginHostFilesystemRootBase, fmt.Sprintf("%s%d-", pluginHostFilesystemPrefix, pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		_ = os.Remove(root)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	cleanupOrphanPluginHostFilesystemRoots()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("orphan plugin filesystem root still exists: %v", err)
	}
}

func pluginHostProcLine(value, prefix string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
