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

