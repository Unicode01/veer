//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPluginHostMountNamespaceOperation(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		path      string
		wantError bool
	}{
		{name: "direct"},
		{name: "missing", path: "/does-not-exist/veer-mount-namespace", wantError: true},
		{name: "wrong-type", path: "/proc/self/ns/net", wantError: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Setenv(pluginHostMountNamespaceEnv, scenario.path)
			called := false
			err := runLinuxPluginHostMountOperation(func() error { called = true; return nil })
			if (err != nil) != scenario.wantError || called == scenario.wantError {
				t.Fatalf("called=%t error=%v", called, err)
			}
		})
	}
	t.Setenv(pluginHostMountNamespaceEnv, "")
	want := errors.New("operation failed")
	if err := runLinuxPluginHostMountOperation(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("error=%v, want %v", err, want)
	}
}

func TestPluginHostMountNamespaceServiceLifecycle(t *testing.T) {
	if os.Getenv("VEER_RUN_SERVICE_PLATFORM_TEST") != "1" {
		t.Skip("set VEER_RUN_SERVICE_PLATFORM_TEST=1 inside the deployment service unit")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, kind := range []string{"mnt", "net"} {
		path := "/proc/thread-self/ns/" + kind
		before, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			after, err := os.Readlink(path)
			if err != nil || before != after {
				t.Errorf("broker changed caller %s namespace: before=%s after=%s error=%v", kind, before, after, err)
			}
		}()
	}
	name := os.Getenv("VEER_SERVICE_TEST_NAMESPACE")
	if _, err := validatePluginControlNamespaceName(name, false); err != nil {
		t.Fatal(err)
	}
	statePath := os.Getenv("VEER_SERVICE_TEST_IDENTITY_FILE")
	admin, ok := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	if !ok {
		t.Fatal("Linux namespace provider unavailable")
	}
	phase := os.Getenv("VEER_SERVICE_TEST_PHASE")
	switch phase {
	case "create":
		created, err := admin.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: name, LoopbackUp: true})
		if err != nil || !created.Created {
			t.Fatalf("create=%+v error=%v", created, err)
		}
		data, err := json.Marshal(created.Info.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	case "reuse", "delete":
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var identity pluginControlNetNamespaceIdentity
		if err := json.Unmarshal(data, &identity); err != nil {
			t.Fatal(err)
		}
		if phase == "reuse" {
			result, err := admin.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: name, LoopbackUp: true})
			if err != nil || result.Created || !pluginControlNamespaceIdentityEqual(result.Info.Identity, identity) {
				t.Fatalf("namespace changed across service restart: result=%+v error=%v", result, err)
			}
			wrongIdentity := identity
			wrongIdentity.Inode++
			if err := admin.NamespaceDelete(name, wrongIdentity); err == nil {
				t.Fatal("namespace deletion accepted a stale identity")
			}
		} else if err := admin.NamespaceDelete(name, identity); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown lifecycle phase %q", phase)
	}
	if phase != "delete" {
		fd, err := unix.Open(fmt.Sprintf("/proc/1/root/run/netns/%s", name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || kind != unix.CLONE_NEWNET {
			t.Fatalf("namespace is not mounted in the host: type=%d error=%v", kind, err)
		}
	}
}
