//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const pluginHostSandboxProbeEnv = "VEER_PLUGIN_SANDBOX_PROBE"

type pluginHostSandboxProbeResult struct {
	State          PluginHostSandboxState `json:"state"`
	FileReadDenied bool                   `json:"file_read_denied"`
	SocketDenied   bool                   `json:"socket_denied"`
}

func TestPluginHostLinuxSandboxEnforcementProbe(t *testing.T) {
	if os.Getenv(pluginHostSandboxProbeEnv) == "1" {
		runPluginHostLinuxSandboxProbeChild()
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	filesystemRoot, cleanup, err := preparePluginHostFilesystemRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	command := exec.Command(executable, "-test.run=^TestPluginHostLinuxSandboxEnforcementProbe$")
	command.Env = append(minimalPluginHostEnvironment(true),
		pluginHostSandboxProbeEnv+"=1",
		pluginHostFilesystemRootEnv+"="+filesystemRoot,
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("sandbox probe: %v", err)
	}
	var result pluginHostSandboxProbeResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode sandbox probe %q: %v", output, err)
	}
	if !result.State.NoNewPrivileges {
		t.Fatalf("sandbox state = %+v", result.State)
	}
	if result.State.FilesystemPolicy && !result.FileReadDenied {
		t.Fatal("filesystem policy reported active but /etc/passwd remained readable")
	}
	if result.State.SyscallPolicy && !result.SocketDenied {
		t.Fatal("seccomp reported active but socket creation remained available")
	}
}

func runPluginHostLinuxSandboxProbeChild() {
	// Landlock is thread-scoped. Mirror the production plugin host, which pins
	// untrusted execution to the restricted thread for the process lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	state, err := applyPluginHostChildSandbox()
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
		os.Exit(2)
	}
	_, fileErr := os.ReadFile("/etc/passwd")
	fd, socketErr := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	result := pluginHostSandboxProbeResult{
		State:          state,
		FileReadDenied: fileErr != nil,
		SocketDenied:   errors.Is(socketErr, unix.EPERM) || errors.Is(socketErr, unix.EACCES),
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	os.Exit(0)
}

func TestPluginHostLinuxChrootFallbackEnforcementProbe(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to verify the empty chroot fallback")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	filesystemRoot, cleanup, err := preparePluginHostFilesystemRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	command := exec.Command(executable, "-test.run=^TestPluginHostLinuxSandboxEnforcementProbe$")
	command.Env = append(minimalPluginHostEnvironment(true),
		pluginHostSandboxProbeEnv+"=1",
		pluginHostFilesystemRootEnv+"="+filesystemRoot,
		pluginHostForceChrootTestEnv+"=1",
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("chroot sandbox probe: %v", err)
	}
	var result pluginHostSandboxProbeResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode chroot sandbox probe %q: %v", output, err)
	}
	if result.State.Level != pluginSandboxLevelFull || !result.State.FilesystemPolicy || !strings.Contains(result.State.Mode, "chroot") {
		t.Fatalf("chroot sandbox state = %+v", result.State)
	}
	if !result.FileReadDenied || !result.SocketDenied {
		t.Fatalf("chroot enforcement result = %+v", result)
	}
}
