//go:build linux

package app

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// pluginNativeWorkerArgv0 is the worker's argv[0]. The embedded worker runs
// from /proc/self/fd/N, which would make both its command line and its
// kernel process name (set by the worker itself) the bare descriptor number.
const pluginNativeWorkerArgv0 = "veer-plugin-worker"

// spawnPluginNativeWorker starts the worker for group with one end of a unix
// socket pair as fd 3. The worker dies with this process. Its command line is
// "veer-plugin-worker <group>"; the worker ignores the arguments.
func spawnPluginNativeWorker(executable, group string, cfg *Config) (*exec.Cmd, net.Conn, io.ReadCloser, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create plugin worker socket: %w", err)
	}
	parent := os.NewFile(uintptr(fds[0]), "veer-plugin-worker-host")
	child := os.NewFile(uintptr(fds[1]), "veer-plugin-worker-child")
	defer child.Close()
	conn, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open plugin worker socket: %w", err)
	}
	command := exec.Command(executable, group)
	command.Args[0] = pluginNativeWorkerArgv0
	command.Env = pluginNativeWorkerEnvironment()
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("open plugin worker stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("start plugin worker %s: %w", executable, err)
	}
	return command, conn, stderr, nil
}

func pluginNativeWorkerEnvironment() []string {
	values := []string{"VEER_PLUGIN_WORKER_FD=3"}
	for _, name := range []string{"LANG", "LC_ALL", "TZ", "PATH"} {
		if value := os.Getenv(name); value != "" {
			values = append(values, name+"="+value)
		}
	}
	return values
}

// pluginNativeSocketPair returns the host end of a new instance socket and
// the end to pass to the worker.
func pluginNativeSocketPair() (net.Conn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create plugin instance socket: %w", err)
	}
	parent := os.NewFile(uintptr(fds[0]), "veer-plugin-instance-host")
	child := os.NewFile(uintptr(fds[1]), "veer-plugin-instance-worker")
	conn, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, fmt.Errorf("open plugin instance socket: %w", err)
	}
	return conn, child, nil
}

// sendPluginNativeFrameWithFile writes one frame with file attached as
// SCM_RIGHTS ancillary data on its first byte.
func sendPluginNativeFrameWithFile(conn net.Conn, data []byte, file *os.File) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("plugin worker control connection is not a unix socket")
	}
	written, _, err := unixConn.WriteMsgUnix(data, syscall.UnixRights(int(file.Fd())), nil)
	if err != nil {
		return err
	}
	if written < len(data) {
		_, err = conn.Write(data[written:])
	}
	return err
}

// pluginNativeMemfdExecutable puts data in a sealed anonymous memory file
// and returns a path that executes it. The descriptor stays open for the
// life of the process, above the low numbers exec.Cmd hands to children.
func pluginNativeMemfdExecutable(data []byte) (string, error) {
	if value, err := os.ReadFile("/proc/sys/vm/memfd_noexec"); err == nil && len(value) > 0 && value[0] == '2' {
		return "", fmt.Errorf("executable memory files are disabled")
	}
	fd, err := unix.MemfdCreate("veer-plugin-worker", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "veer-plugin-worker")
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", err
	}
	_, _ = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL)
	high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 64)
	_ = file.Close()
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/proc/self/fd/%d", high)
	if !pluginNativePathExecutable(path) {
		_ = unix.Close(high)
		return "", fmt.Errorf("memory file is not executable")
	}
	return path, nil
}

// pluginNativePathExecutable reports whether the kernel lets this process
// execute the file: access(2) with X_OK honors noexec mounts.
func pluginNativePathExecutable(path string) bool {
	return unix.Access(path, unix.X_OK) == nil
}
