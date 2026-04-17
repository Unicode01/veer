//go:build linux

package ipcsec

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	ControlSocketDirName  = ".forward-run"
	ControlSocketFileName = "forward-ctl.sock"
)

func PrepareSecureIPCListener(exePath string) (net.Listener, string, error) {
	socketDir := filepath.Join(filepath.Dir(exePath), ControlSocketDirName)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create control socket dir %q: %w", socketDir, err)
	}
	if err := os.Chmod(socketDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("chmod control socket dir %q: %w", socketDir, err)
	}

	sockPath := filepath.Join(socketDir, ControlSocketFileName)
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, "", fmt.Errorf("listen unix socket %q: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, "", fmt.Errorf("chmod control socket %q: %w", sockPath, err)
	}
	return ln, sockPath, nil
}

func CleanupSecureIPCListener(sockPath string) {
	if strings.TrimSpace(sockPath) == "" {
		return
	}
	_ = os.Remove(sockPath)
	socketDir := filepath.Dir(sockPath)
	if filepath.Base(socketDir) == ControlSocketDirName {
		_ = os.Remove(socketDir)
	}
}

func ValidateIPCPeerProcess(conn net.Conn, expectedPID int) error {
	if expectedPID <= 0 {
		return fmt.Errorf("invalid expected pid %d", expectedPID)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unexpected connection type %T", conn)
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw connection: %w", err)
	}

	var (
		cred       *unix.Ucred
		controlErr error
		socketErr  error
	)
	if err := rawConn.Control(func(fd uintptr) {
		cred, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		controlErr = err
	}
	if controlErr != nil {
		return fmt.Errorf("control connection: %w", controlErr)
	}
	if socketErr != nil {
		return fmt.Errorf("read peer credentials: %w", socketErr)
	}
	if cred == nil {
		return fmt.Errorf("missing peer credentials")
	}
	if int(cred.Pid) != expectedPID {
		return fmt.Errorf("unexpected peer pid %d, want %d", cred.Pid, expectedPID)
	}
	return nil
}
