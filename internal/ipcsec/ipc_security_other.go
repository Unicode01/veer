//go:build !linux

package ipcsec

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

	sockPath := filepath.Join(socketDir, ControlSocketFileName)
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, "", fmt.Errorf("listen unix socket %q: %w", sockPath, err)
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
	return nil
}
