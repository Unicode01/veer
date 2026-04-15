//go:build !linux

package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	controlSocketDirName  = ".forward-run"
	controlSocketFileName = "forward-ctl.sock"
)

func prepareSecureIPCListener(exePath string) (net.Listener, string, error) {
	socketDir := filepath.Join(filepath.Dir(exePath), controlSocketDirName)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create control socket dir %q: %w", socketDir, err)
	}

	sockPath := filepath.Join(socketDir, controlSocketFileName)
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, "", fmt.Errorf("listen unix socket %q: %w", sockPath, err)
	}
	return ln, sockPath, nil
}

func cleanupSecureIPCListener(sockPath string) {
	if strings.TrimSpace(sockPath) == "" {
		return
	}
	_ = os.Remove(sockPath)
	socketDir := filepath.Dir(sockPath)
	if filepath.Base(socketDir) == controlSocketDirName {
		_ = os.Remove(socketDir)
	}
}

func validateIPCPeerProcess(conn net.Conn, expectedPID int) error {
	return nil
}
