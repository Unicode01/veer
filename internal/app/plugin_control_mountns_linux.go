//go:build linux

package app

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const pluginHostMountNamespaceEnv = "VEER_HOST_MOUNT_NAMESPACE"

func openLinuxPluginHostMountNamespace() (int, error) {
	path := strings.TrimSpace(os.Getenv(pluginHostMountNamespaceEnv))
	if path == "" {
		return -1, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open host mount namespace: %w", err)
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNS {
		_ = unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("not a mount namespace")
		}
		return -1, fmt.Errorf("validate host mount namespace: %w", err)
	}
	return fd, nil
}

func runLinuxPluginHostMountOperation(operation func() error) error {
	result := make(chan error, 1)
	go func() {
		// Namespace and CLONE_FS changes must never return to Go's thread pool.
		runtime.LockOSThread()
		fd, err := openLinuxPluginHostMountNamespace()
		if err != nil {
			result <- err
			return
		}
		if fd >= 0 {
			defer unix.Close(fd)
			if err := unix.Unshare(unix.CLONE_FS); err != nil {
				result <- fmt.Errorf("unshare namespace broker filesystem state: %w", err)
				return
			}
			if err := unix.Setns(fd, unix.CLONE_NEWNS); err != nil {
				result <- fmt.Errorf("enter host mount namespace: %w", err)
				return
			}
		}
		result <- operation()
	}()
	return <-result
}
