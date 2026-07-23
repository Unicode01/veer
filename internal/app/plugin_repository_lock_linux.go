//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openAndLockPluginRepositoryPublisherFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open plugin repository workspace lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open plugin repository workspace lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errPluginRepositoryPublisherLocked
		}
		return nil, fmt.Errorf("lock plugin repository workspace: %w", err)
	}
	return file, nil
}

func unlockPluginRepositoryPublisherFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("unlock plugin repository workspace: %w", err)
	}
	return nil
}
