//go:build windows

package app

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openAndLockPluginRepositoryPublisherFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open plugin repository workspace lock: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect plugin repository workspace lock: %w", err)
		}
		return nil, fmt.Errorf("plugin repository workspace lock must be a regular file")
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errPluginRepositoryPublisherLocked
		}
		return nil, fmt.Errorf("lock plugin repository workspace: %w", err)
	}
	return file, nil
}

func unlockPluginRepositoryPublisherFile(file *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("unlock plugin repository workspace: %w", err)
	}
	return nil
}
