package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const pluginRepositoryPublisherLockFile = ".repository.lock"

var errPluginRepositoryPublisherLocked = errors.New("plugin repository workspace is locked by another publisher")

type pluginRepositoryPublisherLock struct {
	file *os.File
}

func acquirePluginRepositoryPublisherLock(directory string) (string, *pluginRepositoryPublisherLock, error) {
	workspace, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(workspace)
	if err != nil {
		return "", nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", nil, fmt.Errorf("repository workspace must be a regular directory")
	}
	file, err := openAndLockPluginRepositoryPublisherFile(filepath.Join(workspace, pluginRepositoryPublisherLockFile))
	if err != nil {
		return "", nil, err
	}
	return workspace, &pluginRepositoryPublisherLock{file: file}, nil
}

func (lock *pluginRepositoryPublisherLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return errors.Join(unlockPluginRepositoryPublisherFile(file), file.Close())
}
