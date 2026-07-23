//go:build !linux && !windows

package app

import (
	"fmt"
	"os"
	"runtime"
)

func openAndLockPluginRepositoryPublisherFile(_ string) (*os.File, error) {
	return nil, fmt.Errorf("plugin repository publishing is unsupported on %s", runtime.GOOS)
}

func unlockPluginRepositoryPublisherFile(_ *os.File) error {
	return nil
}
