//go:build !linux && !windows

package app

import (
	"fmt"
)

func preparePluginHostResourceLimitRoot() error {
	return nil
}

func attachPluginHostResourceLimits(_ int, _ string, _ pluginHostResourceLimits) (func(), string, error) {
	return func() {}, "", nil
}

func pluginHostProcessRSS(_ int) (uint64, error) {
	return 0, fmt.Errorf("plugin host RSS monitoring is unavailable")
}
