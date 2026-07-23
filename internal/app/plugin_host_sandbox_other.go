//go:build !linux && !windows

package app

import (
	"fmt"
	"os/exec"
)

func configurePluginHostCommand(command *exec.Cmd) error {
	if command == nil {
		return fmt.Errorf("plugin host command is nil")
	}
	return nil
}

func preparePluginHostFilesystemRoot() (string, func(), error) {
	return "", func() {}, nil
}

func preparePluginHostResourceLimitRoot() error {
	return nil
}

func applyPluginHostChildSandbox() (PluginHostSandboxState, error) {
	return PluginHostSandboxState{
		Platform: "other", Mode: "process_only", Level: "minimal",
		Degraded: []string{"platform sandbox and hard resource limits are unavailable"},
	}, nil
}

func attachPluginHostResourceLimits(_ int, _ string, _ pluginHostResourceLimits) (func(), string, error) {
	return func() {}, "", nil
}

func pluginHostProcessRSS(_ int) (uint64, error) {
	return 0, fmt.Errorf("plugin host RSS monitoring is unavailable")
}

func pluginHostResourceLimitMode() string {
	return "process_only"
}
