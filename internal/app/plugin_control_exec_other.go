//go:build !linux && !windows

package app

import (
	"os/exec"
)

func pluginExecEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}

func configurePluginExecCommand(command *exec.Cmd) func() {
	return func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
}
