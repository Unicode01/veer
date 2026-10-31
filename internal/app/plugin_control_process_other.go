//go:build !linux

package app

import (
	"os"
	"os/exec"
)

func newPluginManagedProcessDirectory() (string, error) {
	return os.MkdirTemp("", "veer-plugin-process-")
}

func preparePluginManagedProcess(cmd *exec.Cmd)   {}
func terminatePluginManagedProcess(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
func limitPluginManagedProcess(cmd *exec.Cmd, owner string, cfg *Config) (func(), error) {
	return func() {}, nil
}
