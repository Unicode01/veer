//go:build !linux

package app

import (
	"os"
	"os/exec"
)

func newPluginManagedProcessDirectory() (string, error) {
	return os.MkdirTemp("", "veer-plugin-process-")
}

func cleanupPluginBinaryStages(root string) error { return os.MkdirAll(root, 0700) }

func preparePluginManagedProcess(cmd *exec.Cmd)   {}
func terminatePluginManagedProcess(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
func limitPluginManagedProcess(cmd *exec.Cmd, owner string, cfg *Config) (func(), error) {
	return func() {}, nil
}
