//go:build !linux

package app

import "os/exec"

func preparePluginManagedProcess(cmd *exec.Cmd)   {}
func terminatePluginManagedProcess(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
func limitPluginManagedProcess(cmd *exec.Cmd, owner string, cfg *Config) (func(), error) {
	return func() {}, nil
}
