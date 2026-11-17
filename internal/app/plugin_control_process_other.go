//go:build !linux

package app

import (
	"fmt"
	"os"
)

func newPluginManagedProcessDirectory() (string, error) {
	return os.MkdirTemp("", "veer-plugin-process-")
}

func cleanupPluginBinaryStages(root string) error { return os.MkdirAll(root, 0700) }

// Managed processes are Linux-only; the plugin API refuses them elsewhere.
func (p *pluginManagedProcess) launch(pluginProcessRequest, string) (*pluginKeeperRun, func(), error) {
	return nil, nil, fmt.Errorf("managed processes require Linux")
}

func (run *pluginKeeperRun) kill() {}

func runPluginProcessKeeper() error {
	return fmt.Errorf("process keepers require Linux")
}

func (r *pluginProcessRegistry) adoptHandedOffProcesses() {}

func handOffPluginProcesses(pluginControlRuntime) *pluginProcessHandoff { return nil }

type pluginProcessHandoff struct{}

func (*pluginProcessHandoff) finalize() error { return nil }
