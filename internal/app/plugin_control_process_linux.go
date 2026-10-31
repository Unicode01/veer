package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func preparePluginManagedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

func terminatePluginManagedProcess(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

func limitPluginManagedProcess(cmd *exec.Cmd, owner string, cfg *Config) (func(), error) {
	if cfg == nil {
		return func() {}, nil
	}
	if err := preparePluginHostResourceLimitRoot(); err != nil {
		if cfg.PluginMinimumSandboxLevel() == pluginSandboxLevelFull {
			return nil, fmt.Errorf("managed process resource limits: %w", err)
		}
		return func() {}, nil
	}
	cleanup, _, err := attachPluginHostResourceLimits(cmd.Process.Pid, owner, pluginHostResourceLimitsFromConfig(cfg))
	if err != nil {
		if cfg.PluginMinimumSandboxLevel() == pluginSandboxLevelFull {
			return nil, fmt.Errorf("managed process resource limits: %w", err)
		}
		return func() {}, nil
	}
	return func() {
		if root, err := pluginHostCgroupRootPath(); err == nil {
			group := filepath.Join(root, fmt.Sprintf("veer-plugins-%d", os.Getpid()), owner)
			_ = os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0600)
		}
		cleanup()
	}, nil
}
