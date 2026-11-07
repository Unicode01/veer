package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func newPluginManagedProcessDirectory() (string, error) {
	root := filepath.Join(os.TempDir(), fmt.Sprintf("veer-plugin-processes-%d", os.Geteuid()))
	if err := cleanupPluginManagedProcessDirectories(root); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, fmt.Sprintf("%d-", os.Getpid()))
}

func cleanupPluginBinaryStages(root string) error {
	return cleanupPluginManagedProcessDirectories(root)
}

// A daemon killed with SIGKILL cannot run defers. Reclaim its private config
// directories on the next start, without touching live owners or symlinks.
func cleanupPluginManagedProcessDirectories(root string) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("managed process directory must be private and owned by the service user")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		pidText, suffix, found := strings.Cut(entry.Name(), "-")
		pid, err := strconv.Atoi(pidText)
		if !found || suffix == "" || err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return fmt.Errorf("clean orphan process directory: %w", err)
		}
	}
	return nil
}

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
