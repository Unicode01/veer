//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	pluginHostCgroupMountRoot    = "/sys/fs/cgroup"
	pluginHostProcSelfCgroupPath = "/proc/self/cgroup"
	pluginHostCgroupMemoryMax    = 512 << 20
	pluginHostProcessRSSMax      = 224 << 20
)

var pluginHostRequiredCgroupControllers = []string{"memory", "pids", "cpu"}

var pluginHostCgroupPreparation struct {
	sync.Mutex
	ready bool
	root  string
	err   error
}

func attachPluginHostResourceLimits(pid int, pluginID string, limits pluginHostResourceLimits) (func(), string, error) {
	if pid <= 0 || !pluginIDPattern.MatchString(pluginID) {
		return func() {}, "", fmt.Errorf("invalid plugin host resource identity")
	}
	warnings := make([]string, 0, 2)
	cgroupRoot, err := pluginHostCgroupRootPath()
	if err != nil {
		return func() {}, "", err
	}
	if err := cleanupOrphanPluginHostCgroupsAt(cgroupRoot); err != nil {
		warnings = append(warnings, "cleanup orphan plugin cgroups: "+err.Error())
	}
	if err := enablePluginHostCgroupControllers(cgroupRoot, pluginHostRequiredCgroupControllers); err != nil {
		return func() {}, "", fmt.Errorf("prepare cgroup v2 root: %w", err)
	}
	base := filepath.Join(cgroupRoot, fmt.Sprintf("veer-plugins-%d", os.Getpid()))
	group := filepath.Join(base, pluginID)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return func() {}, "", err
	}
	cleanup := func() {
		_ = os.Remove(group)
		_ = os.Remove(base)
	}
	if err := enablePluginHostCgroupControllers(base, pluginHostRequiredCgroupControllers); err != nil {
		cleanup()
		return func() {}, "", fmt.Errorf("enable plugin cgroup controllers: %w", err)
	}
	parentLimits := []struct {
		name  string
		value string
	}{
		{"memory.max", strconv.FormatInt(limits.GlobalMemoryBytes, 10)},
		{"pids.max", strconv.Itoa(limits.GlobalPIDs)},
	}
	for _, item := range parentLimits {
		if err := os.WriteFile(filepath.Join(base, item.name), []byte(item.value), 0o644); err != nil {
			cleanup()
			return func() {}, "", fmt.Errorf("configure global %s: %w", item.name, err)
		}
	}
	if err := os.Mkdir(group, 0o755); err != nil && !os.IsExist(err) {
		cleanup()
		return func() {}, "", err
	}
	required := []struct {
		name  string
		value string
	}{
		{"memory.max", strconv.FormatInt(limits.MemoryBytes, 10)},
		{"pids.max", strconv.Itoa(limits.PIDs)},
		{"cpu.max", fmt.Sprintf("%d 100000", int64(limits.CPUPercent)*1000)},
	}
	for _, item := range required {
		name, value := item.name, item.value
		if err := os.WriteFile(filepath.Join(group, name), []byte(value), 0o644); err != nil {
			cleanup()
			return func() {}, "", fmt.Errorf("configure %s: %w", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(group, "memory.oom.group"), []byte("1"), 0o644); err != nil {
		warnings = append(warnings, fmt.Sprintf("configure optional memory.oom.group: %v", err))
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		cleanup()
		return func() {}, "", fmt.Errorf("attach pid to cgroup: %w", err)
	}
	return cleanup, strings.Join(warnings, "; "), nil
}

func preparePluginHostResourceLimitRoot() error {
	pluginHostCgroupPreparation.Lock()
	defer pluginHostCgroupPreparation.Unlock()
	if pluginHostCgroupPreparation.ready {
		return pluginHostCgroupPreparation.err
	}
	pluginHostCgroupPreparation.ready = true

	root, err := currentPluginHostCgroupRootPath()
	if err != nil {
		pluginHostCgroupPreparation.err = err
		return err
	}
	pluginHostCgroupPreparation.root = root
	if err := cleanupOrphanPluginHostMainCgroupsAt(root); err != nil {
		pluginHostCgroupPreparation.err = err
		return err
	}
	missing, err := pluginHostMissingCgroupControllers(root, pluginHostRequiredCgroupControllers)
	if err != nil {
		pluginHostCgroupPreparation.err = err
		return err
	}
	if len(missing) == 0 {
		return nil
	}

	processes, err := os.ReadFile(filepath.Join(root, "cgroup.procs"))
	if err != nil {
		pluginHostCgroupPreparation.err = fmt.Errorf("read delegated cgroup processes: %w", err)
		return pluginHostCgroupPreparation.err
	}
	processIDs := strings.Fields(string(processes))
	self := strconv.Itoa(os.Getpid())
	for _, pidText := range processIDs {
		pid, parseErr := strconv.Atoi(pidText)
		if parseErr != nil || pid <= 0 {
			pluginHostCgroupPreparation.err = fmt.Errorf("delegated cgroup contains a process outside the Veer process tree; cannot enable plugin controllers")
			return pluginHostCgroupPreparation.err
		}
		descends, inspectErr := pluginHostProcessDescendsFrom(pid, os.Getpid())
		if inspectErr != nil {
			if pluginHostProcessUnavailable(inspectErr) {
				continue
			}
			pluginHostCgroupPreparation.err = fmt.Errorf("inspect delegated cgroup process %d: %w", pid, inspectErr)
			return pluginHostCgroupPreparation.err
		}
		if !descends {
			pluginHostCgroupPreparation.err = fmt.Errorf("delegated cgroup contains a process outside the Veer process tree; cannot enable plugin controllers")
			return pluginHostCgroupPreparation.err
		}
	}

	mainLeaf := filepath.Join(root, "veer-main-"+self)
	if err := os.Mkdir(mainLeaf, 0o755); err != nil && !os.IsExist(err) {
		pluginHostCgroupPreparation.err = fmt.Errorf("create Veer main cgroup leaf: %w", err)
		return pluginHostCgroupPreparation.err
	}
	rollback := func() {
		for _, pidText := range processIDs {
			_ = os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte(pidText), 0o644)
		}
		_ = os.Remove(mainLeaf)
	}
	for _, pidText := range processIDs {
		if pidText == self {
			continue
		}
		if err := os.WriteFile(filepath.Join(mainLeaf, "cgroup.procs"), []byte(pidText), 0o644); err != nil && !pluginHostProcessUnavailable(err) {
			rollback()
			pluginHostCgroupPreparation.err = fmt.Errorf("move Veer child %s into main cgroup leaf: %w", pidText, err)
			return pluginHostCgroupPreparation.err
		}
	}
	if err := os.WriteFile(filepath.Join(mainLeaf, "cgroup.procs"), []byte(self), 0o644); err != nil {
		rollback()
		pluginHostCgroupPreparation.err = fmt.Errorf("move Veer into main cgroup leaf: %w", err)
		return pluginHostCgroupPreparation.err
	}
	if err := enablePluginHostCgroupControllers(root, pluginHostRequiredCgroupControllers); err != nil {
		rollback()
		pluginHostCgroupPreparation.err = fmt.Errorf("enable delegated plugin controllers: %w", err)
		return pluginHostCgroupPreparation.err
	}
	return nil
}

func pluginHostProcessDescendsFrom(pid, ancestor int) (bool, error) {
	if pid <= 0 || ancestor <= 0 {
		return false, nil
	}
	for depth := 0; depth < 64 && pid > 0; depth++ {
		if pid == ancestor {
			return true, nil
		}
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			return false, err
		}
		parent, err := pluginHostProcessParent(data)
		if err != nil {
			return false, fmt.Errorf("read parent of process %d: %w", pid, err)
		}
		if parent <= 0 || parent == pid {
			return false, nil
		}
		pid = parent
	}
	return false, nil
}

func pluginHostProcessParent(status []byte) (int, error) {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "PPid:" {
			continue
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent < 0 {
			return 0, fmt.Errorf("invalid PPid value %q", fields[1])
		}
		return parent, nil
	}
	return 0, fmt.Errorf("PPid is unavailable")
}

func pluginHostProcessUnavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func pluginHostMissingCgroupControllers(parent string, required []string) ([]string, error) {
	controllers, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return nil, fmt.Errorf("cgroup v2 is unavailable: %w", err)
	}
	enabled, err := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if err != nil {
		return nil, fmt.Errorf("read cgroup subtree controllers: %w", err)
	}
	return pluginHostCgroupControllerChanges(controllers, enabled, required)
}

func pluginHostCgroupRootPath() (string, error) {
	pluginHostCgroupPreparation.Lock()
	if pluginHostCgroupPreparation.ready {
		root, err := pluginHostCgroupPreparation.root, pluginHostCgroupPreparation.err
		pluginHostCgroupPreparation.Unlock()
		return root, err
	}
	pluginHostCgroupPreparation.Unlock()
	return currentPluginHostCgroupRootPath()
}

func currentPluginHostCgroupRootPath() (string, error) {
	data, err := os.ReadFile(pluginHostProcSelfCgroupPath)
	if err != nil {
		return "", fmt.Errorf("read current cgroup: %w", err)
	}
	root, err := resolvePluginHostCgroupRoot(pluginHostCgroupMountRoot, data)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return "", fmt.Errorf("current delegated cgroup is unavailable: %w", err)
	}
	return root, nil
}

func cleanupOrphanPluginHostMainCgroupsAt(cgroupRoot string) error {
	const prefix = "veer-main-"
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		pidText := strings.TrimPrefix(entry.Name(), prefix)
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if _, err := os.Stat(filepath.Join("/proc", pidText)); err == nil || !os.IsNotExist(err) {
			continue
		}
		path := filepath.Join(cgroupRoot, entry.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cleanup orphan Veer main cgroup %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func resolvePluginHostCgroupRoot(mountRoot string, data []byte) (string, error) {
	mountRoot = filepath.Clean(strings.TrimSpace(mountRoot))
	if !filepath.IsAbs(mountRoot) {
		return "", fmt.Errorf("cgroup mount root must be absolute")
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		cgroupPath := filepath.Clean(parts[2])
		if !filepath.IsAbs(cgroupPath) {
			return "", fmt.Errorf("current unified cgroup path must be absolute")
		}
		if cgroupPath == string(filepath.Separator) {
			return mountRoot, nil
		}
		relative := strings.TrimPrefix(cgroupPath, string(filepath.Separator))
		root := filepath.Join(mountRoot, relative)
		rel, err := filepath.Rel(mountRoot, root)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("current unified cgroup escapes mount root")
		}
		return root, nil
	}
	return "", fmt.Errorf("cgroup v2 unified hierarchy is unavailable")
}

func enablePluginHostCgroupControllers(parent string, required []string) error {
	controllers, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("cgroup v2 is unavailable: %w", err)
	}
	subtreePath := filepath.Join(parent, "cgroup.subtree_control")
	enabledData, err := os.ReadFile(subtreePath)
	if err != nil {
		return fmt.Errorf("read cgroup subtree controllers: %w", err)
	}
	missing, err := pluginHostCgroupControllerChanges(controllers, enabledData, required)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	if err := os.WriteFile(subtreePath, []byte(strings.Join(missing, " ")), 0o644); err != nil {
		return fmt.Errorf("enable cgroup subtree controllers: %w", err)
	}

	enabledData, err = os.ReadFile(subtreePath)
	if err != nil {
		return fmt.Errorf("verify cgroup subtree controllers: %w", err)
	}
	missing, err = pluginHostCgroupControllerChanges(controllers, enabledData, required)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("cgroup v2 controller %s was not enabled", strings.TrimPrefix(missing[0], "+"))
	}
	return nil
}

func pluginHostCgroupControllerChanges(availableData, enabledData []byte, required []string) ([]string, error) {
	available := make(map[string]struct{})
	for _, controller := range strings.Fields(string(availableData)) {
		available[controller] = struct{}{}
	}
	enabled := make(map[string]struct{})
	for _, controller := range strings.Fields(string(enabledData)) {
		enabled[controller] = struct{}{}
	}
	missing := make([]string, 0, len(required))
	for _, controller := range required {
		if _, ok := available[controller]; !ok {
			return nil, fmt.Errorf("cgroup v2 controller %s is unavailable", controller)
		}
		if _, ok := enabled[controller]; !ok {
			missing = append(missing, "+"+controller)
		}
	}
	return missing, nil
}

func cleanupOrphanPluginHostCgroups() error {
	cgroupRoot, err := pluginHostCgroupRootPath()
	if err != nil {
		return err
	}
	return cleanupOrphanPluginHostCgroupsAt(cgroupRoot)
}

func cleanupOrphanPluginHostCgroupsAt(cgroupRoot string) error {
	const prefix = "veer-plugins-"
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return err
	}
	failures := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		pidText := strings.TrimPrefix(entry.Name(), prefix)
		pid, err := strconv.Atoi(pidText)
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if _, err := os.Stat(filepath.Join("/proc", pidText)); err == nil || !os.IsNotExist(err) {
			continue
		}
		base := filepath.Join(cgroupRoot, entry.Name())
		children, err := os.ReadDir(base)
		if err != nil {
			failures = append(failures, entry.Name()+": "+err.Error())
			continue
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			if err := os.Remove(filepath.Join(base, child.Name())); err != nil && !os.IsNotExist(err) {
				failures = append(failures, entry.Name()+"/"+child.Name()+": "+err.Error())
			}
		}
		if err := os.Remove(base); err != nil && !os.IsNotExist(err) {
			failures = append(failures, entry.Name()+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func pluginHostProcessRSS(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "VmRSS:" {
			continue
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kilobytes << 10, nil
	}
	return 0, fmt.Errorf("VmRSS is unavailable")
}
