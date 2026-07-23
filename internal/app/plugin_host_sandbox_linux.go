//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	pluginHostCgroupMountRoot    = "/sys/fs/cgroup"
	pluginHostProcSelfCgroupPath = "/proc/self/cgroup"
	pluginHostFilesystemRootBase = "/tmp"
	pluginHostFilesystemPrefix   = ".veer-plugin-host-root-"
	pluginHostForceChrootTestEnv = "VEER_PLUGIN_HOST_FORCE_CHROOT_TEST"
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

func configurePluginHostCommand(command *exec.Cmd) error {
	if command == nil {
		return fmt.Errorf("plugin host command is nil")
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
		Setpgid:   true,
	}
	return nil
}

func applyPluginHostChildSandbox() (PluginHostSandboxState, error) {
	state := PluginHostSandboxState{Platform: "linux", Level: "partial", Mode: "rlimit+no_new_privs"}
	limits := []struct {
		resource int
		current  uint64
		maximum  uint64
	}{
		{unix.RLIMIT_CORE, 0, 0},
		{unix.RLIMIT_NOFILE, 64, 64},
	}
	for _, limit := range limits {
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.current, Max: limit.maximum}); err != nil {
			return state, err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return state, err
	}
	state.NoNewPrivileges = true
	if err := os.Chdir("/"); err != nil {
		return state, err
	}
	filesystemMode := ""
	landlockReason := ""
	forceChroot := os.Getenv(pluginHostForceChrootTestEnv) == "1" && os.Getenv("VEER_PLUGIN_HOST_TEST") == "1"
	if !forceChroot {
		state.FilesystemPolicy, landlockReason = applyPluginHostLandlock()
		if state.FilesystemPolicy {
			filesystemMode = "landlock"
		}
	}
	if !state.FilesystemPolicy {
		chroot, chrootReason := applyPluginHostEmptyChroot(os.Getenv(pluginHostFilesystemRootEnv))
		state.FilesystemPolicy = chroot
		if chroot {
			filesystemMode = "chroot"
		} else {
			if forceChroot {
				landlockReason = "Landlock bypassed by filesystem fallback test"
			}
			state.Degraded = append(state.Degraded, strings.Trim(strings.Join([]string{landlockReason, chrootReason}, "; "), "; "))
		}
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups([]int{}); err != nil {
			return state, err
		}
		if err := syscall.Setgid(65534); err != nil {
			return state, err
		}
		if err := syscall.Setuid(65534); err != nil {
			return state, err
		}
		state.IdentityIsolated = true
	} else {
		state.Degraded = append(state.Degraded, "dedicated plugin uid/gid requires a root parent process")
	}
	syscall.Umask(0o077)
	seccomp, seccompReason := applyPluginHostSeccomp()
	state.SyscallPolicy = seccomp
	if seccompReason != "" {
		state.Degraded = append(state.Degraded, seccompReason)
	}
	modes := []string{"rlimit", "no_new_privs"}
	if state.IdentityIsolated {
		modes = append(modes, "uid_gid")
	}
	if filesystemMode != "" {
		modes = append(modes, filesystemMode)
	}
	if state.SyscallPolicy {
		modes = append(modes, "seccomp")
	}
	state.Mode = strings.Join(modes, "+")
	if state.IdentityIsolated && state.FilesystemPolicy && state.SyscallPolicy && len(state.Degraded) == 0 {
		state.Level = "full"
	}
	return state, nil
}

func preparePluginHostFilesystemRoot() (string, func(), error) {
	const parent = pluginHostFilesystemRootBase
	info, err := os.Lstat(parent)
	if err != nil {
		return "", func() {}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", func() {}, fmt.Errorf("plugin host filesystem root parent is not a directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", func() {}, fmt.Errorf("plugin host filesystem root parent is not root-owned")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return "", func() {}, fmt.Errorf("plugin host filesystem root parent is writable without the sticky bit")
	}
	cleanupOrphanPluginHostFilesystemRoots()
	root, err := os.MkdirTemp(parent, fmt.Sprintf("%s%d-", pluginHostFilesystemPrefix, os.Getpid()))
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(root) }
	if err := os.Chmod(root, 0o555); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return root, cleanup, nil
}

func applyPluginHostEmptyChroot(root string) (bool, string) {
	root = filepath.Clean(strings.TrimSpace(root))
	if os.Geteuid() != 0 {
		return false, "empty chroot filesystem isolation requires a root parent process"
	}
	if root == "." || !filepath.IsAbs(root) || filepath.Dir(root) != pluginHostFilesystemRootBase || !strings.HasPrefix(filepath.Base(root), pluginHostFilesystemPrefix) {
		return false, "empty chroot filesystem root is invalid"
	}
	info, err := os.Lstat(root)
	if err != nil {
		return false, "inspect empty chroot filesystem root: " + err.Error()
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
		return false, "empty chroot filesystem root is not a read-only directory"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false, "empty chroot filesystem root is not root-owned"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, "inspect empty chroot filesystem root contents: " + err.Error()
	}
	if len(entries) != 0 {
		return false, "empty chroot filesystem root contains files"
	}
	if err := syscall.Chroot(root); err != nil {
		return false, "apply empty chroot filesystem isolation: " + err.Error()
	}
	if err := os.Chdir("/"); err != nil {
		return false, "enter empty chroot filesystem root: " + err.Error()
	}
	return true, ""
}

func cleanupOrphanPluginHostFilesystemRoots() {
	entries, err := os.ReadDir(pluginHostFilesystemRootBase)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, pluginHostFilesystemPrefix) {
			continue
		}
		remainder := strings.TrimPrefix(name, pluginHostFilesystemPrefix)
		separator := strings.IndexByte(remainder, '-')
		if separator <= 0 {
			continue
		}
		pid, err := strconv.Atoi(remainder[:separator])
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err == nil || !os.IsNotExist(err) {
			continue
		}
		path := filepath.Join(pluginHostFilesystemRootBase, name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			continue
		}
		contents, err := os.ReadDir(path)
		if err != nil || len(contents) != 0 {
			continue
		}
		_ = os.Remove(path)
	}
}

func applyPluginHostLandlock() (bool, string) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION))
	if errno != 0 {
		return false, "Landlock filesystem isolation unavailable: " + errno.Error()
	}
	access := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	attr := unix.LandlockRulesetAttr{Access_fs: access}
	fd, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return false, "create Landlock filesystem policy: " + errno.Error()
	}
	defer unix.Close(int(fd))
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return false, "apply Landlock filesystem policy: " + errno.Error()
	}
	return true, ""
}

func applyPluginHostSeccomp() (bool, string) {
	filters, err := pluginHostSeccompFilters(runtime.GOARCH)
	if err != nil {
		return false, err.Error()
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]} // #nosec G115 -- the bounded filter contains fewer than 256 instructions.
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program))); errno != 0 {
		if _, _, fallbackErrno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program))); fallbackErrno != 0 {
			return false, "seccomp syscall isolation unavailable: " + fallbackErrno.Error()
		}
		return true, "seccomp TSYNC unavailable; policy is limited to the locked plugin execution thread"
	}
	return true, ""
}

func pluginHostSeccompFilters(goarch string) ([]unix.SockFilter, error) {
	auditArch, ok := pluginHostAuditArchitecture(goarch)
	if !ok {
		return nil, fmt.Errorf("seccomp syscall isolation does not support architecture %s", goarch)
	}
	blocked := []uintptr{
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
		unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4,
		unix.SYS_PTRACE, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_SETNS, unix.SYS_UNSHARE,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_KEXEC_LOAD,
		unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_USERFAULTFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_QUOTACTL,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
	}
	filters := make([]unix.SockFilter, 0, 6+len(blocked)*2)
	// struct seccomp_data starts with int nr followed by __u32 arch.
	filters = append(filters,
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: auditArch},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	)
	if goarch == "amd64" {
		// x32 reports AUDIT_ARCH_X86_64 but ORs syscall numbers with this bit.
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	for _, syscallNumber := range blocked {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: uint32(syscallNumber)}, // #nosec G115 -- Linux syscall numbers are 32-bit seccomp fields.
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	return filters, nil
}

func pluginHostAuditArchitecture(goarch string) (uint32, bool) {
	switch goarch {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, true
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, true
	case "386":
		return unix.AUDIT_ARCH_I386, true
	case "arm":
		return unix.AUDIT_ARCH_ARM, true
	case "ppc64":
		return unix.AUDIT_ARCH_PPC64, true
	case "ppc64le":
		return unix.AUDIT_ARCH_PPC64LE, true
	case "riscv64":
		return unix.AUDIT_ARCH_RISCV64, true
	case "s390x":
		return unix.AUDIT_ARCH_S390X, true
	default:
		return 0, false
	}
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

func pluginHostResourceLimitMode() string {
	return "cgroup_v2+rss"
}
