package app

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	kernelHelperModuleFile    = optionalKernelModuleName + ".ko"
	kernelHelperModuleDirName = "kernel"
)

// kernelHelperInstall describes the helper modules installed beside a Veer
// binary. The daemon loads only <dir>/kernel/<running release>/veer_kfuncs.ko.
type kernelHelperInstall struct {
	KernelRelease   string
	ModulePath      string
	ModuleInstalled bool
	// OtherReleases lists kernels that have a module but are not running,
	// typically the kernel before an upgrade.
	OtherReleases []string
}

// validKernelRelease accepts the build script's characters ([A-Za-z0-9._+-]).
// Linux releases start with the VERSION number, so requiring a leading digit
// rejects "." / ".." and the kernel/veer_kfuncs source directory.
func validKernelRelease(release string) bool {
	if release == "" || len(release) > 64 || release[0] < '0' || release[0] > '9' {
		return false
	}
	for i := 0; i < len(release); i++ {
		c := release[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '_', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}

func runningKernelRelease() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	release := strings.TrimSpace(string(data))
	if !validKernelRelease(release) {
		return "", fmt.Errorf("unexpected kernel release %q", release)
	}
	return release, nil
}

func kernelHelperModulePath(installDir, release string) string {
	return filepath.Join(installDir, kernelHelperModuleDirName, release, kernelHelperModuleFile)
}

func kernelHelperRegularFile(name string) bool {
	info, err := os.Lstat(name)
	return err == nil && info.Mode().IsRegular()
}

func inspectKernelHelperInstall(installDir, release string) kernelHelperInstall {
	state := kernelHelperInstall{KernelRelease: release}
	if validKernelRelease(release) {
		state.ModulePath = kernelHelperModulePath(installDir, release)
		state.ModuleInstalled = kernelHelperRegularFile(state.ModulePath)
	}
	entries, err := os.ReadDir(filepath.Join(installDir, kernelHelperModuleDirName))
	if err != nil {
		return state
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == release || !entry.IsDir() || !validKernelRelease(name) {
			continue
		}
		if kernelHelperRegularFile(kernelHelperModulePath(installDir, name)) {
			state.OtherReleases = append(state.OtherReleases, name)
		}
	}
	sort.Strings(state.OtherReleases)
	return state
}

func (state kernelHelperInstall) missingReason() string {
	reason := "no " + kernelHelperModuleFile + " for running kernel " + state.KernelRelease
	if len(state.OtherReleases) > 0 {
		reason += " (installed for " + strings.Join(state.OtherReleases, ", ") + ")"
	}
	return reason
}

func kernelHelperBuildCommand(executable, installDir string) string {
	command := executable + " kfuncs build"
	if installDir != "" && installDir != filepath.Dir(executable) {
		command += " --install-dir " + installDir
	}
	return command
}

// currentKernelHelperInstall inspects the directory the daemon loads from.
func currentKernelHelperInstall() (string, kernelHelperInstall, bool) {
	executable, err := os.Executable()
	if err != nil {
		return "", kernelHelperInstall{}, false
	}
	release, err := runningKernelRelease()
	if err != nil {
		return executable, kernelHelperInstall{}, false
	}
	return executable, inspectKernelHelperInstall(filepath.Dir(executable), release), true
}

// optionalKernelModuleStartupDetail turns a missing module file into an
// actionable log line; other failures keep their original error.
func optionalKernelModuleStartupDetail(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, fs.ErrNotExist) {
		if executable, install, ok := currentKernelHelperInstall(); ok && !install.ModuleInstalled {
			return install.missingReason() + "; build it with: " + kernelHelperBuildCommand(executable, "")
		}
	}
	return err.Error()
}

func kernelModuleInfoField(data []byte, key string) string {
	prefix := []byte(key + "=")
	for _, entry := range bytes.Split(data, []byte{0}) {
		if bytes.HasPrefix(entry, prefix) {
			return string(entry[len(prefix):])
		}
	}
	return ""
}

// validateKernelHelperModuleFile checks what finit_module and kfunc
// registration need before the file replaces an installed module.
func validateKernelHelperModuleFile(name, release string) error {
	file, err := elf.Open(name)
	if err != nil {
		return fmt.Errorf("read built module: %w", err)
	}
	defer file.Close()
	section := file.Section(".modinfo")
	if section == nil {
		return errors.New("built module has no .modinfo section")
	}
	data, err := section.Data()
	if err != nil {
		return fmt.Errorf("read built module info: %w", err)
	}
	if got := kernelModuleInfoField(data, "name"); got != "" && got != optionalKernelModuleName {
		return fmt.Errorf("built module is %q, want %q", got, optionalKernelModuleName)
	}
	vermagic := strings.Fields(kernelModuleInfoField(data, "vermagic"))
	if len(vermagic) == 0 {
		return errors.New("built module has no vermagic")
	}
	if vermagic[0] != release {
		return fmt.Errorf("built module is for kernel %s, not %s; check --kdir", vermagic[0], release)
	}
	if file.Section(".BTF") == nil {
		return errors.New("built module has no BTF, so its kfuncs cannot register")
	}
	return nil
}

// installKernelHelperModule atomically places a root-owned 0644 module where
// loadOptionalKernelModule expects it.
func installKernelHelperModule(source, installDir, release string) (string, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	dest := kernelHelperModulePath(installDir, release)
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s must be a directory, not a link", dir)
	}
	temp, err := os.CreateTemp(dir, "."+kernelHelperModuleFile+".next-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	_, err = temp.Write(data)
	if err == nil {
		err = temp.Chmod(0o644)
	}
	if err == nil && os.Geteuid() == 0 {
		err = temp.Chown(0, 0)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tempName, dest)
	}
	if err != nil {
		_ = os.Remove(tempName)
		return "", err
	}
	_ = syncPluginBlobDirectory(dir)
	return dest, nil
}

func extractKernelHelperSource(source fs.FS, dir string) error {
	return fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

// kernelHelperBuildEnv makes --kdir and --vmlinux-btf authoritative over
// values the caller's shell happens to export.
func kernelHelperBuildEnv(base []string, kdir, vmlinuxBTF string) []string {
	env := make([]string, 0, len(base)+2)
	for _, item := range base {
		if strings.HasPrefix(item, "KDIR=") || strings.HasPrefix(item, "VMLINUX_BTF=") {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "KDIR="+kdir)
	if vmlinuxBTF != "" {
		env = append(env, "VMLINUX_BTF="+vmlinuxBTF)
	}
	return env
}

type kernelHelperBuildOptions struct {
	Release    string
	KDIR       string
	VMLinuxBTF string
	InstallDir string
	Force      bool
}

type kernelHelperBuildSystem struct {
	source   func() (fs.FS, bool)
	euid     func() int
	running  func() (string, error)
	lookPath func(string) (string, error)
	run      func(dir string, env []string, stdout, stderr io.Writer) error
}

func defaultKernelHelperBuildSystem() kernelHelperBuildSystem {
	return kernelHelperBuildSystem{
		source:   kernelHelperEmbeddedSource,
		euid:     os.Geteuid,
		running:  runningKernelRelease,
		lookPath: exec.LookPath,
		run: func(dir string, env []string, stdout, stderr io.Writer) error {
			cmd := exec.Command("sh", filepath.Join(dir, "build.sh"))
			cmd.Dir = dir
			cmd.Env = env
			cmd.Stdout = stdout
			cmd.Stderr = stderr
			return cmd.Run()
		},
	}
}

func buildKernelHelperModule(options kernelHelperBuildOptions, system kernelHelperBuildSystem, stdout, stderr io.Writer) error {
	source, ok := system.source()
	if !ok {
		return errors.New("this binary was built without veer_kfuncs support; rebuild Veer with VEER_BUILD_KERNEL_MODULE=1")
	}
	if system.euid() != 0 {
		return errors.New("must run as root: the module is installed root-owned for the daemon to load")
	}
	running, err := system.running()
	if err != nil {
		return fmt.Errorf("read running kernel release: %w", err)
	}
	release := strings.TrimSpace(options.Release)
	if release == "" {
		release = running
	}
	if !validKernelRelease(release) {
		return fmt.Errorf("invalid kernel release %q", release)
	}
	dest := kernelHelperModulePath(options.InstallDir, release)
	if kernelHelperRegularFile(dest) && !options.Force {
		fmt.Fprintf(stdout, "%s is already installed; pass --force to rebuild it\n", dest)
		return nil
	}
	kdir := options.KDIR
	if kdir == "" {
		kdir = path.Join("/lib/modules", release, "build")
	}
	if kdir, err = filepath.Abs(kdir); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(kdir, "Makefile")); err != nil {
		return fmt.Errorf("kernel headers for %s not found in %s; install them (Debian/Ubuntu: linux-headers-%s, Proxmox VE: proxmox-headers-%s, RHEL/Fedora: kernel-devel-%s) or pass --kdir",
			release, kdir, release, release, release)
	}
	vmlinuxBTF := options.VMLinuxBTF
	if vmlinuxBTF != "" {
		if vmlinuxBTF, err = filepath.Abs(vmlinuxBTF); err != nil {
			return err
		}
		if _, err := os.Stat(vmlinuxBTF); err != nil {
			return fmt.Errorf("--vmlinux-btf: %w", err)
		}
	}
	for _, tool := range []string{"sh", "make", "modinfo", "readelf"} {
		if _, err := system.lookPath(tool); err != nil {
			return fmt.Errorf("%s is required to build the module", tool)
		}
	}
	work, err := os.MkdirTemp("", "veer-kfuncs-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := extractKernelHelperSource(source, work); err != nil {
		return fmt.Errorf("extract module source: %w", err)
	}
	fmt.Fprintf(stdout, "building %s for kernel %s with %s\n", kernelHelperModuleFile, release, kdir)
	if err := system.run(work, kernelHelperBuildEnv(os.Environ(), kdir, vmlinuxBTF), stdout, stderr); err != nil {
		if release != running && vmlinuxBTF == "" {
			return fmt.Errorf("build module: %w; for a kernel that is not running, pass --vmlinux-btf with that kernel's vmlinux or BTF, or build after booting it", err)
		}
		return fmt.Errorf("build module: %w", err)
	}
	built := filepath.Join(work, kernelHelperModuleFile)
	if err := validateKernelHelperModuleFile(built, release); err != nil {
		return err
	}
	installed, err := installKernelHelperModule(built, options.InstallDir, release)
	if err != nil {
		return fmt.Errorf("install module: %w", err)
	}
	fmt.Fprintf(stdout, "installed %s\n", installed)
	if release == running {
		fmt.Fprintln(stdout, "restart the Veer service to load it; PPPoE sessions move to the single-port boundary on their next redial")
	} else {
		fmt.Fprintf(stdout, "Veer loads it after the host boots kernel %s\n", release)
	}
	return nil
}
