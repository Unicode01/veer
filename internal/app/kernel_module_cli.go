package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func runKernelHelperCLI(args []string, stdout, stderr io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "kfuncs" {
		return false, nil
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) < 2 {
		writeKernelHelperCLIUsage(stderr)
		return true, errors.New("kfuncs subcommand is required")
	}
	switch args[1] {
	case "status":
		return true, runKernelHelperStatusCLI(args[2:], stdout, stderr)
	case "build":
		return true, runKernelHelperBuildCLI(args[2:], stdout, stderr)
	case "help", "-h", "--help":
		writeKernelHelperCLIUsage(stdout)
		return true, nil
	}
	writeKernelHelperCLIUsage(stderr)
	return true, fmt.Errorf("unknown kfuncs subcommand %q", args[1])
}

func writeKernelHelperCLIUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  veer kfuncs status [--json] [--install-dir DIR]
  veer kfuncs build [--kernel RELEASE] [--kdir DIR] [--vmlinux-btf FILE] [--install-dir DIR] [--force]

status shows whether a veer_kfuncs module is installed for the running kernel.
build compiles the module source embedded in this binary and installs it as
<install-dir>/kernel/<release>/veer_kfuncs.ko. It runs as root and needs make,
the kernel's compiler and headers, plus pahole and resolve_btfids when the
headers cannot emit module BTF. The install directory defaults to the
directory of this binary, which is where the daemon loads modules from.
`)
}

func kernelHelperCLIInstallDir(value string) (string, string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if value == "" {
		return executable, filepath.Dir(executable), nil
	}
	dir, err := filepath.Abs(value)
	return executable, dir, err
}

type kernelHelperCLIStatus struct {
	BinarySupport       bool     `json:"binary_support"`
	KernelRelease       string   `json:"kernel_release"`
	InstallDir          string   `json:"install_dir"`
	ModulePath          string   `json:"module_path"`
	ModuleInstalled     bool     `json:"module_installed"`
	OtherModuleReleases []string `json:"other_module_releases"`
	Loaded              bool     `json:"loaded"`
	NextStep            string   `json:"next_step,omitempty"`
}

func runKernelHelperStatusCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("kfuncs status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print JSON")
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	if err := flags.Parse(args); err != nil {
		return cliFlagError(err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if runtime.GOOS != "linux" {
		return errors.New("kernel helper modules are Linux-only")
	}
	executable, dir, err := kernelHelperCLIInstallDir(*installDir)
	if err != nil {
		return err
	}
	release, err := runningKernelRelease()
	if err != nil {
		return fmt.Errorf("read running kernel release: %w", err)
	}
	_, binarySupport := kernelHelperEmbeddedSource()
	install := inspectKernelHelperInstall(dir, release)
	status := kernelHelperCLIStatus{
		BinarySupport:       binarySupport,
		KernelRelease:       release,
		InstallDir:          dir,
		ModulePath:          install.ModulePath,
		ModuleInstalled:     install.ModuleInstalled,
		OtherModuleReleases: append([]string{}, install.OtherReleases...),
	}
	if info, err := os.Stat("/sys/module/" + optionalKernelModuleName); err == nil && info.IsDir() {
		status.Loaded = true
	}
	switch {
	case !binarySupport:
		status.NextStep = "this binary was built without veer_kfuncs support; rebuild Veer with VEER_BUILD_KERNEL_MODULE=1"
	case !install.ModuleInstalled:
		status.NextStep = kernelHelperBuildCommand(executable, dir)
	}
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	}
	yesNo := func(value bool) string {
		if value {
			return "yes"
		}
		return "no"
	}
	others := "none"
	if len(status.OtherModuleReleases) > 0 {
		others = strings.Join(status.OtherModuleReleases, ", ")
	}
	fmt.Fprintf(stdout, "binary support:   %s\n", yesNo(status.BinarySupport))
	fmt.Fprintf(stdout, "running kernel:   %s\n", status.KernelRelease)
	fmt.Fprintf(stdout, "module:           %s\n", status.ModulePath)
	fmt.Fprintf(stdout, "installed:        %s\n", yesNo(status.ModuleInstalled))
	fmt.Fprintf(stdout, "other kernels:    %s\n", others)
	fmt.Fprintf(stdout, "loaded:           %s\n", yesNo(status.Loaded))
	if status.NextStep != "" {
		fmt.Fprintf(stdout, "next step:        %s\n", status.NextStep)
	}
	return nil
}

func runKernelHelperBuildCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("kfuncs build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	release := flags.String("kernel", "", "target kernel release (default: the running kernel)")
	kdir := flags.String("kdir", "", "kernel build tree (default: /lib/modules/<release>/build)")
	vmlinuxBTF := flags.String("vmlinux-btf", "", "vmlinux or BTF of the target kernel; needed for a kernel that is not running when its headers cannot emit module BTF")
	installDir := flags.String("install-dir", "", "Veer install directory (default: directory of this binary)")
	force := flags.Bool("force", false, "rebuild even when a module is installed for the kernel")
	if err := flags.Parse(args); err != nil {
		return cliFlagError(err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if runtime.GOOS != "linux" {
		return errors.New("kernel helper modules are Linux-only")
	}
	_, dir, err := kernelHelperCLIInstallDir(*installDir)
	if err != nil {
		return err
	}
	return buildKernelHelperModule(kernelHelperBuildOptions{
		Release: *release, KDIR: *kdir, VMLinuxBTF: *vmlinuxBTF, InstallDir: dir, Force: *force,
	}, defaultKernelHelperBuildSystem(), stdout, stderr)
}
