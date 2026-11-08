//go:build linux

package app

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

type kernelHelperTestSection struct {
	name string
	data []byte
}

// kernelHelperTestELF writes a minimal ELF64 relocatable with the given
// sections, enough for debug/elf and validateKernelHelperModuleFile.
func kernelHelperTestELF(sections ...kernelHelperTestSection) []byte {
	names := []byte{0}
	nameOffsets := make([]uint32, len(sections))
	for i, section := range sections {
		nameOffsets[i] = uint32(len(names))
		names = append(append(names, section.name...), 0)
	}
	shstrtabName := uint32(len(names))
	names = append(append(names, ".shstrtab"...), 0)

	var body bytes.Buffer
	body.Write(make([]byte, 64))
	offsets := make([]uint64, len(sections))
	for i, section := range sections {
		offsets[i] = uint64(body.Len())
		body.Write(section.data)
	}
	namesOffset := uint64(body.Len())
	body.Write(names)
	for body.Len()%8 != 0 {
		body.WriteByte(0)
	}
	sectionHeaders := uint64(body.Len())
	writeHeader := func(name uint32, kind elf.SectionType, offset uint64, size int) {
		_ = binary.Write(&body, binary.LittleEndian, elf.Section64{
			Name: name, Type: uint32(kind), Off: offset, Size: uint64(size), Addralign: 1,
		})
	}
	writeHeader(0, elf.SHT_NULL, 0, 0)
	for i, section := range sections {
		writeHeader(nameOffsets[i], elf.SHT_PROGBITS, offsets[i], len(section.data))
	}
	writeHeader(shstrtabName, elf.SHT_STRTAB, namesOffset, len(names))

	var header bytes.Buffer
	_ = binary.Write(&header, binary.LittleEndian, elf.Header64{
		Ident: [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:  uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: sectionHeaders, Ehsize: 64, Shentsize: 64,
		Shnum: uint16(len(sections) + 2), Shstrndx: uint16(len(sections) + 1),
	})
	out := body.Bytes()
	copy(out, header.Bytes())
	return out
}

func kernelHelperTestModule(name, release string, withBTF bool) []byte {
	sections := []kernelHelperTestSection{{
		name: ".modinfo",
		data: []byte("license=GPL\x00name=" + name + "\x00vermagic=" + release + " SMP preempt mod_unload \x00"),
	}}
	if withBTF {
		sections = append(sections, kernelHelperTestSection{name: ".BTF", data: []byte{0x9f, 0xeb, 1, 0}})
	}
	return kernelHelperTestELF(sections...)
}

func TestValidKernelRelease(t *testing.T) {
	for _, release := range []string{"6.12.74+deb12-cloud-amd64", "7.0.14-8-pve", "5.14.0-427.el9.x86_64", "6.6.0"} {
		if !validKernelRelease(release) {
			t.Errorf("validKernelRelease(%q) = false", release)
		}
	}
	for _, release := range []string{"", ".", "..", "../6.1", "6.1/x", "6.1 x", "_6.1", "-6.1", "veer_kfuncs", strings.Repeat("6", 65)} {
		if validKernelRelease(release) {
			t.Errorf("validKernelRelease(%q) = true", release)
		}
	}
}

func TestInspectKernelHelperInstallReportsUpgradeGap(t *testing.T) {
	dir := t.TempDir()
	write := func(release string) {
		path := kernelHelperModulePath(dir, release)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("module"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("6.12.73+deb12-amd64")
	write("6.12.72+deb12-amd64")
	// The source checkout directory and links never count as installs.
	write("veer_kfuncs")
	if err := os.MkdirAll(filepath.Join(dir, "kernel", "6.12.70"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kernelHelperModulePath(dir, "6.12.73+deb12-amd64"), kernelHelperModulePath(dir, "6.12.70")); err != nil {
		t.Fatal(err)
	}

	state := inspectKernelHelperInstall(dir, "6.12.74+deb12-amd64")
	if state.ModuleInstalled {
		t.Fatalf("module for the running kernel must be missing: %+v", state)
	}
	if got := strings.Join(state.OtherReleases, ","); got != "6.12.72+deb12-amd64,6.12.73+deb12-amd64" {
		t.Fatalf("other releases = %q", got)
	}
	reason := state.missingReason()
	if !strings.Contains(reason, "running kernel 6.12.74+deb12-amd64") || !strings.Contains(reason, "installed for 6.12.72+deb12-amd64, 6.12.73+deb12-amd64") {
		t.Fatalf("reason = %q", reason)
	}

	write("6.12.74+deb12-amd64")
	if state := inspectKernelHelperInstall(dir, "6.12.74+deb12-amd64"); !state.ModuleInstalled || len(state.OtherReleases) != 2 {
		t.Fatalf("installed state = %+v", state)
	}
	if state := inspectKernelHelperInstall(dir, "6.12.70"); state.ModuleInstalled {
		t.Fatalf("a symlinked module must not count as installed: %+v", state)
	}
}

func TestValidateKernelHelperModuleFile(t *testing.T) {
	dir := t.TempDir()
	check := func(data []byte, release string) error {
		path := filepath.Join(dir, "module.ko")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return validateKernelHelperModuleFile(path, release)
	}
	if err := check(kernelHelperTestModule("veer_kfuncs", "6.12.74", true), "6.12.74"); err != nil {
		t.Fatalf("valid module rejected: %v", err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"release": {kernelHelperTestModule("veer_kfuncs", "6.12.73", true), "for kernel 6.12.73, not 6.12.74"},
		"btf":     {kernelHelperTestModule("veer_kfuncs", "6.12.74", false), "no BTF"},
		"name":    {kernelHelperTestModule("other", "6.12.74", true), `"other"`},
		"elf":     {[]byte("not an elf"), "read built module"},
	} {
		if err := check(tc.data, "6.12.74"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

type kernelHelperFakeBuild struct {
	calls  int
	module []byte
	env    []string
	err    error
}

func kernelHelperFakeSystem(build *kernelHelperFakeBuild) kernelHelperBuildSystem {
	return kernelHelperBuildSystem{
		source: func() (fs.FS, bool) {
			return fstest.MapFS{
				"build.sh":      {Data: []byte("#!/bin/sh\n")},
				"Kbuild":        {Data: []byte("obj-m += veer_kfuncs.o\n")},
				"Makefile":      {Data: []byte("all:\n")},
				"veer_kfuncs.c": {Data: []byte("/* fixture */\n")},
			}, true
		},
		euid:     func() int { return 0 },
		running:  func() (string, error) { return "6.12.74", nil },
		lookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		run: func(dir string, env []string, stdout, stderr io.Writer) error {
			build.calls++
			build.env = env
			for _, name := range []string{"build.sh", "Kbuild", "Makefile", "veer_kfuncs.c"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					return fmt.Errorf("source not extracted: %w", err)
				}
			}
			if build.err != nil {
				return build.err
			}
			return os.WriteFile(filepath.Join(dir, kernelHelperModuleFile), build.module, 0o644)
		},
	}
}

func kernelHelperTestKDIR(t *testing.T) string {
	t.Helper()
	kdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(kdir, "Makefile"), []byte("all:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return kdir
}

func TestBuildKernelHelperModuleInstallsValidatedModule(t *testing.T) {
	t.Setenv("KDIR", "/inherited/must/not/win")
	t.Setenv("VMLINUX_BTF", "/inherited/btf")
	installDir := t.TempDir()
	kdir := kernelHelperTestKDIR(t)
	build := &kernelHelperFakeBuild{module: kernelHelperTestModule("veer_kfuncs", "6.12.74", true)}
	options := kernelHelperBuildOptions{KDIR: kdir, InstallDir: installDir}
	var stdout bytes.Buffer
	if err := buildKernelHelperModule(options, kernelHelperFakeSystem(build), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	var kdirs, btfs []string
	for _, item := range build.env {
		if strings.HasPrefix(item, "KDIR=") {
			kdirs = append(kdirs, item)
		}
		if strings.HasPrefix(item, "VMLINUX_BTF=") {
			btfs = append(btfs, item)
		}
	}
	if len(kdirs) != 1 || kdirs[0] != "KDIR="+kdir || len(btfs) != 0 {
		t.Fatalf("build env KDIR=%v VMLINUX_BTF=%v", kdirs, btfs)
	}
	dest := kernelHelperModulePath(installDir, "6.12.74")
	info, err := os.Lstat(dest)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("installed module %v mode %v", err, info)
	}
	if data, _ := os.ReadFile(dest); !bytes.Equal(data, build.module) {
		t.Fatal("installed module differs from the build output")
	}
	if !strings.Contains(stdout.String(), "restart the Veer service") {
		t.Fatalf("missing restart hint: %s", stdout.String())
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}

	stdout.Reset()
	if err := buildKernelHelperModule(options, kernelHelperFakeSystem(build), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if build.calls != 1 || !strings.Contains(stdout.String(), "--force") {
		t.Fatalf("existing module must not be rebuilt without --force: calls=%d out=%s", build.calls, stdout.String())
	}
	options.Force = true
	if err := buildKernelHelperModule(options, kernelHelperFakeSystem(build), io.Discard, io.Discard); err != nil || build.calls != 2 {
		t.Fatalf("--force rebuild: err=%v calls=%d", err, build.calls)
	}
}

func TestBuildKernelHelperModuleForPendingKernel(t *testing.T) {
	installDir := t.TempDir()
	kdir := kernelHelperTestKDIR(t)
	btf := filepath.Join(t.TempDir(), "vmlinux")
	if err := os.WriteFile(btf, []byte("btf"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := &kernelHelperFakeBuild{err: errors.New("exit status 1")}
	options := kernelHelperBuildOptions{Release: "6.12.80", KDIR: kdir, InstallDir: installDir}
	err := buildKernelHelperModule(options, kernelHelperFakeSystem(build), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--vmlinux-btf") {
		t.Fatalf("cross-kernel failure must suggest --vmlinux-btf: %v", err)
	}

	build = &kernelHelperFakeBuild{module: kernelHelperTestModule("veer_kfuncs", "6.12.80", true)}
	options.VMLinuxBTF = btf
	var stdout bytes.Buffer
	if err := buildKernelHelperModule(options, kernelHelperFakeSystem(build), &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range build.env {
		found = found || item == "VMLINUX_BTF="+btf
	}
	if !found || !strings.Contains(stdout.String(), "boots kernel 6.12.80") {
		t.Fatalf("pending-kernel build: env=%v out=%s", build.env, stdout.String())
	}
	if !kernelHelperRegularFile(kernelHelperModulePath(installDir, "6.12.80")) {
		t.Fatal("pending-kernel module not installed")
	}
}

func TestBuildKernelHelperModuleRejectsUnsafeOrMismatchedBuilds(t *testing.T) {
	kdir := kernelHelperTestKDIR(t)
	for name, tc := range map[string]struct {
		options func(*kernelHelperBuildOptions)
		system  func(*kernelHelperBuildSystem)
		module  []byte
		want    string
	}{
		"no embedded source": {system: func(s *kernelHelperBuildSystem) {
			s.source = func() (fs.FS, bool) { return nil, false }
		}, want: "VEER_BUILD_KERNEL_MODULE=1"},
		"not root":    {system: func(s *kernelHelperBuildSystem) { s.euid = func() int { return 1000 } }, want: "must run as root"},
		"bad release": {options: func(o *kernelHelperBuildOptions) { o.Release = "../6.12" }, want: "invalid kernel release"},
		"no headers":  {options: func(o *kernelHelperBuildOptions) { o.KDIR = filepath.Join(kdir, "missing") }, want: "linux-headers-6.12.74"},
		"missing tool": {system: func(s *kernelHelperBuildSystem) {
			s.lookPath = func(string) (string, error) { return "", errors.New("nope") }
		}, want: "is required"},
		"wrong kernel":  {module: kernelHelperTestModule("veer_kfuncs", "6.12.73", true), want: "for kernel 6.12.73"},
		"missing BTF":   {module: kernelHelperTestModule("veer_kfuncs", "6.12.74", false), want: "no BTF"},
		"missing BTFfn": {options: func(o *kernelHelperBuildOptions) { o.VMLinuxBTF = filepath.Join(kdir, "nope") }, want: "--vmlinux-btf"},
	} {
		t.Run(name, func(t *testing.T) {
			installDir := t.TempDir()
			module := tc.module
			if module == nil {
				module = kernelHelperTestModule("veer_kfuncs", "6.12.74", true)
			}
			build := &kernelHelperFakeBuild{module: module}
			system := kernelHelperFakeSystem(build)
			if tc.system != nil {
				tc.system(&system)
			}
			options := kernelHelperBuildOptions{KDIR: kdir, InstallDir: installDir}
			if tc.options != nil {
				tc.options(&options)
			}
			err := buildKernelHelperModule(options, system, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if kernelHelperRegularFile(kernelHelperModulePath(installDir, "6.12.74")) {
				t.Fatal("a rejected build must not install a module")
			}
		})
	}
}

func TestKernelHelperStartupDetailExplainsMissingModule(t *testing.T) {
	const executable = "/opt/veer/veer"
	missing := fmt.Errorf("open optional module: %w", fs.ErrNotExist)
	upgraded := kernelHelperInstall{KernelRelease: "6.12.74", OtherReleases: []string{"6.12.73"}}
	detail := kernelHelperStartupDetail(missing, executable, upgraded, true)
	if !strings.Contains(detail, "running kernel 6.12.74") || !strings.Contains(detail, "installed for 6.12.73") || !strings.Contains(detail, executable+" kfuncs build") {
		t.Fatalf("detail after a kernel upgrade = %q", detail)
	}
	// Release binaries carry helper support on every host; one that never
	// installed a module is told so without being asked to build one.
	if got := kernelHelperStartupDetail(missing, executable, kernelHelperInstall{KernelRelease: "6.12.74"}, true); got != kernelHelperNotInstalledReason {
		t.Fatalf("detail without any module = %q, want %q", got, kernelHelperNotInstalledReason)
	}
	if got := kernelHelperStartupDetail(missing, executable, upgraded, false); got != missing.Error() {
		t.Fatalf("uninspected install must keep the error: %q", got)
	}
	if got := kernelHelperStartupDetail(errors.New("load optional module: operation not permitted"), executable, upgraded, true); got != "load optional module: operation not permitted" {
		t.Fatalf("other errors must pass through: %q", got)
	}
	if got := kernelHelperStartupDetail(nil, executable, upgraded, true); got != "" {
		t.Fatalf("no error = %q", got)
	}
}

func TestKernelHelperStatusOffersRebuildOnlyAfterOptIn(t *testing.T) {
	const executable = "/opt/veer/veer"
	base := KernelHelperModuleStatus{Name: optionalKernelModuleName, Compiled: true, Reason: "module is not loaded"}

	dormant := withKernelHelperInstall(base, executable, kernelHelperInstall{KernelRelease: "6.12.74"})
	if dormant.Reason != kernelHelperNotInstalledReason || dormant.RebuildCommand != "" || dormant.ModuleInstalled {
		t.Fatalf("host without any module = %+v", dormant)
	}

	upgraded := withKernelHelperInstall(base, executable, kernelHelperInstall{KernelRelease: "6.12.74", OtherReleases: []string{"6.12.73"}})
	if !strings.Contains(upgraded.Reason, "running kernel 6.12.74") || upgraded.RebuildCommand != executable+" kfuncs build" {
		t.Fatalf("host after a kernel upgrade = %+v", upgraded)
	}

	installed := withKernelHelperInstall(base, executable, kernelHelperInstall{KernelRelease: "6.12.74", ModuleInstalled: true})
	if installed.Reason != base.Reason || installed.RebuildCommand != "" {
		t.Fatalf("an installed module keeps the probe's reason: %+v", installed)
	}

	unsupported := withKernelHelperInstall(KernelHelperModuleStatus{Name: optionalKernelModuleName}, executable, kernelHelperInstall{KernelRelease: "6.12.74", OtherReleases: []string{"6.12.73"}})
	if unsupported.RebuildCommand != "" {
		t.Fatalf("a binary without helper support cannot rebuild: %+v", unsupported)
	}
}

func TestKernelHelperCLIDispatchAndStatus(t *testing.T) {
	if handled, _ := runKernelHelperCLI([]string{"plugin", "lint"}, io.Discard, io.Discard); handled {
		t.Fatal("non-kfuncs commands must fall through")
	}
	if handled, err := runKernelHelperCLI([]string{"kfuncs"}, io.Discard, io.Discard); !handled || err == nil {
		t.Fatalf("missing subcommand: handled=%v err=%v", handled, err)
	}
	if handled, err := runKernelHelperCLI([]string{"kfuncs", "bogus"}, io.Discard, io.Discard); !handled || err == nil {
		t.Fatalf("unknown subcommand: handled=%v err=%v", handled, err)
	}
	var usage bytes.Buffer
	if _, err := runKernelHelperCLI([]string{"kfuncs", "help"}, &usage, io.Discard); err != nil || !strings.Contains(usage.String(), "veer kfuncs build") {
		t.Fatalf("help: err=%v out=%s", err, usage.String())
	}
	if _, err := runningKernelRelease(); err != nil {
		t.Skipf("running kernel release unavailable: %v", err)
	}
	installDir := t.TempDir()
	var stdout bytes.Buffer
	if _, err := runKernelHelperCLI([]string{"kfuncs", "status", "--json", "--install-dir", installDir}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	var status kernelHelperCLIStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("status JSON: %v\n%s", err, stdout.String())
	}
	if status.BinarySupport != optionalKernelModuleCompiled || status.ModuleInstalled || status.InstallDir != installDir || status.NextStep == "" {
		t.Fatalf("status = %+v", status)
	}
	if status.BinarySupport && !strings.Contains(status.NextStep, "kfuncs build --install-dir "+installDir) {
		t.Fatalf("next step = %q", status.NextStep)
	}
}
