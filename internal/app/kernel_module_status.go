package app

import (
	"os"
	"runtime"
)

const optionalKernelModuleName = "veer_kfuncs"

type KernelHelperModuleStatus struct {
	Name      string `json:"name"`
	Compiled  bool   `json:"compiled"`
	Loaded    bool   `json:"loaded"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Install state beside the binary, so a kernel upgrade that left no
	// matching module is reported instead of silently using the base path.
	KernelRelease       string   `json:"kernel_release,omitempty"`
	ModulePath          string   `json:"module_path,omitempty"`
	ModuleInstalled     bool     `json:"module_installed"`
	OtherModuleReleases []string `json:"other_module_releases,omitempty"`
	RebuildCommand      string   `json:"rebuild_command,omitempty"`
}

func optionalKernelModuleRuntimeStatus() KernelHelperModuleStatus {
	feature := optionalKernelModuleFeatureStatus()
	status := KernelHelperModuleStatus{Name: optionalKernelModuleName, Compiled: optionalKernelModuleCompiled,
		Available: feature.Available, Reason: feature.Reason}
	if runtime.GOOS != "linux" {
		return status
	}
	info, err := os.Stat("/sys/module/" + optionalKernelModuleName)
	status.Loaded = err == nil && info.IsDir()
	executable, install, ok := currentKernelHelperInstall()
	if !ok {
		return status
	}
	return withKernelHelperInstall(status, executable, install)
}

func withKernelHelperInstall(status KernelHelperModuleStatus, executable string, install kernelHelperInstall) KernelHelperModuleStatus {
	status.KernelRelease = install.KernelRelease
	status.ModulePath = install.ModulePath
	status.ModuleInstalled = install.ModuleInstalled
	status.OtherModuleReleases = install.OtherReleases
	if status.Compiled && !status.Available && !status.Loaded && !install.ModuleInstalled {
		// The probe's own reason only says /sys/module is absent. Only a host
		// that installed a module for another kernel gets the rebuild command.
		if !install.optedIn() {
			status.Reason = kernelHelperNotInstalledReason
			return status
		}
		status.Reason = install.missingReason()
		status.RebuildCommand = kernelHelperBuildCommand(executable, "")
	}
	return status
}
