package app

import "runtime"

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
	// srcversion of the loaded module and of the installed file. A hot
	// restart keeps the loaded module, so they differ after a module update
	// until a full restart; ReloadHint then says how to load the file.
	LoadedSrcVersion       string `json:"loaded_srcversion,omitempty"`
	InstalledSrcVersion    string `json:"installed_srcversion,omitempty"`
	LoadedMatchesInstalled *bool  `json:"loaded_matches_installed,omitempty"`
	ReloadHint             string `json:"reload_hint,omitempty"`
}

func optionalKernelModuleRuntimeStatus() KernelHelperModuleStatus {
	feature := optionalKernelModuleFeatureStatus()
	status := KernelHelperModuleStatus{Name: optionalKernelModuleName, Compiled: optionalKernelModuleCompiled,
		Available: feature.Available, Reason: feature.Reason}
	if runtime.GOOS != "linux" {
		return status
	}
	loaded, isLoaded := loadedKernelHelperModuleBuild(kernelHelperSysModuleDir)
	status.Loaded = isLoaded
	executable, install, ok := currentKernelHelperInstall()
	if !ok {
		return status
	}
	status = withKernelHelperInstall(status, executable, install)
	if isLoaded && install.ModuleInstalled {
		if installed, err := readKernelHelperModuleBuild(install.ModulePath); err == nil {
			status = withKernelHelperBuilds(status, loaded, installed, install.ModulePath)
		}
	}
	return status
}

func withKernelHelperBuilds(status KernelHelperModuleStatus, loaded, installed kernelHelperModuleBuild, path string) KernelHelperModuleStatus {
	status.LoadedSrcVersion = loaded.SrcVersion
	status.InstalledSrcVersion = installed.SrcVersion
	if matches, known := kernelHelperLoadedMatches(loaded, installed); known {
		status.LoadedMatchesInstalled = &matches
	}
	status.ReloadHint = kernelHelperStaleDetail(loaded, installed, path)
	return status
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
