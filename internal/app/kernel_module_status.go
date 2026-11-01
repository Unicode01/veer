package app

import (
	"os"
	"runtime"
)

type KernelHelperModuleStatus struct {
	Name      string `json:"name"`
	Compiled  bool   `json:"compiled"`
	Loaded    bool   `json:"loaded"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func optionalKernelModuleRuntimeStatus() KernelHelperModuleStatus {
	feature := optionalKernelModuleFeatureStatus()
	loaded := false
	if runtime.GOOS == "linux" {
		info, err := os.Stat("/sys/module/veer_kfuncs")
		loaded = err == nil && info.IsDir()
	}
	return KernelHelperModuleStatus{Name: "veer_kfuncs", Compiled: optionalKernelModuleCompiled,
		Loaded: loaded, Available: feature.Available, Reason: feature.Reason}
}
