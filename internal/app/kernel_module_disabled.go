//go:build !linux || !veer_kfuncs

package app

import "io/fs"

func optionalKernelModuleWANFeatureStatus() PluginHostFeatureStatus {
	return optionalKernelModuleFeatureStatus()
}

const optionalKernelModuleCompiled = false

func kernelHelperEmbeddedSource() (fs.FS, bool) { return nil, false }

func startOptionalKernelModule() (func(), error) { return func() {}, nil }
func optionalKernelModuleFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "host was built without Linux veer_kfuncs support"}
}

func optionalKernelModuleIngressFeatureStatus() PluginHostFeatureStatus {
	return optionalKernelModuleFeatureStatus()
}
