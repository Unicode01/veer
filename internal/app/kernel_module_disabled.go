//go:build !linux || !veer_kfuncs

package app

const optionalKernelModuleCompiled = false

func startOptionalKernelModule() (func(), error) { return func() {}, nil }
func optionalKernelModuleFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "host was built without Linux veer_kfuncs support"}
}

func optionalKernelModuleIngressFeatureStatus() PluginHostFeatureStatus {
	return optionalKernelModuleFeatureStatus()
}
