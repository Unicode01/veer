//go:build !linux || !veer_kfuncs

package app

func startOptionalKernelModule() (func(), error) { return func() {}, nil }
func optionalKernelModuleFeatureStatus() PluginHostFeatureStatus {
	return PluginHostFeatureStatus{Reason: "host was built without Linux veer_kfuncs support"}
}
