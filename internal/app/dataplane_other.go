//go:build !linux

package app

func resolveKernelTransientFallbackBackendMAC(rule Rule, reasonClass string) string {
	return ""
}
