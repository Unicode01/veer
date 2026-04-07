//go:build !linux

package app

func detectKernelAdaptiveMapTotalMemory() uint64 {
	return 0
}
