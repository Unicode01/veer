//go:build !linux

package kernelcap

func DetectAdaptiveMapTotalMemory() uint64 {
	return 0
}
