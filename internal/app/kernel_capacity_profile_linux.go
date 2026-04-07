//go:build linux

package app

import (
	"math"

	"golang.org/x/sys/unix"
)

func detectKernelAdaptiveMapTotalMemory() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}

	total := uint64(info.Totalram)
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	if total > math.MaxUint64/unit {
		return math.MaxUint64
	}
	return total * unit
}
