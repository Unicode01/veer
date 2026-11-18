//go:build linux

package app

import (
	"golang.org/x/sys/unix"
)

// pluginMonotonicNanoseconds reads CLOCK_MONOTONIC, the clock behind
// bpf_ktime_get_ns().
func pluginMonotonicNanoseconds() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return ts.Nano(), nil
}
