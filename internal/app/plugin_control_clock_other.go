//go:build !linux

package app

import "time"

var pluginMonotonicEpoch = time.Now()

// pluginMonotonicNanoseconds has no eBPF clock to match off Linux. It stays
// monotonic by counting from process start on Go's monotonic clock.
func pluginMonotonicNanoseconds() (int64, error) {
	return int64(time.Since(pluginMonotonicEpoch)), nil
}
