package app

import (
	"github.com/dop251/goja"
)

// ebpfMonotonicMs implements ebpf.monotonicMs(): CLOCK_MONOTONIC in
// milliseconds, the clock bpf_ktime_get_ns() reads, so control scripts can
// compare it with ktime nanoseconds an eBPF program stored (divided by 1e6).
// The value may carry a fractional part.
func (h *pluginControlHost) ebpfMonotonicMs(goja.FunctionCall) goja.Value {
	if h.registrationPhase {
		h.throwf("ebpf.monotonicMs is unavailable during plugin registration")
	}
	if h.migrationPhase {
		h.throwf("ebpf.monotonicMs is unavailable during plugin resource migration")
	}
	if h.upgradePhase {
		h.throwf("ebpf.monotonicMs is unavailable during plugin upgrade snapshot/restore")
	}
	nanoseconds, err := pluginMonotonicNanoseconds()
	if err != nil {
		h.throwf("ebpf.monotonicMs: %v", err)
	}
	return h.vm.ToValue(float64(nanoseconds) / 1e6)
}
