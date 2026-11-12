//go:build linux

package app

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// The TC programs only compare flow timestamps against windows of a second
// or more. bpf_ktime_get_coarse_ns (Linux 5.11+) reads the same
// CLOCK_MONOTONIC as bpf_ktime_get_ns at tick resolution, so it lags by at
// most one tick, and it skips the clocksource read, which costs tens of
// nanoseconds per packet on virtualised clocks such as kvm-clock. Older
// kernels keep bpf_ktime_get_ns.
var kernelCoarseClockSupported = sync.OnceValue(func() bool {
	return features.HaveProgramHelper(ebpf.SchedCLS, asm.FnKtimeGetCoarseNs) == nil
})

// useKernelCoarseClock switches every bpf_ktime_get_ns call in spec to
// bpf_ktime_get_coarse_ns and reports how many calls it changed. All TC
// programs share the flow maps, so they must read the same clock.
func useKernelCoarseClock(spec *ebpf.CollectionSpec) int {
	changed := 0
	for _, prog := range spec.Programs {
		for i := range prog.Instructions {
			ins := &prog.Instructions[i]
			if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnKtimeGetNs {
				ins.Constant = int64(asm.FnKtimeGetCoarseNs)
				changed++
			}
		}
	}
	return changed
}
