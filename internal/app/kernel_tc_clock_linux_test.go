//go:build linux

package app

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestUseKernelCoarseClockSwitchesOnlyClockCalls(t *testing.T) {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"main": {Instructions: asm.Instructions{
			asm.FnKtimeGetNs.Call(),
			asm.FnMapLookupElem.Call(),
			asm.Call.Label("sub"),
			asm.Mov.Imm(asm.R0, 5),
			asm.Return(),
		}},
		"other": {Instructions: asm.Instructions{
			asm.FnKtimeGetNs.Call(),
			asm.Return(),
		}},
	}}

	if got := useKernelCoarseClock(spec); got != 2 {
		t.Fatalf("useKernelCoarseClock() = %d, want 2", got)
	}
	first := spec.Programs["main"].Instructions
	if fn := asm.BuiltinFunc(first[0].Constant); fn != asm.FnKtimeGetCoarseNs {
		t.Fatalf("clock call = %v, want %v", fn, asm.FnKtimeGetCoarseNs)
	}
	if fn := asm.BuiltinFunc(first[1].Constant); fn != asm.FnMapLookupElem {
		t.Fatalf("other helper call = %v, want %v", fn, asm.FnMapLookupElem)
	}
	if first[3].Constant != 5 {
		t.Fatalf("immediate operand = %d, want 5", first[3].Constant)
	}
	if fn := asm.BuiltinFunc(spec.Programs["other"].Instructions[0].Constant); fn != asm.FnKtimeGetCoarseNs {
		t.Fatalf("second program clock call = %v, want %v", fn, asm.FnKtimeGetCoarseNs)
	}
}

func TestEmbeddedTCObjectsReadTheClockThroughSwitchableCalls(t *testing.T) {
	for _, enableTrafficStats := range []bool{false, true} {
		objectBytes, objectName := kernelTCObjectBytes(enableTrafficStats)
		if len(objectBytes) == 0 {
			t.Skipf("%s is not built", objectName)
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
		if err != nil {
			t.Fatalf("load %s: %v", objectName, err)
		}
		if got := useKernelCoarseClock(spec); got == 0 {
			t.Fatalf("%s: no bpf_ktime_get_ns call was switched", objectName)
		}
		for name, prog := range spec.Programs {
			for _, ins := range prog.Instructions {
				if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnKtimeGetNs {
					t.Fatalf("%s: program %s still calls bpf_ktime_get_ns", objectName, name)
				}
			}
		}
	}
}
