//go:build linux

package app

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// The TC and XDP objects take their settings when they are loaded instead of
// being built once per combination. Each setting is a const volatile global in
// the object's .rodata. veer writes it into the spec before loading; the loader
// then freezes .rodata read-only, so the verifier reads the value as a constant,
// walks only the branches it selects and removes the rest before the programs
// are JIT-compiled. See forward_load_traffic_stats in forward-tc-bpf.c.
const kernelLoadTrafficStatsVariable = "forward_load_traffic_stats"

// setKernelLoadSettings writes the load-time settings into spec.
func setKernelLoadSettings(spec *ebpf.CollectionSpec, enableTrafficStats bool) error {
	variable := spec.Variables[kernelLoadTrafficStatsVariable]
	if variable == nil {
		return fmt.Errorf("eBPF object has no %s setting", kernelLoadTrafficStatsVariable)
	}
	if !variable.Constant() {
		return fmt.Errorf("eBPF setting %s is not read-only, so the verifier would keep both paths", kernelLoadTrafficStatsVariable)
	}
	var value uint32
	if enableTrafficStats {
		value = 1
	}
	if err := variable.Set(value); err != nil {
		return fmt.Errorf("set eBPF setting %s: %w", kernelLoadTrafficStatsVariable, err)
	}
	foldKernelLoadSettings(spec, variable, int64(value))
	return nil
}

// foldKernelLoadSettings turns reads of a setting into its value. With .rodata
// frozen the verifier already knows the value and drops the code it turns off,
// but each read stays behind: a 64-bit load of the setting's address and a
// load through it, run wherever the setting is checked. A read right after the
// address load folds:
//   - into the register that held the address, the pair becomes the value as
//     a 64-bit immediate and a jump to the next instruction, which the
//     verifier removes;
//   - into another register, the read becomes a move of the value, and the
//     address stays loaded in case later code uses it.
//
// Any other read, and a read that a jump lands on, is left as it is and still
// sees the frozen value. It reports how many reads it folded.
func foldKernelLoadSettings(spec *ebpf.CollectionSpec, variable *ebpf.VariableSpec, value int64) int {
	folded := 0
	for _, prog := range spec.Programs {
		insns := prog.Instructions
		offsets := make([]asm.RawInstructionOffset, len(insns))
		targets := make(map[asm.RawInstructionOffset]bool)
		iter := insns.Iterate()
		for iter.Next() {
			offsets[iter.Index] = iter.Offset
			ins := iter.Ins
			if !ins.OpCode.Class().IsJump() {
				continue
			}
			switch ins.OpCode.JumpOp() {
			case asm.Call, asm.Exit, asm.InvalidJumpOp:
				continue
			}
			jump := int64(ins.Offset)
			if ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja {
				jump = ins.Constant
			}
			targets[asm.RawInstructionOffset(int64(iter.Offset)+1+jump)] = true
		}
		for i := 0; i+1 < len(insns); i++ {
			addr, load := &insns[i], &insns[i+1]
			if !addr.IsLoadFromMap() || addr.Src != asm.PseudoMapValue ||
				addr.Reference() != variable.SectionName || uint32(uint64(addr.Constant)>>32) != variable.Offset {
				continue
			}
			if load.OpCode != asm.LoadMemOp(asm.Word) || load.Src != addr.Dst || load.Offset != 0 || targets[offsets[i+1]] {
				continue
			}
			if load.Dst == addr.Dst {
				*addr = addr.WithReference("")
				addr.Src = asm.R0
				addr.Constant = value
				load.OpCode = asm.Ja.Op(asm.ImmSource)
				load.Dst, load.Src, load.Offset, load.Constant = asm.R0, asm.R0, 0, 0
			} else {
				load.OpCode = asm.Mov.Op(asm.ImmSource)
				load.Src, load.Offset, load.Constant = asm.R0, 0, value
			}
			folded++
		}
	}
	return folded
}

// kernelLoadSettingsTag names the load-time settings for the hot restart
// object hash: the same object loaded with other settings gives other
// programs, as the separate objects per setting used to.
func kernelLoadSettingsTag(enableTrafficStats bool) string {
	if enableTrafficStats {
		return kernelLoadTrafficStatsVariable + "=1"
	}
	return kernelLoadTrafficStatsVariable + "=0"
}
