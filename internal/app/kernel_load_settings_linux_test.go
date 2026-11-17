//go:build linux

package app

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// settingReadSpec builds a program around read: r0 = 0, read, exit. The
// setting lives at offset 8 of .rodata.
func settingReadSpec(read asm.Instructions) (*ebpf.CollectionSpec, *ebpf.VariableSpec) {
	variable := &ebpf.VariableSpec{Name: kernelLoadTrafficStatsVariable, SectionName: ".rodata", Offset: 8, Value: make([]byte, 4)}
	insns := append(asm.Instructions{asm.Mov.Imm(asm.R0, 0)}, read...)
	insns = append(insns, asm.Return())
	return &ebpf.CollectionSpec{
		Programs:  map[string]*ebpf.ProgramSpec{"prog": {Name: "prog", Type: ebpf.SchedCLS, Instructions: insns}},
		Variables: map[string]*ebpf.VariableSpec{variable.Name: variable},
	}, variable
}

// settingAddress loads the address of the .rodata value at offset into dst.
func settingAddress(dst asm.Register, offset uint32) asm.Instruction {
	return asm.LoadMapValue(dst, 0, offset).WithReference(".rodata")
}

// jumpIfZero jumps over skip raw instructions when dst is 0.
func jumpIfZero(dst asm.Register, skip int16) asm.Instruction {
	ins := asm.JEq.Imm(dst, 0, "")
	ins.Offset = skip
	return ins
}

func TestFoldKernelLoadSettingsTurnsASingleReadIntoTheValue(t *testing.T) {
	spec, variable := settingReadSpec(asm.Instructions{
		settingAddress(asm.R1, 8),
		asm.LoadMem(asm.R1, asm.R1, 0, asm.Word),
		jumpIfZero(asm.R1, 1),
		asm.Mov.Imm(asm.R0, 1),
	})
	if got := foldKernelLoadSettings(spec, variable, 1); got != 1 {
		t.Fatalf("folded %d reads, want 1", got)
	}
	insns := spec.Programs["prog"].Instructions
	if ins := insns[1]; ins.OpCode != asm.LoadImmOp(asm.DWord) || ins.Src != asm.R0 || ins.Constant != 1 || ins.Reference() != "" {
		t.Fatalf("address load became %v (reference %q), want r1 = 1 as a plain 64-bit immediate", ins, ins.Reference())
	}
	if ins := insns[2]; ins.OpCode != asm.Ja.Op(asm.ImmSource) || ins.Offset != 0 {
		t.Fatalf("value load became %v, want a jump to the next instruction", ins)
	}
}

func TestFoldKernelLoadSettingsTurnsAReadIntoAnotherRegisterIntoAMove(t *testing.T) {
	spec, variable := settingReadSpec(asm.Instructions{
		settingAddress(asm.R1, 8),
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
		jumpIfZero(asm.R2, 1),
		asm.Mov.Imm(asm.R0, 1),
	})
	if got := foldKernelLoadSettings(spec, variable, 1); got != 1 {
		t.Fatalf("folded %d reads, want 1", got)
	}
	insns := spec.Programs["prog"].Instructions
	if ins := insns[1]; !ins.IsLoadFromMap() || ins.Reference() != ".rodata" {
		t.Fatalf("address load became %v, want it kept for later uses of r1", ins)
	}
	if ins := insns[2]; ins.OpCode != asm.Mov.Op(asm.ImmSource) || ins.Dst != asm.R2 || ins.Constant != 1 {
		t.Fatalf("value load became %v, want r2 = 1", ins)
	}
}

func TestFoldKernelLoadSettingsLeavesOtherReadsAlone(t *testing.T) {
	tests := []struct {
		name string
		read asm.Instructions
	}{
		{
			name: "another variable",
			read: asm.Instructions{settingAddress(asm.R1, 12), asm.LoadMem(asm.R1, asm.R1, 0, asm.Word)},
		},
		{
			name: "read at an offset from the address",
			read: asm.Instructions{settingAddress(asm.R1, 8), asm.LoadMem(asm.R1, asm.R1, 4, asm.Word)},
		},
		{
			name: "wider read",
			read: asm.Instructions{settingAddress(asm.R1, 8), asm.LoadMem(asm.R1, asm.R1, 0, asm.DWord)},
		},
		{
			// The jump at raw offset 1 lands on the read at raw offset 4, so
			// the read may see an address loaded on another path.
			name: "read is a jump target",
			read: asm.Instructions{
				jumpIfZero(asm.R0, 2),
				settingAddress(asm.R1, 8),
				asm.LoadMem(asm.R1, asm.R1, 0, asm.Word),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, variable := settingReadSpec(tt.read)
			if got := foldKernelLoadSettings(spec, variable, 1); got != 0 {
				t.Fatalf("folded %d reads, want 0", got)
			}
		})
	}
}

// The embedded objects read the setting where they check it. Every one of
// those reads must fold, so a check costs a constant move instead of a load.
func TestEmbeddedObjectsFoldEveryTrafficStatsRead(t *testing.T) {
	loaders := []struct {
		name string
		load func(bool) (*ebpf.CollectionSpec, error)
		data []byte
	}{
		{name: "tc", load: loadEmbeddedKernelCollectionSpec, data: embeddedForwardTCObject},
		{name: "xdp", load: loadEmbeddedXDPCollectionSpec, data: embeddedForwardXDPObject},
	}
	for _, loader := range loaders {
		if len(loader.data) == 0 {
			t.Skipf("%s object is not built", loader.name)
		}
		for _, enable := range []bool{false, true} {
			spec, err := loader.load(enable)
			if err != nil {
				t.Fatalf("%s: load(%t): %v", loader.name, enable, err)
			}
			variable := spec.Variables[kernelLoadTrafficStatsVariable]
			var value uint32
			if err := variable.Get(&value); err != nil {
				t.Fatalf("%s: read setting: %v", loader.name, err)
			}
			if want := map[bool]uint32{false: 0, true: 1}[enable]; value != want {
				t.Fatalf("%s: setting = %d, want %d", loader.name, value, want)
			}
			for name, prog := range spec.Programs {
				insns := prog.Instructions
				for i := 0; i+1 < len(insns); i++ {
					addr, next := insns[i], insns[i+1]
					if addr.IsLoadFromMap() && addr.Src == asm.PseudoMapValue && addr.Reference() == variable.SectionName &&
						uint32(uint64(addr.Constant)>>32) == variable.Offset &&
						next.OpCode.Class().IsLoad() && next.Src == addr.Dst {
						t.Fatalf("%s(%t): program %s instruction %d still reads the setting: %v", loader.name, enable, name, i+1, next)
					}
				}
			}
		}
	}
}
