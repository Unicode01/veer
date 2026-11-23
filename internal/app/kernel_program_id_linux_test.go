//go:build linux

package app

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// loadBenchmarkProgram loads a socket filter about the size of a TC entry
// program, since Program.Info copies every translated instruction.
func loadBenchmarkProgram(tb testing.TB) *ebpf.Program {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("needs root to load a BPF program")
	}
	insns := asm.Instructions{asm.Mov.Imm(asm.R0, 0)}
	for i := 0; i < 4000; i++ {
		insns = append(insns, asm.Add.Imm(asm.R0, 1))
	}
	insns = append(insns, asm.Mov.Imm(asm.R0, 0), asm.Return())
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SocketFilter, Instructions: insns, License: "GPL"})
	if err != nil {
		tb.Skipf("load program: %v", err)
	}
	tb.Cleanup(func() { prog.Close() })
	return prog
}

func TestKernelProgramIDMatchesProgramInfo(t *testing.T) {
	prog := loadBenchmarkProgram(t)
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	want, ok := info.ID()
	if !ok {
		t.Skip("kernel reports no program IDs")
	}
	if got := kernelProgramID(prog); got != uint32(want) {
		t.Fatalf("kernelProgramID = %d, Program.Info ID = %d", got, want)
	}
	if kernelProgramID(nil) != 0 {
		t.Fatal("nil program has an ID")
	}
}

func BenchmarkKernelProgramID(b *testing.B) {
	prog := loadBenchmarkProgram(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if kernelProgramID(prog) == 0 {
			b.Fatal("no ID")
		}
	}
}

func BenchmarkKernelProgramIDThroughInfo(b *testing.B) {
	prog := loadBenchmarkProgram(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		info, err := prog.Info()
		if err != nil {
			b.Fatal(err)
		}
		if _, ok := info.ID(); !ok {
			b.Fatal("no ID")
		}
	}
}
