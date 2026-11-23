package app

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestBundledPluginProgramsDoNotMixTailCallsAndSubprograms: a program that
// makes a tail call may not also make BPF-to-BPF calls (noinline or global
// functions) unless the JIT supports it, which arm64 only does since 6.0
// (x86-64 since 5.10). The verifier refuses such a program ("tail_calls are
// not allowed in programs with bpf-to-bpf calls"), so on an older arm64
// kernel the whole object fails to load. pppoe_tunnel's tc_tunnel continued
// the hook chain by tail call while it called two noinline functions.
func TestBundledPluginProgramsDoNotMixTailCallsAndSubprograms(t *testing.T) {
	pluginsDir, err := filepath.Abs(filepath.Join("..", "..", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := filepath.Glob(filepath.Join(pluginsDir, "*", "*.o"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) == 0 {
		t.Skip("no plugin eBPF objects are built here")
	}
	for _, object := range objects {
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			t.Errorf("%s: %v", object, err)
			continue
		}
		for name, program := range spec.Programs {
			if program == nil {
				continue
			}
			if err := checkTailCallsWithoutSubprograms(program.Instructions); err != nil {
				rel, _ := filepath.Rel(pluginsDir, object)
				t.Errorf("%s program %s: %v", filepath.ToSlash(rel), name, err)
			}
		}
	}
}

func checkTailCallsWithoutSubprograms(instructions asm.Instructions) error {
	tailCall, subprogram := false, ""
	for i := range instructions {
		ins := &instructions[i]
		if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnTailCall {
			tailCall = true
		}
		if ins.IsFunctionCall() && subprogram == "" {
			subprogram = ins.Reference()
			if subprogram == "" {
				subprogram = "a BPF-to-BPF call"
			}
		}
	}
	if tailCall && subprogram != "" {
		return errors.New("makes a tail call and calls " + subprogram + ": older arm64 kernels refuse to load it")
	}
	return nil
}

func TestCheckTailCallsWithoutSubprograms(t *testing.T) {
	call := asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoCall, Constant: -1}.WithReference("helper")
	tail := asm.FnTailCall.Call()
	exit := asm.Return()
	if err := checkTailCallsWithoutSubprograms(asm.Instructions{tail, exit}); err != nil {
		t.Fatalf("tail call alone: %v", err)
	}
	if err := checkTailCallsWithoutSubprograms(asm.Instructions{call, exit}); err != nil {
		t.Fatalf("subprogram alone: %v", err)
	}
	if err := checkTailCallsWithoutSubprograms(asm.Instructions{call, tail, exit}); err == nil {
		t.Fatal("a tail call next to a BPF-to-BPF call passed")
	}
}
