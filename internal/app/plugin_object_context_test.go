package app

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestLocalizePluginObjectContextFunctions(t *testing.T) {
	for _, context := range []string{"__sk_buff", "xdp_md"} {
		t.Run(context, func(t *testing.T) {
			pointer := &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: context}}}
			prototype := &btf.FuncProto{Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Typedef{Name: "context_t", Type: pointer}}}}
			entry := &btf.Func{Name: "entry", Linkage: btf.GlobalFunc, Type: prototype}
			global := &btf.Func{Name: "context_subprogram", Linkage: btf.GlobalFunc, Type: prototype}
			static := &btf.Func{Name: "local_subprogram", Linkage: btf.StaticFunc, Type: prototype}
			external := &btf.Func{Name: "external", Linkage: btf.ExternFunc, Type: prototype}
			scalar := &btf.Func{Name: "scalar_subprogram", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{}}
			kernelPointer := &btf.Func{Name: "kernel_pointer", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{Params: []btf.FuncParam{{Type: &btf.Pointer{Target: &btf.Struct{Name: "sk_buff"}}}}}}
			functions := []*btf.Func{entry, global, static, external, scalar, kernelPointer}
			program := &ebpf.ProgramSpec{}
			for _, function := range functions {
				program.Instructions = append(program.Instructions, btf.WithFuncMetadata(asm.Return(), function))
			}
			spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"entry": program, "empty": {}, "nil": nil}}
			localizePluginObjectContextFunctions(spec)
			for i, original := range functions {
				actual := btf.FuncMetadata(&program.Instructions[i])
				if i == 1 {
					if actual == original || actual.Linkage != btf.StaticFunc || actual.Type != original.Type {
						t.Fatal("context subprogram was not localized without changing its prototype")
					}
					if original.Linkage != btf.GlobalFunc {
						t.Fatal("localization mutated the shared ELF type graph")
					}
				} else if actual != original {
					t.Fatalf("unexpected change to %s", original.Name)
				}
				if program.Instructions[i].OpCode != asm.Return().OpCode {
					t.Fatal("localization changed an instruction")
				}
			}
			local := btf.FuncMetadata(&program.Instructions[1])
			localizePluginObjectContextFunctions(spec)
			if btf.FuncMetadata(&program.Instructions[1]) != local {
				t.Fatal("localization is not idempotent")
			}
		})
	}
	localizePluginObjectContextFunctions(nil)
}
