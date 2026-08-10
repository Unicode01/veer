//go:build linux

package app

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func setPresentKernelMapABISizesForTest(t *testing.T, spec *ebpf.CollectionSpec, contracts []kernelMapABIContract) {
	t.Helper()
	for _, contract := range contracts {
		mapSpec := spec.Maps[contract.name]
		if mapSpec == nil {
			continue
		}
		keySize := binary.Size(contract.key)
		valueSize := binary.Size(contract.value)
		if keySize < 0 || valueSize < 0 {
			t.Fatalf("map %q has unsupported ABI test contract", contract.name)
		}
		mapSpec.KeySize = uint32(keySize)
		mapSpec.ValueSize = uint32(valueSize)
	}
}

func TestEmbeddedKernelMapABIs(t *testing.T) {
	tests := []struct {
		name      string
		load      func(bool) (*ebpf.CollectionSpec, error)
		contracts []kernelMapABIContract
	}{
		{name: "tc", load: loadEmbeddedKernelCollectionSpec, contracts: tcKernelMapABIContracts()},
		{name: "xdp", load: loadEmbeddedXDPCollectionSpec, contracts: xdpKernelMapABIContracts()},
	}

	for _, tc := range tests {
		for _, enableTrafficStats := range []bool{false, true} {
			name := tc.name + "-plain"
			if enableTrafficStats {
				name = tc.name + "-stats"
			}
			t.Run(name, func(t *testing.T) {
				spec, err := tc.load(enableTrafficStats)
				if err != nil {
					t.Fatalf("load embedded object: %v", err)
				}
				if err := validateKernelMapABIContracts(spec, tc.name, tc.contracts); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestValidateKernelMapABIContractsRejectsStaleObject(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		kernelRulesMapNameV4: {
			KeySize:   12,
			ValueSize: 44,
		},
	}}
	err := validateKernelMapABIContracts(spec, "tc", []kernelMapABIContract{{
		name:  kernelRulesMapNameV4,
		key:   tcRuleKeyV4{},
		value: tcRuleValueV4{},
	}})
	if err == nil {
		t.Fatal("validateKernelMapABIContracts() error = nil, want stale object rejection")
	}
	for _, want := range []string{"rules_v4", "value_size=44", "value_size=56", "rebuild eBPF objects"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("validateKernelMapABIContracts() error = %q, want %q", err, want)
		}
	}
}

func TestValidatePresentKernelMapABIContractsAllowsMissingMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		kernelRulesMapNameV4: {},
	}}
	setPresentKernelMapABISizesForTest(t, spec, tcKernelMapABIContracts())

	if err := validatePresentKernelMapABIContracts(spec, "tc", tcKernelMapABIContracts()); err != nil {
		t.Fatalf("validatePresentKernelMapABIContracts() error = %v, want nil", err)
	}
}
