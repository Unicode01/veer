//go:build linux

package app

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestNewTCKernelRuleRuntimeEnablesRedirectNeighFast(t *testing.T) {
	t.Parallel()

	rt := newTCKernelRuleRuntime(&Config{
		Experimental: map[string]bool{
			experimentalFeatureKernelTCRedirectNeighFast: true,
		},
	})
	if !rt.enableRedirectNeighFast {
		t.Fatal("newTCKernelRuleRuntime() redirect_neigh_fast = false, want true")
	}
	if got := rt.natConfigFlags(); got != kernelNATConfigFlagTCRedirectNeighFast {
		t.Fatalf("natConfigFlags() = %#x, want %#x", got, kernelNATConfigFlagTCRedirectNeighFast)
	}
}

func TestNewTCKernelRuleRuntimeEnablesPreparedL2(t *testing.T) {
	t.Parallel()

	rt := newTCKernelRuleRuntime(&Config{
		Experimental: map[string]bool{
			experimentalFeatureKernelTCPreparedL2: true,
		},
	})
	if !rt.enablePreparedL2 {
		t.Fatal("newTCKernelRuleRuntime() prepared_l2 = false, want true")
	}
}

func TestNewTCKernelRuleRuntimeEnablesReplyL2Cache(t *testing.T) {
	t.Parallel()

	rt := newTCKernelRuleRuntime(&Config{
		Experimental: map[string]bool{
			experimentalFeatureKernelTCReplyL2Cache: true,
		},
	})
	if !rt.enableReplyL2Cache {
		t.Fatal("newTCKernelRuleRuntime() reply_l2_cache = false, want true")
	}
	if got := rt.natConfigFlags(); got != kernelNATConfigFlagTCReplyL2Cache {
		t.Fatalf("natConfigFlags() = %#x, want %#x", got, kernelNATConfigFlagTCReplyL2Cache)
	}
}

func TestSyncKernelNATConfigMapStoresFlags(t *testing.T) {
	t.Parallel()

	m := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNATConfigMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(tcNATConfigValueV4{})),
		MaxEntries: 1,
	})
	defer m.Close()

	if err := syncKernelNATConfigMap(m, 20000, 40000, kernelNATConfigFlagTCRedirectNeighFast); err != nil {
		t.Fatalf("syncKernelNATConfigMap() error = %v", err)
	}

	var got tcNATConfigValueV4
	if err := m.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got.PortMin != 20000 || got.PortMax != 40000 {
		t.Fatalf("stored range = (%d, %d), want (20000, 40000)", got.PortMin, got.PortMax)
	}
	if got.Pad0 != kernelNATConfigFlagTCRedirectNeighFast {
		t.Fatalf("stored flags = %#x, want %#x", got.Pad0, kernelNATConfigFlagTCRedirectNeighFast)
	}
}

func TestSyncKernelNATConfigMapStoresCombinedFlags(t *testing.T) {
	t.Parallel()

	m := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNATConfigMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(tcNATConfigValueV4{})),
		MaxEntries: 1,
	})
	defer m.Close()

	wantFlags := uint32(kernelNATConfigFlagTCRedirectNeighFast | kernelNATConfigFlagTCReplyL2Cache)
	if err := syncKernelNATConfigMap(m, 20000, 40000, wantFlags); err != nil {
		t.Fatalf("syncKernelNATConfigMap() error = %v", err)
	}

	var got tcNATConfigValueV4
	if err := m.Lookup(uint32(0), &got); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got.Pad0 != wantFlags {
		t.Fatalf("stored flags = %#x, want %#x", got.Pad0, wantFlags)
	}
}
