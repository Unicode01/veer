//go:build linux

package app

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestSyncKernelLocalNetMapMatchesMostSpecificNetwork(t *testing.T) {
	m := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "local_nets_test",
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 16,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	lookup := func(addr string) (uint8, bool) {
		t.Helper()
		var value uint8
		key := kernelLocalNetKeyV4{PrefixLen: 32, Addr: netip.MustParseAddr(addr).As4()}
		if err := m.Lookup(key, &value); err != nil {
			return 0, false
		}
		return value, true
	}

	first := map[netip.Prefix]bool{
		netip.MustParsePrefix("10.0.0.0/8"):       true,
		netip.MustParsePrefix("10.20.0.0/24"):     false,
		netip.MustParsePrefix("192.168.101.0/24"): true,
	}
	if err := syncKernelLocalNetMap(m, first); err != nil {
		t.Fatalf("syncKernelLocalNetMap() error = %v", err)
	}
	for addr, want := range map[string]uint8{"10.9.9.9": 1, "10.20.0.7": 0, "192.168.101.20": 1} {
		if got, ok := lookup(addr); !ok || got != want {
			t.Fatalf("lookup %s = (%d, %v), want %d", addr, got, ok, want)
		}
	}
	if _, ok := lookup("8.8.8.8"); ok {
		t.Fatal("lookup 8.8.8.8 matched, want no network")
	}

	second := map[netip.Prefix]bool{
		netip.MustParsePrefix("10.0.0.0/8"):    false,
		netip.MustParsePrefix("172.16.0.0/12"): true,
	}
	if err := syncKernelLocalNetMap(m, second); err != nil {
		t.Fatalf("syncKernelLocalNetMap() second error = %v", err)
	}
	for addr, want := range map[string]uint8{"10.20.0.7": 0, "10.9.9.9": 0, "172.20.1.1": 1} {
		if got, ok := lookup(addr); !ok || got != want {
			t.Fatalf("after update lookup %s = (%d, %v), want %d", addr, got, ok, want)
		}
	}
	if _, ok := lookup("192.168.101.20"); ok {
		t.Fatal("stale network 192.168.101.0/24 still matches")
	}

	if err := syncKernelLocalNetMap(m, nil); err != nil {
		t.Fatalf("syncKernelLocalNetMap(nil) error = %v", err)
	}
	if _, ok := lookup("172.20.1.1"); ok {
		t.Fatal("cleared map still matches 172.20.1.1")
	}
}
