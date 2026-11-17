//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestKernelTCMapLayoutRulesMatchFlowValue(t *testing.T) {
	t.Parallel()

	// The copy zero-fills everything after the old value, so the old value
	// must be exactly the fields before the flow cache record.
	if got := unsafe.Sizeof(tcFlowValueV4{}); got != 104 {
		t.Fatalf("sizeof(tcFlowValueV4) = %d; if flow_value_v4 grew by appended fields, add 104 to the prefixes in kernelTCMapLayoutRules", got)
	}
	if got := unsafe.Offsetof(tcFlowValueV4{}.Fast); got != 64 {
		t.Fatalf("offsetof(tcFlowValueV4.Fast) = %d, want 64: the 64-byte layout is a prefix only while the record follows it", got)
	}
	spec, err := loadEmbeddedKernelCollectionSpec(false)
	if err != nil {
		t.Fatalf("loadEmbeddedKernelCollectionSpec() error = %v", err)
	}
	for name, rule := range kernelTCMapLayoutRules {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			t.Fatalf("kernelTCMapLayoutRules names %s, which the tc object does not have", name)
		}
		if mapSpec.ValueSize != uint32(unsafe.Sizeof(tcFlowValueV4{})) {
			t.Fatalf("%s value_size = %d, want sizeof(tcFlowValueV4)", name, mapSpec.ValueSize)
		}
		for _, prefix := range rule.prefixes {
			if prefix >= mapSpec.ValueSize {
				t.Fatalf("%s prefix %d is not smaller than the value size %d", name, prefix, mapSpec.ValueSize)
			}
		}
		found := false
		for _, bank := range rule.banks {
			if spec.Maps[bank] == nil {
				t.Fatalf("%s names bank %s, which the tc object does not have", name, bank)
			}
			if spec.Maps[bank].KeySize != mapSpec.KeySize {
				t.Fatalf("%s bank %s has %d-byte keys, want %d", name, bank, spec.Maps[bank].KeySize, mapSpec.KeySize)
			}
			found = found || bank == name
		}
		if !found {
			t.Fatalf("%s banks %v do not include the map itself", name, rule.banks)
		}
	}
}

func TestKernelMapLayoutRuleCopies(t *testing.T) {
	t.Parallel()

	rule := kernelMapLayoutRule{prefixes: []uint32{64}}
	desired := kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 20, ValueSize: 104, MaxEntries: 128}
	tests := []struct {
		name   string
		actual kernelHotRestartMapDescriptor
		want   bool
	}{
		{name: "listed prefix", actual: kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 20, ValueSize: 64, MaxEntries: 64}, want: true},
		{name: "same layout", actual: desired},
		{name: "unlisted size", actual: kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 20, ValueSize: 48, MaxEntries: 128}},
		{name: "larger value", actual: kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 20, ValueSize: 112, MaxEntries: 128}},
		{name: "other key", actual: kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 16, ValueSize: 64, MaxEntries: 128}},
		{name: "other type", actual: kernelHotRestartMapDescriptor{Type: ebpf.LRUHash, KeySize: 20, ValueSize: 64, MaxEntries: 128}},
		{name: "other flags", actual: kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 20, ValueSize: 64, MaxEntries: 128, Flags: 1}},
	}
	for _, tt := range tests {
		if got := rule.copies(tt.actual, desired); got != tt.want {
			t.Errorf("%s: copies() = %t, want %t", tt.name, got, tt.want)
		}
	}
	perCPU := kernelHotRestartMapDescriptor{Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 32}
	old := perCPU
	old.ValueSize = 16
	if (kernelMapLayoutRule{prefixes: []uint32{16}}).copies(old, perCPU) {
		t.Error("copies() = true for a per-CPU map, want false")
	}
}

func layoutCopyTestKey(n uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, n)
}

func layoutCopyTestValue(size int, n uint64) []byte {
	value := make([]byte, size)
	binary.LittleEndian.PutUint64(value, n)
	return value
}

func layoutCopyTestLookup(t *testing.T, m *ebpf.Map, key []byte) ([]byte, bool) {
	t.Helper()
	value := make([]byte, m.ValueSize())
	err := m.Lookup(key, value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("lookup %x: %v", key, err)
	}
	return value, true
}

func TestKernelMapLayoutCopyCopiesThenCatchesUp(t *testing.T) {
	const fromSize, toSize = 8, 16
	source := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "layout_src", Type: ebpf.Hash, KeySize: 4, ValueSize: fromSize, MaxEntries: 32})
	dst := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "layout_dst", Type: ebpf.Hash, KeySize: 4, ValueSize: toSize, MaxEntries: 32})
	other := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "layout_other", Type: ebpf.Hash, KeySize: 4, ValueSize: toSize, MaxEntries: 32})
	maps := map[string]*ebpf.Map{"dst": dst, "other": other}
	put := func(m *ebpf.Map, key uint32, value []byte) {
		t.Helper()
		if err := m.Put(layoutCopyTestKey(key), value); err != nil {
			t.Fatalf("put %d: %v", key, err)
		}
	}
	del := func(m *ebpf.Map, key uint32) {
		t.Helper()
		if err := m.Delete(layoutCopyTestKey(key)); err != nil {
			t.Fatalf("delete %d: %v", key, err)
		}
	}
	for key := uint32(1); key <= 8; key++ {
		put(source, key, layoutCopyTestValue(fromSize, uint64(key)))
	}

	rule := kernelMapLayoutRule{prefixes: []uint32{fromSize}, banks: []string{"dst", "other"}}
	actual := kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 4, ValueSize: fromSize}
	desired := kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 4, ValueSize: toSize}
	c := newKernelMapLayoutCopy("dst", source, rule, actual, desired)
	result, err := c.copyInto(maps)
	if err != nil {
		t.Fatalf("copyInto() error = %v", err)
	}
	if result.Copied != 8 {
		t.Fatalf("copyInto() copied %d entries, want 8", result.Copied)
	}
	if got, ok := layoutCopyTestLookup(t, dst, layoutCopyTestKey(1)); !ok || !bytes.Equal(got, layoutCopyTestValue(toSize, 1)) {
		t.Fatalf("dst[1] = %x, %t; want the old value followed by zeros", got, ok)
	}

	// Until the successor attaches, the predecessor updates entries 1 and 2,
	// closes 3 and 7, and opens 104, 105 and 106.
	put(source, 1, layoutCopyTestValue(fromSize, 101))
	put(source, 2, layoutCopyTestValue(fromSize, 102))
	del(source, 3)
	del(source, 7)
	put(source, 104, layoutCopyTestValue(fromSize, 104))
	put(source, 105, layoutCopyTestValue(fromSize, 105))
	put(source, 106, layoutCopyTestValue(fromSize, 106))
	// From attach on, the successor changes entries 2 and 7, closes 8, and
	// opens 105 in the other bank and 106 in this one.
	put(dst, 2, layoutCopyTestValue(toSize, 202))
	put(dst, 7, layoutCopyTestValue(toSize, 207))
	del(dst, 8)
	put(other, 105, layoutCopyTestValue(toSize, 5))
	put(dst, 106, layoutCopyTestValue(toSize, 6))

	result, err = c.catchUp(maps)
	if err != nil {
		t.Fatalf("catchUp() error = %v", err)
	}
	if want := (kernelMapLayoutCopyResult{Added: 1, Updated: 1, Deleted: 1}); result != want {
		t.Fatalf("catchUp() = %+v, want %+v", result, want)
	}
	want := map[uint32][]byte{
		1:   layoutCopyTestValue(toSize, 101),
		2:   layoutCopyTestValue(toSize, 202),
		4:   layoutCopyTestValue(toSize, 4),
		5:   layoutCopyTestValue(toSize, 5),
		6:   layoutCopyTestValue(toSize, 6),
		7:   layoutCopyTestValue(toSize, 207),
		104: layoutCopyTestValue(toSize, 104),
		106: layoutCopyTestValue(toSize, 6),
	}
	got := make(map[uint32][]byte)
	key := make([]byte, 4)
	value := make([]byte, toSize)
	iter := dst.Iterate()
	for iter.Next(key, value) {
		got[binary.LittleEndian.Uint32(key)] = bytes.Clone(value)
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("dst = %x, want %x", got, want)
	}
	for k, v := range want {
		if !bytes.Equal(got[k], v) {
			t.Fatalf("dst[%d] = %x, want %x (dst = %x)", k, got[k], v, got)
		}
	}
}

func TestKernelMapLayoutCopyRejectsAnotherTarget(t *testing.T) {
	source := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "layout_src", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 4})
	dst := newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: "layout_dst", Type: ebpf.Hash, KeySize: 4, ValueSize: 12, MaxEntries: 4})
	c := newKernelMapLayoutCopy("dst", source, kernelMapLayoutRule{prefixes: []uint32{8}},
		kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 4, ValueSize: 8},
		kernelHotRestartMapDescriptor{Type: ebpf.Hash, KeySize: 4, ValueSize: 16})
	if _, err := c.copyInto(map[string]*ebpf.Map{"dst": dst}); err == nil {
		t.Fatal("copyInto() into a 12-byte map = nil error, want the layout mismatch")
	}
	if _, err := c.copyInto(map[string]*ebpf.Map{}); err == nil {
		t.Fatal("copyInto() without the target map = nil error, want an error")
	}
}
