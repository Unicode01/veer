//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestPluginMapTransactionLinuxCommitsGenerationSelector(t *testing.T) {
	config := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_config", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 4,
	})
	selector := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_selector", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1,
	})
	keyA, keyB := pluginMapTestUint32(1), pluginMapTestUint32(2)
	oldValue := pluginMapTestUint64(10)
	newValueA, newValueB := pluginMapTestUint64(20), pluginMapTestUint64(30)
	if err := config.Put(keyA, oldValue); err != nil {
		t.Fatal(err)
	}
	refs := []loadedPluginObjectRef{{
		PluginID: "tx_plugin", ObjectID: "dataplane",
		coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{"config": config, "selector": selector}},
	}}
	request := pluginEBPFMapTransactionRequest{
		Operations: []pluginEBPFMapMutation{
			{Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: keyA, Value: newValueA},
			{Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: keyB, Value: newValueB},
		},
		Commit: &pluginEBPFMapMutation{
			Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "selector",
			Key: pluginMapTestUint32(0), Value: pluginMapTestUint32(1),
		},
	}
	if err := transactPluginMapsInRefs(refs, "tx_plugin", request); err != nil {
		t.Fatalf("map transaction: %v", err)
	}
	assertPluginMapTestValue(t, config, keyA, newValueA)
	assertPluginMapTestValue(t, config, keyB, newValueB)
	assertPluginMapTestValue(t, selector, pluginMapTestUint32(0), pluginMapTestUint32(1))
}

func TestPluginMapTransactionLinuxRollsBackMutationFailure(t *testing.T) {
	config := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_full", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	keyA, keyB := pluginMapTestUint32(1), pluginMapTestUint32(2)
	oldValue := pluginMapTestUint64(10)
	if err := config.Put(keyA, oldValue); err != nil {
		t.Fatal(err)
	}
	refs := []loadedPluginObjectRef{{
		PluginID: "tx_plugin", ObjectID: "dataplane", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{"config": config}},
	}}
	err := transactPluginMapsInRefs(refs, "tx_plugin", pluginEBPFMapTransactionRequest{Operations: []pluginEBPFMapMutation{
		{Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: keyA, Value: pluginMapTestUint64(20)},
		{Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: keyB, Value: pluginMapTestUint64(30)},
	}})
	if err == nil || !strings.Contains(err.Error(), "operation 1 failed") {
		t.Fatalf("transaction error = %v, want second operation failure", err)
	}
	assertPluginMapTestValue(t, config, keyA, oldValue)
	assertPluginMapTestMissing(t, config, keyB)
}

func TestPluginMapTransactionLinuxRollsBackFailedCommit(t *testing.T) {
	config := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_data", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 2,
	})
	selector := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_commit", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1,
	})
	dataKey := pluginMapTestUint32(1)
	oldData := pluginMapTestUint64(10)
	if err := config.Put(dataKey, oldData); err != nil {
		t.Fatal(err)
	}
	if err := selector.Put(pluginMapTestUint32(0), pluginMapTestUint32(0)); err != nil {
		t.Fatal(err)
	}
	refs := []loadedPluginObjectRef{{
		PluginID: "tx_plugin", ObjectID: "dataplane",
		coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{"config": config, "selector": selector}},
	}}
	err := transactPluginMapsInRefs(refs, "tx_plugin", pluginEBPFMapTransactionRequest{
		Operations: []pluginEBPFMapMutation{{
			Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: dataKey, Value: pluginMapTestUint64(20),
		}},
		Commit: &pluginEBPFMapMutation{
			Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "selector",
			Key: pluginMapTestUint32(1), Value: pluginMapTestUint32(1),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "operation 1 failed") {
		t.Fatalf("transaction error = %v, want commit failure", err)
	}
	assertPluginMapTestValue(t, config, dataKey, oldData)
	assertPluginMapTestValue(t, selector, pluginMapTestUint32(0), pluginMapTestUint32(0))
	assertPluginMapTestMissing(t, selector, pluginMapTestUint32(1))
}

func TestPluginMapTransactionLinuxRejectsAliasedDuplicateSlot(t *testing.T) {
	config := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_tx_alias", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 2,
	})
	key := pluginMapTestUint32(1)
	oldValue := pluginMapTestUint64(10)
	if err := config.Put(key, oldValue); err != nil {
		t.Fatal(err)
	}
	refs := []loadedPluginObjectRef{{
		PluginID: "tx_plugin", ObjectID: "dataplane", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{"config": config}},
	}}
	err := transactPluginMapsInRefs(refs, "tx_plugin", pluginEBPFMapTransactionRequest{Operations: []pluginEBPFMapMutation{
		{Operation: pluginEBPFMapMutationPut, MapName: "config", Key: key, Value: pluginMapTestUint64(20)},
		{Operation: pluginEBPFMapMutationPut, ObjectID: "dataplane", MapName: "config", Key: key, Value: pluginMapTestUint64(30)},
	}})
	if err == nil || !strings.Contains(err.Error(), "duplicate slot") {
		t.Fatalf("transaction error = %v, want duplicate slot", err)
	}
	assertPluginMapTestValue(t, config, key, oldValue)
}

func TestPluginMapScanLinuxPaginatesKernelMap(t *testing.T) {
	m := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_scan_test", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 8,
	})
	for key, value := range map[uint32]uint64{1: 101, 2: 102, 3: 103} {
		if err := m.Put(key, value); err != nil {
			t.Fatalf("put %d: %v", key, err)
		}
	}
	refs := []loadedPluginObjectRef{{PluginID: "scan_plugin", ObjectID: "stats", coll: &ebpf.Collection{Maps: map[string]*ebpf.Map{"stats": m}}}}
	request := pluginEBPFMapScanRequest{Limit: 2, MaxBytes: 128}
	first, err := scanPluginMapInRefs(refs, "scan_plugin", "stats", "stats", request)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if len(first.Entries) != 2 || first.Done || len(first.Cursor) != 4 {
		t.Fatalf("first scan = %+v, want two entries and cursor", first)
	}
	request.Cursor = first.Cursor
	second, err := scanPluginMapInRefs(refs, "scan_plugin", "stats", "stats", request)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(second.Entries) != 1 || !second.Done || len(second.Cursor) != 0 {
		t.Fatalf("second scan = %+v, want final entry", second)
	}
	seen := make(map[string]struct{}, 3)
	for _, page := range []pluginEBPFMapScanResult{first, second} {
		for _, entry := range page.Entries {
			seen[string(entry.Key)] = struct{}{}
			if len(entry.Value) != 8 {
				t.Fatalf("value size = %d, want 8", len(entry.Value))
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("scanned keys = %d, want 3", len(seen))
	}
}

func TestPluginRingReadLinuxTimesOutWithoutRecords(t *testing.T) {
	m := newPluginMapAPITestMap(t, &ebpf.MapSpec{Name: "veer_plugin_ring_test", Type: ebpf.RingBuf, MaxEntries: 4096})
	result, err := readPluginRingBuffer(m, "events", pluginEBPFRingReadRequest{MaxRecords: 4, MaxBytes: 4096, TimeoutMS: 10})
	if err != nil {
		t.Fatalf("read empty ring buffer: %v", err)
	}
	if !result.TimedOut || len(result.Records) != 0 || result.Bytes != 0 {
		t.Fatalf("empty ring result = %+v, want timeout", result)
	}
}

func TestPluginRingReadLinuxRejectsNonRingMap(t *testing.T) {
	m := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "veer_plugin_not_ring", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	if _, err := readPluginRingBuffer(m, "events", pluginEBPFRingReadRequest{MaxRecords: 1, MaxBytes: 64, TimeoutMS: 1}); err == nil {
		t.Fatal("read non-ring map succeeded")
	}
}

func newPluginMapAPITestMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()
	_ = rlimit.RemoveMemlock()
	m, err := ebpf.NewMap(spec)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("eBPF map creation unavailable: %v", err)
		}
		t.Fatalf("create eBPF map %s: %v", spec.Name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func pluginMapTestUint32(value uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, value)
	return out
}

func pluginMapTestUint64(value uint64) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, value)
	return out
}

func assertPluginMapTestValue(t *testing.T, m *ebpf.Map, key, want []byte) {
	t.Helper()
	got, err := m.LookupBytes(key)
	if err != nil {
		t.Fatalf("lookup map value: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("map value = %x, want %x", got, want)
	}
}

func assertPluginMapTestMissing(t *testing.T, m *ebpf.Map, key []byte) {
	t.Helper()
	value, err := m.LookupBytes(key)
	if err == nil && value == nil {
		return
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("map key %x error = %v, want missing", key, err)
	}
}
