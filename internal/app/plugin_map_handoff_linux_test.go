//go:build linux

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func resetPluginMapHandoffRegistry() {
	r := &pluginMapHandoff
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.entries {
		for _, m := range entry.maps {
			_ = m.Close()
		}
	}
	r.loaded, r.released, r.entries = false, false, nil
}

func resetPluginMapHandoffForTest(t *testing.T) {
	t.Helper()
	resetPluginMapHandoffRegistry()
	t.Cleanup(func() {
		resetPluginMapHandoffRegistry()
		clearKernelHotRestartState(pluginMapHandoffEngine)
	})
}

func pluginMapHandoffTestRef(t *testing.T, contracts []PluginObjectStateMap) (loadedPluginObjectRef, map[string]*ebpf.Map) {
	t.Helper()
	maps := make(map[string]*ebpf.Map)
	for _, contract := range contracts {
		maps[contract.Name] = newKernelHotRestartTestMap(t, &ebpf.MapSpec{Name: contract.Name, Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16})
	}
	return loadedPluginObjectRef{
		PluginID:     "firewall",
		ObjectID:     "firewall",
		ObjectSHA256: "aa",
		StateMaps:    contracts,
		coll:         &ebpf.Collection{Maps: maps},
	}, maps
}

func pluginMapHandoffTestPin(t *testing.T, mapName string) string {
	t.Helper()
	pin, err := pluginMapHandoffPinName("firewall", "firewall", mapName)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// Pin names stay unique where joined names would not, and fit the pattern
// the successor checks for the longest IDs a manifest allows.
func TestPluginMapHandoffPinNames(t *testing.T) {
	a, errA := pluginMapHandoffPinName("a--b", "c", "m")
	b, errB := pluginMapHandoffPinName("a", "b--c", "m")
	if errA != nil || errB != nil {
		t.Fatalf("pin names: %v, %v", errA, errB)
	}
	if a == b {
		t.Fatalf("plugin a--b object c and plugin a object b--c share pin %s", a)
	}
	long := strings.Repeat("p", 64)
	pin, err := pluginMapHandoffPinName(long, strings.Repeat("o", 64), "fw_rate_limit_state_v6")
	if err != nil || !pluginMapHandoffNamePattern.MatchString(pin) {
		t.Fatalf("pin for 64-character IDs = %q, %v; want a name matching %s", pin, err, pluginMapHandoffNamePattern)
	}
	again, _ := pluginMapHandoffPinName(long, strings.Repeat("o", 64), "fw_rate_limit_state_v6")
	if again != pin {
		t.Fatalf("pin name not stable: %s then %s", pin, again)
	}
	for _, bad := range [][3]string{{"", "o", "m"}, {"p", "", "m"}, {"p", "o", ""}} {
		if _, err := pluginMapHandoffPinName(bad[0], bad[1], bad[2]); err == nil {
			t.Fatalf("pin name for %q accepted", bad)
		}
	}
}

// The predecessor pins only maps its contract keeps; the successor sees them
// with their contents as the previous object, adopts them through the usual
// contract checks, and the startup release removes every pin.
func TestPluginMapHandoffKeepsPreservedMaps(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(veerBPFStateDirEnv, bpfRoot)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	resetPluginMapHandoffForTest(t)

	contracts := []PluginObjectStateMap{
		{Name: "kept", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
		{Name: "dropped", Policy: pluginObjectMapReset},
	}
	ref, maps := pluginMapHandoffTestRef(t, contracts)
	if err := maps["kept"].Put(uint32(1), uint32(7)); err != nil {
		t.Fatal(err)
	}
	if err := handOffPluginStateMaps([]loadedPluginObjectRef{ref}); err != nil {
		t.Fatalf("handOffPluginStateMaps() error = %v", err)
	}
	dir := kernelHotRestartEngineDir(pluginMapHandoffEngine)
	if _, err := os.Stat(filepath.Join(dir, pluginMapHandoffTestPin(t, "kept"))); err != nil {
		t.Fatalf("kept map not pinned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, pluginMapHandoffTestPin(t, "dropped"))); !os.IsNotExist(err) {
		t.Fatalf("reset map pinned: %v", err)
	}
	// The predecessor exits: only the pin holds the map now.
	for _, m := range maps {
		_ = m.Close()
	}

	previous := pluginMapHandoffPrevious("firewall", "firewall")
	if previous == nil || previous.coll.Maps["kept"] == nil || previous.coll.Maps["dropped"] != nil {
		t.Fatalf("pluginMapHandoffPrevious() = %+v", previous)
	}
	var value uint32
	if err := previous.coll.Maps["kept"].Lookup(uint32(1), &value); err != nil || value != 7 {
		t.Fatalf("kept[1] = %d, %v; want 7", value, err)
	}
	if pluginMapHandoffPrevious("firewall", "other") != nil {
		t.Fatal("an object that handed nothing off got a previous object")
	}

	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"kept":    {Name: "kept", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16},
		"dropped": {Name: "dropped", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16},
	}}
	replacements, err := pluginPipelineMapReplacements(spec, nil, contracts, previous, false)
	if err != nil {
		t.Fatalf("pluginPipelineMapReplacements() error = %v", err)
	}
	if replacements["kept"] == nil || replacements["dropped"] != nil {
		t.Fatalf("replacements = %v, want only kept", replacements)
	}
	// A schema the new object does not keep compatible: the object loads
	// with empty maps instead of failing.
	var calls []*loadedPluginObjectRef
	object, err := loadPluginObjectWithHandoff("firewall", "firewall", nil, false, func(previous *loadedPluginObjectRef, unchanged bool) (*loadedPluginObject, error) {
		calls = append(calls, previous)
		if previous != nil {
			if _, err := pluginPipelineMapReplacements(spec, nil, []PluginObjectStateMap{{Name: "kept", Policy: pluginObjectMapPreserve, SchemaVersion: 2}}, previous, unchanged); err != nil {
				return nil, err
			}
		}
		return &loadedPluginObject{}, nil
	})
	if err != nil || object == nil || len(calls) != 2 || calls[0] == nil || calls[1] != nil {
		t.Fatalf("fallback load: object=%v err=%v calls=%v", object, err, calls)
	}

	releasePluginMapHandoff()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("handoff pins left after release: %v", err)
	}
	if _, err := os.Stat(kernelHotRestartMetadataPath(pluginMapHandoffEngine)); !os.IsNotExist(err) {
		t.Fatalf("handoff metadata left after release: %v", err)
	}
	if pluginMapHandoffPrevious("firewall", "firewall") != nil {
		t.Fatal("previous object offered after release")
	}
}

// A pinned map whose layout no longer matches the record is not offered.
func TestPluginMapHandoffSkipsMapsThatDoNotMatchTheirRecord(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(veerBPFStateDirEnv, bpfRoot)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	resetPluginMapHandoffForTest(t)

	ref, maps := pluginMapHandoffTestRef(t, []PluginObjectStateMap{{Name: "kept", Policy: pluginObjectMapPreserve, SchemaVersion: 1}})
	if err := handOffPluginStateMaps([]loadedPluginObjectRef{ref}); err != nil {
		t.Fatal(err)
	}
	_ = maps["kept"].Close()
	meta, err := readPluginMapHandoffMetadata()
	if err != nil {
		t.Fatal(err)
	}
	meta.Objects[0].Maps[0].Descriptor.MaxEntries = 32
	if err := writePluginMapHandoffMetadata(meta); err != nil {
		t.Fatal(err)
	}
	if previous := pluginMapHandoffPrevious("firewall", "firewall"); previous != nil {
		t.Fatalf("previous object = %+v, want none", previous)
	}
}

// Pins are written only when the process ends in a hot restart, and the
// runtimes report the objects they hold.
func TestPluginMapHandoffNeedsHotRestart(t *testing.T) {
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(veerBPFStateDirEnv, bpfRoot)
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())
	marker := filepath.Join(t.TempDir(), "hot-restart")
	t.Setenv(veerHotRestartMarkerEnv, marker)
	resetPluginMapHandoffForTest(t)

	source := &kernelXDPPluginPipelineRuntime{}
	ref, _ := pluginMapHandoffTestRef(t, []PluginObjectStateMap{{Name: "kept", Policy: pluginObjectMapPreserve, SchemaVersion: 1}})
	source.loaded = []loadedPluginObjectRef{ref}
	if err := handOffPluginStateMapsForHotRestart(source, nil, disabledPluginDataplaneRuntime{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(kernelHotRestartEngineDir(pluginMapHandoffEngine)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pins written without a hot restart: %v", err)
	}
	if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := handOffPluginStateMapsForHotRestart(source, nil, disabledPluginDataplaneRuntime{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(kernelHotRestartEngineDir(pluginMapHandoffEngine), pluginMapHandoffTestPin(t, "kept"))); err != nil {
		t.Fatalf("map not pinned for a hot restart: %v", err)
	}
}
