package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestPluginControlUpgradeGateDrainsInheritedWork(t *testing.T) {
	gate := newPluginControlUpgradeGate()
	outer, err := gate.enter(false, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("enter outer lease: %v", err)
	}
	type beginResult struct {
		lease *pluginControlUpgradeLease
		err   error
	}
	started := make(chan beginResult, 1)
	go func() {
		lease, beginErr := gate.begin(time.Now().Add(time.Second))
		started <- beginResult{lease: lease, err: beginErr}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		upgrading := gate.upgrading
		gate.mu.Unlock()
		if upgrading {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upgrade gate did not enter quiescing state")
		}
		time.Sleep(time.Millisecond)
	}

	inherited, err := gate.enter(true, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("enter inherited lease while quiescing: %v", err)
	}
	outer.release()
	select {
	case result := <-started:
		if result.lease != nil {
			result.lease.release()
		}
		t.Fatalf("upgrade started before inherited work drained: %v", result.err)
	case <-time.After(20 * time.Millisecond):
	}
	inherited.release()
	var exclusive *pluginControlUpgradeLease
	select {
	case result := <-started:
		if result.err != nil {
			t.Fatalf("begin upgrade: %v", result.err)
		}
		exclusive = result.lease
	case <-time.After(time.Second):
		t.Fatal("upgrade did not start after inherited work drained")
	}

	readerDone := make(chan error, 1)
	go func() {
		lease, enterErr := gate.enter(false, time.Now().Add(time.Second))
		if lease != nil {
			lease.release()
		}
		readerDone <- enterErr
	}()
	select {
	case err := <-readerDone:
		t.Fatalf("normal request entered during exclusive upgrade: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	exclusive.release()
	select {
	case err := <-readerDone:
		if err != nil {
			t.Fatalf("normal request after upgrade: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal request did not resume after upgrade")
	}
}

func TestPluginControlUpgradeGateTimeoutLeavesOldRuntimeAvailable(t *testing.T) {
	gate := newPluginControlUpgradeGate()
	active, err := gate.enter(false, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("enter active lease: %v", err)
	}
	if lease, err := gate.begin(time.Now().Add(20 * time.Millisecond)); err == nil {
		if lease != nil {
			lease.release()
		}
		t.Fatal("begin upgrade error = nil, want drain timeout")
	}
	probe, err := gate.enter(false, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("old runtime gate remained blocked after timeout: %v", err)
	}
	probe.release()
	active.release()
}

func TestPluginControlUpgradeSnapshotStateLimit(t *testing.T) {
	runtime := goja.New()
	host := &pluginControlHost{vm: runtime}
	if _, err := host.exportUpgradeState(runtime.ToValue(strings.Repeat("x", pluginControlUpgradeMaxStateBytes))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("exportUpgradeState(oversized) error = %v, want size rejection", err)
	}
	if state, err := host.exportUpgradeState(runtime.ToValue(map[string]any{"ok": true})); err != nil || state == nil {
		t.Fatalf("exportUpgradeState(valid) = %#v/%v, want JSON state", state, err)
	}
}

func TestPluginControlUpgradeSnapshotPreservesJavaScriptNumberSemantics(t *testing.T) {
	runtime := goja.New()
	host := &pluginControlHost{vm: runtime}
	state, err := host.exportUpgradeState(runtime.ToValue(map[string]any{
		"schema_version": 1,
		"handoffs":       1,
	}))
	if err != nil {
		t.Fatalf("exportUpgradeState() error = %v", err)
	}
	decoded, ok := state.(map[string]any)
	if !ok {
		t.Fatalf("upgrade state type = %T, want map[string]any", state)
	}
	for _, key := range []string{"schema_version", "handoffs"} {
		if _, ok := decoded[key].(float64); !ok {
			t.Fatalf("upgrade state %s type = %T, want float64", key, decoded[key])
		}
	}
	if err := runtime.Set("upgradeState", state); err != nil {
		t.Fatalf("set upgrade state: %v", err)
	}
	value, err := runtime.RunString(`
if (typeof upgradeState.schema_version !== 'number') throw new Error('schema type');
if (upgradeState.schema_version !== 1) throw new Error('schema value');
upgradeState.handoffs + 1;
`)
	if err != nil {
		t.Fatalf("evaluate restored upgrade state: %v", err)
	}
	if got := value.Export(); got != int64(2) {
		t.Fatalf("restored numeric addition = %v (%T), want 2", got, got)
	}
}

func TestPluginControlUpgradeSnapshotConsecutiveNumericHandoffs(t *testing.T) {
	state := any(map[string]any{"schema_version": float64(1), "handoffs": float64(0)})
	for generation := 1; generation <= 2; generation++ {
		runtime := goja.New()
		if err := runtime.Set("state", state); err != nil {
			t.Fatalf("generation %d set state: %v", generation, err)
		}
		value, err := runtime.RunString(`({
  schema_version: state.schema_version,
  handoffs: state.handoffs + 1
})`)
		if err != nil {
			t.Fatalf("generation %d restore state: %v", generation, err)
		}
		host := &pluginControlHost{vm: runtime}
		state, err = host.exportUpgradeState(value)
		if err != nil {
			t.Fatalf("generation %d export state: %v", generation, err)
		}
		decoded := state.(map[string]any)
		if got := decoded["handoffs"]; got != float64(generation) {
			t.Fatalf("generation %d handoffs = %v (%T), want %d", generation, got, got, generation)
		}
		if got := fmt.Sprint(decoded["handoffs"]); got != fmt.Sprint(generation) {
			t.Fatalf("generation %d handoffs text = %q, want %d", generation, got, generation)
		}
	}
}
