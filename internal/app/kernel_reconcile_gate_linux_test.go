//go:build linux

package app

import (
	"testing"
	"time"
)

func TestOrderedKernelRuntimeReportsAnEngineReconcile(t *testing.T) {
	engine := &reconcilingKernelRuntimeTest{}
	rt := &orderedKernelRuleRuntime{entries: []orderedKernelRuntimeEntry{{name: kernelEngineTC, rt: engine}}}
	if kernelRuntimeReconcileInProgress(rt) {
		t.Fatal("reconcile reported with none running")
	}
	// A plugin reconcile reconciles the TC engine without the ordered runtime.
	engine.reconciling.Store(true)
	if !kernelRuntimeReconcileInProgress(rt) {
		t.Fatal("an engine's reconcile was not reported")
	}
	engine.reconciling.Store(false)
	end := rt.reconciling.begin()
	if !kernelRuntimeReconcileInProgress(rt) {
		t.Fatal("the ordered runtime's own reconcile was not reported")
	}
	end()
}

// The plugin list reads the TC engine's plugin state; while a reconcile holds
// the engine's lock it gets the state from before that reconcile.
func TestTCPluginSnapshotDoesNotWaitForAReconcile(t *testing.T) {
	rt := &linuxKernelRuleRuntime{}
	rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{"firewall": {Mode: "tc", Attached: true}}}
	if got := rt.PluginSnapshot(); !got.Plugins["firewall"].Attached {
		t.Fatalf("plugin snapshot = %+v, want the attached firewall", got)
	}

	end := rt.reconciling.begin()
	defer end()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	done := make(chan pluginRuntimeSnapshot, 1)
	go func() { done <- rt.PluginSnapshot() }()
	select {
	case got := <-done:
		if !got.Plugins["firewall"].Attached {
			t.Fatalf("plugin snapshot during a reconcile = %+v, want the last one", got)
		}
		got.Plugins["firewall"] = PluginRuntimeState{}
		if last := rt.lastPluginSnapshot.Load(); !last.Plugins["firewall"].Attached {
			t.Fatal("the caller's copy shares its map with the kept snapshot")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the plugin snapshot waited for the reconcile")
	}
}
