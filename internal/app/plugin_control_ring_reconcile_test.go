package app

import (
	"testing"
	"time"
)

// A plugin_reconcile resource written from a control handler (hook bindings)
// reconciles only the dataplane. The ring readers must follow it: the object
// may have attached, or been reloaded, right there.
func TestPluginRingReconcileAfterDataplaneFollowsAttachState(t *testing.T) {
	controller := &pluginRingReadControllerTest{}
	controller.responses = []pluginRingReadResponse{{result: pluginEBPFRingReadResult{
		Records: []pluginEBPFRingRecord{{RawSample: []byte{1, 2, 3}}}, Bytes: 3,
	}}}
	runtime, plugin := newPluginRingRuntimeForTest(t, controller, PluginRingSubscription{
		ID: "events", Object: "main", Map: "events", Worker: "reader", Handler: "onRing",
		QueueSize: 4, MaxRecords: 4, MaxBytes: 4096, PollTimeoutMS: 10,
	}, `
exports.onRing = function (ctx) {
  metrics.counter("ring_records", ctx.payload.records.length);
};`)

	detached := pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{plugin.ID: {Mode: pluginRuntimeModeDataplane}}}
	runtime.ReconcilePluginRingSubscriptionsAfterDataplane(detached)
	if state := runtime.pluginRingBusSnapshot(plugin.ID); state.SubscriptionCount != 0 {
		t.Fatalf("ring readers before the object attached: %+v", state)
	}
	runtime.ReconcilePluginRingSubscriptionsAfterDataplane(attachedPluginRingSnapshot(plugin.ID))
	waitForPluginMetricValue(t, runtime, plugin.ID, "ring_records", 1, 3*time.Second)
	runtime.ReconcilePluginRingSubscriptionsAfterDataplane(detached)
	if state := runtime.pluginRingBusSnapshot(plugin.ID); state.SubscriptionCount != 0 {
		t.Fatalf("ring readers after the object detached: %+v", state)
	}
}

type ringReconcileRecorder struct {
	pluginControlRuntime
	snapshots []pluginRuntimeSnapshot
}

func (r *ringReconcileRecorder) ReconcilePluginRingSubscriptionsAfterDataplane(snapshot pluginRuntimeSnapshot) {
	r.snapshots = append(r.snapshots, snapshot)
}

func TestPluginReconcileResourceFromControlReconcilesRingSubscriptions(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "control_plugin", `{
  "api_version": "v1",
  "id": "control_plugin",
  "name": "Control Plugin",
  "version": "0.1.0",
  "kind": "control",
  "resources": [{
    "id": "hook_bindings",
    "methods": ["list", "create", "update", "delete", "get"],
    "runtime_update": "plugin_reconcile",
    "max_records": 4,
    "max_record_bytes": 2048
  }]
}`)
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{WebBind: "127.0.0.1", WebPort: 8080, WebToken: "test-token", PluginsDir: dir})
	attached := pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"control_plugin": {Mode: pluginRuntimeModeDataplane, Attached: true, Attachable: true},
	}}
	pm := &ProcessManager{db: db, cfg: cfg, pluginRuntime: pluginDataplaneRuntimeTest{snapshot: attached}}
	recorder := &ringReconcileRecorder{pluginControlRuntime: newPluginControlRuntime(db, cfg, pm)}
	pm.pluginControlRuntime = recorder
	defer recorder.Close()

	plugin, err := loadPluginFromDir(dir+"/control_plugin", "control_plugin")
	if err != nil {
		t.Fatal(err)
	}
	resource := PluginResource{ID: "hook_bindings", RuntimeUpdate: "plugin_reconcile"}
	if err := pm.ApplyPluginResourceReconcileFromControl(plugin, resource); err != nil {
		t.Fatalf("ApplyPluginResourceReconcileFromControl() error = %v", err)
	}
	if len(recorder.snapshots) != 1 {
		t.Fatalf("ring subscriptions reconciled %d times, want once", len(recorder.snapshots))
	}
	if state, ok := recorder.snapshots[0].stateFor("control_plugin"); !ok || !state.Attached {
		t.Fatalf("ring reconcile got snapshot %+v, want the dataplane's", recorder.snapshots[0])
	}
}
