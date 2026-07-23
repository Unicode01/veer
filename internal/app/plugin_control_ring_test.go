package app

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestPluginRingSubscribeRegistersBoundedWorkerPush(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "ring_register",
			Control: &PluginControl{Permissions: []string{"ebpf.load", "ebpf.map_read", "worker"}},
		},
		Objects: []PluginObject{{ID: "main"}},
	}
	host := &pluginControlHost{vm: goja.New(), plugin: plugin, registrationPhase: true}
	host.ebpfRingSubscribe(goja.FunctionCall{Arguments: []goja.Value{host.vm.ToValue(map[string]any{
		"id": "events", "object": "main", "map": "events", "worker": "reader", "handler": "onRing",
	})}})
	surface := host.surface
	if len(surface.RingSubscriptions) != 1 {
		t.Fatalf("ring subscriptions = %+v", surface.RingSubscriptions)
	}
	spec := surface.RingSubscriptions[0]
	if spec.QueueSize != pluginRingDefaultQueueSize || spec.MaxRecords != pluginRingDefaultBatchRecords ||
		spec.MaxBytes != pluginRingDefaultBatchBytes || spec.PollTimeoutMS != pluginRingDefaultPollTimeoutMS {
		t.Fatalf("normalized ring subscription = %+v", spec)
	}
	plugin.RingSubscriptions = surface.RingSubscriptions
	if err := validatePluginRingSubscriptions(&plugin); err != nil {
		t.Fatal(err)
	}
	if err := pluginRingReadConflictError(plugin, "main", "events"); err == nil || !strings.Contains(err.Error(), "second consumer") {
		t.Fatalf("ring read conflict error = %v", err)
	}
}

func TestPluginRingSubscriptionsRejectDuplicateMapConsumer(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{ID: "ring_duplicate", Control: &PluginControl{Permissions: []string{"ebpf.load", "ebpf.map_read", "worker"}}},
		Objects:        []PluginObject{{ID: "main"}},
		RingSubscriptions: []PluginRingSubscription{
			{ID: "first", Object: "main", Map: "events", Worker: "one", Handler: "onRing"},
			{ID: "second", Object: "main", Map: "events", Worker: "two", Handler: "onRing"},
		},
	}
	if err := validatePluginRingSubscriptions(&plugin); err == nil || !strings.Contains(err.Error(), "multiple consumers") {
		t.Fatalf("duplicate ring consumer error = %v", err)
	}
}

func TestPluginRingPushDeliversBatchesAndRecoversReadErrors(t *testing.T) {
	controller := &pluginRingReadControllerTest{}
	controller.responses = []pluginRingReadResponse{
		{err: errors.New("temporary reader failure")},
		{result: pluginEBPFRingReadResult{
			Records: []pluginEBPFRingRecord{{RawSample: []byte{1, 2, 3}, Remaining: 0}}, Bytes: 3,
		}},
	}
	runtime, plugin := newPluginRingRuntimeForTest(t, controller, PluginRingSubscription{
		ID: "events", Object: "main", Map: "events", Worker: "reader", Handler: "onRing",
		QueueSize: 4, MaxRecords: 4, MaxBytes: 4096, PollTimeoutMS: 10,
	}, `
exports.onRing = function (ctx) {
  metrics.counter("ring_batches", 1);
  metrics.counter("ring_records", ctx.payload.records.length);
};`)
	runtime.reconcilePluginRingSubscriptions(map[string]LoadedPlugin{plugin.ID: plugin}, attachedPluginRingSnapshot(plugin.ID))
	waitForPluginMetricValue(t, runtime, plugin.ID, "ring_records", 1, 3*time.Second)
	state := waitForPluginRingState(t, runtime, plugin.ID, 3*time.Second, func(state PluginRingBusState) bool {
		return state.DeliveredBatches == 1
	})
	if state.SubscriptionCount != 1 || state.ReadErrors != 1 || state.ReadRecords != 1 || state.ReadBytes != 3 ||
		state.EnqueuedBatches != 1 || state.DeliveredBatches != 1 || state.HandlerErrors != 0 {
		t.Fatalf("ring push state = %+v", state)
	}
	if state.Subscriptions[0].LastReadAt == "" || state.Subscriptions[0].LastDeliveryAt == "" {
		t.Fatalf("ring timestamps = %+v", state.Subscriptions[0])
	}
}

func waitForPluginRingState(t *testing.T, runtime *gojaPluginControlRuntime, pluginID string, timeout time.Duration, ready func(PluginRingBusState) bool) PluginRingBusState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		state := runtime.pluginRingBusSnapshot(pluginID)
		if ready(state) {
			return state
		}
		if time.Now().After(deadline) {
			t.Fatalf("ring state did not become ready: %+v", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginRingPushDropsBatchesUnderWorkerBackpressure(t *testing.T) {
	controller := &pluginRingReadControllerTest{burst: 80}
	runtime, plugin := newPluginRingRuntimeForTest(t, controller, PluginRingSubscription{
		ID: "events", Object: "main", Map: "events", Worker: "reader", Handler: "onRing",
		QueueSize: 1, MaxRecords: 1, MaxBytes: 128, PollTimeoutMS: 10,
	}, `
exports.onRing = function () {
  var until = Date.now() + 25;
  while (Date.now() < until) {}
};`)
	runtime.reconcilePluginRingSubscriptions(map[string]LoadedPlugin{plugin.ID: plugin}, attachedPluginRingSnapshot(plugin.ID))
	deadline := time.Now().Add(3 * time.Second)
	for {
		state := runtime.pluginRingBusSnapshot(plugin.ID)
		if state.DroppedBatches > 0 && state.DroppedRecords > 0 && state.DeliveredBatches > 0 {
			if state.PendingBytes > state.PendingByteLimit || state.Subscriptions[0].PeakPendingBytes > state.PendingByteLimit {
				t.Fatalf("ring pending byte budget exceeded: %+v", state)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ring backpressure state = %+v", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type pluginRingReadResponse struct {
	result pluginEBPFRingReadResult
	err    error
}

type pluginRingReadControllerTest struct {
	pluginControlMapControllerTest
	mu        sync.Mutex
	responses []pluginRingReadResponse
	burst     int
}

func (c *pluginRingReadControllerTest) ReadPluginRingBuffer(_ string, _ string, _ string, request pluginEBPFRingReadRequest) (pluginEBPFRingReadResult, error) {
	c.mu.Lock()
	if len(c.responses) > 0 {
		response := c.responses[0]
		c.responses = c.responses[1:]
		c.mu.Unlock()
		return response.result, response.err
	}
	if c.burst > 0 {
		c.burst--
		c.mu.Unlock()
		return pluginEBPFRingReadResult{Records: []pluginEBPFRingRecord{{RawSample: []byte{1}}}, Bytes: 1}, nil
	}
	c.mu.Unlock()
	time.Sleep(time.Duration(request.TimeoutMS) * time.Millisecond)
	return pluginEBPFRingReadResult{TimedOut: true}, nil
}

func newPluginRingRuntimeForTest(t *testing.T, controller *pluginRingReadControllerTest, spec PluginRingSubscription, handler string) (*gojaPluginControlRuntime, LoadedPlugin) {
	t.Helper()
	dir := t.TempDir()
	writeTestPlugin(t, dir, "ring_push", `{
  "api_version":"v1","id":"ring_push","name":"Ring Push","version":"1.0.0","kind":"control","stability":"lab",
  "control":{"main":"control.js","permissions":["ebpf.load","ebpf.map_read","metrics","worker"]}
}`)
	writePluginControlScript(t, dir, "ring_push", handler)
	plugin, err := loadPluginFromDir(filepath.Join(dir, "ring_push"), "ring_push")
	if err != nil || plugin.Status != pluginStatusActive {
		t.Fatalf("load ring push plugin = %+v, err=%v", plugin, err)
	}
	plugin.Objects = []PluginObject{{ID: "main"}}
	plugin.RingSubscriptions = []PluginRingSubscription{spec}
	if err := validatePluginRingSubscriptions(&plugin); err != nil {
		t.Fatal(err)
	}
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(openTestDB(t), cfg, controller).(*gojaPluginControlRuntime)
	runtime.mu.Lock()
	runtime.plugins = map[string]LoadedPlugin{plugin.ID: plugin}
	runtime.snapshot = attachedPluginRingSnapshot(plugin.ID)
	runtime.mu.Unlock()
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, plugin
}

func attachedPluginRingSnapshot(pluginID string) pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		pluginID: {Mode: pluginRuntimeModeDataplane, Attached: true, Attachable: true},
	}}
}

func waitForPluginMetricValue(t *testing.T, runtime *gojaPluginControlRuntime, pluginID, name string, want float64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, metric := range runtime.pluginMetricSnapshot(pluginID) {
			if metric.Name == name && metric.Value == want {
				return
			}
		}
		if time.Now().After(deadline) {
			data, _ := json.Marshal(runtime.pluginRingBusSnapshot(pluginID))
			t.Fatalf("metric %s did not reach %v; ring state=%s", name, want, data)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
