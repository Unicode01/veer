//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

// The native plugin tests need a built worker and the echo example plugin:
//
//	VEER_PLUGIN_WORKER=.../veer-plugin-worker
//	VEER_TEST_NATIVE_ECHO=.../libnative_echo.so
//
// scripts/build-native-plugins.sh builds both.
func nativeEchoLibraryForTest(t *testing.T) string {
	t.Helper()
	library := os.Getenv("VEER_TEST_NATIVE_ECHO")
	if library == "" || os.Getenv(pluginNativeWorkerEnv) == "" {
		t.Skip("VEER_TEST_NATIVE_ECHO and VEER_PLUGIN_WORKER are required for native plugin tests")
	}
	if pluginNativeHostTriple() == "" {
		t.Skip("native plugins are not supported on this host")
	}
	return library
}

const nativeEchoActions = `[
  {"id": "echo", "runtime_update": "runtime_query"},
  {"id": "count", "runtime_update": "runtime_query"},
  {"id": "kv", "runtime_update": "runtime_query"},
  {"id": "call_from_thread", "runtime_update": "runtime_query"},
  {"id": "fail", "runtime_update": "runtime_apply"},
  {"id": "host_error", "runtime_update": "runtime_apply"},
  {"id": "panic", "runtime_update": "runtime_apply"},
  {"id": "crash", "runtime_update": "runtime_apply"},
  {"id": "sleep", "runtime_update": "runtime_apply"},
  {"id": "post", "runtime_update": "runtime_apply"},
  {"id": "timer", "runtime_update": "runtime_apply"},
  {"id": "dispatch", "runtime_update": "runtime_apply"}
]`

func writeNativeEchoPlugin(t *testing.T, pluginsDir, library, worker string) {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, "native_echo")
	libDir := filepath.Join(pluginDir, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(library)
	if err != nil {
		t.Fatalf("read echo library: %v", err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libnative_echo.so"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "native_echo",
  "name": "Native Echo",
  "version": "1.0.0",
  "kind": "control",
  "stability": "lab",
  "control": {
    "library": {"` + pluginNativeHostTriple() + `": {"path": "lib/libnative_echo.so"}},
    "worker": "` + worker + `",
    "permissions": ["event", "kv", "plugin.register", "resource", "timer", "worker"],
    "register": {
      "actions": ` + nativeEchoActions + `,
      "resources": [{"id": "items", "methods": ["list", "get"]}],
      "subscriptions": [{"id": "items_changed", "topic": "resource.changed", "handler": "onCount", "queue_size": 256}]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newNativeEchoHarness(t *testing.T, worker string) (*pluginControlManager, LoadedPlugin, func(key string) string) {
	t.Helper()
	library := nativeEchoLibraryForTest(t)
	dir := t.TempDir()
	writeNativeEchoPlugin(t, dir, library, worker)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "native_echo")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*pluginControlManager)
	t.Cleanup(func() { _ = rt.Close() })
	catalog := loadPluginCatalog(cfg)
	applyPluginRuntimeSnapshot(&catalog, rt.Reconcile(catalog))
	kv := func(key string) string {
		record, err := store.GetPluginRecord(db, "native_echo", pluginControlKVResourceID, key)
		if err != nil {
			return ""
		}
		return record.DataJSON
	}
	return rt, plugin, kv
}

func nativeEchoAction(t *testing.T, plugin LoadedPlugin, id string) PluginAction {
	t.Helper()
	for _, action := range plugin.Actions {
		if action.ID == id {
			return action
		}
	}
	t.Fatalf("action %s is not registered; actions = %+v", id, plugin.Actions)
	return PluginAction{}
}

func waitForNativeEcho(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNativePluginRegistersSurfaceFromManifest(t *testing.T) {
	_, plugin, _ := newNativeEchoHarness(t, "shared")
	if len(plugin.Actions) != 12 {
		t.Fatalf("registered actions = %d, want 12: %+v (runtime %s: %s)", len(plugin.Actions), plugin.Actions, plugin.Runtime.Reason, plugin.Runtime.Error)
	}
}

func TestNativePluginQueryAndHostCalls(t *testing.T) {
	rt, plugin, kv := newNativeEchoHarness(t, "shared")
	value, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatalf("echo query error = %v", err)
	}
	encoded, _ := json.Marshal(value)
	if !strings.Contains(string(encoded), `"echo":{"x":1}`) || !strings.Contains(string(encoded), `"handler":"onAction"`) {
		t.Fatalf("echo result = %s", encoded)
	}
	value, err = rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "kv"), json.RawMessage(`{"stored":true}`))
	if err != nil {
		t.Fatalf("kv query error = %v", err)
	}
	encoded, _ = json.Marshal(value)
	if !strings.Contains(string(encoded), `"data":{"stored":true}`) {
		t.Fatalf("kv round trip = %s", encoded)
	}
	if got := kv("value"); got != `{"stored":true}` {
		t.Fatalf("kv value = %q", got)
	}
}

func TestNativePluginReconcileReachesInstance(t *testing.T) {
	_, _, kv := newNativeEchoHarness(t, "shared")
	waitForNativeEcho(t, "reconcile", func() bool { return kv("reconciles") != "" })
}

func TestNativePluginHandlerErrors(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "fail"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "on purpose") {
		t.Fatalf("fail action error = %v", err)
	}
	err = rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "host_error"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "no.such.method") {
		t.Fatalf("host_error action error = %v", err)
	}
	value, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "call_from_thread"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("call_from_thread error = %v", err)
	}
	encoded, _ := json.Marshal(value)
	if !strings.Contains(string(encoded), "dispatch thread") {
		t.Fatalf("call_from_thread result = %s, want a dispatch thread error", encoded)
	}
}

func TestNativePluginPanicRestartsInstance(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "panic"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("panic action error = %v", err)
	}
	waitForNativeEcho(t, "instance restart", func() bool {
		_, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{}`))
		return err == nil
	})
}

func TestNativePluginCrashDemotesSharedPlugin(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	if _, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("echo before crash error = %v", err)
	}
	err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "crash"), json.RawMessage(`{}`))
	if err == nil || !errors.Is(err, errPluginHostProcessExited) {
		t.Fatalf("crash action error = %v, want a worker exit", err)
	}
	if reason := rt.nativePool.demotionReason("native_echo"); reason == "" {
		t.Fatalf("crashing plugin was not demoted")
	}
	waitForNativeEcho(t, "dedicated worker", func() bool {
		_, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{}`))
		return err == nil
	})
	states := rt.nativePool.snapshot()
	if len(states) != 1 || states[0].Group != "dedicated:native_echo" {
		t.Fatalf("workers after demotion = %+v", states)
	}
}

func TestNativePluginTimeoutKillsWorker(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "dedicated")
	rt.executionTimeout = 300 * time.Millisecond
	started := time.Now()
	err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "sleep"), json.RawMessage(`{"ms":5000}`))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("sleep action error = %v, want a timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	waitForNativeEcho(t, "worker restart", func() bool {
		_, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{}`))
		return err == nil
	})
}

func TestNativePluginPostDeliversWake(t *testing.T) {
	rt, plugin, kv := newNativeEchoHarness(t, "shared")
	if err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "post"), json.RawMessage(`{"n":7}`)); err != nil {
		t.Fatalf("post action error = %v", err)
	}
	waitForNativeEcho(t, "wake", func() bool { return kv("woke") == `{"n":7}` })
}

// TestNativePluginDispatchRunsOnItsOwnInstance: worker.dispatch work runs on
// an instance of its own, so the plugin's queue keeps serving meanwhile.
func TestNativePluginDispatchRunsOnItsOwnInstance(t *testing.T) {
	rt, plugin, kv := newNativeEchoHarness(t, "shared")
	if err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "dispatch"), json.RawMessage(`{"ms":1500}`)); err != nil {
		t.Fatalf("dispatch action error = %v", err)
	}
	started := time.Now()
	if _, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "echo"), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("echo during dispatched work: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("echo waited %s behind the dispatched work", elapsed)
	}
	if kv("slow_done") != "" {
		t.Fatal("dispatched work finished before it could have")
	}
	waitForNativeEcho(t, "dispatched work", func() bool { return kv("slow_done") == "true" })
}

func TestNativePluginTimerFires(t *testing.T) {
	rt, plugin, kv := newNativeEchoHarness(t, "shared")
	if err := rt.ApplyPluginAction(plugin, nativeEchoAction(t, plugin, "timer"), json.RawMessage(`{"ms":20}`)); err != nil {
		t.Fatalf("timer action error = %v", err)
	}
	waitForNativeEcho(t, "timer", func() bool { return kv("timer") == `"echo_timer"` })
}

// TestNativePluginMessageLatency reports the cost of one message round trip
// through the worker, with and without a host call inside the handler.
func TestNativePluginMessageLatency(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	echo := nativeEchoAction(t, plugin, "echo")
	kvAction := nativeEchoAction(t, plugin, "kv")
	for i := 0; i < 50; i++ {
		if _, err := rt.QueryPluginAction(plugin, echo, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("warm-up: %v", err)
		}
	}
	const rounds = 2000
	started := time.Now()
	for i := 0; i < rounds; i++ {
		if _, err := rt.QueryPluginAction(plugin, echo, json.RawMessage(`{"i":1}`)); err != nil {
			t.Fatalf("echo: %v", err)
		}
	}
	perMessage := time.Since(started) / rounds
	started = time.Now()
	for i := 0; i < rounds/4; i++ {
		if _, err := rt.QueryPluginAction(plugin, kvAction, json.RawMessage(`{"i":1}`)); err != nil {
			t.Fatalf("kv: %v", err)
		}
	}
	perKV := time.Since(started) / (rounds / 4)
	t.Logf("native message round trip: %s; with kv.set+kv.get: %s", perMessage, perKV)
}

// TestNativePluginRawExchangeLatency measures the worker round trip alone:
// one frame to the worker, the plugin's handler, one frame back.
func TestNativePluginRawExchangeLatency(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "dedicated")
	instance, err := rt.nativePool.load(plugin, pluginNativeInstanceHooks{}, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer instance.unload(time.Now().Add(time.Second))
	payload := []byte(`{"kind":"action","action":{"id":"echo"},"payload":{}}`)
	noCalls := func(string, []byte) (int32, []byte) { return pluginNativeStatusPerm, nil }
	for i := 0; i < 100; i++ {
		if _, _, err := instance.exchange(pluginNativeMsgAction, "onAction", payload, noCalls, time.Now().Add(time.Second)); err != nil {
			t.Fatalf("warm-up: %v", err)
		}
	}
	const rounds = 5000
	started := time.Now()
	for i := 0; i < rounds; i++ {
		status, _, err := instance.exchange(pluginNativeMsgAction, "onAction", payload, noCalls, time.Now().Add(time.Second))
		if err != nil || status != pluginNativeStatusOK {
			t.Fatalf("exchange status=%d err=%v", status, err)
		}
	}
	t.Logf("raw worker round trip: %s", time.Since(started)/rounds)
}

// TestNativePluginEventLatency measures event delivery to a native plugin:
// one event at a time, and bursts the subscription queue batches, with the
// CPU time the host and the worker spend per event.
func TestNativePluginEventLatency(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	count := func() int64 {
		value, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "count"), json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		switch typed := value.(type) {
		case float64:
			return int64(typed)
		case int64:
			return typed
		}
		t.Fatalf("count result %T %v", value, value)
		return 0
	}
	resource := plugin.Resources[0]
	sub := func() *pluginControlEventSubscriptionRuntime {
		rt.eventMu.Lock()
		defer rt.eventMu.Unlock()
		for _, candidate := range rt.eventSubscriptions {
			if candidate.pluginID == "native_echo" {
				return candidate
			}
		}
		return nil
	}
	waitForNativeEcho(t, "subscription", func() bool { return sub() != nil })
	_ = count()
	delivered := func() uint64 { return sub().delivered.Load() }
	workerPID := 0
	for _, state := range rt.nativePool.snapshot() {
		workerPID = state.PID
	}
	cpu := func() time.Duration {
		var usage syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
		total := time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", workerPID)); err == nil {
			fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+2:]))
			if len(fields) > 12 {
				utime, _ := strconv.ParseInt(fields[11], 10, 64)
				stime, _ := strconv.ParseInt(fields[12], 10, 64)
				total += time.Duration(utime+stime) * 10 * time.Millisecond
			}
		}
		return total
	}
	base := delivered()
	const single = 2000
	cpuBefore := cpu()
	started := time.Now()
	for i := 0; i < single; i++ {
		target := base + uint64(i) + 1
		rt.publishPluginResourceChanged("native_echo", plugin, resource, "update", "k")
		deadline := time.Now().Add(5 * time.Second)
		for delivered() < target {
			if time.Now().After(deadline) {
				t.Fatalf("event %d was not delivered; errors=%d", i, sub().errors.Load())
			}
			time.Sleep(5 * time.Microsecond)
		}
	}
	perEvent := time.Since(started) / single
	cpuSingle := (cpu() - cpuBefore) / single
	const rounds, burst = 20, 200
	cpuBefore = cpu()
	started = time.Now()
	for round := 0; round < rounds; round++ {
		base = delivered()
		for i := 0; i < burst; i++ {
			rt.publishPluginResourceChanged("native_echo", plugin, resource, "update", "k")
		}
		waitForNativeEcho(t, "burst", func() bool { return delivered() >= base+burst })
	}
	perBurstEvent := time.Since(started) / (rounds * burst)
	cpuBurst := (cpu() - cpuBefore) / (rounds * burst)
	if got := count(); got < single+rounds*burst {
		t.Fatalf("plugin counted %d events, want at least %d", got, single+rounds*burst)
	}
	t.Logf("native event delivery: one at a time %s (CPU %s); in bursts of %d %s (CPU %s) per event", perEvent, cpuSingle, burst, perBurstEvent, cpuBurst)
}
