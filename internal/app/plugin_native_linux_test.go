//go:build linux

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
  {"id": "dispatch", "runtime_update": "runtime_apply"},
  {"id": "host_call", "runtime_update": "runtime_query"}
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
    "permissions": ["crypto", "event", "kv", "net.admin", "net.l2", "net.udp", "plugin.register", "resource", "timer", "worker"],
    "net_access": [
      {"interfaces": ["*"], "operations": ["link.read", "l2"]},
      {"interfaces": ["lo"], "operations": ["udp"], "remote_cidrs": ["127.0.0.0/8"]}
    ],
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
	if len(plugin.Actions) != 13 {
		t.Fatalf("registered actions = %d, want 13: %+v (runtime %s: %s)", len(plugin.Actions), plugin.Actions, plugin.Runtime.Reason, plugin.Runtime.Error)
	}
}

// TestNativePluginLocalCallsMatchHost checks that the methods the worker
// serves itself answer exactly as the host's own implementation does:
// results, errors and their texts.
func TestNativePluginLocalCallsMatchHost(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	rt.mu.Lock()
	vm := rt.controlVMs[plugin.ID]
	rt.mu.Unlock()
	if vm == nil {
		t.Fatal("native_echo has no control VM")
	}
	host, err := vm.newControlHost(plugin)
	if err != nil {
		t.Fatal(err)
	}
	host.registrationPhase = false
	// Counters move between two reads of the same link.
	scrub := func(value any) any {
		var walk func(any) any
		walk = func(value any) any {
			switch typed := value.(type) {
			case map[string]any:
				delete(typed, "statistics")
				for key, item := range typed {
					typed[key] = walk(item)
				}
			case []any:
				for i, item := range typed {
					typed[i] = walk(item)
				}
			}
			return value
		}
		return walk(value)
	}
	normalize := func(raw []byte) any {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return scrub(value)
	}
	for _, call := range []struct {
		method string
		args   []any
	}{
		{"net.link.get", []any{"lo"}},
		{"net.link.get", []any{"lo", "host"}},
		{"net.link.get", []any{"veer-nosuch0"}},
		{"net.link.get", []any{}},
		{"net.link.get", []any{"bad/name"}},
		{"net.link.list", []any{}},
		{"net.link.getOffloads", []any{"lo"}},
		{"net.link.getOffloads", []any{"veer-nosuch0"}},
		{"crypto.md5", []any{"abc", map[string]any{"hex": "01:02"}, []any{3, 4}}},
		{"crypto.md5", []any{}},
		{"crypto.randomBytes", []any{0}},
		{"net.l2.send", []any{map[string]any{}}},
		{"net.l2.send", []any{"text"}},
		{"net.l2.send", []any{map[string]any{"interface": "veer-nosuch0", "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff"}}},
		{"net.l2.send", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff"}}},
		{"net.l2.send", []any{map[string]any{"interface": "lo", "ethertype": 0, "dst_mac": "ff:ff:ff:ff:ff:ff"}}},
		{"net.l2.send", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "dst_mac": "zz"}}},
		{"net.l2.send", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff", "payload": "abc"}}},
		{"net.l2.recv", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "timeout_ms": 20}}},
		{"net.l2.recv", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "timeout_ms": 0}}},
		{"net.l2.recv", []any{map[string]any{"interface": "lo", "ethertype": "0x8863", "pppoe_code": 300}}},
		{"net.l2.recvMany", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "timeout_ms": 20}}},
		{"net.l2.recvMany", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "max_frames": 65}}},
		{"net.l2.exchange", []any{map[string]any{"interface": "lo", "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff", "src_mac": "02:00:00:00:00:01", "recv_ethertype": "x"}}},
		{"net.l2.exchangeMany", []any{map[string]any{"interface": "veer-nosuch0", "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff"}}},
		{"net.udp.send", []any{map[string]any{"interface": "lo", "remote_port": 9}}},
		{"net.udp.send", []any{map[string]any{"interface": "lo", "remote_ip": "10.0.0.1", "remote_port": 9}}},
		{"net.udp.send", []any{map[string]any{"interface": "eth9", "remote_ip": "127.0.0.1", "remote_port": 9}}},
		{"net.udp.send", []any{map[string]any{"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 70000}}},
		{"net.udp.send", []any{map[string]any{"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 9, "timeout_ms": 0}}},
		{"net.udp.recv", []any{map[string]any{"interface": "lo"}}},
		{"net.udp.recv", []any{map[string]any{"interface": "lo", "local_port": 40391, "timeout_ms": 20}}},
		{"net.udp.recv", []any{map[string]any{"interface": "lo", "local_port": 40391, "max_bytes": 0}}},
		{"net.udp.exchange", []any{map[string]any{"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 9, "timeout_ms": 20}}},
	} {
		name := call.method + fmt.Sprint(call.args)
		payload, _ := json.Marshal(map[string]any{"method": call.method, "args": call.args})
		worker, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "host_call"), payload)
		if err != nil {
			t.Fatalf("%s through the worker: %v", name, err)
		}
		workerJSON, _ := json.Marshal(worker)
		value, _, hostErr := host.callPluginHostMethod(call.method, call.args)
		want := map[string]any{"value": value}
		if hostErr != nil {
			want = map[string]any{"error": boundedPluginHostError(hostErr.Error())}
		}
		wantJSON, _ := json.Marshal(want)
		got, expected := normalize(workerJSON), normalize(wantJSON)
		gotText, _ := json.Marshal(got)
		expectedText, _ := json.Marshal(expected)
		if string(gotText) != string(expectedText) {
			t.Errorf("%s:\n worker %s\n host   %s", name, gotText, expectedText)
		}
	}
	// The worker answered every one of them itself.
	for _, method := range []string{"net.link.get", "net.link.list", "net.link.getOffloads", "crypto.md5", "crypto.randomBytes",
		"net.l2.send", "net.l2.recv", "net.l2.recvMany", "net.l2.exchange", "net.l2.exchangeMany", "net.udp.send", "net.udp.recv", "net.udp.exchange"} {
		if count := rt.nativeHostCallCount(plugin.ID, method); count != 0 {
			t.Errorf("%s reached the host %d times; the worker should serve it", method, count)
		}
	}
	if _, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "kv"), json.RawMessage(`{"counted":true}`)); err != nil {
		t.Fatal(err)
	}
	if rt.nativeHostCallCount(plugin.ID, "kv.set") == 0 {
		t.Fatal("kv.set is not counted: the host call counter is not wired")
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

// TestNativePluginLocalL2FramesMatchHost moves frames over a veth pair: the
// worker's net.l2.recv must report a frame exactly as the host's does, and
// the host must receive what the worker's net.l2.send puts on the wire.
func TestNativePluginLocalL2FramesMatchHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for a veth pair and raw frames")
	}
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	rt.mu.Lock()
	vm := rt.controlVMs[plugin.ID]
	rt.mu.Unlock()
	host, err := vm.newControlHost(plugin)
	if err != nil {
		t.Fatal(err)
	}
	host.registrationPhase = false
	a, b := "veerl2a"+strconv.Itoa(os.Getpid()%1000), "veerl2b"+strconv.Itoa(os.Getpid()%1000)
	_ = exec.Command("ip", "link", "del", a).Run()
	if out, err := exec.Command("ip", "link", "add", a, "type", "veth", "peer", "name", b).CombinedOutput(); err != nil {
		t.Fatalf("add veth pair: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	for _, name := range []string{a, b} {
		if out, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput(); err != nil {
			t.Fatalf("set %s up: %v: %s", name, err, out)
		}
	}
	transport := newPluginControlL2Transport()
	sendLater := func(payload byte) {
		go func() {
			time.Sleep(150 * time.Millisecond)
			_ = transport.Send(pluginControlL2SendRequest{Interface: a, EtherType: 0x88b5, DstMAC: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Payload: []byte{payload, 2, 3}})
		}()
	}
	recvRequest := map[string]any{"interface": b, "ethertype": "0x88b5", "timeout_ms": 2000}

	sendLater(1)
	payload, _ := json.Marshal(map[string]any{"method": "net.l2.recv", "args": []any{recvRequest}})
	worker, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "host_call"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sendLater(1)
	value, _, err := host.callPluginHostMethod("net.l2.recv", []any{recvRequest})
	if err != nil {
		t.Fatal(err)
	}
	workerJSON, _ := json.Marshal(worker)
	hostJSON, _ := json.Marshal(map[string]any{"value": value})
	if string(workerJSON) != string(hostJSON) || !strings.Contains(string(workerJSON), `"payload_hex":"010203"`) {
		t.Fatalf("net.l2.recv:\n worker %s\n host   %s", workerJSON, hostJSON)
	}

	received := make(chan pluginControlL2Frame, 1)
	go func() {
		frame, err := transport.Recv(pluginControlL2RecvRequest{Interface: a, EtherType: 0x88b5, Timeout: 2 * time.Second, MaxBytes: 2048})
		if err == nil {
			received <- frame
		}
		close(received)
	}()
	time.Sleep(100 * time.Millisecond)
	payload, _ = json.Marshal(map[string]any{"method": "net.l2.send", "args": []any{map[string]any{"interface": b, "ethertype": "0x88b5", "dst_mac": "ff:ff:ff:ff:ff:ff", "payload": "0a0b"}}})
	if _, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "host_call"), payload); err != nil {
		t.Fatal(err)
	}
	frame, ok := <-received
	if !ok || !bytes.Equal(frame.Payload, []byte{0x0a, 0x0b}) {
		t.Fatalf("host did not receive the worker's frame: %+v ok=%t", frame, ok)
	}
}

// TestNativePluginLocalUDPMatchesHost receives one datagram on the loopback
// through the worker and one through the host: both must read the same.
func TestNativePluginLocalUDPMatchesHost(t *testing.T) {
	rt, plugin, _ := newNativeEchoHarness(t, "shared")
	rt.mu.Lock()
	vm := rt.controlVMs[plugin.ID]
	rt.mu.Unlock()
	host, err := vm.newControlHost(plugin)
	if err != nil {
		t.Fatal(err)
	}
	host.registrationPhase = false
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40392})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	sendLater := func() {
		go func() {
			time.Sleep(150 * time.Millisecond)
			_, _ = sender.WriteToUDP([]byte{1, 2, 3}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40393})
		}()
	}
	request := map[string]any{"interface": "lo", "local_ip": "127.0.0.1", "local_port": 40393, "timeout_ms": 2000}
	sendLater()
	payload, _ := json.Marshal(map[string]any{"method": "net.udp.recv", "args": []any{request}})
	worker, err := rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "host_call"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sendLater()
	value, _, err := host.callPluginHostMethod("net.udp.recv", []any{request})
	if err != nil {
		t.Fatal(err)
	}
	workerJSON, _ := json.Marshal(worker)
	hostJSON, _ := json.Marshal(map[string]any{"value": value})
	if string(workerJSON) != string(hostJSON) || !strings.Contains(string(workerJSON), `"remote_addr":"127.0.0.1:40392"`) {
		t.Fatalf("net.udp.recv:\n worker %s\n host   %s", workerJSON, hostJSON)
	}
	// A send reports the same shape, apart from the kernel's source port.
	payload, _ = json.Marshal(map[string]any{"method": "net.udp.send", "args": []any{map[string]any{"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 40392, "payload": "0a"}}})
	worker, err = rt.QueryPluginAction(plugin, nativeEchoAction(t, plugin, "host_call"), payload)
	if err != nil {
		t.Fatal(err)
	}
	workerJSON, _ = json.Marshal(worker)
	if !strings.Contains(string(workerJSON), `"bytes":1`) || !strings.Contains(string(workerJSON), `"remote_addr":"127.0.0.1:40392"`) || !strings.Contains(string(workerJSON), `"local_ip":"0.0.0.0"`) {
		t.Fatalf("net.udp.send through the worker = %s", workerJSON)
	}
	buffer := make([]byte, 16)
	_ = sender.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := sender.ReadFromUDP(buffer); err != nil || n != 1 || buffer[0] != 0x0a {
		t.Fatalf("the worker's datagram did not arrive: n=%d err=%v", n, err)
	}
}
