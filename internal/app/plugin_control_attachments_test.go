package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type pluginAttachmentStatusControllerTest struct {
	*pluginControlMapControllerTest
	mu        sync.Mutex
	states    map[string]PluginRuntimeState
	requested []string
	pinned    bool
}

func (c *pluginAttachmentStatusControllerTest) PluginAttachmentRuntimeState(pluginID string) PluginRuntimeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requested = append(c.requested, pluginID)
	return c.states[pluginID]
}

func (c *pluginAttachmentStatusControllerTest) PluginCoreEnginePinnedToTC() bool {
	return c.pinned
}

func (c *pluginAttachmentStatusControllerTest) requestedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requested...)
}

const pluginAttachmentStatusTestScript = `
var registrationErrors = [];
try { plugin.attachments(); } catch (err) { registrationErrors.push(String(err)); }
try { ebpf.monotonicMs(); } catch (err) { registrationErrors.push(String(err)); }
exports.onAction = function () {
  var host = plugin.host();
  var before = ebpf.monotonicMs();
  return {
    registration_errors: registrationErrors,
    main: plugin.attachments(),
    worker: worker.call('probe', 'onProbe', {}),
    order: host.kernel_engine_order,
    pinned: host.core_engine_pinned_to_tc,
    before: before,
    after: ebpf.monotonicMs()
  };
};
exports.onProbe = function () {
  return {status: plugin.attachments(), now: ebpf.monotonicMs()};
};
`

func writePluginAttachmentStatusTestPlugin(t *testing.T, dir, id string) {
	t.Helper()
	writeTestPlugin(t, dir, id, `{
  "api_version":"v1",
  "id":"`+id+`",
  "name":"Attachment Status",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"status","runtime_update":"runtime_query"}],
  "control":{"main":"control.js","permissions":["worker"]}
}`)
	writePluginControlScript(t, dir, id, pluginAttachmentStatusTestScript)
}

type pluginAttachmentStatusTestResult struct {
	RegistrationErrors []string       `json:"registration_errors"`
	Main               map[string]any `json:"main"`
	Worker             struct {
		Status map[string]any `json:"status"`
		Now    float64        `json:"now"`
	} `json:"worker"`
	Order  []string `json:"order"`
	Pinned bool     `json:"pinned"`
	Before float64  `json:"before"`
	After  float64  `json:"after"`
}

func queryPluginAttachmentStatusForTest(t *testing.T, cfg *Config, controller pluginEBPFMapController, id string) pluginAttachmentStatusTestResult {
	t.Helper()
	plugin := loadTestPluginByID(t, cfg, id)
	runtime := newPluginControlRuntime(openTestDB(t), cfg, controller).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	value, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result pluginAttachmentStatusTestResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return result
}

func TestPluginAttachmentsReportOnlyTheCallingPlugin(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		name := "in_process"
		if isolated {
			name = "isolated"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginAttachmentStatusTestPlugin(t, dir, "attach_status")
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			if isolated {
				cfg = isolatedPluginsTestConfig(&Config{PluginsDir: dir})
			}
			cfg.KernelEngineOrder = []string{"xdp", "tc"}
			controller := &pluginAttachmentStatusControllerTest{
				pluginControlMapControllerTest: &pluginControlMapControllerTest{},
				pinned:                         true,
				states: map[string]PluginRuntimeState{
					"attach_status": {
						Mode:     pluginRuntimeModeDataplane,
						Attached: true,
						Reason:   "xdp hook filter skipped missing interface eth9",
						Attachments: []PluginAttachmentState{
							{HookID: "filter", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Interface: "eth0", Program: "fw:xdp_filter", Mode: "enforce", ChainSlot: 3, XDPMode: "generic", Status: "attached"},
							{HookID: "filter", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Interface: "eth1", Program: "fw:xdp_filter", Mode: "enforce", ChainSlot: 3, XDPMode: "driver", Status: "attached"},
						},
					},
					"other_plugin": {
						Mode:        pluginRuntimeModeDataplane,
						Attached:    true,
						Attachments: []PluginAttachmentState{{HookID: "secret", Engine: kernelEngineXDP, Interface: "eth7", XDPMode: "driver", Status: "attached"}},
					},
				},
			}
			result := queryPluginAttachmentStatusForTest(t, cfg, controller, "attach_status")

			if len(result.RegistrationErrors) != 2 ||
				!strings.Contains(result.RegistrationErrors[0], "plugin.attachments is unavailable during plugin registration") ||
				!strings.Contains(result.RegistrationErrors[1], "ebpf.monotonicMs is unavailable during plugin registration") {
				t.Fatalf("registration errors = %q", result.RegistrationErrors)
			}
			wantMain := map[string]any{
				"mode": "dataplane", "attached": true, "reason": "xdp hook filter skipped missing interface eth9", "error": "",
				"attachments": []any{
					map[string]any{"hook_id": "filter", "engine": "xdp", "attach": "ingress", "stage": "pre_forward", "interface": "eth0", "program": "fw:xdp_filter", "status": "attached", "error": "", "xdp_mode": "generic"},
					map[string]any{"hook_id": "filter", "engine": "xdp", "attach": "ingress", "stage": "pre_forward", "interface": "eth1", "program": "fw:xdp_filter", "status": "attached", "error": "", "xdp_mode": "driver"},
				},
			}
			if !reflect.DeepEqual(result.Main, wantMain) {
				t.Fatalf("main attachments = %#v, want %#v", result.Main, wantMain)
			}
			if !reflect.DeepEqual(result.Worker.Status, wantMain) {
				t.Fatalf("worker attachments = %#v, want %#v", result.Worker.Status, wantMain)
			}
			for _, requested := range controller.requestedIDs() {
				if requested != "attach_status" {
					t.Fatalf("attachment state requested for %q, want only the calling plugin", requested)
				}
			}
			if len(controller.requestedIDs()) != 2 {
				t.Fatalf("attachment state requests = %q, want main and worker", controller.requestedIDs())
			}
			if !reflect.DeepEqual(result.Order, []string{"xdp", "tc"}) || !result.Pinned {
				t.Fatalf("host engine order = %q pinned = %v", result.Order, result.Pinned)
			}
			if result.Before <= 0 || result.After < result.Before || result.Worker.Now < result.Before {
				t.Fatalf("monotonic clock went backwards or is unset: before=%v after=%v worker=%v", result.Before, result.After, result.Worker.Now)
			}
		})
	}
}

func TestPluginAttachmentsEmptyWithoutDataplane(t *testing.T) {
	dir := t.TempDir()
	writePluginAttachmentStatusTestPlugin(t, dir, "attach_empty")
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	result := queryPluginAttachmentStatusForTest(t, cfg, nil, "attach_empty")
	want := map[string]any{"mode": "registered", "attached": false, "reason": "", "error": "", "attachments": []any{}}
	if !reflect.DeepEqual(result.Main, want) || !reflect.DeepEqual(result.Worker.Status, want) {
		t.Fatalf("attachments without a dataplane = main %#v worker %#v, want %#v", result.Main, result.Worker.Status, want)
	}
	if !reflect.DeepEqual(result.Order, []string{"tc"}) || result.Pinned {
		t.Fatalf("default host engine order = %q pinned = %v", result.Order, result.Pinned)
	}
}

func TestPluginAttachmentsReportDataplaneFailure(t *testing.T) {
	dir := t.TempDir()
	writePluginAttachmentStatusTestPlugin(t, dir, "attach_failed")
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	failure := "attach xdp plugin dispatcher on eth1: interface already has xdp program id 7; Veer will not replace it"
	state := pluginRuntimeErrorState(failure)
	state.Reason = "xdp plugin pipeline failed"
	controller := &pluginAttachmentStatusControllerTest{
		pluginControlMapControllerTest: &pluginControlMapControllerTest{},
		states:                         map[string]PluginRuntimeState{"attach_failed": state},
	}
	result := queryPluginAttachmentStatusForTest(t, cfg, controller, "attach_failed")
	want := map[string]any{"mode": "error", "attached": false, "reason": "xdp plugin pipeline failed", "error": failure, "attachments": []any{}}
	if !reflect.DeepEqual(result.Main, want) {
		t.Fatalf("failed attachments = %#v, want %#v", result.Main, want)
	}
}

func TestPluginAttachmentStatusMapEngineFields(t *testing.T) {
	status := pluginAttachmentStatusMap(PluginRuntimeState{Attachments: []PluginAttachmentState{
		{HookID: "tc", Engine: kernelEngineTC, Attach: "ingress", Stage: "pre_forward", Interface: "veer-pipeline", Program: "obj:tc", Status: "chained"},
		{HookID: "nf", Engine: pluginEngineNetfilter, Attach: "forward", Stage: "filter", Interface: "host", Family: "ipv4", NetfilterHook: "forward", Phase: "filter", Namespace: "host", Program: "obj:nf", Status: "staging"},
	}})
	if status["attached"] != true || status["mode"] != pluginRuntimeModeRegistered {
		t.Fatalf("status summary = %#v", status)
	}
	attachments := status["attachments"].([]any)
	tc := attachments[0].(map[string]any)
	if _, ok := tc["namespace"]; ok || tc["xdp_mode"] != "" || tc["status"] != "chained" {
		t.Fatalf("tc attachment = %#v", tc)
	}
	nf := attachments[1].(map[string]any)
	if nf["namespace"] != "host" || nf["family"] != "ipv4" || nf["netfilter_hook"] != "forward" || nf["phase"] != "filter" || nf["xdp_mode"] != "" {
		t.Fatalf("netfilter attachment = %#v", nf)
	}
}

type pluginDataplaneRuntimeSnapshotTest struct {
	snapshot pluginRuntimeSnapshot
}

func (rt *pluginDataplaneRuntimeSnapshotTest) Reconcile(PluginCatalog) pluginRuntimeSnapshot {
	panic("plugin.attachments must not reconcile the dataplane")
}

func (rt *pluginDataplaneRuntimeSnapshotTest) Snapshot() pluginRuntimeSnapshot {
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *pluginDataplaneRuntimeSnapshotTest) Close() error { return nil }

type pluginCorePinnedKernelRuntimeTest struct {
	*pluginPipelineKernelRuntimeTest
	pinned bool
}

func (rt *pluginCorePinnedKernelRuntimeTest) CoreEnginePinnedToTC() bool { return rt.pinned }

func TestProcessManagerPluginAttachmentRuntimeStateCombinesOwnSnapshots(t *testing.T) {
	kernel := &pluginPipelineKernelRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"fw": {Mode: pluginRuntimeModeDataplane, Attached: true, Attachments: []PluginAttachmentState{
			{HookID: "filter", Engine: kernelEngineXDP, Attach: "ingress", Interface: "eth0", Program: "fw:xdp", XDPMode: "driver", Status: "attached"},
		}},
		"other": {Mode: pluginRuntimeModeDataplane, Attached: true, Attachments: []PluginAttachmentState{
			{HookID: "other", Engine: kernelEngineXDP, Interface: "eth9", Status: "attached"},
		}},
	}}}
	dataplane := &pluginDataplaneRuntimeSnapshotTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"fw": {Mode: pluginRuntimeModeDataplane, Attached: true, Reason: "netfilter hook staged", Attachments: []PluginAttachmentState{
			{HookID: "nf", Engine: pluginEngineNetfilter, Attach: "forward", Interface: "host", Namespace: "host", Program: "fw:nf", Status: "attached"},
		}},
	}}}
	pm := &ProcessManager{kernelRuntime: kernel, pluginRuntime: dataplane}
	state := pm.PluginAttachmentRuntimeState("fw")
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 2 || state.Reason != "netfilter hook staged" {
		t.Fatalf("combined state = %+v", state)
	}
	for _, attachment := range state.Attachments {
		if attachment.HookID == "other" {
			t.Fatalf("combined state leaked another plugin's attachment: %+v", state.Attachments)
		}
	}
	if got := pm.PluginAttachmentRuntimeState("missing"); got.Mode != "" || len(got.Attachments) != 0 {
		t.Fatalf("unknown plugin state = %+v", got)
	}
	if pm.PluginCoreEnginePinnedToTC() {
		t.Fatal("a kernel runtime that cannot pin the core must report false")
	}
	pm.kernelRuntime = &pluginCorePinnedKernelRuntimeTest{pluginPipelineKernelRuntimeTest: kernel, pinned: true}
	if !pm.PluginCoreEnginePinnedToTC() {
		t.Fatal("pinned kernel runtime reported false")
	}
	var nilPM *ProcessManager
	if nilPM.PluginCoreEnginePinnedToTC() || nilPM.PluginAttachmentRuntimeState("fw").Mode != "" {
		t.Fatal("nil process manager must report an empty state")
	}
}

func TestPluginMonotonicMsUsesTheBPFClockDomain(t *testing.T) {
	first, err := pluginMonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	second, err := pluginMonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	if first < 0 || second < first {
		t.Fatalf("monotonic clock = %d then %d", first, second)
	}
}
