//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestKernelXDPPluginAttachmentStatesReportAttachMode(t *testing.T) {
	programs := []loadedKernelXDPPluginProgram{{plan: kernelXDPPluginHookPlan{
		PluginID: "fw", HookID: "filter", ObjectID: "fw", ProgramRef: "xdp_filter", Stage: "pre_forward", Mode: "enforce",
		Interfaces: []string{"eth0", "eth1", "eth2"}, InterfaceIndexes: []uint32{3, 4, 5},
	}}}
	attachments := []xdpAttachment{{ifindex: 3, flags: nl.XDP_FLAGS_DRV_MODE}, {ifindex: 4, flags: nl.XDP_FLAGS_SKB_MODE}}
	states := kernelXDPPluginAttachmentStates(programs, 0, attachments, nil)["fw"]
	if len(states) != 3 {
		t.Fatalf("states = %+v", states)
	}
	want := map[string]string{"eth0": "driver", "eth1": "generic", "eth2": ""}
	for _, state := range states {
		if state.XDPMode != want[state.Interface] || state.Status != "attached" || state.Mode != "enforce" {
			t.Fatalf("state for %s = %+v, want xdp_mode %q", state.Interface, state, want[state.Interface])
		}
	}
}

func stableXDPHookPluginForPinTest() LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{ID: "stable_xdp_filter", Name: "Stable XDP Filter", Version: "1.0.0", Kind: "pipeline", Stability: pluginStabilityStable},
		Hooks: []PluginHook{{
			ID: "filter", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 10,
			Program: "fw:xdp_filter", Mode: "enforce", Interfaces: []string{"eth0"},
		}},
		Status: pluginStatusActive,
	}
}

func TestOrderedKernelRuntimeReportsCorePinnedToTC(t *testing.T) {
	enabled := true
	rt := &orderedKernelRuleRuntime{
		cfg: pluginsEnabledTestConfig(&Config{PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled}),
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineXDP}},
			{name: kernelEngineTC, rt: &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineTC}},
		},
	}
	if rt.CoreEnginePinnedToTC() {
		t.Fatal("pinned before any reconcile")
	}
	for _, tc := range []struct {
		name    string
		catalog *PluginCatalog
		want    bool
	}{
		{name: "xdp plugin hook", catalog: &PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), stableXDPHookPluginForPinTest()}}, want: true},
		{name: "no plugin hooks", catalog: &PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin()}}, want: false},
		{name: "tc plugin hook", catalog: &PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), stableTCHookPluginForOrderTest()}}, want: true},
		{name: "reconcile without catalog", catalog: nil, want: false},
	} {
		var err error
		if tc.catalog == nil {
			_, err = rt.Reconcile([]Rule{{ID: 1, Enabled: true}})
		} else {
			_, err = rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, *tc.catalog)
		}
		if err != nil {
			t.Fatalf("%s: reconcile error = %v", tc.name, err)
		}
		if got := rt.CoreEnginePinnedToTC(); got != tc.want {
			t.Fatalf("%s: CoreEnginePinnedToTC() = %v, want %v", tc.name, got, tc.want)
		}
	}
	var nilRuntime *orderedKernelRuleRuntime
	if nilRuntime.CoreEnginePinnedToTC() {
		t.Fatal("nil runtime reported pinned")
	}
}

// TestPluginAttachmentsReportLiveXDPDispatcherModes attaches a real XDP
// plugin hook on a veth (driver mode) and a dummy link (no native XDP, so
// generic mode) and reads the state back through plugin.attachments().
func TestPluginAttachmentsReportLiveXDPDispatcherModes(t *testing.T) {
	if os.Getenv(kernelXDPPluginTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged XDP plugin attachment status test", kernelXDPPluginTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	t.Setenv(veerRuntimeStateDirEnv, t.TempDir())

	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	vethName, peerName, dummyName := "vas"+suffix, "vat"+suffix, "vad"+suffix
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: vethName}, PeerName: peerName}); err != nil {
		t.Skipf("create attachment status veth: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(vethName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}}); err != nil {
		t.Skipf("create attachment status dummy link: %v", err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(dummyName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	for _, name := range []string{vethName, peerName, dummyName} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}

	const pluginID = "xdp_status_live"
	pluginsDir := t.TempDir()
	writeTestPlugin(t, pluginsDir, pluginID, `{
  "api_version":"v1",
  "id":"`+pluginID+`",
  "name":"XDP Status Live",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"status","runtime_update":"runtime_query"}],
  "control":{"main":"control.js","permissions":[]}
}`)
	writePluginControlScript(t, pluginsDir, pluginID, `
exports.onAction = function () {
  var host = plugin.host();
  return {status: plugin.attachments(), order: host.kernel_engine_order, pinned: host.core_engine_pinned_to_tc, now: ebpf.monotonicMs()};
};`)

	objectDir := t.TempDir()
	objectPath := compileAttachmentStatusXDPObject(t, objectDir)
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	dataplanePlugin := LoadedPlugin{
		PluginManifest: PluginManifest{ID: pluginID, Name: "XDP Status Live", Version: "1.0.0", Kind: "pipeline", Stability: pluginStabilityLab},
		Objects: []PluginObject{{
			ID: "status", Path: filepath.Base(objectPath), ResolvedSHA256: fmt.Sprintf("%x", sum[:]), Status: pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{{ID: "xdp_pass", Section: "xdp/pass", Type: kernelEngineXDP}},
		}},
		Hooks: []PluginHook{{
			ID: "filter", Engine: kernelEngineXDP, Attach: "ingress", Stage: "pre_forward", Priority: 10,
			Program: "status:xdp_pass", Mode: "observe", Interfaces: []string{vethName, dummyName},
		}},
		Status:  pluginStatusActive,
		rootDir: objectDir,
	}

	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir, PluginsEnabledSetting: &enabled, PluginsDataplaneSetting: &enabled})
	cfg.KernelEngineOrder = []string{kernelEngineXDP, kernelEngineTC}
	kernel := &orderedKernelRuleRuntime{
		cfg: cfg,
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineXDP}},
			{name: kernelEngineTC, rt: &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineTC}},
		},
		xdpPlugins: newKernelXDPPluginPipelineRuntime(cfg),
	}
	t.Cleanup(func() { _ = kernel.xdpPlugins.Close() })
	if _, err := kernel.ReconcileWithPluginCatalog(nil, PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), dataplanePlugin}}); err != nil {
		t.Fatalf("reconcile xdp plugin hook: %v", err)
	}

	pm := &ProcessManager{kernelRuntime: kernel, pluginRuntime: disabledPluginDataplaneRuntime{}}
	controlPlugin := loadTestPluginByID(t, cfg, pluginID)
	control := newPluginControlRuntime(openTestDB(t), cfg, pm).(*pluginControlManager)
	t.Cleanup(func() { _ = control.Close() })
	value, err := control.QueryPluginAction(controlPlugin, controlPlugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	raw, _ := json.Marshal(value)
	var result struct {
		Status struct {
			Mode        string `json:"mode"`
			Attached    bool   `json:"attached"`
			Error       string `json:"error"`
			Attachments []struct {
				HookID    string `json:"hook_id"`
				Engine    string `json:"engine"`
				Interface string `json:"interface"`
				Status    string `json:"status"`
				XDPMode   string `json:"xdp_mode"`
			} `json:"attachments"`
		} `json:"status"`
		Order  []string `json:"order"`
		Pinned bool     `json:"pinned"`
		Now    float64  `json:"now"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	t.Logf("plugin.attachments() = %s", raw)
	if result.Status.Mode != pluginRuntimeModeDataplane || !result.Status.Attached || result.Status.Error != "" || len(result.Status.Attachments) != 2 {
		t.Fatalf("live attachment status = %s", raw)
	}
	wantModes := map[string]string{vethName: "driver", dummyName: "generic"}
	for _, attachment := range result.Status.Attachments {
		if attachment.HookID != "filter" || attachment.Engine != kernelEngineXDP || attachment.Status != "attached" {
			t.Fatalf("live attachment = %+v", attachment)
		}
		if attachment.XDPMode != wantModes[attachment.Interface] {
			t.Fatalf("%s xdp_mode = %q, want %q", attachment.Interface, attachment.XDPMode, wantModes[attachment.Interface])
		}
		link, err := netlink.LinkByName(attachment.Interface)
		if err != nil {
			t.Fatal(err)
		}
		xdp := link.Attrs().Xdp
		kernelMode := ""
		if xdp != nil {
			switch xdp.AttachMode {
			case nl.XDP_ATTACHED_DRV:
				kernelMode = "driver"
			case nl.XDP_ATTACHED_SKB:
				kernelMode = "generic"
			}
		}
		if kernelMode != attachment.XDPMode {
			t.Fatalf("%s kernel reports xdp mode %q (%+v), plugin.attachments() reports %q", attachment.Interface, kernelMode, xdp, attachment.XDPMode)
		}
	}
	if len(result.Order) != 2 || result.Order[0] != kernelEngineXDP || !result.Pinned {
		t.Fatalf("host engine order = %q pinned = %v, want xdp-first order pinned to tc", result.Order, result.Pinned)
	}
	if result.Now <= 0 {
		t.Fatalf("ebpf.monotonicMs() = %v", result.Now)
	}
	nowNS, err := pluginMonotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	if delta := float64(nowNS)/1e6 - result.Now; delta < 0 || delta > 60_000 {
		t.Fatalf("ebpf.monotonicMs() = %v is %v ms away from CLOCK_MONOTONIC", result.Now, delta)
	}
}

func compileAttachmentStatusXDPObject(t *testing.T, dir string) string {
	t.Helper()
	sourcePath := filepath.Join(dir, "xdp_status.bpf.c")
	objectPath := filepath.Join(dir, "xdp_status.o")
	source := `
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
struct xdp_md;
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def SEC("maps") xdp_prog_chain = {3, sizeof(__u32), sizeof(__u32), 24, 0};
static void (*bpf_tail_call)(void *, void *, __u32) = (void *)12;
SEC("xdp/pass") int xdp_pass(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &xdp_prog_chain, 7);
  return 2;
}
char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	return objectPath
}
