//go:build linux

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestPluginDataplaneRuntimeAttachesTCObservePlugin(t *testing.T) {
	if os.Getenv("FORWARD_RUN_PLUGIN_DATAPLANE_TEST") != "1" {
		t.Skip("set FORWARD_RUN_PLUGIN_DATAPLANE_TEST=1 to attach a TC plugin filter")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to attach TC filters")
	}

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "packet_observer")
	uiDir := filepath.Join(pluginDir, "ui")
	if err := os.MkdirAll(uiDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("plugin asset ok"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.html) error = %v", err)
	}
	objectPath := compileTestBPFObject(t, pluginDir, "observer.o")
	sum, err := sha256File(objectPath)
	if err != nil {
		t.Fatalf("sha256File() error = %v", err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "packet_observer",
  "name": "Packet Observer",
  "version": "0.1.0",
  "kind": "pipeline",
  "control": {"main": "control.js", "permissions": ["ebpf.load", "hook.attach", "ui"]}
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	writePluginControlScript(t, dir, "packet_observer", `
ebpf.loadObject({
  id: 'observer',
  path: 'observer.o',
  sha256: '`+sum+`',
  programs: [{id: 'tc_ingress', section: 'tc/ingress', type: 'tc'}]
});
hooks.attach({
  id: 'observe-ingress',
  engine: 'tc',
  attach: 'ingress',
  stage: 'forward',
  priority: 10,
  program: 'observer:tc_ingress',
  mode: 'observe',
  interfaces: ['lo']
});
ui.register({static_dir: 'ui', entry: 'index.html'});
`)

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              dir,
	}
	catalog := loadPluginCatalogWithControlRegistration(cfg)
	rt := newPluginDataplaneRuntime(cfg)
	defer rt.Close()

	snapshot := rt.Reconcile(catalog)
	state, ok := snapshot.stateFor("packet_observer")
	if !ok {
		t.Fatalf("snapshot = %+v, want packet_observer runtime state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attachable || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin runtime state = %+v, want attached dataplane plugin", state)
	}
	if len(state.Attachments) != 1 || state.Attachments[0].Interface != "lo" || state.Attachments[0].Attach != "ingress" {
		t.Fatalf("attachments = %+v, want one lo ingress attachment", state.Attachments)
	}
	if !tcPluginFilterPresent(t, "lo", "packet_observer") {
		t.Fatal("TC plugin filter not found on lo ingress after reconcile")
	}

	if err := rt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if tcPluginFilterPresent(t, "lo", "packet_observer") {
		t.Fatal("TC plugin filter still present on lo ingress after Close")
	}
}

func TestAssignPluginTCFilterIDsAssignsStableSlots(t *testing.T) {
	items := []pluginDataplaneDesiredPlugin{
		{attachments: []pluginTCAttachPlan{{}, {}}},
		{attachments: []pluginTCAttachPlan{{}}},
	}

	if err := assignPluginTCFilterIDs(items); err != nil {
		t.Fatalf("assignPluginTCFilterIDs() error = %v", err)
	}

	if got, want := items[0].attachments[0].Priority, pluginTCFilterPriorityBase; got != want {
		t.Fatalf("first priority = %d, want %d", got, want)
	}
	if got, want := items[0].attachments[1].HandleMinor, pluginTCFilterHandleBase+1; got != want {
		t.Fatalf("second handle minor = %d, want %d", got, want)
	}
	if got, want := items[1].attachments[0].Priority, pluginTCFilterPriorityBase+2; got != want {
		t.Fatalf("third priority = %d, want %d", got, want)
	}
}

func TestAssignPluginTCFilterIDsRejectsGlobalOverflow(t *testing.T) {
	items := []pluginDataplaneDesiredPlugin{
		{attachments: make([]pluginTCAttachPlan, pluginTCFilterMaxCount)},
		{attachments: []pluginTCAttachPlan{{}}},
	}

	err := assignPluginTCFilterIDs(items)
	if err == nil || !strings.Contains(err.Error(), "too many plugin tc attachments") {
		t.Fatalf("assignPluginTCFilterIDs() error = %v, want overflow error", err)
	}
}

func TestPluginDataplaneStabilityGateAllowsLabByDefault(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "lab_plugin",
			Name:      "Lab Plugin",
			Version:   "0.1.0",
			Kind:      "pipeline",
			Stability: pluginStabilityLab,
		},
		Status: pluginStatusActive,
	}

	ok, reason := pluginDataplaneStabilityAllowed(plugin, &Config{})
	if !ok || reason != "" {
		t.Fatalf("pluginDataplaneStabilityAllowed(lab default) = %t/%q, want allowed", ok, reason)
	}
}

func TestPluginDataplaneStabilityGateBlocksDeprecated(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "old_plugin",
			Name:      "Old Plugin",
			Version:   "0.1.0",
			Kind:      "pipeline",
			Stability: pluginStabilityDeprecated,
		},
		Status: pluginStatusActive,
	}

	ok, reason := pluginDataplaneStabilityAllowed(plugin, &Config{})
	if ok || !strings.Contains(reason, "deprecated") {
		t.Fatalf("pluginDataplaneStabilityAllowed(deprecated) = %t/%q, want blocked", ok, reason)
	}
}

func TestBuildDesiredPluginsReportsMissingInterfaceForAllowedLabPlugin(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "lab_plugin",
			Name:      "Lab Plugin",
			Version:   "0.1.0",
			Kind:      "pipeline",
			Stability: pluginStabilityLab,
		},
		Objects: []PluginObject{{
			ID:     "observer",
			Path:   "observer.o",
			Status: pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{{
				ID:      "tc_ingress",
				Section: "tc/ingress",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:         "observe-ingress",
			Engine:     kernelEngineTC,
			Attach:     "ingress",
			Stage:      "forward",
			Program:    "observer:tc_ingress",
			Mode:       "observe",
			Interfaces: []string{"definitely-missing0"},
		}},
		Status: pluginStatusActive,
	}
	rt := &linuxPluginDataplaneRuntime{cfg: &Config{}}

	desired, states := rt.buildDesiredPlugins(PluginCatalog{Plugins: []LoadedPlugin{plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired plugins = %+v, want none for missing interface", desired)
	}
	state, ok := states["lab_plugin"]
	if !ok || state.Mode != pluginRuntimeModeError || !strings.Contains(state.Error, "resolve plugin hook interface") {
		t.Fatalf("state = %+v/%t, want missing interface runtime error", state, ok)
	}
}

func TestBuildDesiredPluginDataplaneSkipsAttachNone(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "no_attach",
			Name:    "No Attach",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:     "observer",
			Path:   "observer.o",
			Status: pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{{
				ID:      "tc_ingress",
				Section: "tc/ingress",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:         "observe-none",
			Engine:     kernelEngineTC,
			Attach:     "none",
			Stage:      "pre_forward",
			Program:    "observer:tc_ingress",
			Mode:       "observe",
			Interfaces: []string{"lo"},
		}},
		Status: pluginStatusActive,
	}

	item, state := buildDesiredPluginDataplane(plugin)
	if len(item.attachments) != 0 {
		t.Fatalf("attachments = %+v, want none for attach=none", item.attachments)
	}
	if state.Mode != pluginRuntimeModeRegistered || !strings.Contains(state.Reason, "attach=none") {
		t.Fatalf("state = %+v, want registered attach=none reason", state)
	}
}

func TestBuildDesiredPluginDataplaneKeepsXDPHooksRegistrationOnly(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "xdp_probe",
			Name:    "XDP Probe",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:     "probe",
			Path:   "probe.o",
			Status: pluginObjectStatusVerified,
			Programs: []PluginObjectProgram{{
				ID:      "xdp_ingress",
				Section: "xdp",
				Type:    kernelEngineXDP,
			}},
		}},
		Hooks: []PluginHook{{
			ID:         "xdp-ingress",
			Engine:     kernelEngineXDP,
			Attach:     "ingress",
			Stage:      "forward",
			Program:    "probe:xdp_ingress",
			Mode:       "observe",
			Interfaces: []string{"lo"},
		}},
		Status: pluginStatusActive,
	}

	item, state := buildDesiredPluginDataplane(plugin)
	if len(item.attachments) != 0 {
		t.Fatalf("attachments = %+v, want none for registration-only xdp hook", item.attachments)
	}
	if state.Mode != pluginRuntimeModeRegistered || state.Attachable || state.Attached || state.AttachmentCount != 0 {
		t.Fatalf("state = %+v, want registered non-attachable xdp hook", state)
	}
	if !strings.Contains(state.Reason, "xdp dataplane plugins are not attached yet") {
		t.Fatalf("state reason = %q, want xdp registration-only reason", state.Reason)
	}
}

func tcPluginFilterPresent(t *testing.T, ifaceName, pluginID string) bool {
	t.Helper()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		t.Fatalf("LinkByName(%q) error = %v", ifaceName, err)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatalf("FilterList(%q ingress) error = %v", ifaceName, err)
	}
	for _, filter := range filters {
		bpf, ok := filter.(*netlink.BpfFilter)
		if !ok || bpf == nil {
			continue
		}
		if strings.Contains(bpf.Name, pluginID) {
			return true
		}
	}
	return false
}
