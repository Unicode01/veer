package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestNormalizePluginHookTCEgress(t *testing.T) {
	hook := PluginHook{ID: "filter", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCEgress: "  fw:egress  "}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("xdp hook with tc_egress: %v", err)
	}
	if hook.TCEgress != "fw:egress" {
		t.Fatalf("tc_egress = %q, want it trimmed", hook.TCEgress)
	}
	for name, item := range map[string]struct {
		hook PluginHook
		want string
	}{
		"tc engine":  {PluginHook{ID: "a", Engine: "tc", Stage: "pre_forward", Program: "fw:tc", TCEgress: "fw:tc"}, "only available to xdp hooks"},
		"no program": {PluginHook{ID: "a", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCEgress: "egress"}, "object:program"},
		"nul":        {PluginHook{ID: "a", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCEgress: "fw:e\x00g"}, "invalid characters"},
	} {
		hook := item.hook
		if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), item.want) {
			t.Errorf("%s: error = %v, want %q", name, err, item.want)
		}
	}
}

func TestValidatePluginHookTCEgressProgramRefs(t *testing.T) {
	plugin := func(egress string) *LoadedPlugin {
		return &LoadedPlugin{
			Objects: []PluginObject{
				{ID: "fw", Path: "fw.o", Status: pluginObjectStatusVerified, Programs: []PluginObjectProgram{
					{ID: "filter", Section: "xdp/fw", Type: kernelEngineXDP},
					{ID: "filter_tc", Section: "tc/fw", Type: kernelEngineTC},
					{ID: "egress", Section: "tc/fw_egress", Type: kernelEngineTC},
					{ID: "other_xdp", Section: "xdp/other", Type: kernelEngineXDP},
				}},
				{ID: "other", Path: "other.o", Status: pluginObjectStatusVerified, Programs: []PluginObjectProgram{
					{ID: "egress", Section: "tc/fw_egress", Type: kernelEngineTC},
				}},
			},
			Hooks: []PluginHook{{ID: "filter", Engine: kernelEngineXDP, Stage: "pre_forward", Program: "fw:filter", TCFallback: "fw:filter_tc", TCEgress: egress}},
		}
	}
	for _, ok := range []string{"", "fw:egress", "fw.o:tc/fw_egress"} {
		if err := validatePluginHookProgramRefs(plugin(ok)); err != nil {
			t.Errorf("tc_egress %q: %v", ok, err)
		}
	}
	for egress, want := range map[string]string{
		"other:egress": "the object of the xdp program",
		"fw:missing":   "not found",
		"fw:other_xdp": "want tc",
	} {
		if err := validatePluginHookProgramRefs(plugin(egress)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("tc_egress %q: error = %v, want %q", egress, err, want)
		}
	}
}

func TestPluginRequiredHostFeaturesTCEgress(t *testing.T) {
	plugin := LoadedPlugin{Hooks: []PluginHook{{ID: "filter", Engine: kernelEngineXDP, Stage: "pre_forward", Program: "fw:filter"}}}
	if features := pluginRequiredHostFeatures(plugin); slices.Contains(features, "dataplane.xdp_tc_egress.v1") {
		t.Fatalf("plain xdp hook requires %v", features)
	}
	plugin.Hooks[0].TCEgress = "fw:egress"
	if features := pluginRequiredHostFeatures(plugin); !slices.Contains(features, "dataplane.xdp_tc_egress.v1") {
		t.Fatalf("xdp hook with tc_egress requires %v", features)
	}
	if !slices.Contains(pluginRuntimeFeatures, "dataplane.xdp_tc_egress.v1") {
		t.Fatal("runtime does not advertise dataplane.xdp_tc_egress.v1")
	}
}

// A binding record decides per hook whether the tc_egress program goes on
// the bound interfaces: absent or true attaches it, false leaves it off.
func TestPluginHookBindingTCEgressOptOut(t *testing.T) {
	for name, item := range map[string]struct {
		data string
		want string
	}{
		"absent": {`{"hook_id":"filter","interfaces":["eth0"]}`, "fw:egress"},
		"true":   {`{"hook_id":"filter","interfaces":["eth0"],"tc_egress":true}`, "fw:egress"},
		"false":  {`{"hook_id":"filter","interfaces":["eth0"],"tc_egress":false}`, ""},
	} {
		db := openTestDB(t)
		if _, err := store.AddPluginRecord(db, &store.PluginRecord{PluginID: "fw", ResourceID: pluginHookBindingsResourceID, RecordKey: "filter", DataJSON: item.data, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "fw"}, Status: pluginStatusActive,
			Resources: []PluginResource{{ID: pluginHookBindingsResourceID}},
			Hooks:     []PluginHook{{ID: "filter", Engine: kernelEngineXDP, Program: "fw:filter", TCEgress: "fw:egress", BindingRequired: true}}}
		hooks := applyPluginHookBindingsFromDB(PluginCatalog{Plugins: []LoadedPlugin{plugin}}, db).Plugins[0].Hooks
		if len(hooks) != 1 || hooks[0].TCEgress != item.want || !slices.Equal(hooks[0].Interfaces, []string{"eth0"}) {
			t.Errorf("%s: hooks = %+v, want tc_egress %q on eth0", name, hooks, item.want)
		}
	}
}
