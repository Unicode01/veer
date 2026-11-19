package app

import (
	"slices"
	"strings"
	"testing"
)

func TestNormalizePluginHookTCFallback(t *testing.T) {
	hook := PluginHook{ID: "filter", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCFallback: "  fw:tc  "}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("xdp hook with tc_fallback: %v", err)
	}
	if hook.TCFallback != "fw:tc" {
		t.Fatalf("tc_fallback = %q, want it trimmed", hook.TCFallback)
	}
	for name, item := range map[string]struct {
		hook PluginHook
		want string
	}{
		"tc engine":  {PluginHook{ID: "a", Engine: "tc", Stage: "pre_forward", Program: "fw:tc", TCFallback: "fw:tc"}, "only available to xdp hooks"},
		"no program": {PluginHook{ID: "a", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCFallback: "tc"}, "object:program"},
		"nul":        {PluginHook{ID: "a", Engine: "xdp", Stage: "pre_forward", Program: "fw:xdp", TCFallback: "fw:t\x00c"}, "invalid characters"},
	} {
		hook := item.hook
		if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), item.want) {
			t.Errorf("%s: error = %v, want %q", name, err, item.want)
		}
	}
}

func TestValidatePluginHookTCFallbackProgramRefs(t *testing.T) {
	plugin := func(fallback string) *LoadedPlugin {
		return &LoadedPlugin{
			Objects: []PluginObject{
				{ID: "fw", Path: "fw.o", Status: pluginObjectStatusVerified, Programs: []PluginObjectProgram{
					{ID: "filter", Section: "xdp/fw", Type: kernelEngineXDP},
					{ID: "filter_tc", Section: "tc/fw", Type: kernelEngineTC},
					{ID: "other_xdp", Section: "xdp/other", Type: kernelEngineXDP},
				}},
				{ID: "other", Path: "other.o", Status: pluginObjectStatusVerified, Programs: []PluginObjectProgram{
					{ID: "filter_tc", Section: "tc/fw", Type: kernelEngineTC},
				}},
			},
			Hooks: []PluginHook{{ID: "filter", Engine: kernelEngineXDP, Stage: "pre_forward", Program: "fw:filter", TCFallback: fallback}},
		}
	}
	for _, ok := range []string{"", "fw:filter_tc", "fw.o:tc/fw"} {
		if err := validatePluginHookProgramRefs(plugin(ok)); err != nil {
			t.Errorf("tc_fallback %q: %v", ok, err)
		}
	}
	for fallback, want := range map[string]string{
		"other:filter_tc": "the object of the xdp program",
		"fw:missing":      "not found",
		"fw:other_xdp":    "want tc",
	} {
		if err := validatePluginHookProgramRefs(plugin(fallback)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("tc_fallback %q: error = %v, want %q", fallback, err, want)
		}
	}
}

func TestPluginRequiredHostFeaturesTCFallback(t *testing.T) {
	plugin := LoadedPlugin{Hooks: []PluginHook{{ID: "filter", Engine: kernelEngineXDP, Stage: "pre_forward", Program: "fw:filter"}}}
	if features := pluginRequiredHostFeatures(plugin); slices.Contains(features, "dataplane.xdp_tc_fallback.v1") {
		t.Fatalf("plain xdp hook requires %v", features)
	}
	plugin.Hooks[0].TCFallback = "fw:filter_tc"
	features := pluginRequiredHostFeatures(plugin)
	if !slices.Contains(features, "dataplane.xdp_tc_fallback.v1") || !slices.Contains(features, "dataplane.xdp_pipeline.v1") {
		t.Fatalf("xdp hook with tc_fallback requires %v", features)
	}
	if !slices.Contains(pluginRuntimeFeatures, "dataplane.xdp_tc_fallback.v1") {
		t.Fatal("runtime does not advertise dataplane.xdp_tc_fallback.v1")
	}
}

func TestNormalizePluginObjectAllowsXDPWithTCFallback(t *testing.T) {
	object := PluginObject{ID: "fw", Path: "fw.o", Programs: []PluginObjectProgram{
		{ID: "filter", Section: "xdp/fw", Type: kernelEngineXDP},
		{ID: "filter_tc", Section: "tc/fw", Type: kernelEngineTC},
	}}
	if err := normalizePluginObject(&object); err != nil {
		t.Fatalf("xdp program with its tc twin: %v", err)
	}
	object.Programs = append(object.Programs, PluginObjectProgram{ID: "nf", Section: "netfilter/fw", Type: pluginEngineNetfilter})
	if err := normalizePluginObject(&object); err == nil || !strings.Contains(err.Error(), "cannot mix") {
		t.Fatalf("xdp, tc and netfilter programs: error = %v, want a mix rejection", err)
	}
}

func TestValidatePluginHookProgramRefsKeepsMixedObjectTCForFallbacks(t *testing.T) {
	plugin := &LoadedPlugin{
		Objects: []PluginObject{{ID: "fw", Path: "fw.o", Status: pluginObjectStatusVerified, Programs: []PluginObjectProgram{
			{ID: "filter", Section: "xdp/fw", Type: kernelEngineXDP},
			{ID: "filter_tc", Section: "tc/fw", Type: kernelEngineTC},
		}}},
		Hooks: []PluginHook{{ID: "tc", Engine: kernelEngineTC, Stage: "pre_forward", Program: "fw:filter_tc"}},
	}
	if err := validatePluginHookProgramRefs(plugin); err == nil || !strings.Contains(err.Error(), "only serve as an xdp hook's tc_fallback") {
		t.Fatalf("tc hook on an object with xdp programs: error = %v", err)
	}
}
