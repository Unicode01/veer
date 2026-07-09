//go:build linux

package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

const kernelPluginPipelineTestEnv = "FORWARD_RUN_PLUGIN_PIPELINE_TEST"

func packetObserverPluginSourceDirForPipelineTest(t *testing.T) string {
	t.Helper()
	if sourceDir := strings.TrimSpace(os.Getenv(dataplanePerfPluginSourceEnv)); sourceDir != "" {
		return sourceDir
	}
	return filepath.Join(findRepoRoot(t), "examples", "plugins", "packet_observer")
}

func copyPacketObserverPluginForPipelineTest(t *testing.T, pluginsRoot string) string {
	t.Helper()

	sourceDir := packetObserverPluginSourceDirForPipelineTest(t)
	if includeDir := filepath.Join(filepath.Dir(sourceDir), "include"); isDirForPipelineTest(includeDir) {
		copyDirForTest(t, includeDir, filepath.Join(pluginsRoot, "include"))
	}
	pluginDir := filepath.Join(pluginsRoot, "packet_observer")
	copyDirForTest(t, sourceDir, pluginDir)
	return pluginDir
}

func isDirForPipelineTest(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func TestPreparedKernelRulesUseDispatchV4HonorsPluginPipeline(t *testing.T) {
	transparent := []preparedKernelRule{{
		spec:  kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		value: tcRuleValueV4{},
	}}
	fullNAT := []preparedKernelRule{{
		spec:  kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		value: tcRuleValueV4{Flags: kernelRuleFlagFullNAT},
	}}

	if preparedKernelRulesUseDispatchV4(transparent, false) {
		t.Fatal("transparent IPv4 rule without plugin pipeline unexpectedly requires dispatch")
	}
	if !preparedKernelRulesUseDispatchV4(transparent, true) {
		t.Fatal("transparent IPv4 rule with plugin pipeline should use dispatch")
	}
	if !preparedKernelRulesUseDispatchV4(fullNAT, false) {
		t.Fatal("full-NAT IPv4 rule should keep using dispatch without plugin pipeline")
	}
}

func TestNewTCKernelRuleRuntimeEnablesPluginPipelineFromConfig(t *testing.T) {
	enabled := true
	disabled := false

	rt := newTCKernelRuleRuntime(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	})
	if !rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = false, want true when external dataplane plugins are enabled")
	}

	rt = newTCKernelRuleRuntime(&Config{
		PluginsEnabledSetting:   &disabled,
		PluginsDataplaneSetting: &enabled,
	})
	if rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = true, want false when plugin scanning is disabled")
	}

	rt = newTCKernelRuleRuntime(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &disabled,
	})
	if rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = true, want false when plugin dataplane loading is disabled")
	}
}

func TestOrderedKernelRuntimePrefersTCWhenRuntimeTCPluginHooksActive(t *testing.T) {
	enabled := true
	xdp := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineXDP}
	tc := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineTC}
	rt := &orderedKernelRuleRuntime{
		cfg: &Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled,
		},
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinFVTapPlugin(), stableTCHookPluginForOrderTest()},
	})
	if err != nil {
		t.Fatalf("ReconcileWithPluginCatalog() error = %v", err)
	}
	if result := results[1]; !result.Running || result.Engine != kernelEngineTC {
		t.Fatalf("rule result = %+v, want tc because active tc plugin hooks must not be bypassed by xdp", result)
	}
	if len(xdp.assignments) != 0 {
		t.Fatalf("xdp assignments = %+v, want no rules assigned when tc plugin hooks are active", xdp.assignments)
	}
	if tc.reconcileWithCatalogCalls != 1 {
		t.Fatalf("tc ReconcileWithPluginCatalog calls = %d, want 1", tc.reconcileWithCatalogCalls)
	}
}

func TestOrderedKernelRuntimeDoesNotFallbackToXDPWhenRuntimeTCPluginHooksActive(t *testing.T) {
	enabled := true
	xdp := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Running: true, Engine: kernelEngineXDP},
		},
	}
	tc := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Error: "tc attach failed"},
		},
	}
	rt := &orderedKernelRuleRuntime{
		cfg: &Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled,
		},
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinFVTapPlugin(), stableTCHookPluginForOrderTest()},
	})
	if err != nil {
		t.Fatalf("ReconcileWithPluginCatalog() error = %v", err)
	}
	result := results[1]
	if result.Running || result.Engine == kernelEngineXDP || !strings.Contains(result.Error, "tc attach failed") {
		t.Fatalf("rule result = %+v, want tc failure without xdp bypass", result)
	}
	assertKernelRuntimeOnlyCleanupCalls(t, xdp.reconcileCalls)
	assertReconcileCallPrefix(t, tc.reconcileCalls, []int64{1})
}

func TestOrderedKernelRuntimeMigratesRetainedXDPAssignmentsWhenRuntimeTCPluginHooksActive(t *testing.T) {
	enabled := true
	xdp := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Running: true, Engine: kernelEngineXDP},
		},
		assignments: map[int64]string{1: kernelEngineXDP},
	}
	tc := &mockKernelRuntime{
		available: true,
		reconcileResult: map[int64]kernelRuleApplyResult{
			1: {Running: true, Engine: kernelEngineTC},
			2: {Running: true, Engine: kernelEngineTC},
		},
		assignments: map[int64]string{
			1: kernelEngineTC,
			2: kernelEngineTC,
		},
	}
	rt := &orderedKernelRuleRuntime{
		cfg: &Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled,
		},
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileRetainingAssignmentsWithPluginCatalog(
		map[string][]Rule{
			kernelEngineXDP: {{ID: 1, Enabled: true}},
		},
		[]Rule{{ID: 2, Enabled: true}},
		PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), stableTCHookPluginForOrderTest()}},
	)
	if err != nil {
		t.Fatalf("ReconcileRetainingAssignmentsWithPluginCatalog() error = %v", err)
	}
	for _, id := range []int64{1, 2} {
		if result := results[id]; !result.Running || result.Engine != kernelEngineTC {
			t.Fatalf("rule %d result = %+v, want migrated/running tc", id, result)
		}
	}
	assertKernelRuntimeOnlyCleanupCalls(t, xdp.reconcileCalls)
	assertReconcileCallPrefix(t, tc.reconcileCalls, []int64{1, 2})
}

func TestOrderedKernelRuntimeKeepsEngineOrderWhenPluginDataplaneDisabled(t *testing.T) {
	disabled := false
	xdp := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineXDP}
	tc := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineTC}
	rt := &orderedKernelRuleRuntime{
		cfg: &Config{
			PluginsDataplaneSetting: &disabled,
		},
		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinFVTapPlugin(), stableTCHookPluginForOrderTest()},
	})
	if err != nil {
		t.Fatalf("ReconcileWithPluginCatalog() error = %v", err)
	}
	if result := results[1]; !result.Running || result.Engine != kernelEngineXDP {
		t.Fatalf("rule result = %+v, want xdp when plugin dataplane is disabled", result)
	}
	if xdp.reconcileWithCatalogCalls != 1 {
		t.Fatalf("xdp ReconcileWithPluginCatalog calls = %d, want 1", xdp.reconcileWithCatalogCalls)
	}
	if tc.reconcileCalls != 1 {
		t.Fatalf("tc cleanup Reconcile calls = %d, want 1 cleanup after xdp assignment", tc.reconcileCalls)
	}
}

func TestKernelAttachmentProgramsUsesPipelineProgramWhenPluginPipelineEnabled(t *testing.T) {
	pieces := kernelCollectionPieces{
		forwardProg:                 &ebpf.Program{},
		replyProg:                   &ebpf.Program{},
		forwardDispatchProg:         &ebpf.Program{},
		forwardPipelineProg:         &ebpf.Program{},
		forwardCoreProg:             &ebpf.Program{},
		forwardPluginContinueProg:   &ebpf.Program{},
		forwardPluginPostLookupProg: &ebpf.Program{},
		forwardTransparentProg:      &ebpf.Program{},
		forwardFullNATProg:          &ebpf.Program{},
		forwardEgressNATProg:        &ebpf.Program{},
		replyDispatchProg:           &ebpf.Program{},
		replyPipelineProg:           &ebpf.Program{},
		replyCoreProg:               &ebpf.Program{},
		replyPluginContinueProg:     &ebpf.Program{},
		replyPluginPostReplyProg:    &ebpf.Program{},
		replyTransparentProg:        &ebpf.Program{},
		replyFullNATProg:            &ebpf.Program{},
		progChainV4:                 &ebpf.Map{},
		pluginConfigV4:              &ebpf.Map{},
		dispatchScratchV4:           &ebpf.Map{},
		pluginCtxV4:                 &ebpf.Map{},
	}

	programs := kernelAttachmentProgramsFromPieces(pieces, false, kernelTCAttachmentProgramModePipelineV4)
	if programs.mode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("mode = %q, want %q", programs.mode, kernelTCAttachmentProgramModePipelineV4)
	}
	if programs.forwardProg != pieces.forwardPipelineProg {
		t.Fatal("forward program did not select the plugin pipeline wrapper")
	}
	if programs.replyProg != pieces.replyPipelineProg {
		t.Fatal("reply program did not select the plugin pipeline wrapper")
	}
}

func TestBuildKernelPluginPipelineDesiredAllowsInterfaceFreePreForward(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "packet_observer",
			Name:    "Packet Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_forward",
				Section: "tc/fvtap/pre_forward",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:       "observe-ingress",
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    "pre_forward",
			Priority: 10,
			Program:  "observer:tc_pre_forward",
			Mode:     "observe",
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no registered/error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 1 {
		t.Fatalf("desired = %+v, want one pipeline hook", desired)
	}
	hook := desired[0].hooks[0]
	if hook.PluginID != "packet_observer" || hook.ProgramRef != "tc_pre_forward" || hook.ObjectPath == "" {
		t.Fatalf("hook = %+v, want resolved packet_observer tc_pre_forward hook", hook)
	}
}

func TestKernelPluginPipelineExplicitInterfacesContributeAttachmentTargets(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName(lo) error = %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "interface_observer",
			Name:    "Interface Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{
				{ID: "tc_pre_forward", Section: "tc/fvtap/pre_forward", Type: kernelEngineTC},
				{ID: "tc_pre_reply", Section: "tc/fvtap/pre_reply", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "forward-lo", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_forward", Mode: "observe", Interfaces: []string{"lo"}},
			{ID: "reply-lo", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_reply", Mode: "observe", Interfaces: []string{"lo"}},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	desired, states, forwardIfRules, replyIfRules := kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no interface resolution error", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two explicit-interface hooks", desired)
	}
	if _, ok := forwardIfRules[lo.Index]; !ok {
		t.Fatalf("forwardIfRules = %+v, want lo ifindex %d", forwardIfRules, lo.Index)
	}
	if _, ok := replyIfRules[lo.Index]; !ok {
		t.Fatalf("replyIfRules = %+v, want lo ifindex %d", replyIfRules, lo.Index)
	}
	if !kernelPluginPipelineHasAttachmentTargets(forwardIfRules, replyIfRules) {
		t.Fatal("kernelPluginPipelineHasAttachmentTargets = false, want true")
	}
}

func TestKernelPluginPipelineNoRuleFilterRequiresExplicitPreCoreHook(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "interface_free",
			Name:    "Interface Free",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_forward",
				Section: "tc/fvtap/pre_forward",
				Type:    kernelEngineTC,
			}, {
				ID:      "tc_post_lookup",
				Section: "tc/fvtap/post_lookup",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{
			{
				ID:       "interface-free-forward",
				Engine:   kernelEngineTC,
				Attach:   "ingress",
				Stage:    kernelPluginPipelineStageForward,
				Priority: pluginPipelineCorePriority - 10,
				Program:  "observer:tc_pre_forward",
				Mode:     "observe",
			},
			{
				ID:         "post-core-explicit",
				Engine:     kernelEngineTC,
				Attach:     "ingress",
				Stage:      kernelPluginPipelineStageForward,
				Priority:   pluginPipelineCorePriority + 10,
				Program:    "observer:tc_post_lookup",
				Mode:       "observe",
				Interfaces: []string{"lo"},
			},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	desired, states, forwardIfRules, replyIfRules := kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no state error", states)
	}
	if len(desired) != 1 {
		t.Fatalf("desired = %+v, want rule-driven hook to remain loadable", desired)
	}
	if !kernelPluginPipelineHasAttachmentTargets(forwardIfRules, replyIfRules) {
		t.Fatalf("forwardIfRules=%+v replyIfRules=%+v, want post-core explicit hook to resolve an attachment target", forwardIfRules, replyIfRules)
	}
	filtered := kernelPluginPipelineFilterNoRulePlugins(desired)
	if len(filtered) != 1 || len(filtered[0].hooks) != 1 || filtered[0].hooks[0].HookID != "post-core-explicit" {
		t.Fatalf("plugin-only filter = %+v, want only explicit-interface post-core hook for no-rule attachment", filtered)
	}
}

func TestKernelPluginPipelineInvalidExplicitInterfaceFiltersPlugin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "bad_interface",
			Name:    "Bad Interface",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_forward",
				Section: "tc/fvtap/pre_forward",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:         "forward-missing",
			Engine:     kernelEngineTC,
			Attach:     "ingress",
			Stage:      kernelPluginPipelineStageForward,
			Priority:   pluginPipelineCorePriority - 10,
			Program:    "observer:tc_pre_forward",
			Mode:       "observe",
			Interfaces: []string{"forward_missing0"},
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	desired, states, forwardIfRules, replyIfRules := kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want plugin filtered after interface resolution failure", desired)
	}
	if kernelPluginPipelineHasAttachmentTargets(forwardIfRules, replyIfRules) {
		t.Fatalf("forwardIfRules=%+v replyIfRules=%+v, want no attachment target for failed plugin", forwardIfRules, replyIfRules)
	}
	state, ok := states["bad_interface"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "forward_missing0") {
		t.Fatalf("state = %+v, want interface resolution error", state)
	}
}

func TestKernelPluginPipelineNoRuleFilterValidatesPostCoreInvalidInterface(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "mixed_interface",
			Name:    "Mixed Interface",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{
				{ID: "tc_pre_forward", Section: "tc/fvtap/pre_forward", Type: kernelEngineTC},
				{ID: "tc_post_lookup", Section: "tc/fvtap/post_lookup", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "pre-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_forward", Mode: "observe", Interfaces: []string{"lo"}},
			{ID: "post-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_post_lookup", Mode: "observe", Interfaces: []string{"forward_missing0"}},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	desired = kernelPluginPipelineFilterNoRulePlugins(desired)
	desired, states, forwardIfRules, replyIfRules := kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want plugin filtered after post-core interface resolution failure", desired)
	}
	if kernelPluginPipelineHasAttachmentTargets(forwardIfRules, replyIfRules) {
		t.Fatalf("forwardIfRules=%+v replyIfRules=%+v, want no attachment target for failed plugin", forwardIfRules, replyIfRules)
	}
	state, ok := states["mixed_interface"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "forward_missing0") {
		t.Fatalf("state = %+v, want post-core interface resolution error", state)
	}
}

func TestBuildKernelPluginPipelineDesiredMapsForwardPriorityAroundCore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "priority_observer",
			Name:    "Priority Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{
				{ID: "tc_before_core", Section: "tc/fvtap/pre_forward", Type: kernelEngineTC},
				{ID: "tc_after_core", Section: "tc/fvtap/post_lookup", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_after_core", Mode: "observe"},
			{ID: "before-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_before_core", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no registered/error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two priority-mapped pipeline hooks", desired)
	}
	if desired[0].hooks[0].HookID != "before-core" || desired[0].hooks[0].Stage != kernelPluginPipelineStagePreForward {
		t.Fatalf("first hook = %+v, want before-core mapped to pre_forward", desired[0].hooks[0])
	}
	if desired[0].hooks[1].HookID != "after-core" || desired[0].hooks[1].Stage != kernelPluginPipelineStagePostLookup {
		t.Fatalf("second hook = %+v, want after-core mapped to post_lookup", desired[0].hooks[1])
	}
}

func TestBuildKernelPluginPipelineDesiredMapsReplyPriorityAroundCore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "reply_observer",
			Name:    "Reply Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{
				{ID: "tc_before_reply", Section: "tc/fvtap/pre_reply", Type: kernelEngineTC},
				{ID: "tc_after_reply", Section: "tc/fvtap/post_reply", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-reply-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_after_reply", Mode: "observe"},
			{ID: "before-reply-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_before_reply", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no registered/error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two reply priority-mapped pipeline hooks", desired)
	}
	if desired[0].hooks[0].HookID != "before-reply-core" || desired[0].hooks[0].Stage != kernelPluginPipelineStagePreReply {
		t.Fatalf("first hook = %+v, want before-reply-core mapped to pre_reply", desired[0].hooks[0])
	}
	if len(desired[0].hooks[0].Context) != 0 {
		t.Fatalf("pre_reply context = %+v, want empty", desired[0].hooks[0].Context)
	}
	if desired[0].hooks[1].HookID != "after-reply-core" || desired[0].hooks[1].Stage != kernelPluginPipelineStagePostReply {
		t.Fatalf("second hook = %+v, want after-reply-core mapped to post_reply", desired[0].hooks[1])
	}
	if len(desired[0].hooks[1].Context) != 1 || desired[0].hooks[1].Context[0] != pluginHookContextTCPluginCtxV4 {
		t.Fatalf("post_reply context = %+v, want %s", desired[0].hooks[1].Context, pluginHookContextTCPluginCtxV4)
	}
}

func TestBuildKernelPluginPipelineDesiredRejectsForwardCorePriorityCollision(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "core_collision",
			Name:    "Core Collision",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_forward",
				Section: "tc/fvtap/pre_forward",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:       "same-as-core",
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    kernelPluginPipelineStageForward,
			Priority: pluginPipelineCorePriority,
			Program:  "observer:tc_forward",
			Mode:     "observe",
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want no hooks for core priority collision", desired)
	}
	state, ok := states["core_collision"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "collides with fvtap core priority") {
		t.Fatalf("state = %+v, want core priority collision error", state)
	}
}

func TestBuildKernelPluginPipelineDesiredAllowsPostLookup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "rule_observer",
			Name:    "Rule Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{
				{ID: "tc_post_lookup", Section: "tc/fvtap/post_lookup", Type: kernelEngineTC},
				{ID: "tc_pre_forward", Section: "tc/fvtap/pre_forward", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-rule", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStagePostLookup, Priority: 5, Program: "observer:tc_post_lookup", Mode: "observe"},
			{ID: "before-parse", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStagePreForward, Priority: 10, Program: "observer:tc_pre_forward", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no registered/error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two pipeline hooks", desired)
	}
	if desired[0].hooks[0].Stage != kernelPluginPipelineStagePreForward || desired[0].hooks[1].Stage != kernelPluginPipelineStagePostLookup {
		t.Fatalf("hook order = %+v, want pre_forward before post_lookup", desired[0].hooks)
	}
}

func TestBuildKernelPluginPipelineDesiredForRuntimeAllowsLabByDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "lab_observer",
			Name:      "Lab Observer",
			Version:   "0.1.0",
			Kind:      "pipeline",
			Stability: pluginStabilityLab,
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_forward",
				Section: "tc/fvtap/pre_forward",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:       "before-core",
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    kernelPluginPipelineStageForward,
			Priority: pluginPipelineCorePriority - 100,
			Program:  "observer:tc_pre_forward",
			Mode:     "observe",
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}}

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	}
	desired, states := buildKernelPluginPipelineDesiredForRuntime(catalog, cfg)
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no lab stability block", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 1 {
		t.Fatalf("desired = %+v, want lab hook", desired)
	}
	if !kernelPluginPipelineCatalogHasRuntimeHooks(catalog, cfg) {
		t.Fatal("kernelPluginPipelineCatalogHasRuntimeHooks() = false for allowed lab dataplane")
	}
}

func TestBuildKernelPluginPipelineDesiredAllowsFirewallStyleMultiObjectContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "firewall_pre.o"), []byte("fake-pre"), 0o644); err != nil {
		t.Fatalf("WriteFile(firewall_pre.o) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "firewall_post.o"), []byte("fake-post"), 0o644); err != nil {
		t.Fatalf("WriteFile(firewall_post.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "firewall",
			Name:    "Firewall",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{
			{
				ID:             "firewall_pre",
				Path:           "firewall_pre.o",
				Status:         pluginObjectStatusVerified,
				ResolvedSHA256: "pre",
				Programs: []PluginObjectProgram{{
					ID:      "tc_pre_filter",
					Section: "tc/fvtap/pre_filter",
					Type:    kernelEngineTC,
				}},
			},
			{
				ID:             "firewall_post",
				Path:           "firewall_post.o",
				Status:         pluginObjectStatusVerified,
				ResolvedSHA256: "post",
				Programs: []PluginObjectProgram{{
					ID:      "tc_post_filter",
					Section: "tc/fvtap/post_filter",
					Type:    kernelEngineTC,
				}},
			},
		},
		Hooks: []PluginHook{
			{ID: "pre-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 100, Program: "firewall_pre:tc_pre_filter", Mode: "drop"},
			{ID: "post-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 100, Program: "firewall_post:tc_post_filter", Mode: "drop"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two firewall hooks", desired)
	}
	pre := desired[0].hooks[0]
	post := desired[0].hooks[1]
	if pre.HookID != "pre-core" || pre.ObjectID != "firewall_pre" || pre.Stage != kernelPluginPipelineStagePreForward {
		t.Fatalf("pre hook = %+v, want firewall_pre pre_forward", pre)
	}
	if len(pre.Context) != 0 {
		t.Fatalf("pre context = %+v, want empty", pre.Context)
	}
	if post.HookID != "post-core" || post.ObjectID != "firewall_post" || post.Stage != kernelPluginPipelineStagePostLookup {
		t.Fatalf("post hook = %+v, want firewall_post post_lookup", post)
	}
	if len(post.Context) != 1 || post.Context[0] != pluginHookContextTCPluginCtxV4 {
		t.Fatalf("post context = %+v, want %s", post.Context, pluginHookContextTCPluginCtxV4)
	}
	if pre.ObjectPath == post.ObjectPath {
		t.Fatalf("object paths should be distinct for firewall pre/post hooks: pre=%q post=%q", pre.ObjectPath, post.ObjectPath)
	}
}

func TestBuildKernelPluginPipelineDesiredAllowsSameObjectPrePostContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "firewall.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(firewall.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "firewall",
			Name:    "Firewall",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "firewall",
			Path:           "firewall.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "same-object",
			Programs: []PluginObjectProgram{
				{ID: "tc_pre_filter", Section: "tc/fvtap/pre_filter", Type: kernelEngineTC},
				{ID: "tc_post_filter", Section: "tc/fvtap/post_filter", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "pre-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 100, Program: "firewall:tc_pre_filter", Mode: "drop"},
			{ID: "post-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 100, Program: "firewall:tc_post_filter", Mode: "drop"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(states) != 0 {
		t.Fatalf("states = %+v, want no error state", states)
	}
	if len(desired) != 1 || len(desired[0].hooks) != 2 {
		t.Fatalf("desired = %+v, want two hooks from one object", desired)
	}
	pre := desired[0].hooks[0]
	post := desired[0].hooks[1]
	if pre.ObjectPath != post.ObjectPath {
		t.Fatalf("object paths = %q and %q, want same object path", pre.ObjectPath, post.ObjectPath)
	}
	if len(pre.Context) != 0 {
		t.Fatalf("pre context = %+v, want empty", pre.Context)
	}
	if len(post.Context) != 1 || post.Context[0] != pluginHookContextTCPluginCtxV4 {
		t.Fatalf("post context = %+v, want %s", post.Context, pluginHookContextTCPluginCtxV4)
	}
	if kernelPluginPipelineObjectCacheKey(pre.ObjectPath, kernelPluginPipelineHookNeedsContext(pre, pluginHookContextTCPluginCtxV4)) ==
		kernelPluginPipelineObjectCacheKey(post.ObjectPath, kernelPluginPipelineHookNeedsContext(post, pluginHookContextTCPluginCtxV4)) {
		t.Fatalf("same object pre/post hooks must use isolated load cache keys")
	}
}

func TestBuildKernelPluginPipelineDesiredRejectsPreForwardPluginContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "firewall_pre.o"), []byte("fake-pre"), 0o644); err != nil {
		t.Fatalf("WriteFile(firewall_pre.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "bad_firewall",
			Name:    "Bad Firewall",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "firewall_pre",
			Path:           "firewall_pre.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "pre",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_filter",
				Section: "tc/fvtap/pre_filter",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:       "pre-core",
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    kernelPluginPipelineStagePreForward,
			Priority: 10,
			Program:  "firewall_pre:tc_pre_filter",
			Mode:     "drop",
			Context:  []string{pluginHookContextTCPluginCtxV4},
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want rejected pre-core context", desired)
	}
	state, ok := states["bad_firewall"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "only available after fvtap core lookup") {
		t.Fatalf("state = %+v, want pre-core context error", state)
	}
}

func TestKernelPluginPipelineObjectCacheKeySeparatesContextNeed(t *testing.T) {
	objectPath := filepath.Join("plugins", "runtime", "firewall", "firewall.o")
	preKey := kernelPluginPipelineObjectCacheKey(objectPath, false)
	postKey := kernelPluginPipelineObjectCacheKey(objectPath, true)

	if preKey == postKey {
		t.Fatalf("cache keys are equal for context-free and context-aware loads: %q", preKey)
	}
	if !strings.Contains(postKey, pluginHookContextTCPluginCtxV4) {
		t.Fatalf("post-core cache key = %q, want context marker %q", postKey, pluginHookContextTCPluginCtxV4)
	}
	if strings.Contains(preKey, pluginHookContextTCPluginCtxV4) {
		t.Fatalf("pre-core cache key = %q, want no context marker", preKey)
	}
}

func TestBuildKernelPluginPipelineDesiredRejectsHookLimitOverflow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observer.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(observer.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "too_many_hooks",
			Name:    "Too Many Hooks",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "observer",
			Path:           "observer.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "fake",
			Programs: []PluginObjectProgram{{
				ID:      "tc_pre_filter",
				Section: "tc/fvtap/pre_filter",
				Type:    kernelEngineTC,
			}},
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}
	for i := 0; i < tcProgramChainV4PluginPreForwardMax+1; i++ {
		plugin.Hooks = append(plugin.Hooks, PluginHook{
			ID:       "pre-core-" + string(rune('a'+i)),
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    kernelPluginPipelineStagePreForward,
			Priority: i,
			Program:  "observer:tc_pre_filter",
			Mode:     "observe",
		})
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want rejected hook overflow", desired)
	}
	state, ok := states["too_many_hooks"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "too many pre-core tc plugin hooks") {
		t.Fatalf("state = %+v, want pre-core hook limit error", state)
	}
}

func TestKernelPluginPipelineFingerprintIncludesCoreConfig(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "observer",
			Name:    "Observer",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Status: pluginStatusActive,
	}
	desired := []kernelPluginPipelineDesiredPlugin{{
		plugin: plugin,
		hooks: []kernelPluginPipelineHookPlan{{
			PluginID:       plugin.ID,
			HookID:         "observe",
			ObjectID:       "observer",
			ObjectPath:     "/tmp/observer.o",
			ProgramRef:     "tc_observe",
			ProgramSection: "tc/fvtap/pre_forward",
			Stage:          kernelPluginPipelineStagePreForward,
			Attach:         "ingress",
			Mode:           "observe",
			Priority:       10,
		}},
	}}

	disabled := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	enabled := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{Forward: true, Reply: true})
	if disabled == enabled {
		t.Fatalf("fingerprint did not change when core config changed: %s", disabled)
	}
}

func TestNormalizePluginHookAllowsPhysicalPipelineStages(t *testing.T) {
	for _, stage := range []string{
		kernelPluginPipelineStagePreForward,
		kernelPluginPipelineStagePostLookup,
		kernelPluginPipelineStagePreReply,
		kernelPluginPipelineStagePostReply,
	} {
		hook := PluginHook{
			ID:       "hook-" + strings.ReplaceAll(stage, "_", "-"),
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    stage,
			Priority: 10,
			Program:  "observer:tc_observe",
			Mode:     "observe",
		}
		if err := normalizePluginHook(&hook); err != nil {
			t.Fatalf("normalizePluginHook(stage=%s) error = %v", stage, err)
		}
		if hook.Stage != stage {
			t.Fatalf("normalizePluginHook(stage=%s) normalized stage = %s", stage, hook.Stage)
		}
	}
}

func TestKernelPluginPipelineKeepsXDPHooksRegistrationOnly(t *testing.T) {
	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
	}
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
			Priority:   10,
			Program:    "probe:xdp_ingress",
			Mode:       "observe",
			Interfaces: []string{"lo"},
		}},
		Status: pluginStatusActive,
	}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinFVTapPlugin(), plugin}}

	if kernelPluginPipelineCatalogHasRuntimeHooks(catalog, cfg) {
		t.Fatal("kernelPluginPipelineCatalogHasRuntimeHooks() = true, want false for xdp-only plugin")
	}
	desired, states := buildKernelPluginPipelineDesiredWithConfig(catalog, cfg, true)
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want no tc pipeline hooks for xdp-only plugin", desired)
	}
	state, ok := states["xdp_probe"]
	if !ok {
		t.Fatal("missing xdp_probe runtime state")
	}
	if state.Mode != pluginRuntimeModeRegistered || state.Attachable || state.Attached || state.AttachmentCount != 0 {
		t.Fatalf("state = %+v, want registered non-attachable xdp hook", state)
	}
	if !strings.Contains(state.Reason, "xdp hooks are registration-only in the tc pipeline") {
		t.Fatalf("state reason = %q, want xdp registration-only reason", state.Reason)
	}
}

func TestKernelPluginPipelineRuntimeChainsPreForwardPlugin(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	pluginDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	rule := Rule{
		ID:               1,
		InInterface:      topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Transparent:      true,
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
		Remark:           "plugin-pipeline-smoke",
		Tag:              "test",
	}
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result = %+v, want running tc", result)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q; plugin snapshot = %+v", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4, rt.PluginSnapshot())
	}

	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("packet_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want packet_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}
	if len(state.Attachments) != 1 || state.Attachments[0].Interface != kernelPluginPipelineInterface || state.Attachments[0].Status != "chained" {
		t.Fatalf("plugin attachments = %+v, want chained fvtap attachment", state.Attachments)
	}
	if state.Attachments[0].Stage != kernelPluginPipelineStagePreForward || state.Attachments[0].ChainSlot != tcProgramChainIndexV4PluginBase {
		t.Fatalf("plugin attachment = %+v, want pre_forward slot %d", state.Attachments[0], tcProgramChainIndexV4PluginBase)
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 1 {
		t.Fatalf("pre_forward_count = %d, want 1", config.PreForwardCount)
	}
	if config.PostLookupCount != 0 {
		t.Fatalf("post_lookup_count = %d, want 0", config.PostLookupCount)
	}
	if config.ForwardCoreEnable != 1 || config.ReplyCoreEnable != 1 {
		t.Fatalf("plugin core config = %+v, want forward/reply core enabled with prepared rules", config)
	}
	if _, ok := stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward"); !ok {
		t.Fatalf("plugin state attachments = %+v, want packet_observer:tc_pre_forward", state.Attachments)
	}

	enabled = false
	results, err = rt.ReconcileWithPluginCatalog([]Rule{rule}, loadPluginCatalog(cfg))
	if err != nil {
		t.Fatalf("ReconcileWithPluginCatalog(disabled plugins) error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result after disabling plugins = %+v, want running tc", result)
	}
	if rt.attachmentMode == kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode after disabling plugins = %q, want non-pipeline mode", rt.attachmentMode)
	}
	snapshot = rt.PluginSnapshot()
	if state, ok := snapshot.stateFor("packet_observer"); ok {
		t.Fatalf("plugin snapshot still contains packet_observer after disabling plugins with active rule: %+v", state)
	}
	pieces, err = lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces(after disabling plugins with active rule) error = %v", err)
	}
	assertKernelPluginPipelineClearedForTest(t, pieces)
}

func TestKernelPluginPipelineRuntimeAttachesExplicitInterfaceWithoutRules(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	topology := setupDataplanePerfTopology(t)
	pluginsRoot := t.TempDir()
	pluginDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ClientHostIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	results, err := rt.Reconcile(nil)
	if err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %+v, want no rule results", results)
	}
	if len(rt.preparedRules) != 0 {
		t.Fatalf("preparedRules = %+v, want empty rule set", rt.preparedRules)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4)
	}
	if len(rt.attachments) == 0 {
		t.Fatal("attachments = 0, want explicit plugin pipeline attachment")
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 1 || config.PostLookupCount != 0 || config.PreReplyCount != 0 || config.PostReplyCount != 0 || config.ForwardCoreEnable != 0 || config.ReplyCoreEnable != 0 {
		t.Fatalf("plugin config = %+v, want one pre-forward hook with core disabled", config)
	}
	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("packet_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want packet_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}
}

func TestKernelPluginPipelineRuntimeReconcilePluginsBootstrapsExplicitInterfaceWithoutRules(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	topology := setupDataplanePerfTopology(t)
	pluginsRoot := t.TempDir()
	pluginDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ClientHostIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	snapshot := rt.ReconcilePlugins(loadPluginCatalog(cfg))
	if rt.coll == nil {
		t.Fatal("rt.coll = nil, want ReconcilePlugins to bootstrap explicit plugin pipeline")
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4)
	}
	if len(rt.attachments) == 0 {
		t.Fatal("attachments = 0, want explicit plugin pipeline attachment")
	}
	state, ok := snapshot.stateFor("packet_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want packet_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}

	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ClientHostIF, topology.BackendHostIF)
	snapshot = rt.ReconcilePlugins(loadPluginCatalog(cfg))
	if len(rt.attachments) < 2 {
		t.Fatalf("attachments = %d, want ReconcilePlugins to add the second explicit interface", len(rt.attachments))
	}
	state, ok = snapshot.stateFor("packet_observer")
	if !ok || state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("updated plugin state = %+v, want chained dataplane attachment after interface update", state)
	}

	enabled = false
	snapshot = rt.ReconcilePlugins(loadPluginCatalog(cfg))
	if rt.pluginPipelineActive {
		t.Fatal("pluginPipelineActive = true after disabling plugins, want false")
	}
	if state, ok := snapshot.stateFor("packet_observer"); ok {
		t.Fatalf("plugin snapshot still contains packet_observer after disabling plugins: %+v", state)
	}
	if rt.coll != nil {
		pieces, err := lookupKernelCollectionPieces(rt.coll)
		if err != nil {
			t.Fatalf("lookupKernelCollectionPieces(after disable) error = %v", err)
		}
		assertKernelPluginPipelineClearedForTest(t, pieces)
	}
	if rt.coll != nil || len(rt.attachments) != 0 {
		t.Fatalf("runtime after disabling idle plugin pipeline = coll:%v attachments:%d, want fully detached idle runtime", rt.coll != nil, len(rt.attachments))
	}
}

func TestKernelPluginPipelineRuntimeNoRulePostLookupPluginAttachesWithCoreDisabled(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	topology := setupDataplanePerfTopology(t)
	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "rule_observer")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(rule_observer) error = %v", err)
	}
	writePostLookupPluginForTest(t, pluginDir, topology.ClientHostIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "rule_observer.bpf.c"), filepath.Join(pluginDir, "rule_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	results, err := rt.Reconcile(nil)
	if err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %+v, want no rule results", results)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q; plugin snapshot = %+v", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4, rt.PluginSnapshot())
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 0 || config.PostLookupCount != 1 || config.PreReplyCount != 0 || config.PostReplyCount != 0 || config.ForwardCoreEnable != 0 || config.ReplyCoreEnable != 0 {
		t.Fatalf("plugin config = %+v, want post_lookup hook with core disabled", config)
	}

	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("rule_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want rule_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}
	if len(state.Attachments) != 1 || state.Attachments[0].Stage != kernelPluginPipelineStagePostLookup || state.Attachments[0].ChainSlot != tcProgramChainIndexV4PluginPostBase {
		t.Fatalf("plugin attachment = %+v, want post_lookup slot %d", state.Attachments, tcProgramChainIndexV4PluginPostBase)
	}
}

func assertKernelPluginPipelineClearedForTest(t *testing.T, pieces kernelCollectionPieces) {
	t.Helper()
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 0 || config.PostLookupCount != 0 || config.PreReplyCount != 0 || config.PostReplyCount != 0 || config.ForwardCoreEnable != 0 || config.ReplyCoreEnable != 0 {
		t.Fatalf("plugin config = %+v, want all hook counts cleared", config)
	}
	assertMissing := func(slot int) {
		t.Helper()
		var fd uint32
		err := pieces.progChainV4.Lookup(uint32(slot), &fd)
		if err == nil {
			t.Fatalf("tc plugin chain slot %d still contains fd %d, want deleted", slot, fd)
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("lookup tc plugin chain slot %d error = %v, want ErrKeyNotExist", slot, err)
		}
	}
	for i := 0; i < tcProgramChainV4PluginPreForwardMax; i++ {
		assertMissing(tcProgramChainIndexV4PluginBase + i)
	}
	for i := 0; i < tcProgramChainV4PluginPostLookupMax; i++ {
		assertMissing(tcProgramChainIndexV4PluginPostBase + i)
	}
	for i := 0; i < tcProgramChainV4PluginPreReplyMax; i++ {
		assertMissing(tcProgramChainIndexV4PluginReplyBase + i)
	}
	for i := 0; i < tcProgramChainV4PluginPostReplyMax; i++ {
		assertMissing(tcProgramChainIndexV4PluginReplyPostBase + i)
	}
}

func TestKernelPluginPipelineRuntimeNoRulePreCorePluginCanDropTraffic(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping command is required")
	}

	topology := setupDataplanePerfTopology(t)
	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfFrontAddr); err != nil {
		t.Fatalf("baseline ping failed before plugin drop: %v\n%s", err, output)
	}

	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "drop_core")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(drop_core) error = %v", err)
	}
	writeDropCorePluginForTest(t, pluginDir, topology.ClientHostIF)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "drop_core.bpf.c"), filepath.Join(pluginDir, "drop_core.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	if results, err := rt.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	} else if len(results) != 0 {
		t.Fatalf("results = %+v, want no rule results", results)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4)
	}
	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("drop_core")
	if !ok || state.Mode != pluginRuntimeModeDataplane || !state.Attached {
		t.Fatalf("plugin state = %+v, want attached drop_core dataplane plugin", state)
	}

	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfFrontAddr); err == nil {
		t.Fatalf("ping succeeded after drop plugin attached, want traffic dropped\n%s", output)
	}
}

func TestKernelPluginPipelineRuntimeNoRulePreCorePluginCanRedirectBetweenInterfaces(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping command is required")
	}

	topology := setupDataplanePerfTopology(t)
	restore := setDataplanePerfIPv4ForwardingForTest(t, topology, "0")
	defer restore()
	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfFrontAddr); err != nil {
		t.Fatalf("client gateway arp warmup failed: %v\n%s", err, output)
	}
	if output, err := runDataplanePerfPing(topology.BackendNS, dataplanePerfBackendHost); err != nil {
		t.Fatalf("backend gateway arp warmup failed: %v\n%s", err, output)
	}
	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfBackendAddr); err == nil {
		t.Fatalf("baseline ping to backend succeeded with ip_forward=0 before plugin redirect, want unreachable\n%s", output)
	}

	clientHost, err := net.InterfaceByName(topology.ClientHostIF)
	if err != nil {
		t.Fatalf("InterfaceByName(%s) error = %v", topology.ClientHostIF, err)
	}
	backendHost, err := net.InterfaceByName(topology.BackendHostIF)
	if err != nil {
		t.Fatalf("InterfaceByName(%s) error = %v", topology.BackendHostIF, err)
	}
	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "redirect_core")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(redirect_core) error = %v", err)
	}
	writeRedirectCorePluginForTest(t, pluginDir, redirectCorePluginSpec{
		clientHostIF:   topology.ClientHostIF,
		clientHostIdx:  clientHost.Index,
		clientHostMAC:  clientHost.HardwareAddr.String(),
		clientNSMAC:    mustReadDataplanePerfNetnsMAC(t, topology.ClientNS, topology.ClientNSIF),
		backendHostIF:  topology.BackendHostIF,
		backendHostIdx: backendHost.Index,
		backendHostMAC: backendHost.HardwareAddr.String(),
		backendNSMAC:   mustReadDataplanePerfNetnsMAC(t, topology.BackendNS, topology.BackendNSIF),
	})
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "redirect_core.bpf.c"), filepath.Join(pluginDir, "redirect_core.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	if results, err := rt.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	} else if len(results) != 0 {
		t.Fatalf("results = %+v, want no rule results", results)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4)
	}
	if len(rt.attachments) < 2 {
		t.Fatalf("attachments = %d, want both client and backend host interfaces attached", len(rt.attachments))
	}

	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfBackendAddr); err != nil {
		t.Fatalf("plugin redirect ping failed: %v\n%s", err, output)
	}
}

func TestKernelPluginPipelineRuntimeChainsPostLookupPlugin(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "rule_observer")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(rule_observer) error = %v", err)
	}
	writePostLookupPluginForTest(t, pluginDir)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "rule_observer.bpf.c"), filepath.Join(pluginDir, "rule_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	rule := Rule{
		ID:               1,
		InInterface:      topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Transparent:      true,
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
		Remark:           "plugin-post-lookup-smoke",
		Tag:              "test",
	}
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result = %+v, want running tc", result)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q; plugin snapshot = %+v", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4, rt.PluginSnapshot())
	}

	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("rule_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want rule_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}
	if len(state.Attachments) != 1 || state.Attachments[0].Stage != kernelPluginPipelineStagePostLookup || state.Attachments[0].ChainSlot != tcProgramChainIndexV4PluginPostBase {
		t.Fatalf("plugin attachment = %+v, want post_lookup slot %d", state.Attachments, tcProgramChainIndexV4PluginPostBase)
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 0 {
		t.Fatalf("pre_forward_count = %d, want 0", config.PreForwardCount)
	}
	if config.PostLookupCount != 1 {
		t.Fatalf("post_lookup_count = %d, want 1", config.PostLookupCount)
	}
	if config.ForwardCoreEnable != 1 || config.ReplyCoreEnable != 1 {
		t.Fatalf("plugin core config = %+v, want forward/reply core enabled with prepared rules", config)
	}
	if _, ok := stateHasAttachmentProgram(state, "observer:tc_post_lookup"); !ok {
		t.Fatalf("plugin state attachments = %+v, want observer:tc_post_lookup", state.Attachments)
	}
}

func TestKernelPluginPipelineRuntimeChainsPostReplyPlugin(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "reply_observer")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(reply_observer) error = %v", err)
	}
	writePostReplyPluginForTest(t, pluginDir)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "reply_observer.bpf.c"), filepath.Join(pluginDir, "reply_observer.o"))

	enabled := true
	cfg := &Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}
	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)

	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()

	rule := Rule{
		ID:               1,
		InInterface:      topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Transparent:      true,
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
		Remark:           "plugin-post-reply-smoke",
		Tag:              "test",
	}
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result = %+v, want running tc", result)
	}
	if rt.attachmentMode != kernelTCAttachmentProgramModePipelineV4 {
		t.Fatalf("attachmentMode = %q, want %q", rt.attachmentMode, kernelTCAttachmentProgramModePipelineV4)
	}

	snapshot := rt.PluginSnapshot()
	state, ok := snapshot.stateFor("reply_observer")
	if !ok {
		t.Fatalf("plugin snapshot = %+v, want reply_observer state", snapshot)
	}
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 1 {
		t.Fatalf("plugin state = %+v, want one chained dataplane attachment", state)
	}
	if len(state.Attachments) != 1 || state.Attachments[0].Stage != kernelPluginPipelineStagePostReply || state.Attachments[0].ChainSlot != tcProgramChainIndexV4PluginReplyPostBase {
		t.Fatalf("plugin attachment = %+v, want post_reply slot %d", state.Attachments, tcProgramChainIndexV4PluginReplyPostBase)
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardCount != 0 {
		t.Fatalf("pre_forward_count = %d, want 0", config.PreForwardCount)
	}
	if config.PostLookupCount != 0 {
		t.Fatalf("post_lookup_count = %d, want 0", config.PostLookupCount)
	}
	if config.PreReplyCount != 0 {
		t.Fatalf("pre_reply_count = %d, want 0", config.PreReplyCount)
	}
	if config.PostReplyCount != 1 {
		t.Fatalf("post_reply_count = %d, want 1", config.PostReplyCount)
	}
	if config.ForwardCoreEnable != 1 || config.ReplyCoreEnable != 1 {
		t.Fatalf("plugin core config = %+v, want forward/reply core enabled with prepared rules", config)
	}
	if _, ok := stateHasAttachmentProgram(state, "observer:tc_post_reply"); !ok {
		t.Fatalf("plugin state attachments = %+v, want observer:tc_post_reply", state.Attachments)
	}
}

func runDataplanePerfPing(netns string, target string) (string, error) {
	cmd := exec.Command("ip", "netns", "exec", netns, "ping", "-c", "1", "-W", "2", target)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func setDataplanePerfIPv4ForwardingForTest(t *testing.T, topology dataplanePerfTopology, value string) func() {
	t.Helper()
	paths := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/default/forwarding",
	}
	for _, ifName := range []string{topology.ClientHostIF, topology.BackendHostIF} {
		if strings.TrimSpace(ifName) == "" {
			continue
		}
		paths = append(paths, filepath.Join("/proc/sys/net/ipv4/conf", ifName, "forwarding"))
	}
	return setDataplanePerfProcFilesForTest(t, paths, value)
}

func setDataplanePerfProcFilesForTest(t *testing.T, paths []string, value string) func() {
	t.Helper()
	type originalValue struct {
		path string
		data []byte
	}
	originals := make([]originalValue, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		original, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		originals = append(originals, originalValue{path: path, data: original})
	}
	return func() {
		for i := len(originals) - 1; i >= 0; i-- {
			item := originals[i]
			if err := os.WriteFile(item.path, item.data, 0o644); err != nil {
				t.Logf("restore %s failed: %v", item.path, err)
			}
		}
	}
}

func setControlScriptInterfacesForPipelineTest(t *testing.T, pluginDir string, ifNames ...string) {
	t.Helper()

	controlPath := filepath.Join(pluginDir, "control.js")
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("ReadFile(control.js) error = %v", err)
	}
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		if !strings.Contains(line, "interfaces:") {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + "interfaces: " + jsStringListForPipelineTest(ifNames...) + ","
		replaced = true
		break
	}
	if !replaced {
		t.Fatalf("control.js does not contain an interfaces field")
	}
	if err := os.WriteFile(controlPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile(control.js) error = %v", err)
	}
}

func jsStringListForPipelineTest(values ...string) string {
	if len(values) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%q", value))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func writeControlRegisteredPipelinePluginForTest(t *testing.T, pluginDir string, id string, name string, controlSource string) {
	t.Helper()

	manifest := fmt.Sprintf(`{
  "api_version": "v1",
  "id": %q,
  "name": %q,
  "version": "0.1.0",
  "kind": "pipeline",
  "stability": "lab",
  "control": {
    "main": "control.js",
    "permissions": ["ebpf.load", "hook.attach", "plugin.register"]
  }
}`, id, name)
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatalf("WriteFile(%s manifest) error = %v", id, err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "control.js"), []byte(controlSource), 0o644); err != nil {
		t.Fatalf("WriteFile(%s control.js) error = %v", id, err)
	}
}

func writeDropCorePluginForTest(t *testing.T, pluginDir string, ifName string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "drop_core", "Drop Core", fmt.Sprintf(`plugin.capabilities(['drop', 'tc']);
ebpf.loadObject({
  id: 'drop',
  path: 'drop_core.o',
  programs: [{id: 'tc_drop', section: 'tc/fvtap/pre_forward', type: 'tc'}]
});
hooks.attach({
  id: 'drop-ingress',
  engine: 'tc',
  attach: 'ingress',
  stage: 'forward',
  priority: %d,
  program: 'drop:tc_drop',
  mode: 'drop',
  interfaces: %s
});
`, pluginPipelineCorePriority-10, jsStringListForPipelineTest(ifName)))
	const source = `
#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define TC_ACT_SHOT 2

struct __sk_buff;

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

SEC("tc/fvtap/pre_forward")
int tc_drop(struct __sk_buff *skb)
{
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(filepath.Join(pluginDir, "drop_core.bpf.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(drop_core source) error = %v", err)
	}
}

type redirectCorePluginSpec struct {
	clientHostIF   string
	clientHostIdx  int
	clientHostMAC  string
	clientNSMAC    string
	backendHostIF  string
	backendHostIdx int
	backendHostMAC string
	backendNSMAC   string
}

func writeRedirectCorePluginForTest(t *testing.T, pluginDir string, spec redirectCorePluginSpec) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "redirect_core", "Redirect Core", fmt.Sprintf(`plugin.capabilities(['redirect', 'tc']);
ebpf.loadObject({
  id: 'redirect',
  path: 'redirect_core.o',
  programs: [{id: 'tc_redirect', section: 'tc/fvtap/pre_forward', type: 'tc'}]
});
hooks.attach({
  id: 'redirect-ingress',
  engine: 'tc',
  attach: 'ingress',
  stage: 'forward',
  priority: %d,
  program: 'redirect:tc_redirect',
  mode: 'redirect',
  interfaces: %s
});
`, pluginPipelineCorePriority-10, jsStringListForPipelineTest(spec.clientHostIF, spec.backendHostIF)))
	source := fmt.Sprintf(`
#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_FUNC_skb_store_bytes 9
#define BPF_FUNC_redirect 23
#define TC_ACT_UNSPEC (-1)

#define CLIENT_HOST_IFINDEX %d
#define BACKEND_HOST_IFINDEX %d

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
};

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

static long (*const bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*const bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

static __inline int redirect_with_l2(struct __sk_buff *skb, __u32 ifindex, const unsigned char *dst, const unsigned char *src)
{
	if (bpf_skb_store_bytes(skb, 0, dst, 6, 0) < 0)
		return TC_ACT_UNSPEC;
	if (bpf_skb_store_bytes(skb, 6, src, 6, 0) < 0)
		return TC_ACT_UNSPEC;
	return bpf_redirect(ifindex, 0);
}

SEC("tc/fvtap/pre_forward")
int tc_redirect(struct __sk_buff *skb)
{
	if (skb->ifindex == CLIENT_HOST_IFINDEX) {
		unsigned char dst[6] = {%s};
		unsigned char src[6] = {%s};
		return redirect_with_l2(skb, BACKEND_HOST_IFINDEX, dst, src);
	}
	if (skb->ifindex == BACKEND_HOST_IFINDEX) {
		unsigned char dst[6] = {%s};
		unsigned char src[6] = {%s};
		return redirect_with_l2(skb, CLIENT_HOST_IFINDEX, dst, src);
	}
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`, spec.clientHostIdx, spec.backendHostIdx,
		macLiteralForPluginTest(t, spec.backendNSMAC),
		macLiteralForPluginTest(t, spec.backendHostMAC),
		macLiteralForPluginTest(t, spec.clientNSMAC),
		macLiteralForPluginTest(t, spec.clientHostMAC))
	if err := os.WriteFile(filepath.Join(pluginDir, "redirect_core.bpf.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(redirect_core source) error = %v", err)
	}
}

func macLiteralForPluginTest(t *testing.T, value string) string {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("ParseMAC(%q) error = %v", value, err)
	}
	if len(mac) != 6 {
		t.Fatalf("ParseMAC(%q) length = %d, want 6", value, len(mac))
	}
	parts := make([]string, 0, 6)
	for _, b := range mac {
		parts = append(parts, fmt.Sprintf("0x%02x", b))
	}
	return strings.Join(parts, ", ")
}

func controlScriptInterfacesPropertyForPipelineTest(ifNames ...string) string {
	if len(ifNames) == 0 {
		return ""
	}
	return "  interfaces: " + jsStringListForPipelineTest(ifNames...) + ",\n"
}

func writePostLookupPluginForTest(t *testing.T, pluginDir string, ifNames ...string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "rule_observer", "Rule Observer", fmt.Sprintf(`plugin.capabilities(['observe', 'tc']);
ebpf.loadObject({
  id: 'observer',
  path: 'rule_observer.o',
  programs: [{id: 'tc_post_lookup', section: 'tc/fvtap/post_lookup', type: 'tc'}]
});
hooks.attach({
  id: 'after-rule',
  engine: 'tc',
  attach: 'ingress',
  stage: 'post_lookup',
  priority: 10,
  program: 'observer:tc_post_lookup',
  mode: 'observe',
%s
});
`, controlScriptInterfacesPropertyForPipelineTest(ifNames...)))
	const source = `#define SEC(name) __attribute__((section(name), used))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_tail_call 12
#define TC_ACT_UNSPEC (-1)
#define FVTAP_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE 9

struct __sk_buff;

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct tc_plugin_ctx_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u32 rule_id;
	__u32 backend_addr;
	__u32 out_ifindex;
	__u32 nat_addr;
	__u16 src_port;
	__u16 dst_port;
	__u16 backend_port;
	__u16 rule_flags;
	__u8 proto;
	__u8 rule_wildcard_addr;
	__u8 have_rule;
	__u8 have_flow;
	__u8 direction;
	__u8 pad[3];
	__u32 front_addr;
	__u32 client_addr;
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v4),
	.max_entries = 1,
};

SEC("tc/fvtap/post_lookup")
int tc_post_lookup(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct tc_plugin_ctx_v4 *ctx = bpf_map_lookup_elem(&tc_plugin_ctx_v4, &key);
	if (ctx && ctx->have_rule == 0)
		return TC_ACT_UNSPEC;
	bpf_tail_call(skb, &tc_prog_chain_v4, FVTAP_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(filepath.Join(pluginDir, "rule_observer.bpf.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(rule_observer.bpf.c) error = %v", err)
	}
}

func writePostReplyPluginForTest(t *testing.T, pluginDir string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "reply_observer", "Reply Observer", `plugin.capabilities(['observe', 'tc']);
ebpf.loadObject({
  id: 'observer',
  path: 'reply_observer.o',
  programs: [{id: 'tc_post_reply', section: 'tc/fvtap/post_reply', type: 'tc'}]
});
hooks.attach({
  id: 'after-reply',
  engine: 'tc',
  attach: 'ingress',
  stage: 'post_reply',
  priority: 10,
  program: 'observer:tc_post_reply',
  mode: 'observe'
});
`)
	const source = `#define SEC(name) __attribute__((section(name), used))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_tail_call 12
#define TC_ACT_UNSPEC (-1)
#define FVTAP_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE 28

struct __sk_buff;

struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct tc_plugin_ctx_v4 {
	__u32 ifindex;
	__u32 src_addr;
	__u32 dst_addr;
	__u32 rule_id;
	__u32 backend_addr;
	__u32 out_ifindex;
	__u32 nat_addr;
	__u16 src_port;
	__u16 dst_port;
	__u16 backend_port;
	__u16 rule_flags;
	__u8 proto;
	__u8 rule_wildcard_addr;
	__u8 have_rule;
	__u8 have_flow;
	__u8 direction;
	__u8 pad[3];
	__u32 front_addr;
	__u32 client_addr;
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 45,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v4),
	.max_entries = 1,
};

SEC("tc/fvtap/post_reply")
int tc_post_reply(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct tc_plugin_ctx_v4 *ctx = bpf_map_lookup_elem(&tc_plugin_ctx_v4, &key);
	if (ctx && ctx->have_flow == 0)
		return TC_ACT_UNSPEC;
	bpf_tail_call(skb, &tc_prog_chain_v4, FVTAP_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(filepath.Join(pluginDir, "reply_observer.bpf.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(reply_observer.bpf.c) error = %v", err)
	}
}

func stateHasAttachmentProgram(state PluginRuntimeState, program string) (PluginAttachmentState, bool) {
	for _, attachment := range state.Attachments {
		if strings.TrimSpace(attachment.Program) == program {
			return attachment, true
		}
	}
	return PluginAttachmentState{}, false
}

func stableTCHookPluginForOrderTest() LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "stable_observer",
			Name:      "Stable Observer",
			Version:   "1.0.0",
			Kind:      "pipeline",
			Stability: pluginStabilityStable,
		},
		Hooks: []PluginHook{{
			ID:       "forward",
			Engine:   kernelEngineTC,
			Attach:   "ingress",
			Stage:    kernelPluginPipelineStageForward,
			Priority: pluginPipelineCorePriority - 10,
			Program:  "observer:tc_observe",
			Mode:     "observe",
		}},
		Status: pluginStatusActive,
	}
}

type orderedKernelRuntimeEntryTestRuntime struct {
	engine                    string
	reconcileCalls            int
	reconcileWithCatalogCalls int
	assignments               map[int64]string
}

func (rt *orderedKernelRuntimeEntryTestRuntime) Available() (bool, string) {
	return true, ""
}

func (rt *orderedKernelRuntimeEntryTestRuntime) SupportsRule(Rule) (bool, string) {
	return true, ""
}

func (rt *orderedKernelRuntimeEntryTestRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	rt.reconcileCalls++
	return rt.apply(rules), nil
}

func (rt *orderedKernelRuntimeEntryTestRuntime) ReconcileWithPluginCatalog(rules []Rule, _ PluginCatalog) (map[int64]kernelRuleApplyResult, error) {
	rt.reconcileWithCatalogCalls++
	return rt.apply(rules), nil
}

func (rt *orderedKernelRuntimeEntryTestRuntime) apply(rules []Rule) map[int64]kernelRuleApplyResult {
	rt.assignments = make(map[int64]string, len(rules))
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		rt.assignments[rule.ID] = rt.engine
		results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: rt.engine}
	}
	return results
}

func (rt *orderedKernelRuntimeEntryTestRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *orderedKernelRuntimeEntryTestRuntime) Maintain() error {
	return nil
}

func (rt *orderedKernelRuntimeEntryTestRuntime) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(rt.assignments))
	for id, engine := range rt.assignments {
		out[id] = engine
	}
	return out
}

func (rt *orderedKernelRuntimeEntryTestRuntime) Close() error {
	return nil
}
