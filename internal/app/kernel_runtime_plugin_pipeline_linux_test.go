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
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const kernelPluginPipelineTestEnv = "FORWARD_RUN_PLUGIN_PIPELINE_TEST"

func packetObserverPluginSourceDirForPipelineTest(t *testing.T) string {
	t.Helper()
	if sourceDir := strings.TrimSpace(os.Getenv(dataplanePerfPluginSourceEnv)); sourceDir != "" {
		return sourceDir
	}
	return filepath.Join(findRepoRoot(t), "plugins", "packet_observer")
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

	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled}))
	if !rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = false, want true when external dataplane plugins are enabled")
	}

	rt = newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &disabled,
		PluginsDataplaneSetting: &enabled}))
	if rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = true, want false when plugin scanning is disabled")
	}

	rt = newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &disabled}))
	if rt.pluginPipelineEnabled {
		t.Fatal("pluginPipelineEnabled = true, want false when plugin dataplane loading is disabled")
	}
}

func TestOrderedKernelRuntimePrefersTCWhenRuntimeTCPluginHooksActive(t *testing.T) {
	enabled := true
	xdp := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineXDP}
	tc := &orderedKernelRuntimeEntryTestRuntime{engine: kernelEngineTC}
	rt := &orderedKernelRuleRuntime{
		cfg: pluginsEnabledTestConfig(&Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled}),

		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinVeerPlugin(), stableTCHookPluginForOrderTest()},
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
		cfg: pluginsEnabledTestConfig(&Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled}),

		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinVeerPlugin(), stableTCHookPluginForOrderTest()},
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
		cfg: pluginsEnabledTestConfig(&Config{
			PluginsEnabledSetting:   &enabled,
			PluginsDataplaneSetting: &enabled}),

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
		PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), stableTCHookPluginForOrderTest()}},
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
		cfg: pluginsEnabledTestConfig(&Config{
			PluginsDataplaneSetting: &disabled}),

		entries: []orderedKernelRuntimeEntry{
			{name: kernelEngineXDP, rt: xdp},
			{name: kernelEngineTC, rt: tc},
		},
	}

	results, err := rt.ReconcileWithPluginCatalog([]Rule{{ID: 1, Enabled: true}}, PluginCatalog{
		Plugins: []LoadedPlugin{builtinVeerPlugin(), stableTCHookPluginForOrderTest()},
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
		forwardEgressPipelineProg:   &ebpf.Program{},
		forwardPipelineProgV6:       &ebpf.Program{},
		forwardEgressPipelineProgV6: &ebpf.Program{},
		forwardCoreProg:             &ebpf.Program{},
		forwardPluginContinueProg:   &ebpf.Program{},
		forwardPluginPostLookupProg: &ebpf.Program{},
		forwardPluginPostApplyProg:  &ebpf.Program{},
		forwardTransparentProg:      &ebpf.Program{},
		forwardFullNATProg:          &ebpf.Program{},
		forwardEgressNATProg:        &ebpf.Program{},
		replyDispatchProg:           &ebpf.Program{},
		replyPipelineProg:           &ebpf.Program{},
		replyEgressPipelineProg:     &ebpf.Program{},
		replyPipelineProgV6:         &ebpf.Program{},
		replyEgressPipelineProgV6:   &ebpf.Program{},
		replyCoreProg:               &ebpf.Program{},
		replyPluginContinueProg:     &ebpf.Program{},
		replyPluginPostReplyProg:    &ebpf.Program{},
		replyPluginPostApplyProg:    &ebpf.Program{},
		replyTransparentProg:        &ebpf.Program{},
		replyFullNATProg:            &ebpf.Program{},
		progChainV4:                 &ebpf.Map{},
		pluginConfigV4:              &ebpf.Map{},
		pluginInterfacesV4:          &ebpf.Map{},
		dispatchScratchV4:           &ebpf.Map{},
		dispatchScratchV6:           &ebpf.Map{},
		pluginCtxV4:                 &ebpf.Map{},
		pluginCtxV6:                 &ebpf.Map{},
		pluginMetrics:               &ebpf.Map{},
		packetMetadataGenerationV4:  &ebpf.Map{},
		packetMetadataGenerationV6:  &ebpf.Map{},
		packetMetadataV4:            &ebpf.Map{},
		packetMetadataV6:            &ebpf.Map{},
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
	if programs.forwardEgressProg != pieces.forwardEgressPipelineProg || programs.replyEgressProg != pieces.replyEgressPipelineProg {
		t.Fatal("egress programs did not select the plugin pipeline wrappers")
	}
	if programs.forwardProgV6 != pieces.forwardPipelineProgV6 || programs.replyProgV6 != pieces.replyPipelineProgV6 {
		t.Fatal("IPv6 ingress programs did not select the plugin pipeline wrappers")
	}
	if programs.forwardEgressProgV6 != pieces.forwardEgressPipelineProgV6 || programs.replyEgressProgV6 != pieces.replyEgressPipelineProgV6 {
		t.Fatal("IPv6 egress programs did not select the plugin pipeline wrappers")
	}
}

func TestTCPluginPipelineABIV2SlotLayoutHasNoOverlap(t *testing.T) {
	owners := make(map[int]string, tcProgramChainV4MaxEntries)
	claim := func(name string, base, count int) {
		t.Helper()
		for slot := base; slot < base+count; slot++ {
			if slot < 0 || slot >= tcProgramChainV4MaxEntries {
				t.Fatalf("%s claims slot %d outside [0,%d)", name, slot, tcProgramChainV4MaxEntries)
			}
			if previous := owners[slot]; previous != "" {
				t.Fatalf("slot %d is shared by %s and %s", slot, previous, name)
			}
			owners[slot] = name
		}
	}

	claim("core-forward", tcProgramChainIndexV4Transparent, 10)
	claim("bank0-pre-reply", tcProgramChainIndexV4PluginReplyBase, tcProgramChainV4PluginPreReplyMax)
	claim("bank0-post-reply", tcProgramChainIndexV4PluginReplyPostBase, tcProgramChainV4PluginPostReplyMax)
	claim("reply-control", tcProgramChainIndexV4ReplyCore, 3)
	claim("bank0-pre-forward", tcProgramChainIndexV4PluginBase, tcProgramChainV4PluginPreForwardMax)
	claim("bank0-post-lookup", tcProgramChainIndexV4PluginPostBase, tcProgramChainV4PluginPostLookupMax)
	claim("bank1-pre-forward", tcProgramChainIndexV4PluginBank1Base, tcProgramChainV4PluginPreForwardMax)
	claim("bank1-post-lookup", tcProgramChainIndexV4PluginBank1PostBase, tcProgramChainV4PluginPostLookupMax)
	claim("bank1-pre-reply", tcProgramChainIndexV4PluginBank1ReplyBase, tcProgramChainV4PluginPreReplyMax)
	claim("bank1-post-reply", tcProgramChainIndexV4PluginBank1ReplyPostBase, tcProgramChainV4PluginPostReplyMax)
	claim("apply-control", tcProgramChainIndexV4PluginPostApply, 2)
	claim("bank0-post-apply", tcProgramChainIndexV4PluginApplyBase, tcProgramChainV4PluginPostApplyMax)
	claim("bank1-post-apply", tcProgramChainIndexV4PluginBank1ApplyBase, tcProgramChainV4PluginPostApplyMax)
	claim("bank0-reply-apply", tcProgramChainIndexV4PluginReplyApplyBase, tcProgramChainV4PluginPostReplyApplyMax)
	claim("bank1-reply-apply", tcProgramChainIndexV4PluginBank1ReplyApplyBase, tcProgramChainV4PluginPostReplyApplyMax)

	if len(owners) != tcProgramChainV4MaxEntries {
		t.Fatalf("ABI v2 slot coverage = %d, want %d", len(owners), tcProgramChainV4MaxEntries)
	}
	if tcProgramChainV4PluginTotalMax > 14 || tcProgramChainV4PluginReplyTotalMax > 14 {
		t.Fatalf("plugin hook totals exceed the tail-call depth budget: forward=%d reply=%d", tcProgramChainV4PluginTotalMax, tcProgramChainV4PluginReplyTotalMax)
	}
}

func TestKernelPluginMetricKeyMapsEveryPipelineStage(t *testing.T) {
	tests := []struct {
		stage     string
		chainBase int
		metricKey uint32
	}{
		{kernelPluginPipelineStagePreForward, tcProgramChainIndexV4PluginBase, tcPluginMetricPreForwardBase},
		{kernelPluginPipelineStagePostLookup, tcProgramChainIndexV4PluginPostBase, tcPluginMetricPostLookupBase},
		{kernelPluginPipelineStagePostApply, tcProgramChainIndexV4PluginApplyBase, tcPluginMetricPostApplyBase},
		{kernelPluginPipelineStagePreReply, tcProgramChainIndexV4PluginReplyBase, tcPluginMetricPreReplyBase},
		{kernelPluginPipelineStagePostReply, tcProgramChainIndexV4PluginReplyPostBase, tcPluginMetricPostReplyBase},
		{kernelPluginPipelineStageReplyApply, tcProgramChainIndexV4PluginReplyApplyBase, tcPluginMetricReplyApplyBase},
	}
	for _, test := range tests {
		for index := 0; index < tcPluginMetricStageWidth; index++ {
			got, ok := kernelPluginMetricKey(PluginAttachmentState{Stage: test.stage, ChainSlot: test.chainBase + index})
			if !ok || got != test.metricKey+uint32(index) {
				t.Fatalf("kernelPluginMetricKey(%s, %d) = (%d, %t), want (%d, true)", test.stage, test.chainBase+index, got, ok, test.metricKey+uint32(index))
			}
		}
	}
	if _, ok := kernelPluginMetricKey(PluginAttachmentState{Stage: "unknown", ChainSlot: 1}); ok {
		t.Fatal("kernelPluginMetricKey(unknown) succeeded")
	}
	if _, ok := kernelPluginMetricKey(PluginAttachmentState{Stage: kernelPluginPipelineStagePreForward, ChainSlot: tcProgramChainIndexV4PluginBase + tcPluginMetricStageWidth}); ok {
		t.Fatal("kernelPluginMetricKey(out-of-range slot) succeeded")
	}
}

func TestPluginPacketMetricsClassifiesTerminalPackets(t *testing.T) {
	got := pluginPacketMetrics(20, 2048, 12, 3, true)
	if got.Packets != 20 || got.Bytes != 2048 || got.ContinuedPackets != 12 || got.TailCallMisses != 3 || got.TerminalPackets != 5 || got.DroppedPackets != 5 {
		t.Fatalf("pluginPacketMetrics() = %+v", got)
	}
	got = pluginPacketMetrics(2, 128, 4, 1, false)
	if got.TerminalPackets != 0 || got.DroppedPackets != 0 {
		t.Fatalf("pluginPacketMetrics(inconsistent snapshot) = %+v, want clamped zero terminal count", got)
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
				Section: "tc/veer/pre_forward",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				{ID: "tc_pre_forward", Section: "tc/veer/pre_forward", Type: kernelEngineTC},
				{ID: "tc_pre_reply", Section: "tc/veer/pre_reply", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "forward-lo", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_forward", Mode: "observe", Interfaces: []string{"lo"}},
			{ID: "reply-lo", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_reply", Mode: "observe", Interfaces: []string{"lo"}},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
	desired[0].hooks[0].InterfaceIndexes = []uint32{999}
	desired, _, _, _ = kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if len(desired[0].hooks[0].InterfaceIndexes) != 1 || desired[0].hooks[0].InterfaceIndexes[0] != uint32(lo.Index) {
		t.Fatalf("resolved interface indexes = %+v, want stale indexes replaced with lo=%d", desired[0].hooks[0].InterfaceIndexes, lo.Index)
	}
}

func TestKernelPluginPipelineEgressInterfaceUsesEgressAttachment(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName(lo) error = %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "egress.o"), []byte("fake"), 0o644); err != nil {
		t.Fatalf("WriteFile(egress.o) error = %v", err)
	}
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:      "egress_stage",
			Name:    "Egress stage",
			Version: "0.1.0",
			Kind:    "pipeline",
		},
		Objects: []PluginObject{{
			ID:             "egress",
			Path:           "egress.o",
			Status:         pluginObjectStatusVerified,
			ResolvedSHA256: "abc",
			Programs: []PluginObjectProgram{{
				ID:      "tc_forward",
				Section: "tc/veer/forward",
				Type:    kernelEngineTC,
			}},
		}},
		Hooks: []PluginHook{{
			ID:         "local-egress",
			Engine:     kernelEngineTC,
			Attach:     "egress",
			Stage:      kernelPluginPipelineStageForward,
			Priority:   pluginPipelineCorePriority - 10,
			Program:    "egress:tc_forward",
			Mode:       "transform",
			Interfaces: []string{"lo"},
		}},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	desired, states, targets := kernelPluginPipelineResolveExplicitAttachTargets(desired, states)
	if len(states) != 0 || len(desired) != 1 {
		t.Fatalf("desired=%+v states=%+v, want one valid egress plugin", desired, states)
	}
	if len(targets.ForwardIngress) != 0 || len(targets.ReplyIngress) != 0 || len(targets.ReplyEgress) != 0 {
		t.Fatalf("targets=%+v, egress hook must not create ingress/reply targets", targets)
	}
	if _, ok := targets.ForwardEgress[lo.Index]; !ok {
		t.Fatalf("ForwardEgress=%+v, want lo ifindex %d", targets.ForwardEgress, lo.Index)
	}
	forwardEgress := &ebpf.Program{}
	plans := desiredKernelAttachmentPlansForRuleSets(targets, kernelAttachmentPrograms{forwardEgressProg: forwardEgress})
	if len(plans) != 1 {
		t.Fatalf("plans=%+v, want one egress attachment", plans)
	}
	plan := plans[0]
	if plan.key.parent != netlink.HANDLE_MIN_EGRESS || plan.attach != kernelPluginPipelineAttachEgress {
		t.Fatalf("plan=%+v, want TC egress parent", plan)
	}
	if plan.name != kernelForwardEgressPipelineProgramName || plan.prog != forwardEgress {
		t.Fatalf("plan=%+v, want forward egress pipeline program", plan)
	}
}

func TestKernelPluginPipelinePlansDualStackIngressAndEgress(t *testing.T) {
	programs := kernelAttachmentPrograms{
		forwardProg:         &ebpf.Program{},
		forwardProgV6:       &ebpf.Program{},
		forwardEgressProg:   &ebpf.Program{},
		forwardEgressProgV6: &ebpf.Program{},
	}
	sets := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{10: nil},
		ForwardEgress:  map[int][]int64{20: nil},
	}
	plans := desiredKernelAttachmentPlansForRuleSets(sets, programs)
	if len(plans) != 4 {
		t.Fatalf("plans = %+v, want IPv4/IPv6 ingress and egress attachments", plans)
	}
	want := map[string]bool{
		kernelForwardProgramName:                 false,
		kernelForwardProgramNameV6:               false,
		kernelForwardEgressPipelineProgramName:   false,
		kernelForwardEgressPipelineProgramNameV6: false,
	}
	for _, plan := range plans {
		if _, ok := want[plan.name]; !ok {
			t.Fatalf("unexpected dual-stack attachment plan: %+v", plan)
		}
		want[plan.name] = true
	}
	for name, found := range want {
		if !found {
			t.Fatalf("dual-stack attachment plan is missing %q", name)
		}
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
				Section: "tc/veer/pre_forward",
				Type:    kernelEngineTC,
			}, {
				ID:      "tc_post_lookup",
				Section: "tc/veer/post_lookup",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				Section: "tc/veer/pre_forward",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				{ID: "tc_pre_forward", Section: "tc/veer/pre_forward", Type: kernelEngineTC},
				{ID: "tc_post_lookup", Section: "tc/veer/post_lookup", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "pre-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_pre_forward", Mode: "observe", Interfaces: []string{"lo"}},
			{ID: "post-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_post_lookup", Mode: "observe", Interfaces: []string{"forward_missing0"}},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				{ID: "tc_before_core", Section: "tc/veer/pre_forward", Type: kernelEngineTC},
				{ID: "tc_after_core", Section: "tc/veer/post_lookup", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_after_core", Mode: "observe"},
			{ID: "before-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_before_core", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				{ID: "tc_before_reply", Section: "tc/veer/pre_reply", Type: kernelEngineTC},
				{ID: "tc_after_reply", Section: "tc/veer/post_reply", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-reply-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority + 10, Program: "observer:tc_after_reply", Mode: "observe"},
			{ID: "before-reply-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageReply, Priority: pluginPipelineCorePriority - 10, Program: "observer:tc_before_reply", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
	if len(desired[0].hooks[1].Context) != 2 || desired[0].hooks[1].Context[0] != pluginHookContextTCPluginCtxV4 || desired[0].hooks[1].Context[1] != pluginHookContextTCPluginCtxV6 {
		t.Fatalf("post_reply context = %+v, want dual-stack plugin contexts", desired[0].hooks[1].Context)
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
				Section: "tc/veer/pre_forward",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want no hooks for core priority collision", desired)
	}
	state, ok := states["core_collision"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "collides with Veer Core priority") {
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
				{ID: "tc_post_lookup", Section: "tc/veer/post_lookup", Type: kernelEngineTC},
				{ID: "tc_pre_forward", Section: "tc/veer/pre_forward", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "after-rule", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStagePostLookup, Priority: 5, Program: "observer:tc_post_lookup", Mode: "observe"},
			{ID: "before-parse", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStagePreForward, Priority: 10, Program: "observer:tc_pre_forward", Mode: "observe"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
				Section: "tc/veer/pre_forward",
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
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled})

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
					Section: "tc/veer/pre_filter",
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
					Section: "tc/veer/post_filter",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
	if len(post.Context) != 2 || post.Context[0] != pluginHookContextTCPluginCtxV4 || post.Context[1] != pluginHookContextTCPluginCtxV6 {
		t.Fatalf("post context = %+v, want dual-stack plugin contexts", post.Context)
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
				{ID: "tc_pre_filter", Section: "tc/veer/pre_filter", Type: kernelEngineTC},
				{ID: "tc_post_filter", Section: "tc/veer/post_filter", Type: kernelEngineTC},
			},
		}},
		Hooks: []PluginHook{
			{ID: "pre-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority - 100, Program: "firewall:tc_pre_filter", Mode: "drop"},
			{ID: "post-core", Engine: kernelEngineTC, Attach: "ingress", Stage: kernelPluginPipelineStageForward, Priority: pluginPipelineCorePriority + 100, Program: "firewall:tc_post_filter", Mode: "drop"},
		},
		Status:  pluginStatusActive,
		rootDir: dir,
	}

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
	if len(post.Context) != 2 || post.Context[0] != pluginHookContextTCPluginCtxV4 || post.Context[1] != pluginHookContextTCPluginCtxV6 {
		t.Fatalf("post context = %+v, want dual-stack plugin contexts", post.Context)
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
				Section: "tc/veer/pre_filter",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want rejected pre-core context", desired)
	}
	state, ok := states["bad_firewall"]
	if !ok || state.Error == "" || !strings.Contains(state.Error, "only available after Veer Core lookup") {
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

func TestPreviousKernelPluginPipelineObjectTracksDefinitionChanges(t *testing.T) {
	hash := strings.Repeat("a", 64)
	stateMaps := []PluginObjectStateMap{{Name: "sessions", Policy: pluginObjectMapPreserve, SchemaVersion: 1}}
	refs := []loadedPluginObjectRef{{
		PluginID:     "stateful_plugin",
		ObjectID:     "dataplane",
		ObjectPath:   "/old/snapshot/dataplane.o",
		ObjectSHA256: hash,
		StateMaps:    stateMaps,
		coll:         &ebpf.Collection{},
	}}
	plan := kernelPluginPipelineHookPlan{
		PluginID:        "stateful_plugin",
		ObjectID:        "dataplane",
		ObjectPath:      "/new/snapshot/dataplane.o",
		ObjectSHA256:    strings.ToUpper(hash),
		ObjectStateMaps: append([]PluginObjectStateMap(nil), stateMaps...),
	}
	got, unchanged := previousKernelPluginPipelineObject(refs, plan)
	if got == nil || got.ObjectPath != refs[0].ObjectPath || !unchanged {
		t.Fatalf("previous object = %+v unchanged=%t, want matching definition", got, unchanged)
	}

	plan.ObjectSHA256 = strings.Repeat("b", 64)
	got, unchanged = previousKernelPluginPipelineObject(refs, plan)
	if got == nil || unchanged {
		t.Fatalf("previous object with changed hash = %+v unchanged=%t, want migratable previous object", got, unchanged)
	}
	plan.ObjectSHA256 = strings.ToUpper(hash)
	plan.ObjectStateMaps[0].SchemaVersion = 2
	got, unchanged = previousKernelPluginPipelineObject(refs, plan)
	if got == nil || unchanged {
		t.Fatalf("previous object with changed state contract = %+v unchanged=%t, want migration path", got, unchanged)
	}
}

func TestPluginPipelineVersionedMapReplacementsRequireExplicitReset(t *testing.T) {
	previous := &loadedPluginObjectRef{
		StateMaps: []PluginObjectStateMap{{Name: "sessions", Policy: pluginObjectMapPreserve, SchemaVersion: 1}},
		coll:      &ebpf.Collection{Maps: map[string]*ebpf.Map{}},
	}
	if _, err := pluginPipelineVersionedMapReplacements(&ebpf.CollectionSpec{}, map[string]*ebpf.Map{}, nil, previous); err == nil || !strings.Contains(err.Error(), "declare policy=reset") {
		t.Fatalf("removed state map error = %v, want explicit reset requirement", err)
	}
	changed := []PluginObjectStateMap{{Name: "sessions", Policy: pluginObjectMapPreserve, SchemaVersion: 2}}
	if _, err := pluginPipelineVersionedMapReplacements(&ebpf.CollectionSpec{}, map[string]*ebpf.Map{}, changed, previous); err == nil || !strings.Contains(err.Error(), "schema changed from 1 to 2") {
		t.Fatalf("changed state map error = %v, want schema transition rejection", err)
	}
	reset := []PluginObjectStateMap{{Name: "sessions", Policy: pluginObjectMapReset}}
	got, err := pluginPipelineVersionedMapReplacements(&ebpf.CollectionSpec{}, map[string]*ebpf.Map{}, reset, previous)
	if err != nil || len(got) != 0 {
		t.Fatalf("explicit reset replacements = %v, error = %v", got, err)
	}
}

func TestPluginPipelineVersionedMapReplacementsReuseCompatibleStateMapFD(t *testing.T) {
	stateMap := newPluginMapAPITestMap(t, &ebpf.MapSpec{
		Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 16,
	})
	key := uint32(7)
	value := uint64(99)
	if err := stateMap.Put(key, value); err != nil {
		t.Fatalf("seed state map: %v", err)
	}
	contract := []PluginObjectStateMap{{Name: "sessions", Policy: pluginObjectMapPreserve, SchemaVersion: 1}}
	previous := &loadedPluginObjectRef{
		StateMaps: contract,
		coll:      &ebpf.Collection{Maps: map[string]*ebpf.Map{"sessions": stateMap}},
	}
	nextSpec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"sessions": {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 16},
	}}
	replacements, err := pluginPipelineVersionedMapReplacements(nextSpec, map[string]*ebpf.Map{}, contract, previous)
	if err != nil {
		t.Fatal(err)
	}
	if replacements["sessions"] != stateMap {
		t.Fatalf("replacement map = %p, want previous FD %p", replacements["sessions"], stateMap)
	}
	var got uint64
	if err := replacements["sessions"].Lookup(key, &got); err != nil || got != value {
		t.Fatalf("preserved state value = %d, error = %v, want %d", got, err, value)
	}

	incompatible := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"sessions": {Name: "sessions", Type: ebpf.Hash, KeySize: 4, ValueSize: 16, MaxEntries: 16},
	}}
	if _, err := pluginPipelineVersionedMapReplacements(incompatible, map[string]*ebpf.Map{}, contract, previous); err == nil || !strings.Contains(err.Error(), "preserve state map") {
		t.Fatalf("incompatible state map error = %v", err)
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
				Section: "tc/veer/pre_filter",
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

	desired, states := buildKernelPluginPipelineDesired(PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}})
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
			ProgramSection: "tc/veer/pre_forward",
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

func TestKernelPluginPipelineFingerprintIncludesResolvedInterfaces(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{{
		plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "scoped"}},
		hooks: []kernelPluginPipelineHookPlan{{
			PluginID:         "scoped",
			HookID:           "pre",
			Stage:            kernelPluginPipelineStagePreForward,
			Priority:         pluginPipelineCorePriority - 1,
			Interfaces:       []string{"tap0"},
			InterfaceIndexes: []uint32{10},
		}},
	}}
	first := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	desired[0].hooks[0].InterfaceIndexes = []uint32{11}
	second := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	if first == second {
		t.Fatalf("fingerprints are equal after ifindex change: %s", first)
	}
}

func TestKernelPluginPipelineFingerprintUsesVerifiedObjectContentAcrossCatalogSnapshots(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{{
		plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "pppoe_client"}},
		hooks: []kernelPluginPipelineHookPlan{{
			PluginID:       "pppoe_client",
			HookID:         "pppoe-ingress",
			ObjectID:       "pppoe_tunnel",
			ObjectPath:     "/tmp/veer-plugin-catalog-a/pppoe_client/pppoe_tunnel.o",
			ObjectSHA256:   strings.Repeat("a", 64),
			ProgramRef:     "tc_tunnel",
			ProgramSection: "tc/veer/pre_forward",
			Stage:          kernelPluginPipelineStagePreForward,
			Attach:         "ingress",
			Mode:           "rewrite",
			Priority:       20,
		}},
	}}
	first := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	desired[0].hooks[0].ObjectPath = "/tmp/veer-plugin-catalog-b/pppoe_client/pppoe_tunnel.o"
	second := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	if first != second {
		t.Fatalf("fingerprint changed for identical verified object content: %s != %s", first, second)
	}
	desired[0].hooks[0].ObjectSHA256 = strings.Repeat("b", 64)
	third := kernelPluginPipelineFingerprint(desired, nil, kernelPluginPipelineCoreConfig{})
	if second == third {
		t.Fatalf("fingerprint did not change after object content changed: %s", second)
	}
}

func TestBuildKernelPluginPipelineInterfaceMasksSeparatesScopedHooks(t *testing.T) {
	programs := []loadedKernelPluginPipelineProgram{
		{plan: kernelPluginPipelineHookPlan{PluginID: "global", HookID: "global-pre", Stage: kernelPluginPipelineStagePreForward}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "scoped", HookID: "scoped-pre", Stage: kernelPluginPipelineStagePreForward, Interfaces: []string{"tap10"}, InterfaceIndexes: []uint32{10}}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "scoped", HookID: "scoped-post", Stage: kernelPluginPipelineStagePostLookup, Interfaces: []string{"tap10", "tap20"}, InterfaceIndexes: []uint32{10, 20}}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "reply", HookID: "reply", Stage: kernelPluginPipelineStagePreReply, Interfaces: []string{"tap20"}, InterfaceIndexes: []uint32{20}}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "egress", HookID: "egress", Stage: kernelPluginPipelineStagePreForward, Attach: "egress", Interfaces: []string{"tap10"}, InterfaceIndexes: []uint32{10}}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "apply", HookID: "global-apply", Stage: kernelPluginPipelineStagePostApply}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "apply", HookID: "scoped-apply", Stage: kernelPluginPipelineStagePostApply, Interfaces: []string{"tap10"}, InterfaceIndexes: []uint32{10}}},
		{plan: kernelPluginPipelineHookPlan{PluginID: "reply", HookID: "reply-apply", Stage: kernelPluginPipelineStageReplyApply, Attach: "egress", Interfaces: []string{"tap20"}, InterfaceIndexes: []uint32{20}}},
	}
	masks, err := buildKernelPluginPipelineInterfaceMasks(programs)
	if err != nil {
		t.Fatalf("buildKernelPluginPipelineInterfaceMasks() error = %v", err)
	}
	ingressGlobal := masks.globalByAttach[kernelPluginPipelineAttachIngress]
	if ingressGlobal.PreForwardMask != 0b01 || ingressGlobal.PostLookupMask != 0 || ingressGlobal.PreReplyMask != 0 || ingressGlobal.PostApplyMask != 0b01 {
		t.Fatalf("ingress global masks = %+v, want pre-forward and post-apply slot 0", ingressGlobal)
	}
	if got := masks.byInterface[kernelPluginPipelineInterfaceScope{IfIndex: 10, Attach: kernelPluginPipelineAttachIngress}]; got.PreForwardMask != 0b10 || got.PostLookupMask != 0b1 || got.PreReplyMask != 0 || got.PostApplyMask != 0b10 {
		t.Fatalf("ifindex 10 masks = %+v, want scoped pre/post hooks", got)
	}
	if got := masks.byInterface[kernelPluginPipelineInterfaceScope{IfIndex: 20, Attach: kernelPluginPipelineAttachIngress}]; got.PreForwardMask != 0 || got.PostLookupMask != 0b1 || got.PreReplyMask != 0b1 {
		t.Fatalf("ifindex 20 masks = %+v, want scoped post/reply hooks", got)
	}
	if got := masks.byInterface[kernelPluginPipelineInterfaceScope{IfIndex: 10, Attach: kernelPluginPipelineAttachEgress}]; got.PreForwardMask != 0b100 || got.PostLookupMask != 0 || got.PreReplyMask != 0 {
		t.Fatalf("ifindex 10 egress masks = %+v, want only egress pre-forward slot 2", got)
	}
	if got := masks.byInterface[kernelPluginPipelineInterfaceScope{IfIndex: 20, Attach: kernelPluginPipelineAttachEgress}]; got.ReplyApplyMask != 0b1 {
		t.Fatalf("ifindex 20 egress masks = %+v, want reply apply slot 0", got)
	}
}

func TestNormalizePluginHookAllowsPhysicalPipelineStages(t *testing.T) {
	for _, stage := range []string{
		kernelPluginPipelineStagePreForward,
		kernelPluginPipelineStagePostLookup,
		kernelPluginPipelineStagePostApply,
		kernelPluginPipelineStagePreReply,
		kernelPluginPipelineStagePostReply,
		kernelPluginPipelineStageReplyApply,
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

func TestKernelPluginPipelineDelegatesXDPHooksToDispatcher(t *testing.T) {
	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled})

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
	catalog := PluginCatalog{Plugins: []LoadedPlugin{builtinVeerPlugin(), plugin}}

	if kernelPluginPipelineCatalogHasRuntimeHooks(catalog, cfg) {
		t.Fatal("kernelPluginPipelineCatalogHasRuntimeHooks() = true, want false for xdp-only plugin")
	}
	desired, states := buildKernelPluginPipelineDesiredWithConfig(catalog, cfg, true)
	if len(desired) != 0 {
		t.Fatalf("desired = %+v, want no tc pipeline hooks for xdp-only plugin", desired)
	}
	if _, ok := states["xdp_probe"]; ok {
		t.Fatalf("tc pipeline emitted xdp runtime state = %+v, want xdp dispatcher ownership", states["xdp_probe"])
	}
	if !kernelXDPPluginCatalogHasRuntimeHooks(catalog, cfg) {
		t.Fatal("kernelXDPPluginCatalogHasRuntimeHooks() = false, want true")
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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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
		t.Fatalf("plugin attachments = %+v, want chained veer attachment", state.Attachments)
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
	if config.ActiveBank != 1 || config.PreForwardGlobalMask != 1 {
		t.Fatalf("plugin bank config = %+v, want initial inactive bank 1 with global pre-forward slot", config)
	}
	var pluginFD uint32
	if err := pieces.progChainV4.Lookup(uint32(tcProgramChainIndexV4PluginBank1Base), &pluginFD); err != nil || pluginFD == 0 {
		t.Fatalf("lookup bank 1 pre-forward plugin slot: fd=%d err=%v", pluginFD, err)
	}
	if _, ok := stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward"); !ok {
		t.Fatalf("plugin state attachments = %+v, want packet_observer:tc_pre_forward", state.Attachments)
	}
	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfClientAddr {
		t.Fatalf("initial transparent plugin probe observed source %q, want %q", observed, dataplanePerfClientAddr)
	}
	state, _ = rt.PluginSnapshot().stateFor("packet_observer")
	metricAttachment, ok := stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward")
	if !ok || metricAttachment.Metrics == nil || metricAttachment.Metrics.IPv4.Packets == 0 {
		t.Fatalf("initial plugin attachment metrics = %+v, want observed IPv4 packets", metricAttachment.Metrics)
	}

	setControlScriptInterfacesForPipelineTest(t, pluginDir, topology.ClientHostIF)
	results, err = rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile(scoped hot update) error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result after scoped hot update = %+v, want running tc", result)
	}
	pieces, err = lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces(after hot update) error = %v", err)
	}
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config after hot update: %v", err)
	}
	if config.ActiveBank != 0 || config.PreForwardGlobalMask != 0 {
		t.Fatalf("plugin config after hot update = %+v, want atomic switch to bank 0 with scoped hook", config)
	}
	clientInterface, err := net.InterfaceByName(topology.ClientHostIF)
	if err != nil {
		t.Fatalf("resolve scoped client interface: %v", err)
	}
	interfaceKey := kernelTCPluginInterfaceKeyV4{IfIndex: uint32(clientInterface.Index), Bank: config.ActiveBank}
	var interfaceMask kernelTCPluginInterfaceValueV4
	if err := pieces.pluginInterfacesV4.Lookup(interfaceKey, &interfaceMask); err != nil || interfaceMask.PreForwardMask != 1 {
		t.Fatalf("scoped interface mask key=%+v value=%+v err=%v, want pre-forward bit 0", interfaceKey, interfaceMask, err)
	}
	pluginFD = 0
	if err := pieces.progChainV4.Lookup(uint32(tcProgramChainIndexV4PluginBank1Base), &pluginFD); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("previous bank slot remains after hot-switch grace: fd=%d err=%v", pluginFD, err)
	}
	state, _ = rt.PluginSnapshot().stateFor("packet_observer")
	metricAttachment, ok = stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward")
	if !ok || metricAttachment.Metrics == nil || metricAttachment.Metrics.IPv4.Packets != 0 {
		t.Fatalf("plugin metrics after chain generation switch = %+v, want reset IPv4 counters", metricAttachment.Metrics)
	}
	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfClientAddr {
		t.Fatalf("updated transparent plugin probe observed source %q, want %q", observed, dataplanePerfClientAddr)
	}
	state, _ = rt.PluginSnapshot().stateFor("packet_observer")
	metricAttachment, _ = stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward")
	if metricAttachment.Metrics == nil || metricAttachment.Metrics.Total.Packets == 0 {
		t.Fatalf("updated plugin attachment metrics = %+v, want observed packets", metricAttachment.Metrics)
	}
	packetsBeforeFailedUpdate := metricAttachment.Metrics.Total.Packets
	if err := os.WriteFile(filepath.Join(pluginDir, "control.js"), []byte(`pipeline.attach({`), 0o644); err != nil {
		t.Fatalf("write broken control.js: %v", err)
	}
	results, err = rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile(broken plugin hot update) error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result after broken plugin hot update = %+v, want retained running tc", result)
	}
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config after broken hot update: %v", err)
	}
	if config.ActiveBank != 0 || config.PreForwardCount != 1 {
		t.Fatalf("plugin config after broken hot update = %+v, want previous bank 0 chain retained", config)
	}
	state, ok = rt.PluginSnapshot().stateFor("packet_observer")
	if !ok || !state.Attached || state.Error == "" || !strings.Contains(state.Reason, "previous chain preserved") {
		t.Fatalf("plugin state after broken hot update = %+v, want attached previous chain with reload error", state)
	}
	metricAttachment, _ = stateHasAttachmentProgram(state, "packet_observer:tc_pre_forward")
	if metricAttachment.Metrics == nil || metricAttachment.Metrics.Total.Packets < packetsBeforeFailedUpdate {
		t.Fatalf("plugin metrics after failed chain update = %+v, want previous generation counters preserved", metricAttachment.Metrics)
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

func TestKernelPluginPipelineRuntimePreservesDeclaredMapAcrossObjectUpgrade(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline map upgrade test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	copyDirForTest(t, filepath.Join(findRepoRoot(t), "plugins", "include"), filepath.Join(pluginsRoot, "include"))
	pluginDir := filepath.Join(pluginsRoot, "stateful_map")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(pluginDir, "stateful_map.bpf.c")
	objectPath := filepath.Join(pluginDir, "stateful_map.o")
	writeStatefulPipelinePluginForTest(t, pluginDir, pluginObjectMapPreserve, 1)
	writeStatefulPipelineBPFForTest(t, sourcePath, 1)
	compileBPFObjectFromSource(t, sourcePath, objectPath)

	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	})
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
	}
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("initial reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	oldRef := kernelPluginPipelineObjectRefForTest(t, rt, "stateful_map", "dataplane")
	oldHash := oldRef.ObjectSHA256
	oldMap := oldRef.coll.Maps["sessions"]
	key := uint32(7)
	want := uint64(0x1122334455667788)
	if err := oldMap.Put(key, want); err != nil {
		t.Fatalf("seed old session map: %v", err)
	}

	writeStatefulPipelineBPFForTest(t, sourcePath, 2)
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("object upgrade reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	newRef := kernelPluginPipelineObjectRefForTest(t, rt, "stateful_map", "dataplane")
	if newRef.ObjectSHA256 == oldHash {
		t.Fatalf("object hash did not change across compiled program upgrade: %s", oldHash)
	}
	var got uint64
	if err := newRef.coll.Maps["sessions"].Lookup(key, &got); err != nil || got != want {
		t.Fatalf("state after object upgrade = %#x, error = %v, want %#x", got, err, want)
	}

	writeStatefulPipelinePluginForTest(t, pluginDir, pluginObjectMapPreserve, 2)
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("incompatible schema reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	state, ok := rt.PluginSnapshot().stateFor("stateful_map")
	if !ok || state.Error == "" || !strings.Contains(state.Reason, "previous chain preserved") {
		t.Fatalf("state after incompatible schema = %+v, want retained chain error", state)
	}
	retained := kernelPluginPipelineObjectRefForTest(t, rt, "stateful_map", "dataplane")
	got = 0
	if err := retained.coll.Maps["sessions"].Lookup(key, &got); err != nil || got != want {
		t.Fatalf("state after rejected schema upgrade = %#x, error = %v, want %#x", got, err, want)
	}

	writeStatefulPipelinePluginForTest(t, pluginDir, pluginObjectMapReset, 0)
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("explicit reset reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	resetRef := kernelPluginPipelineObjectRefForTest(t, rt, "stateful_map", "dataplane")
	got = 0
	if err := resetRef.coll.Maps["sessions"].Lookup(key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("state map lookup after explicit reset = %#x, error = %v, want missing key", got, err)
	}
}

func TestKernelPluginPipelineRuntimeMigratesStateMapAndRollsBackToPreservedSource(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline map migration test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	copyDirForTest(t, filepath.Join(findRepoRoot(t), "plugins", "include"), filepath.Join(pluginsRoot, "include"))
	pluginDir := filepath.Join(pluginsRoot, "migrating_map")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(pluginDir, "migrating_map.bpf.c")
	objectPath := filepath.Join(pluginDir, "migrating_map.o")
	writeMigratingPipelinePluginForTest(t, pluginDir, 1)
	writeMigratingPipelineBPFForTest(t, sourcePath, 1)
	compileBPFObjectFromSource(t, sourcePath, objectPath)

	enabled := true
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	})
	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)
	rt := newTCKernelRuleRuntime(cfg)
	defer rt.Close()
	rule := Rule{
		ID: 1, InInterface: topology.ClientHostIF, InIP: dataplanePerfFrontAddr, InPort: dataplanePerfFrontPort,
		OutInterface: topology.BackendHostIF, OutIP: dataplanePerfBackendAddr, OutPort: dataplanePerfBackendPort,
		Protocol: "tcp", Transparent: true, Enabled: true, EnginePreference: ruleEngineKernel,
	}
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("initial reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	v1Ref := kernelPluginPipelineObjectRefForTest(t, rt, "migrating_map", "dataplane")
	key := uint32(7)
	wantV1 := uint64(0x1122334455667788)
	if err := v1Ref.coll.Maps["sessions_v1"].Put(key, wantV1); err != nil {
		t.Fatalf("seed v1 session map: %v", err)
	}

	writeMigratingPipelinePluginForTest(t, pluginDir, 2)
	writeMigratingPipelineBPFForTest(t, sourcePath, 2)
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("migration candidate reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	v2Ref := kernelPluginPipelineObjectRefForTest(t, rt, "migrating_map", "dataplane")
	var gotV1 uint64
	if err := v2Ref.coll.Maps["sessions_v1"].Lookup(key, &gotV1); err != nil || gotV1 != wantV1 {
		t.Fatalf("preserved v1 state = %#x, error = %v, want %#x", gotV1, err, wantV1)
	}
	pending := rt.PendingPluginEBPFStateMigrations()
	if len(pending) != 1 || pending[0].SourceMap != "sessions_v1" || pending[0].TargetMap != "sessions_v2" {
		t.Fatalf("pending migrations = %+v", pending)
	}
	type sessionV2 struct {
		Value  uint64
		Marker uint64
	}
	wantV2 := sessionV2{Value: wantV1, Marker: 2}
	if err := v2Ref.coll.Maps["sessions_v2"].Put(key, wantV2); err != nil {
		t.Fatalf("write migrated v2 state: %v", err)
	}
	var gotV2 sessionV2
	if err := v2Ref.coll.Maps["sessions_v2"].Lookup(key, &gotV2); err != nil || gotV2 != wantV2 {
		t.Fatalf("migrated v2 state = %+v, error = %v, want %+v", gotV2, err, wantV2)
	}
	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfClientAddr {
		t.Fatalf("traffic through migration candidate observed source %q, want %q", observed, dataplanePerfClientAddr)
	}
	rt.CompletePluginEBPFStateMigrations(pending)
	if remaining := rt.PendingPluginEBPFStateMigrations(); len(remaining) != 0 {
		t.Fatalf("completed migration remains pending: %+v", remaining)
	}

	writeMigratingPipelinePluginForTest(t, pluginDir, 1)
	writeMigratingPipelineBPFForTest(t, sourcePath, 1)
	compileBPFObjectFromSource(t, sourcePath, objectPath)
	if results, err := rt.Reconcile([]Rule{rule}); err != nil || !results[rule.ID].Running {
		t.Fatalf("rollback reconcile result = %+v, error = %v", results[rule.ID], err)
	}
	rollbackRef := kernelPluginPipelineObjectRefForTest(t, rt, "migrating_map", "dataplane")
	gotV1 = 0
	if err := rollbackRef.coll.Maps["sessions_v1"].Lookup(key, &gotV1); err != nil || gotV1 != wantV1 {
		t.Fatalf("v1 state after rollback = %#x, error = %v, want %#x", gotV1, err, wantV1)
	}
	if rollbackRef.coll.Maps["sessions_v2"] != nil {
		t.Fatal("v2 candidate map remained loaded after rollback")
	}
	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfClientAddr {
		t.Fatalf("traffic after migration rollback observed source %q, want %q", observed, dataplanePerfClientAddr)
	}
}

func TestKernelPluginPipelineRuntimeIPv6PostApplyForwardsTraffic(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	pluginDir := filepath.Join(pluginsRoot, "post_apply_observer")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(post_apply_observer) error = %v", err)
	}
	writePostApplyObserverPluginForTest(t, pluginDir)
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "post_apply_observer.bpf.c"), filepath.Join(pluginDir, "post_apply_observer.o"))

	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)
	seedTCIPv6IntegrationNeighbors(t, topology)
	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}))
	defer rt.Close()

	rule := Rule{
		ID:               1,
		InInterface:      topology.ClientHostIF,
		InIP:             tcIPv6IntegrationFrontAddr,
		InPort:           tcIPv6IntegrationFrontPort,
		OutInterface:     topology.BackendHostIF,
		OutIP:            tcIPv6IntegrationBackendAddr,
		OutSourceIP:      tcIPv6IntegrationBackendHost,
		OutPort:          tcIPv6IntegrationBackendPort,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
		Remark:           "plugin-ipv6-post-apply",
		Tag:              "test",
	}
	ipv4Rule := Rule{
		ID:               2,
		InInterface:      topology.ClientHostIF,
		InIP:             dataplanePerfFrontAddr,
		InPort:           dataplanePerfFrontPort,
		OutInterface:     topology.BackendHostIF,
		OutIP:            dataplanePerfBackendAddr,
		OutSourceIP:      dataplanePerfBackendHost,
		OutPort:          dataplanePerfBackendPort,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
		Remark:           "plugin-ipv4-post-apply",
		Tag:              "test",
	}
	results, err := rt.Reconcile([]Rule{rule, ipv4Rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result = %+v, want running tc", result)
	}
	if result := results[ipv4Rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("IPv4 rule result = %+v, want running tc", result)
	}
	state, ok := rt.PluginSnapshot().stateFor("post_apply_observer")
	if !ok || !state.Attached || state.AttachmentCount != 2 {
		t.Fatalf("plugin state = %+v, want forward and reply post-apply attachments", state)
	}
	if attachment, ok := stateHasAttachmentProgram(state, "observer:tc_post_apply"); !ok || attachment.Stage != kernelPluginPipelineStagePostApply || attachment.ChainSlot != tcProgramChainIndexV4PluginApplyBase {
		t.Fatalf("plugin attachments = %+v, want post_apply slot %d", state.Attachments, tcProgramChainIndexV4PluginApplyBase)
	}
	if attachment, ok := stateHasAttachmentProgram(state, "observer:tc_reply_apply"); !ok || attachment.Stage != kernelPluginPipelineStageReplyApply || attachment.ChainSlot != tcProgramChainIndexV4PluginReplyApplyBase {
		t.Fatalf("plugin attachments = %+v, want post_reply_apply slot %d", state.Attachments, tcProgramChainIndexV4PluginReplyApplyBase)
	}

	if err := runTCIPv6IntegrationProbePorts(t, topology, "tcp", tcIPv6IntegrationFrontPort, tcIPv6IntegrationBackendPort); err != nil {
		t.Fatalf("IPv6 full-NAT traffic through post-apply plugin failed: %v", err)
	}
	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfBackendHost {
		t.Fatalf("IPv4 full-NAT backend observed source %q, want %q", observed, dataplanePerfBackendHost)
	}
	countMap, err := findPluginLoadedMap(rt.pluginPipelineLoaded, "post_apply_observer", "observer", "post_apply_counts")
	if err != nil {
		t.Fatalf("find post_apply_counts: %v", err)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("get possible CPUs: %v", err)
	}
	type postApplyCounts struct {
		IPv4ForwardRedirect uint64
		IPv6ForwardRedirect uint64
		IPv4ReplyRedirect   uint64
		IPv6ReplyRedirect   uint64
	}
	values := make([]postApplyCounts, possibleCPUs)
	if err := countMap.Lookup(uint32(0), &values); err != nil {
		t.Fatalf("read post_apply_counts: %v", err)
	}
	var ipv6ForwardRedirects uint64
	var ipv6ReplyRedirects uint64
	for _, value := range values {
		ipv6ForwardRedirects += value.IPv6ForwardRedirect
		ipv6ReplyRedirects += value.IPv6ReplyRedirect
	}
	var ipv4ForwardRedirects uint64
	var ipv4ReplyRedirects uint64
	for _, value := range values {
		ipv4ForwardRedirects += value.IPv4ForwardRedirect
		ipv4ReplyRedirects += value.IPv4ReplyRedirect
	}
	if ipv4ForwardRedirects == 0 || ipv4ReplyRedirects == 0 || ipv6ForwardRedirects == 0 || ipv6ReplyRedirects == 0 {
		t.Fatalf("post_apply_counts = %+v, want IPv4/IPv6 forward and reply redirect observations", values)
	}
	snapshot := rt.PluginSnapshot()
	state, ok = snapshot.stateFor("post_apply_observer")
	if !ok {
		t.Fatalf("plugin snapshot after traffic = %+v, want post_apply_observer", snapshot)
	}
	for _, program := range []string{"observer:tc_post_apply", "observer:tc_reply_apply"} {
		attachment, found := stateHasAttachmentProgram(state, program)
		if !found || attachment.Metrics == nil {
			t.Fatalf("attachment %s = %+v, want host metrics", program, attachment)
		}
		if attachment.Metrics.IPv4.Packets == 0 || attachment.Metrics.IPv6.Packets == 0 {
			t.Fatalf("attachment %s metrics = %+v, want IPv4 and IPv6 packets", program, attachment.Metrics)
		}
		if attachment.Metrics.IPv4.ContinuedPackets == 0 || attachment.Metrics.IPv6.ContinuedPackets == 0 {
			t.Fatalf("attachment %s metrics = %+v, want IPv4 and IPv6 continuation", program, attachment.Metrics)
		}
		if attachment.Metrics.Total.TailCallMisses != 0 || attachment.Metrics.Total.TerminalPackets != 0 {
			t.Fatalf("attachment %s metrics = %+v, want no misses or terminal packets", program, attachment.Metrics)
		}
	}
}

func TestKernelPluginPipelineRuntimePacketMetadataAcrossPluginsDualStack(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC packet metadata test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	pluginsRoot := t.TempDir()
	producerDir, consumerDir := writePacketMetadataPluginPairForTest(t, pluginsRoot)
	compileBPFObjectFromSource(t, filepath.Join(producerDir, "metadata_producer.bpf.c"), filepath.Join(producerDir, "metadata_producer.o"))
	compileBPFObjectFromSource(t, filepath.Join(consumerDir, "metadata_consumer.bpf.c"), filepath.Join(consumerDir, "metadata_consumer.o"))

	topology := setupDataplanePerfTopology(t)
	seedDataplanePerfNeighbors(t, topology)
	seedTCIPv6IntegrationNeighbors(t, topology)
	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot,
	}))
	defer rt.Close()

	ipv4Rule := Rule{
		ID: 1, InInterface: topology.ClientHostIF, InIP: dataplanePerfFrontAddr, InPort: dataplanePerfFrontPort,
		OutInterface: topology.BackendHostIF, OutIP: dataplanePerfBackendAddr, OutSourceIP: dataplanePerfBackendHost,
		OutPort: dataplanePerfBackendPort, Protocol: "tcp", Enabled: true, EnginePreference: ruleEngineKernel,
		Remark: "plugin-metadata-v4", Tag: "test",
	}
	ipv6Rule := Rule{
		ID: 2, InInterface: topology.ClientHostIF, InIP: tcIPv6IntegrationFrontAddr, InPort: tcIPv6IntegrationFrontPort,
		OutInterface: topology.BackendHostIF, OutIP: tcIPv6IntegrationBackendAddr, OutSourceIP: tcIPv6IntegrationBackendHost,
		OutPort: tcIPv6IntegrationBackendPort, Protocol: "tcp", Enabled: true, EnginePreference: ruleEngineKernel,
		Remark: "plugin-metadata-v6", Tag: "test",
	}
	results, err := rt.Reconcile([]Rule{ipv4Rule, ipv6Rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for _, rule := range []Rule{ipv4Rule, ipv6Rule} {
		if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
			t.Fatalf("rule %d result = %+v, want running tc", rule.ID, result)
		}
	}

	producerState, producerOK := rt.PluginSnapshot().stateFor("metadata_producer")
	consumerState, consumerOK := rt.PluginSnapshot().stateFor("metadata_consumer")
	if !producerOK || !consumerOK || !producerState.Attached || !consumerState.Attached {
		t.Fatalf("plugin states producer=%+v consumer=%+v", producerState, consumerState)
	}
	producerAttachment, producerAttached := stateHasAttachmentProgram(producerState, "producer:tc_produce")
	consumerAttachment, consumerAttached := stateHasAttachmentProgram(consumerState, "consumer:tc_consume")
	if !producerAttached || !consumerAttached || producerAttachment.ChainSlot != tcProgramChainIndexV4PluginBase || consumerAttachment.ChainSlot != tcProgramChainIndexV4PluginBase+1 {
		t.Fatalf("metadata attachment order producer=%+v consumer=%+v", producerAttachment, consumerAttachment)
	}

	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardMetadataMask != 0x3 {
		t.Fatalf("pre-forward metadata mask = %#x, want %#x", config.PreForwardMetadataMask, uint32(0x3))
	}

	producerRef := kernelPluginPipelineObjectRefForTest(t, rt, "metadata_producer", "producer")
	consumerRef := kernelPluginPipelineObjectRefForTest(t, rt, "metadata_consumer", "consumer")
	for name, check := range map[string]struct {
		ref    loadedPluginObjectRef
		access uint8
	}{
		"producer": {ref: producerRef, access: kernelPluginPacketMetadataAccessRead | kernelPluginPacketMetadataAccessWrite},
		"consumer": {ref: consumerRef, access: kernelPluginPacketMetadataAccessRead},
	} {
		bindingMap := check.ref.coll.Maps[kernelTCPacketMetadataBindingsMapName]
		var binding kernelTCPluginMetadataBindingV1
		if bindingMap == nil || bindingMap.Lookup(uint32(0), &binding) != nil {
			t.Fatalf("%s metadata binding map is unavailable", name)
		}
		if binding.NamespaceSlot != 0 || binding.SchemaVersion != 2 || binding.MaxBytes != 8 || binding.Access != check.access {
			t.Fatalf("%s metadata binding = %+v", name, binding)
		}
	}

	if observed := runXDPFullNATIntegrationProbe(t, topology, "tcp", dataplanePerfFrontPort, dataplanePerfBackendPort); observed != dataplanePerfBackendHost {
		t.Fatalf("IPv4 metadata pipeline observed source %q, want %q", observed, dataplanePerfBackendHost)
	}
	if err := runTCIPv6IntegrationProbePorts(t, topology, "tcp", tcIPv6IntegrationFrontPort, tcIPv6IntegrationBackendPort); err != nil {
		t.Fatalf("IPv6 metadata pipeline traffic failed: %v", err)
	}

	countMap := consumerRef.coll.Maps["metadata_observed"]
	if countMap == nil {
		t.Fatal("consumer metadata_observed map is unavailable")
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("get possible CPUs: %v", err)
	}
	type metadataObserved struct {
		IPv4    uint64
		IPv6    uint64
		Invalid uint64
	}
	values := make([]metadataObserved, possibleCPUs)
	if err := countMap.Lookup(uint32(0), &values); err != nil {
		t.Fatalf("read metadata_observed: %v", err)
	}
	var total metadataObserved
	for _, value := range values {
		total.IPv4 += value.IPv4
		total.IPv6 += value.IPv6
		total.Invalid += value.Invalid
	}
	if total.IPv4 == 0 || total.IPv6 == 0 {
		t.Fatalf("metadata observations = %+v, want IPv4 and IPv6 payloads", total)
	}
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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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

	packetCount, err := findPluginLoadedMap(rt.pluginPipelineLoaded, "packet_observer", "packet_observer", "packet_count")
	if err != nil {
		t.Fatalf("find packet_count before core enable: %v", err)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("get possible CPUs: %v", err)
	}
	wantCounts := make([]uint64, possibleCPUs)
	for cpu := range wantCounts {
		wantCounts[cpu] = (uint64(1) << 48) + uint64(cpu+101)
	}
	if err := packetCount.Put(uint32(0), wantCounts); err != nil {
		t.Fatalf("seed packet_count before core enable: %v", err)
	}

	seedDataplanePerfNeighbors(t, topology)
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
	}
	results, err = rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile(core enable) error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Engine != kernelEngineTC || result.Error != "" {
		t.Fatalf("rule result after core enable = %+v, want running tc", result)
	}
	packetCount, err = findPluginLoadedMap(rt.pluginPipelineLoaded, "packet_observer", "packet_observer", "packet_count")
	if err != nil {
		t.Fatalf("find packet_count after core enable: %v", err)
	}
	var gotCounts []uint64
	if err := packetCount.Lookup(uint32(0), &gotCounts); err != nil {
		t.Fatalf("read packet_count after core enable: %v", err)
	}
	if len(gotCounts) != len(wantCounts) {
		t.Fatalf("packet_count CPU values = %d, want %d", len(gotCounts), len(wantCounts))
	}
	for cpu := range wantCounts {
		if gotCounts[cpu] < wantCounts[cpu] {
			t.Fatalf("packet_count CPU %d = %d, want at least preserved sentinel %d", cpu, gotCounts[cpu], wantCounts[cpu])
		}
	}
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config after core enable: %v", err)
	}
	if config.ForwardCoreEnable != 1 || config.ReplyCoreEnable != 1 {
		t.Fatalf("plugin config after core enable = %+v, want forward/reply core enabled", config)
	}
}

func TestKernelPluginPipelineRuntimeAttachesExplicitEgressInterfaceWithoutRules(t *testing.T) {
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
	setControlScriptAttachForPipelineTest(t, pluginDir, "egress")
	compileBPFObjectFromSource(t, filepath.Join(pluginDir, "packet_observer.bpf.c"), filepath.Join(pluginDir, "packet_observer.o"))

	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot}))
	defer rt.Close()

	if _, err := rt.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	}
	if len(rt.attachments) != 2 || rt.attachments[0].filter == nil || rt.attachments[1].filter == nil {
		t.Fatalf("attachments = %+v, want IPv4 and IPv6 egress filters", rt.attachments)
	}
	wantNames := map[string]bool{
		kernelForwardEgressPipelineProgramName:   false,
		kernelForwardEgressPipelineProgramNameV6: false,
	}
	for _, attachment := range rt.attachments {
		filter := attachment.filter
		if filter.Parent != netlink.HANDLE_MIN_EGRESS {
			t.Fatalf("filter parent = %#x, want HANDLE_MIN_EGRESS %#x", filter.Parent, uint32(netlink.HANDLE_MIN_EGRESS))
		}
		if _, ok := wantNames[filter.Name]; !ok {
			t.Fatalf("unexpected egress filter name %q", filter.Name)
		}
		wantNames[filter.Name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("missing egress filter %q", name)
		}
	}
	link, err := netlink.LinkByName(topology.ClientHostIF)
	if err != nil {
		t.Fatalf("LinkByName(%s) error = %v", topology.ClientHostIF, err)
	}
	if _, ok := rt.attachmentRuleSets.ForwardEgress[link.Attrs().Index]; !ok {
		t.Fatalf("attachmentRuleSets = %+v, want egress ifindex %d", rt.attachmentRuleSets, link.Attrs().Index)
	}
	if len(rt.attachmentRuleSets.ForwardIngress) != 0 || len(rt.attachmentRuleSets.ReplyIngress) != 0 || len(rt.attachmentRuleSets.ReplyEgress) != 0 {
		t.Fatalf("attachmentRuleSets = %+v, egress plugin must not add other directions", rt.attachmentRuleSets)
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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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
	for bank := uint32(0); bank < 2; bank++ {
		for _, stage := range []struct {
			name  string
			count int
		}{
			{name: kernelPluginPipelineStagePreForward, count: tcProgramChainV4PluginPreForwardMax},
			{name: kernelPluginPipelineStagePostLookup, count: tcProgramChainV4PluginPostLookupMax},
			{name: kernelPluginPipelineStagePreReply, count: tcProgramChainV4PluginPreReplyMax},
			{name: kernelPluginPipelineStagePostReply, count: tcProgramChainV4PluginPostReplyMax},
		} {
			base, _ := kernelPluginPipelineBankStageBase(bank, stage.name)
			for i := 0; i < stage.count; i++ {
				assertMissing(base + i)
			}
		}
	}
	iterator := pieces.pluginInterfacesV4.Iterate()
	var key kernelTCPluginInterfaceKeyV4
	var value kernelTCPluginInterfaceValueV4
	if iterator.Next(&key, &value) {
		t.Fatalf("tc plugin interface map still contains key=%+v value=%+v", key, value)
	}
	if err := iterator.Err(); err != nil {
		t.Fatalf("iterate tc plugin interface map: %v", err)
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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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

func TestKernelPluginPipelineRuntimeScopesHooksPerInterface(t *testing.T) {
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
		t.Fatalf("client baseline ping failed: %v\n%s", err, output)
	}
	if output, err := runDataplanePerfPing(topology.BackendNS, dataplanePerfBackendHost); err != nil {
		t.Fatalf("backend baseline ping failed: %v\n%s", err, output)
	}

	pluginsRoot := t.TempDir()
	observerDir := copyPacketObserverPluginForPipelineTest(t, pluginsRoot)
	setControlScriptInterfacesForPipelineTest(t, observerDir, topology.BackendHostIF)
	compileBPFObjectFromSource(t, filepath.Join(observerDir, "packet_observer.bpf.c"), filepath.Join(observerDir, "packet_observer.o"))
	dropDir := filepath.Join(pluginsRoot, "drop_core")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(drop_core) error = %v", err)
	}
	writeDropCorePluginForTest(t, dropDir, topology.ClientHostIF)
	compileBPFObjectFromSource(t, filepath.Join(dropDir, "drop_core.bpf.c"), filepath.Join(dropDir, "drop_core.o"))

	enabled := true
	rt := newTCKernelRuleRuntime(pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot}))
	defer rt.Close()
	if results, err := rt.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	} else if len(results) != 0 {
		t.Fatalf("results = %+v, want no rule results", results)
	}
	if len(rt.attachments) != 4 {
		t.Fatalf("attachments = %d, want dual-stack filters on both scoped interfaces", len(rt.attachments))
	}
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	var config kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &config); err != nil {
		t.Fatalf("lookup plugin config: %v", err)
	}
	if config.PreForwardGlobalMask != 0 {
		t.Fatalf("pre-forward global mask = %#x, want only scoped hooks", config.PreForwardGlobalMask)
	}
	lookupMask := func(ifindex int) kernelTCPluginInterfaceValueV4 {
		t.Helper()
		key := kernelTCPluginInterfaceKeyV4{IfIndex: uint32(ifindex), Bank: config.ActiveBank}
		var value kernelTCPluginInterfaceValueV4
		if err := pieces.pluginInterfacesV4.Lookup(key, &value); err != nil {
			t.Fatalf("lookup interface mask %+v: %v", key, err)
		}
		return value
	}
	clientInterface, err := net.InterfaceByName(topology.ClientHostIF)
	if err != nil {
		t.Fatalf("resolve client host interface: %v", err)
	}
	backendInterface, err := net.InterfaceByName(topology.BackendHostIF)
	if err != nil {
		t.Fatalf("resolve backend host interface: %v", err)
	}
	clientMask := lookupMask(clientInterface.Index).PreForwardMask
	backendMask := lookupMask(backendInterface.Index).PreForwardMask
	if clientMask == 0 || backendMask == 0 || clientMask&backendMask != 0 {
		t.Fatalf("scoped pre-forward masks client=%#x backend=%#x, want distinct non-zero slots", clientMask, backendMask)
	}

	if output, err := runDataplanePerfPing(topology.ClientNS, dataplanePerfFrontAddr); err == nil {
		t.Fatalf("client ping succeeded with client-scoped drop hook\n%s", output)
	}
	if output, err := runDataplanePerfPing(topology.BackendNS, dataplanePerfBackendHost); err != nil {
		t.Fatalf("backend ping was affected by client-scoped drop hook: %v\n%s", err, output)
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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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
	cfg := pluginsEnabledTestConfig(&Config{
		PluginsEnabledSetting:   &enabled,
		PluginsDataplaneSetting: &enabled,
		PluginsDir:              pluginsRoot})

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

func TestKernelPluginPipelineRuntimePersistsReplyFlowSnapshotState(t *testing.T) {
	if os.Getenv(kernelPluginPipelineTestEnv) != "1" {
		t.Skipf("set %s=1 to run the privileged TC plugin pipeline smoke test", kernelPluginPipelineTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	for _, tc := range []struct {
		name        string
		transparent bool
	}{
		{name: "transparent", transparent: true},
		{name: "full-nat", transparent: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pluginsRoot := t.TempDir()
			pluginDir := filepath.Join(pluginsRoot, "reply_observer")
			if err := os.MkdirAll(pluginDir, 0o755); err != nil {
				t.Fatalf("MkdirAll(reply_observer) error = %v", err)
			}
			writePostReplyPluginForTest(t, pluginDir)
			compileBPFObjectFromSource(t, filepath.Join(pluginDir, "reply_observer.bpf.c"), filepath.Join(pluginDir, "reply_observer.o"))

			enabled := true
			cfg := pluginsEnabledTestConfig(&Config{
				PluginsEnabledSetting:   &enabled,
				PluginsDataplaneSetting: &enabled,
				PluginsDir:              pluginsRoot})

			topology := setupDataplanePerfTopology(t)
			seedDataplanePerfNeighbors(t, topology)
			backendCmd, backendLogs := startDataplanePerfBackend(t, topology)
			defer stopDataplanePerfHelper(t, backendCmd)

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
				Transparent:      tc.transparent,
				Enabled:          true,
				EnginePreference: ruleEngineKernel,
				Remark:           "plugin-reply-flow-state",
				Tag:              "test",
			}
			if !tc.transparent {
				rule.OutSourceIP = dataplanePerfBackendHost
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

			pieces, err := lookupKernelCollectionPieces(rt.coll)
			if err != nil {
				t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
			}
			statsMap := rt.coll.Maps[kernelStatsMapName]
			if pieces.flowsV4 == nil || statsMap == nil {
				t.Fatalf("runtime maps are incomplete: flows=%v stats=%v", pieces.flowsV4, statsMap)
			}

			type clientResult struct {
				result dataplanePerfClientResult
				err    error
			}
			clientCh := make(chan clientResult, 1)
			go func() {
				result, err := runDataplanePerfClientBenchmarkRaw(topology.ClientNS, 1, 1, 16<<10, 4<<10, 6)
				clientCh <- clientResult{result: result, err: err}
			}()

			fullNAT := !tc.transparent
			flowKey, flowValue, assertionErr := waitForKernelPluginReplyFlowV4(
				pieces.flowsV4,
				uint32(rule.ID),
				fullNAT,
				2*time.Second,
				func(value tcFlowValueV4) bool {
					return value.Flags&kernelFlowFlagReplySeen != 0 &&
						value.Flags&kernelFlowFlagCounted != 0 &&
						value.LastSeenNS != 0
				},
			)
			if assertionErr == nil {
				stats, found, lookupErr := lookupKernelStatsValue(statsMap, uint32(rule.ID))
				if lookupErr != nil {
					assertionErr = lookupErr
				} else if !found || stats.TCPActiveConns != 1 {
					assertionErr = fmt.Errorf("initial TCPActiveConns = %d (found=%t), want 1", stats.TCPActiveConns, found)
				}
			}

			initialLastSeen := flowValue.LastSeenNS
			if assertionErr == nil {
				flowValue.LastSeenNS = 0
				if err := pieces.flowsV4.Put(flowKey, flowValue); err != nil {
					assertionErr = fmt.Errorf("clear reply flow last_seen_ns: %w", err)
				}
			}
			if assertionErr == nil {
				_, refreshed, waitErr := waitForKernelPluginReplyFlowV4(
					pieces.flowsV4,
					uint32(rule.ID),
					fullNAT,
					2*time.Second,
					func(value tcFlowValueV4) bool {
						return value.Flags&kernelFlowFlagReplySeen != 0 && value.LastSeenNS > initialLastSeen
					},
				)
				if waitErr != nil {
					assertionErr = fmt.Errorf("reply flow did not refresh after another packet: %w", waitErr)
				} else if refreshed.LastSeenNS == 0 {
					assertionErr = errors.New("reply flow last_seen_ns remained zero")
				}
			}
			if assertionErr == nil {
				time.Sleep(250 * time.Millisecond)
				stats, found, lookupErr := lookupKernelStatsValue(statsMap, uint32(rule.ID))
				if lookupErr != nil {
					assertionErr = lookupErr
				} else if !found || stats.TCPActiveConns != 1 {
					assertionErr = fmt.Errorf("TCPActiveConns after repeated replies = %d (found=%t), want 1", stats.TCPActiveConns, found)
				}
			}

			client := <-clientCh
			if client.err != nil {
				t.Fatalf("steady TCP client failed: %v\nbackend logs:\n%s", client.err, backendLogs.String())
			}
			if client.result.PayloadBytes <= 0 {
				t.Fatalf("steady TCP client transferred no payload: %+v", client.result)
			}
			if assertionErr != nil {
				t.Fatalf("reply flow state assertion failed: %v\nbackend logs:\n%s", assertionErr, backendLogs.String())
			}
		})
	}
}

func waitForKernelPluginReplyFlowV4(flows *ebpf.Map, ruleID uint32, fullNAT bool, timeout time.Duration, accept func(tcFlowValueV4) bool) (tcFlowKeyV4, tcFlowValueV4, error) {
	deadline := time.Now().Add(timeout)
	var lastKey tcFlowKeyV4
	var lastValue tcFlowValueV4
	var found bool
	for {
		iter := flows.Iterate()
		var key tcFlowKeyV4
		var value tcFlowValueV4
		for iter.Next(&key, &value) {
			if value.RuleID != ruleID || value.Flags&kernelFlowFlagFrontEntry != 0 {
				continue
			}
			if (value.Flags&kernelFlowFlagFullNAT != 0) != fullNAT {
				continue
			}
			lastKey = key
			lastValue = value
			found = true
			if accept == nil || accept(value) {
				return key, value, nil
			}
		}
		if err := iter.Err(); err != nil {
			return tcFlowKeyV4{}, tcFlowValueV4{}, fmt.Errorf("iterate reply flows: %w", err)
		}
		if !time.Now().Before(deadline) {
			if found {
				return lastKey, lastValue, fmt.Errorf("timed out waiting for reply flow state: key=%+v value=%+v", lastKey, lastValue)
			}
			return tcFlowKeyV4{}, tcFlowValueV4{}, fmt.Errorf("timed out waiting for reply flow for rule %d", ruleID)
		}
		time.Sleep(10 * time.Millisecond)
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

func setControlScriptAttachForPipelineTest(t *testing.T, pluginDir string, attach string) {
	t.Helper()

	controlPath := filepath.Join(pluginDir, "control.js")
	data, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatalf("ReadFile(control.js) error = %v", err)
	}
	needle := "  direction: 'forward',\n"
	replacement := needle + fmt.Sprintf("  attach: %q,\n", attach)
	updated := strings.Replace(string(data), needle, replacement, 1)
	if updated == string(data) {
		t.Fatal("control.js does not contain a forward pipeline direction")
	}
	if err := os.WriteFile(controlPath, []byte(updated), 0o644); err != nil {
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

func writeStatefulPipelinePluginForTest(t *testing.T, pluginDir string, policy string, schemaVersion int) {
	t.Helper()
	stateContract := fmt.Sprintf(`{name: 'sessions', policy: %q}`, policy)
	if policy == pluginObjectMapPreserve {
		stateContract = fmt.Sprintf(`{name: 'sessions', policy: %q, schema_version: %d}`, policy, schemaVersion)
	}
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "stateful_map", "Stateful Map", fmt.Sprintf(`
plugin.capabilities(['stateful', 'tc']);
ebpf.loadObject({
  id: 'dataplane',
  path: 'stateful_map.o',
  state_maps: [%s],
  programs: [{id: 'tc_stateful', section: 'tc/veer/pre_forward', type: 'tc'}]
});
pipeline.attach({
  id: 'stateful-ingress',
  direction: 'forward',
  priority: 10,
  program: 'dataplane:tc_stateful',
  mode: 'observe',
  interfaces: []
});
`, stateContract))
}

func writeStatefulPipelineBPFForTest(t *testing.T, sourcePath string, increment int) {
	t.Helper()
	source := fmt.Sprintf(`#include "../include/veer_plugin_helpers.h"

#define BPF_MAP_TYPE_HASH 1

struct __sk_buff;

struct bpf_map_def SEC("maps") sessions = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 16,
};

VEER_DECLARE_PROG_CHAIN_V4();

SEC("tc/veer/pre_forward")
int tc_stateful(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *value = veer_bpf_map_lookup_elem(&sessions, &key);
	if (value)
		*value += %d;
	veer_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`, increment)
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write stateful BPF source: %v", err)
	}
}

func writeMigratingPipelinePluginForTest(t *testing.T, pluginDir string, version int) {
	t.Helper()
	stateMaps := `[{name:'sessions_v1', policy:'preserve', schema_version:1}]`
	if version == 2 {
		stateMaps = `[
  {name:'sessions_v1', policy:'preserve', schema_version:1},
  {name:'sessions_v2', policy:'migrate', schema_version:2, migrate_from:'sessions_v1'}
]`
	}
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "migrating_map", "Migrating Map", fmt.Sprintf(`
plugin.capabilities(['stateful', 'tc']);
ebpf.loadObject({
  id:'dataplane', path:'migrating_map.o', state_maps:%s,
  programs:[{id:'tc_stateful', section:'tc/veer/pre_forward', type:'tc'}]
});
pipeline.attach({
  id:'stateful-ingress', direction:'forward', priority:10,
  program:'dataplane:tc_stateful', mode:'observe', interfaces:[]
});
exports.onReconcile = function () {};
`, stateMaps))
}

func writeMigratingPipelineBPFForTest(t *testing.T, sourcePath string, version int) {
	t.Helper()
	v2Map := ""
	v2Logic := ""
	if version == 2 {
		v2Map = `
struct session_v2 { __u64 value; __u64 marker; };
struct bpf_map_def SEC("maps") sessions_v2 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct session_v2),
	.max_entries = 16,
};
`
		v2Logic = `
	struct session_v2 *next = veer_bpf_map_lookup_elem(&sessions_v2, &key);
	if (next && current) {
		next->value += 1;
		*current = next->value;
	} else if (current) {
		*current += 1;
	}
`
	} else {
		v2Logic = `
	if (current)
		*current += 1;
`
	}
	source := fmt.Sprintf(`#include "../include/veer_plugin_helpers.h"

#define BPF_MAP_TYPE_HASH 1

struct __sk_buff;

struct bpf_map_def SEC("maps") sessions_v1 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 16,
};
%s
VEER_DECLARE_PROG_CHAIN_V4();

SEC("tc/veer/pre_forward")
int tc_stateful(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *current = veer_bpf_map_lookup_elem(&sessions_v1, &key);
%s
	veer_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`, v2Map, v2Logic)
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write migrating BPF source: %v", err)
	}
}

func kernelPluginPipelineObjectRefForTest(t *testing.T, rt *linuxKernelRuleRuntime, pluginID, objectID string) loadedPluginObjectRef {
	t.Helper()
	for _, ref := range rt.pluginPipelineLoaded {
		if ref.PluginID == pluginID && ref.ObjectID == objectID && ref.coll != nil {
			return ref
		}
	}
	t.Fatalf("loaded plugin object %s/%s not found: %+v", pluginID, objectID, rt.pluginPipelineLoaded)
	return loadedPluginObjectRef{}
}

func writeDropCorePluginForTest(t *testing.T, pluginDir string, ifName string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "drop_core", "Drop Core", fmt.Sprintf(`plugin.capabilities(['drop', 'tc']);
ebpf.loadObject({
  id: 'drop',
  path: 'drop_core.o',
  programs: [{id: 'tc_drop', section: 'tc/veer/pre_forward', type: 'tc'}]
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
	.max_entries = 111,
};

SEC("tc/veer/pre_forward")
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
  programs: [{id: 'tc_redirect', section: 'tc/veer/pre_forward', type: 'tc'}]
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
	.max_entries = 111,
};

static __inline int redirect_with_l2(struct __sk_buff *skb, __u32 ifindex, const unsigned char *dst, const unsigned char *src)
{
	if (bpf_skb_store_bytes(skb, 0, dst, 6, 0) < 0)
		return TC_ACT_UNSPEC;
	if (bpf_skb_store_bytes(skb, 6, src, 6, 0) < 0)
		return TC_ACT_UNSPEC;
	return bpf_redirect(ifindex, 0);
}

SEC("tc/veer/pre_forward")
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

func writePacketMetadataPluginPairForTest(t *testing.T, pluginsRoot string) (string, string) {
	t.Helper()
	producerDir := filepath.Join(pluginsRoot, "metadata_producer")
	consumerDir := filepath.Join(pluginsRoot, "metadata_consumer")
	header := filepath.Join(findRepoRoot(t), "plugins", "include", "veer_plugin_helpers.h")
	for _, dir := range []string{producerDir, consumerDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", dir, err)
		}
		copyFile(t, header, filepath.Join(dir, "veer_plugin_helpers.h"))
	}

	writeControlRegisteredPipelinePluginForTest(t, producerDir, "metadata_producer", "Metadata Producer", `
plugin.capabilities(['packet-metadata', 'tc']);
ebpf.loadObject({
  id: 'producer', path: 'metadata_producer.o',
  programs: [{id: 'tc_produce', section: 'tc/veer/pre_forward', type: 'tc'}]
});
hooks.attach({
  id: 'produce', engine: 'tc', attach: 'ingress', stage: 'pre_forward', priority: 20,
  program: 'producer:tc_produce', mode: 'rewrite',
  packet_metadata: [{slot: 0, namespace: 'metadata_producer/classification', schema_version: 2, max_bytes: 8, access: 'read_write'}]
});
`)
	writeControlRegisteredPipelinePluginForTest(t, consumerDir, "metadata_consumer", "Metadata Consumer", `
plugin.capabilities(['packet-metadata', 'tc']);
ebpf.loadObject({
  id: 'consumer', path: 'metadata_consumer.o',
  programs: [{id: 'tc_consume', section: 'tc/veer/pre_forward', type: 'tc'}]
});
hooks.attach({
  id: 'consume', engine: 'tc', attach: 'ingress', stage: 'pre_forward', priority: 10,
  after: ['metadata_producer/produce'], program: 'consumer:tc_consume', mode: 'observe',
  packet_metadata: [{slot: 0, namespace: 'metadata_producer/classification', schema_version: 2, max_bytes: 8, access: 'read'}]
});
`)

	const producerSource = `#include "veer_plugin_helpers.h"

#define METADATA_MAGIC 0x56454552

struct metadata_payload {
	__u32 magic;
	__u8 family;
	__u8 flags;
	__u16 reserved;
};

VEER_DECLARE_PROG_CHAIN_V4();
VEER_DECLARE_PACKET_METADATA();

SEC("tc/veer/pre_forward")
int tc_produce(struct __sk_buff *skb)
{
	struct veer_packet_metadata_value_v1 *metadata = veer_packet_metadata_write_begin_for_skb(skb, 0);
	struct metadata_payload *payload;

	if (metadata) {
		payload = (struct metadata_payload *)metadata->payload;
		payload->magic = METADATA_MAGIC;
		payload->family = (__u8)veer_packet_family(skb);
		payload->flags = 1;
		payload->reserved = 0;
		veer_packet_metadata_commit(metadata, sizeof(*payload));
	}
	veer_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	const consumerSource = `#include "veer_plugin_helpers.h"

#define METADATA_MAGIC 0x56454552

struct metadata_payload {
	__u32 magic;
	__u8 family;
	__u8 flags;
	__u16 reserved;
};

struct metadata_observed {
	__u64 ipv4;
	__u64 ipv6;
	__u64 invalid;
};

VEER_DECLARE_PROG_CHAIN_V4();
VEER_DECLARE_PACKET_METADATA();

struct bpf_map_def SEC("maps") metadata_observed = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct metadata_observed),
	.max_entries = 1,
};

SEC("tc/veer/pre_forward")
int tc_consume(struct __sk_buff *skb)
{
	__u32 key = 0;
	int family = veer_packet_family(skb);
	struct metadata_observed *observed = veer_bpf_map_lookup_elem(&metadata_observed, &key);
	struct veer_packet_metadata_value_v1 *metadata = veer_packet_metadata_read_for_skb(skb, 0);
	struct metadata_payload *payload = metadata ? (struct metadata_payload *)metadata->payload : 0;

	if (observed) {
		if (!metadata || metadata->payload_len != sizeof(*payload) || payload->magic != METADATA_MAGIC || payload->family != family || payload->flags != 1)
			observed->invalid++;
		else if (family == VEER_PACKET_FAMILY_IPV4)
			observed->ipv4++;
		else if (family == VEER_PACKET_FAMILY_IPV6)
			observed->ipv6++;
		else
			observed->invalid++;
	}
	veer_continue_pre_forward(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(filepath.Join(producerDir, "metadata_producer.bpf.c"), []byte(producerSource), 0o644); err != nil {
		t.Fatalf("write metadata producer source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(consumerDir, "metadata_consumer.bpf.c"), []byte(consumerSource), 0o644); err != nil {
		t.Fatalf("write metadata consumer source: %v", err)
	}
	return producerDir, consumerDir
}

func writePostApplyObserverPluginForTest(t *testing.T, pluginDir string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "post_apply_observer", "Post Apply Observer", `plugin.capabilities(['observe', 'tc']);
ebpf.loadObject({
  id: 'observer',
  path: 'post_apply_observer.o',
  programs: [
    {id: 'tc_post_apply', section: 'tc/veer/post_apply', type: 'tc'},
    {id: 'tc_reply_apply', section: 'tc/veer/post_reply_apply', type: 'tc'}
  ]
});
pipeline.attach({
  id: 'after-forward-apply',
  direction: 'forward',
  phase: 'after_apply',
  priority: 10,
  program: 'observer:tc_post_apply',
  mode: 'observe'
});
pipeline.attach({
  id: 'after-reply-apply',
  direction: 'reply',
  phase: 'after_apply',
  priority: 10,
  program: 'observer:tc_reply_apply',
  mode: 'observe'
});
`)
	repoRoot := findRepoRoot(t)
	copyFile(t, filepath.Join(repoRoot, "plugins", "include", "veer_plugin_helpers.h"), filepath.Join(pluginDir, "veer_plugin_helpers.h"))
	const source = `#include "veer_plugin_helpers.h"

struct post_apply_counts {
	__u64 ipv4_forward_redirect;
	__u64 ipv6_forward_redirect;
	__u64 ipv4_reply_redirect;
	__u64 ipv6_reply_redirect;
};

VEER_DECLARE_PROG_CHAIN_V4();
VEER_DECLARE_PLUGIN_CONTEXTS();

struct bpf_map_def SEC("maps") post_apply_counts = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct post_apply_counts),
	.max_entries = 1,
};

SEC("tc/veer/post_apply")
int tc_post_apply(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct post_apply_counts *counts = veer_bpf_map_lookup_elem(&post_apply_counts, &key);

	if (counts && veer_packet_family(skb) == VEER_PACKET_FAMILY_IPV6) {
		struct tc_plugin_ctx_v6 *ctx = veer_lookup_plugin_ctx_v6_for_skb(skb);
		if (ctx && ctx->have_rule && ctx->final_action == TC_ACT_REDIRECT)
			counts->ipv6_forward_redirect++;
	} else if (counts) {
		struct tc_plugin_ctx_v4 *ctx = veer_lookup_plugin_ctx_v4_for_skb(skb);
		if (ctx && ctx->have_rule && ctx->final_action == TC_ACT_REDIRECT)
			counts->ipv4_forward_redirect++;
	}
	veer_continue_post_apply(skb);
	return TC_ACT_UNSPEC;
}

SEC("tc/veer/post_reply_apply")
int tc_reply_apply(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct post_apply_counts *counts = veer_bpf_map_lookup_elem(&post_apply_counts, &key);

	if (counts && veer_packet_family(skb) == VEER_PACKET_FAMILY_IPV6) {
		struct tc_plugin_ctx_v6 *ctx = veer_lookup_plugin_ctx_v6_for_skb(skb);
		if (ctx && ctx->have_flow && ctx->final_action == TC_ACT_REDIRECT)
			counts->ipv6_reply_redirect++;
	} else if (counts) {
		struct tc_plugin_ctx_v4 *ctx = veer_lookup_plugin_ctx_v4_for_skb(skb);
		if (ctx && ctx->have_flow && ctx->final_action == TC_ACT_REDIRECT)
			counts->ipv4_reply_redirect++;
	}
	veer_continue_reply_apply(skb);
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
`
	if err := os.WriteFile(filepath.Join(pluginDir, "post_apply_observer.bpf.c"), []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile(post_apply_observer.bpf.c) error = %v", err)
	}
}

func writePostLookupPluginForTest(t *testing.T, pluginDir string, ifNames ...string) {
	t.Helper()
	writeControlRegisteredPipelinePluginForTest(t, pluginDir, "rule_observer", "Rule Observer", fmt.Sprintf(`plugin.capabilities(['observe', 'tc']);
ebpf.loadObject({
  id: 'observer',
  path: 'rule_observer.o',
  programs: [{id: 'tc_post_lookup', section: 'tc/veer/post_lookup', type: 'tc'}]
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
#define VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE 9

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
	int final_action;
};

struct tc_plugin_ctx_v6 {
	__u32 ifindex;
	__u32 rule_id;
	__u32 out_ifindex;
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
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u8 backend_addr[16];
	__u8 nat_addr[16];
	__u8 front_addr[16];
	__u8 client_addr[16];
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
	int final_action;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 111,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v6),
	.max_entries = 1,
};

SEC("tc/veer/post_lookup")
int tc_post_lookup(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct tc_plugin_ctx_v4 *ctx = bpf_map_lookup_elem(&tc_plugin_ctx_v4, &key);
	if (ctx && ctx->have_rule == 0)
		return TC_ACT_UNSPEC;
	bpf_tail_call(skb, &tc_prog_chain_v4, VEER_TC_PROG_V4_PLUGIN_POST_LOOKUP_CONTINUE);
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
  programs: [{id: 'tc_post_reply', section: 'tc/veer/post_reply', type: 'tc'}]
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
#define VEER_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE 28

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
	int final_action;
};

struct tc_plugin_ctx_v6 {
	__u32 ifindex;
	__u32 rule_id;
	__u32 out_ifindex;
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
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u8 backend_addr[16];
	__u8 nat_addr[16];
	__u8 front_addr[16];
	__u8 client_addr[16];
	__u16 front_port;
	__u16 client_port;
	__u16 nat_port;
	__u16 pad1;
	int final_action;
};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static void (*const bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *)BPF_FUNC_tail_call;

struct bpf_map_def SEC("maps") tc_prog_chain_v4 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 111,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v4 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v4),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tc_plugin_ctx_v6 = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_plugin_ctx_v6),
	.max_entries = 1,
};

SEC("tc/veer/post_reply")
int tc_post_reply(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct tc_plugin_ctx_v4 *ctx = bpf_map_lookup_elem(&tc_plugin_ctx_v4, &key);
	if (ctx && ctx->have_flow == 0)
		return TC_ACT_UNSPEC;
	bpf_tail_call(skb, &tc_prog_chain_v4, VEER_TC_PROG_V4_PLUGIN_POST_REPLY_CONTINUE);
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
