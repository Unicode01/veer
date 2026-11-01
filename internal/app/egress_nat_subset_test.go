package app

import (
	"reflect"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func egressNATSubsetFixture() ([]EgressNAT, egressNATInterfaceSnapshot) {
	return []EgressNAT{
			{ID: 1, ParentInterface: "vmbr0", OutInterface: "wan0", Protocol: "tcp+udp+icmp", NATType: egressNATTypeSymmetric, Enabled: true},
			{ID: 2, ParentInterface: "vmbr0", ChildInterface: "tap100", OutInterface: "wg0", Protocol: "tcp", NATType: egressNATTypeSymmetric, Enabled: true},
		}, newEgressNATInterfaceSnapshot([]InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100", Parent: "vmbr0", Kind: "tuntap"},
			{Name: "tap101", Parent: "vmbr0", Kind: "tuntap"},
			{Name: "wan0", Kind: "device"},
			{Name: "wg0", Kind: "wireguard"},
		}, nil)
}

func buildEgressNATSubsetTestCandidates(t *testing.T, items []EgressNAT, snapshot egressNATInterfaceSnapshot) ([]kernelCandidateRule, map[int64]ruleDataplanePlan) {
	t.Helper()
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{available: true, supported: true}, ruleEngineKernel)
	nextID := int64(1)
	return buildEgressNATKernelCandidatesWithSnapshot(items, planner, 0, 0, &nextID, snapshot)
}

func egressNATSubsetCandidateOwners(t *testing.T, candidates []kernelCandidateRule) map[string]int64 {
	t.Helper()
	out := make(map[string]int64)
	for _, candidate := range candidates {
		key := candidate.rule.InInterface + "/" + candidate.rule.Protocol
		if previous, exists := out[key]; exists {
			t.Fatalf("duplicate effective target %s: owners %d and %d", key, previous, candidate.owner.id)
		}
		out[key] = candidate.owner.id
	}
	return out
}

func TestEgressNATSubsetsSelectOneExitPerInterfaceAndProtocol(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	want := map[string]int64{"tap100/tcp": 2, "tap100/udp": 1, "tap100/icmp": 1, "tap101/tcp": 1, "tap101/udp": 1, "tap101/icmp": 1}
	for _, reversed := range []bool{false, true} {
		if reversed {
			items[0], items[1] = items[1], items[0]
		}
		candidates, plans := buildEgressNATSubsetTestCandidates(t, items, snapshot)
		if got := egressNATSubsetCandidateOwners(t, candidates); !reflect.DeepEqual(got, want) {
			t.Fatalf("reversed=%t owners = %v, want %v", reversed, got, want)
		}
		for _, candidate := range candidates {
			wantExit := "wan0"
			if candidate.owner.id == 2 {
				wantExit = "wg0"
			}
			if candidate.rule.OutInterface != wantExit {
				t.Fatalf("rule = %+v, want exit %s", candidate.rule, wantExit)
			}
		}
		for _, id := range []int64{1, 2} {
			if plans[id].EffectiveEngine != ruleEngineKernel || plans[id].FallbackReason != "" {
				t.Fatalf("owner %d plan = %+v", id, plans[id])
			}
		}
	}
}

func TestEgressNATSubsetsRestoreInheritanceAndIncludeNewChildren(t *testing.T) {
	t.Parallel()
	for _, remove := range []bool{false, true} {
		items, snapshot := egressNATSubsetFixture()
		if remove {
			items = items[:1]
		} else {
			items[1].Enabled = false
		}
		snapshot = newEgressNATInterfaceSnapshot(append(snapshot.Infos, InterfaceInfo{Name: "tap102", Parent: "vmbr0", Kind: "tuntap"}), nil)
		candidates, _ := buildEgressNATSubsetTestCandidates(t, items, snapshot)
		owners := egressNATSubsetCandidateOwners(t, candidates)
		if len(owners) != 9 {
			t.Fatalf("remove=%t owners = %v, want 3 children and 3 protocols", remove, owners)
		}
		for key, id := range owners {
			if id != 1 {
				t.Fatalf("remove=%t %s owner = %d, want default", remove, key, id)
			}
		}
	}
}

func TestEgressNATSubsetsReserveMissingChildAndNeverTakeOverAnotherBridge(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	items[1].Protocol = "tcp+udp+icmp"
	// A configured child on a different bridge is unavailable. It must not
	// suppress that bridge's default just because it has the same interface name.
	items[1].ParentInterface = "vmbr1"
	candidates, plans := buildEgressNATSubsetTestCandidates(t, items, snapshot)
	if len(candidates) != 6 || plans[2].FallbackReason == "" {
		t.Fatalf("reparented child: candidates=%+v plans=%+v", candidates, plans)
	}
	items[1].ParentInterface = "vmbr0"
	snapshot = newEgressNATInterfaceSnapshot([]InterfaceInfo{snapshot.Infos[0], snapshot.Infos[2], snapshot.Infos[3]}, nil)
	candidates, plans = buildEgressNATSubsetTestCandidates(t, items, snapshot)
	if len(candidates) != 3 || plans[2].FallbackReason == "" {
		t.Fatalf("missing child: candidates=%+v plans=%+v", candidates, plans)
	}
	for _, candidate := range candidates {
		if candidate.rule.InInterface != "tap101" || candidate.owner.id != 1 {
			t.Fatalf("unrelated child lost default: %+v", candidate)
		}
	}
}

type egressNATSubsetFailedExitRuntime struct{ stubKernelSupportRuntime }

func (rt egressNATSubsetFailedExitRuntime) SupportsRule(rule Rule) (bool, string) {
	if rule.OutInterface == "wg0" {
		return false, "selected exit is unavailable"
	}
	return true, ""
}

func TestEgressNATSubsetsDoNotFallBackWhenSelectedExitFails(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	planner := newRuleDataplanePlanner(egressNATSubsetFailedExitRuntime{stubKernelSupportRuntime{available: true}}, ruleEngineKernel)
	nextID := int64(1)
	candidates, plans := buildEgressNATKernelCandidatesWithSnapshot(items, planner, 0, 0, &nextID, snapshot)
	owners := egressNATSubsetCandidateOwners(t, candidates)
	if owners["tap100/tcp"] != 2 || len(owners) != 6 || plans[2].FallbackReason == "" {
		t.Fatalf("failed exit fell back: owners=%v plans=%+v", owners, plans)
	}
	for _, candidate := range candidates {
		if candidate.rule.kernelUnavailable != (candidate.owner.id == 2) {
			t.Fatalf("only the failed exit must be guarded: %+v", candidate)
		}
	}
}

func TestEgressNATSubsetsSurviveOwnerFilteringAndRejectStaleRetention(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	projected := compileEgressNATSubsets(items, snapshot)
	// The child owner is retained separately. Rebuilding only the parent must
	// still exclude the child's TCP rule.
	candidates, _ := buildEgressNATSubsetTestCandidates(t, projected[:1], snapshot)
	owners := egressNATSubsetCandidateOwners(t, candidates)
	if _, leaked := owners["tap100/tcp"]; leaked || len(owners) != 5 {
		t.Fatalf("filtered parent reclaimed selected exit: %v", owners)
	}
	rules := make([]Rule, 0, len(candidates))
	for _, candidate := range candidates {
		rules = append(rules, candidate.rule)
	}
	if !activeOwnerRulesMatchEgressNAT(rules, projected[0]) {
		t.Fatal("unchanged partial protocol subsets cannot be retained")
	}
	desired := buildEgressNATDesiredCandidateShapes(projected[0], snapshot)
	if got := egressNATSubsetCandidateOwners(t, desired); !reflect.DeepEqual(got, owners) {
		t.Fatalf("retention desired shape reclaimed overridden protocols: %v, want %v", got, owners)
	}
	rules = append(rules, buildEgressNATSyntheticRule(items[0], "tap100", 100, "tcp"))
	if activeOwnerRulesMatchEgressNAT(rules, projected[0]) {
		t.Fatal("stale parent rule retained the child's selected TCP exit")
	}
}

func TestEgressNATSubsetsKeepUnrelatedRuleIdentities(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	before, _ := buildEgressNATSubsetTestCandidates(t, items[:1], snapshot)
	previous := make([]Rule, 0, len(before))
	for _, candidate := range before {
		previous = append(previous, candidate.rule)
	}
	after, _ := buildEgressNATSubsetTestCandidates(t, items, snapshot)
	if err := stabilizeKernelCandidateRuleIDs(after, previous); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range after {
		if candidate.owner.id != 1 {
			continue
		}
		found := false
		for _, old := range previous {
			if old.InInterface == candidate.rule.InInterface && old.Protocol == candidate.rule.Protocol {
				found = true
				if old.ID != candidate.rule.ID {
					t.Fatalf("unrelated rule %s/%s changed ID: %d -> %d", old.InInterface, old.Protocol, old.ID, candidate.rule.ID)
				}
			}
		}
		if !found {
			t.Fatalf("unexpected default rule: %+v", candidate.rule)
		}
	}
}

func TestEgressNATSubsetsFullyCoveredDefaultHasExplicitStatus(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	items[1].Protocol = "tcp+udp+icmp"
	second := items[1]
	second.ID, second.ChildInterface = 3, "tap101"
	items = append(items, second)
	candidates, plans := buildEgressNATSubsetTestCandidates(t, items, snapshot)
	if len(candidates) != 6 || plans[1].FallbackReason != "" || !plans[1].KernelEligible {
		t.Fatalf("fully covered default: candidates=%+v plans=%+v", candidates, plans)
	}
	pm := &ProcessManager{
		ready:                  true,
		egressNATPlans:         plans,
		enabledEgressNATs:      map[int64]bool{1: true, 2: true, 3: true},
		kernelEgressNATs:       map[int64]bool{2: true, 3: true},
		kernelEgressNATEngines: map[int64]string{2: kernelEngineTC, 3: kernelEngineTC},
	}
	if status := pm.egressNATRuntimeStatus(1, true); status != "overridden" {
		t.Fatalf("default status = %s, want overridden", status)
	}
	if status := pm.egressNATRuntimeStatus(1, false); status != "stopped" {
		t.Fatalf("disabled default status = %s, want stopped", status)
	}
	if egressNATPlanIsUnavailable(plans[1]) {
		t.Fatal("fully covered default reported an unavailable plan")
	}
	if !pm.isReady() {
		t.Fatal("fully covered default made healthy child exits unready")
	}
	delete(pm.kernelEgressNATs, 2)
	if pm.isReady() {
		t.Fatal("fully covered default hid an unavailable child exit")
	}
}

func TestEgressNATSubsetsStillRejectEqualScopeProtocolConflicts(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	for _, base := range items {
		duplicate := base
		duplicate.ID = 3
		for _, projected := range [][]EgressNAT{{base, duplicate}, {duplicate, base}} {
			if issues := validateProjectedEgressNATs(projected, snapshot.IfaceByName, "update", 3); len(issues) != 1 {
				t.Fatalf("equal scope accepted: %+v issues=%+v", projected, issues)
			}
		}
	}
}

func TestPluginAndManagedEgressNATDefaultsAllowExplicitChildSubsets(t *testing.T) {
	t.Parallel()
	items, snapshot := egressNATSubsetFixture()
	child := items[1]
	for _, pluginFirst := range []bool{false, true} {
		parentJSON := `{"parent_interface":"vmbr0","out_interface":"wan0","protocol":"tcp+udp+icmp","enabled":true}`
		childJSON := `{"parent_interface":"vmbr0","child_interface":"tap100","out_interface":"wg0","protocol":"tcp","enabled":true}`
		records := []store.PluginRecord{
			{PluginID: "lan_core", RecordKey: "default", DataJSON: parentJSON, Enabled: true},
			{PluginID: "other", RecordKey: "child", DataJSON: childJSON, Enabled: true},
		}
		if pluginFirst {
			records[0], records[1] = records[1], records[0]
		}
		compiled, warnings := compilePluginEgressNATPlansWithWarnings(records, nil, snapshot)
		if len(compiled) != 2 || len(warnings) != 0 {
			t.Fatalf("plugin subsets: items=%+v warnings=%v", compiled, warnings)
		}
		compiled, warnings = compilePluginEgressNATPlansWithWarnings(records, []EgressNAT{child}, snapshot)
		if len(compiled) != 1 || compiled[0].ChildInterface != "" || len(warnings) != 1 {
			t.Fatalf("manual child precedence: items=%+v warnings=%v", compiled, warnings)
		}
	}
	compiled := compileManagedNetworkRuntime([]ManagedNetwork{{ID: 1, Name: "lab", Bridge: "vmbr0", UplinkInterface: "wan0", AutoEgressNAT: true, Enabled: true}}, nil, []EgressNAT{child}, snapshot.Infos)
	if len(compiled.EgressNATs) != 1 || len(compiled.Warnings) != 0 {
		t.Fatalf("managed default suppressed by a child: %+v", compiled)
	}
	candidates, _ := buildEgressNATSubsetTestCandidates(t, append(compiled.EgressNATs, child), snapshot)
	owners := egressNATSubsetCandidateOwners(t, candidates)
	if len(owners) != 6 || owners["tap100/tcp"] != child.ID || owners["tap101/tcp"] == child.ID {
		t.Fatalf("managed subset owners = %v", owners)
	}
}

func TestEgressNATSubsetsEffectivePlanRefreshesPluginDefaultAfterChildDeletion(t *testing.T) {
	items, snapshot := egressNATSubsetFixture()
	previousLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) { return snapshot.Infos, nil }
	t.Cleanup(func() { loadInterfaceInfosForEgressNATTests = previousLoad })
	db := openTestDB(t)
	childID, err := dbAddEgressNAT(db, &items[1])
	if err != nil {
		t.Fatal(err)
	}
	insertPluginEgressNATPlanForTest(t, db, "lan_core", "default", `{"parent_interface":"vmbr0","out_interface":"wan0","protocol":"tcp+udp+icmp","enabled":true}`, true)
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "lan_core", Stability: pluginStabilityStable},
		Resources:      []PluginResource{{ID: pluginEgressNATPlansResourceID}},
		Status:         pluginStatusActive,
	}}}
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: t.TempDir()})
	for _, deleted := range []bool{false, true} {
		if deleted {
			if err := dbDeleteEgressNAT(db, childID); err != nil {
				t.Fatal(err)
			}
		}
		plan, err := loadEffectiveNetworkPlan(db, cfg, effectiveNetworkPlanLoadOptions{PluginCatalog: &catalog})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.SyntheticEgressNATs) != 1 || len(plan.Warnings.EgressNAT) != 0 {
			t.Fatalf("deleted=%t plugin default missing: %+v", deleted, plan)
		}
		// Filtering the explicit child after the full load must preserve the
		// compiled exclusion, while a fresh load after deletion must remove it.
		var parent EgressNAT
		for _, item := range plan.EgressNATs {
			if item.ChildInterface == "" {
				parent = item
			}
		}
		candidates, _ := buildEgressNATSubsetTestCandidates(t, []EgressNAT{parent}, snapshot)
		owners := egressNATSubsetCandidateOwners(t, candidates)
		if _, inherited := owners["tap100/tcp"]; inherited != deleted {
			t.Fatalf("deleted=%t parent inheritance=%t: %v", deleted, inherited, owners)
		}
	}
}
