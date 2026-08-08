package app

import "testing"

func kernelRuleIDTestCandidate(kind string, ownerID int64, ruleID int64, inInterface string, inPort int, protocol string) kernelCandidateRule {
	rule := Rule{
		ID:           ruleID,
		InInterface:  inInterface,
		InIP:         "0.0.0.0",
		InPort:       inPort,
		OutInterface: "vmbr0",
		OutIP:        "192.0.2.10",
		OutPort:      22,
		Protocol:     protocol,
		Enabled:      true,
	}
	owner := kernelCandidateOwner{kind: kind, id: ownerID}
	annotateKernelCandidateRule(&rule, owner)
	return kernelCandidateRule{owner: owner, rule: rule}
}

func TestStabilizeKernelCandidateRuleIDsPreservesTCPUDPVariantWhenHighRuleIsAdded(t *testing.T) {
	previous := []Rule{
		kernelRuleIDTestCandidate(workerKindRule, 10, 10, "vmbr1", 20022, "tcp").rule,
		kernelRuleIDTestCandidate(workerKindRule, 10, 11, "vmbr1", 20022, "udp").rule,
	}
	desired := []kernelCandidateRule{
		kernelRuleIDTestCandidate(workerKindRule, 5000, 5000, "vmbr2", 443, "tcp"),
		kernelRuleIDTestCandidate(workerKindRule, 10, 10, "vmbr1", 20022, "tcp"),
		kernelRuleIDTestCandidate(workerKindRule, 10, 5001, "vmbr1", 20022, "udp"),
	}

	if err := stabilizeKernelCandidateRuleIDs(desired, previous); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if got := desired[2].rule.ID; got != 11 {
		t.Fatalf("udp candidate id = %d, want retained id 11", got)
	}
	if got := desired[0].rule.ID; got != 5000 {
		t.Fatalf("new primary rule id = %d, want 5000", got)
	}
}

func TestStabilizeKernelCandidateRuleIDsPreservesRangePortsAcrossExpansionAndReorder(t *testing.T) {
	previous := []Rule{
		kernelRuleIDTestCandidate(workerKindRange, 7, 40, "vmbr1", 30000, "tcp").rule,
		kernelRuleIDTestCandidate(workerKindRange, 7, 41, "vmbr1", 30001, "tcp").rule,
	}
	desired := []kernelCandidateRule{
		kernelRuleIDTestCandidate(workerKindRange, 7, 44, "vmbr1", 30002, "tcp"),
		kernelRuleIDTestCandidate(workerKindRange, 7, 43, "vmbr1", 30001, "tcp"),
		kernelRuleIDTestCandidate(workerKindRange, 7, 42, "vmbr1", 30000, "tcp"),
	}

	if err := stabilizeKernelCandidateRuleIDs(desired, previous); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if got := desired[1].rule.ID; got != 41 {
		t.Fatalf("port 30001 id = %d, want retained id 41", got)
	}
	if got := desired[2].rule.ID; got != 40 {
		t.Fatalf("port 30000 id = %d, want retained id 40", got)
	}
	if desired[0].rule.ID == 40 || desired[0].rule.ID == 41 {
		t.Fatalf("new port reused an active id: %d", desired[0].rule.ID)
	}
}

func TestStabilizeKernelCandidateRuleIDsPreservesEgressNATWhenChildInterfaceIsAdded(t *testing.T) {
	previousCandidate := kernelRuleIDTestCandidate(workerKindEgressNAT, -1, 90, "tap100i0", 0, "tcp")
	previousCandidate.rule.kernelMode = kernelModeEgressNAT
	previous := []Rule{previousCandidate.rule}

	newChild := kernelRuleIDTestCandidate(workerKindEgressNAT, -1, 91, "tap101i0", 0, "tcp")
	newChild.rule.kernelMode = kernelModeEgressNAT
	existingChild := kernelRuleIDTestCandidate(workerKindEgressNAT, -1, 92, "tap100i0", 0, "tcp")
	existingChild.rule.kernelMode = kernelModeEgressNAT
	desired := []kernelCandidateRule{newChild, existingChild}

	if err := stabilizeKernelCandidateRuleIDs(desired, previous); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if got := desired[1].rule.ID; got != 90 {
		t.Fatalf("existing child egress nat id = %d, want retained id 90", got)
	}
	if desired[0].rule.ID == 90 {
		t.Fatal("new child reused the active egress nat id 90")
	}
}

func TestBuildEgressNATCandidatesKeepsExistingPVEChildIDAfterEarlierChildIsAdded(t *testing.T) {
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{available: true, supported: true}, ruleEngineKernel)
	item := EgressNAT{
		ID:              -1,
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		OutSourceIP:     "198.51.100.10",
		Protocol:        "tcp",
		Enabled:         true,
	}
	baseSnapshot := egressNATInterfaceSnapshot{Infos: []InterfaceInfo{
		{Name: "vmbr0", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		{Name: "eno1", Kind: "device", Addrs: []string{"198.51.100.10"}},
	}}
	nextID := int64(100)
	previous, _ := buildEgressNATKernelCandidatesWithSnapshot([]EgressNAT{item}, planner, 0, 0, &nextID, baseSnapshot)
	if err := stabilizeKernelCandidateRuleIDs(previous, nil); err != nil {
		t.Fatalf("stabilize initial egress nat candidates: %v", err)
	}
	if len(previous) != 1 {
		t.Fatalf("initial egress nat candidate count = %d, want 1", len(previous))
	}
	previousRules := []Rule{previous[0].rule}

	expandedSnapshot := egressNATInterfaceSnapshot{Infos: []InterfaceInfo{
		{Name: "vmbr0", Kind: "bridge"},
		{Name: "tap099i0", Parent: "vmbr0", Kind: "tuntap"},
		{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
		{Name: "eno1", Kind: "device", Addrs: []string{"198.51.100.10"}},
	}}
	nextID = 100
	desired, _ := buildEgressNATKernelCandidatesWithSnapshot([]EgressNAT{item}, planner, 0, 0, &nextID, expandedSnapshot)
	if err := stabilizeKernelCandidateRuleIDs(desired, previousRules); err != nil {
		t.Fatalf("stabilize expanded egress nat candidates: %v", err)
	}
	if len(desired) != 2 {
		t.Fatalf("expanded egress nat candidate count = %d, want 2", len(desired))
	}
	idsByInterface := make(map[string]int64, len(desired))
	for _, candidate := range desired {
		idsByInterface[candidate.rule.InInterface] = candidate.rule.ID
	}
	if got := idsByInterface["tap100i0"]; got != previous[0].rule.ID {
		t.Fatalf("existing PVE child id = %d, want retained id %d", got, previous[0].rule.ID)
	}
	if got := idsByInterface["tap099i0"]; got == previous[0].rule.ID || !validKernelDataplaneRuleID(got) {
		t.Fatalf("new PVE child id = %d, want valid non-colliding id", got)
	}
}

func TestStabilizeKernelCandidateRuleIDsMovesNewPrimaryRuleOnActiveSyntheticCollision(t *testing.T) {
	previousSynthetic := kernelRuleIDTestCandidate(workerKindRange, 7, 50, "vmbr1", 31000, "tcp")
	desired := []kernelCandidateRule{
		kernelRuleIDTestCandidate(workerKindRule, 50, 50, "vmbr2", 443, "tcp"),
		kernelRuleIDTestCandidate(workerKindRange, 7, 51, "vmbr1", 31000, "tcp"),
	}

	if err := stabilizeKernelCandidateRuleIDs(desired, []Rule{previousSynthetic.rule}); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if got := desired[1].rule.ID; got != 50 {
		t.Fatalf("active synthetic candidate id = %d, want retained id 50", got)
	}
	if got := desired[0].rule.ID; got == 50 || !validKernelDataplaneRuleID(got) {
		t.Fatalf("new primary rule id = %d, want a valid non-colliding id", got)
	}
}

func TestStabilizeKernelCandidateRuleIDsUsesPluginOwnerKeyAcrossAPIRuleIDDrift(t *testing.T) {
	previousCandidate := kernelRuleIDTestCandidate(workerKindRule, 100, 600, "vmbr1", 8443, "tcp")
	previousCandidate.rule.kernelOwnerKey = pluginForwardRuleOwnerKey("example", "record-a")
	desiredCandidate := kernelRuleIDTestCandidate(workerKindRule, 200, 700, "vmbr1", 8443, "tcp")
	desiredCandidate.rule.kernelOwnerKey = pluginForwardRuleOwnerKey("example", "record-a")
	desired := []kernelCandidateRule{desiredCandidate}

	if err := stabilizeKernelCandidateRuleIDs(desired, []Rule{previousCandidate.rule}); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if got := desired[0].rule.ID; got != 600 {
		t.Fatalf("plugin candidate id = %d, want retained id 600", got)
	}
}

func TestStabilizeKernelCandidateRuleIDsPreservesLegacyAllocationWithoutSnapshot(t *testing.T) {
	desired := []kernelCandidateRule{
		kernelRuleIDTestCandidate(workerKindRule, 12, 12, "vmbr1", 443, "tcp"),
		kernelRuleIDTestCandidate(workerKindRule, 12, 13, "vmbr1", 443, "udp"),
		kernelRuleIDTestCandidate(workerKindRange, 4, 14, "vmbr1", 10000, "tcp"),
	}

	if err := stabilizeKernelCandidateRuleIDs(desired, nil); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	for idx, want := range []int64{12, 13, 14} {
		if got := desired[idx].rule.ID; got != want {
			t.Fatalf("candidate %d id = %d, want legacy id %d", idx, got, want)
		}
	}
}
