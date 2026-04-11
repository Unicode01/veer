//go:build linux

package app

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestValidateKernelCollectionSpecAllowsMissingIPv6Maps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelForwardProgramName: &ebpf.ProgramSpec{},
			kernelReplyProgramName:   &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:              &ebpf.MapSpec{},
			kernelFlowsMapNameV4:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:           &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV4:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV6:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.MapSpec{},
			kernelTCFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelIfParentMapName:             &ebpf.MapSpec{},
			kernelLocalIPv4MapName:            &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName:   &ebpf.MapSpec{},
			kernelNATConfigMapName:            &ebpf.MapSpec{},
			kernelStatsMapName:                &ebpf.MapSpec{},
			kernelOccupancyMapName:            &ebpf.MapSpec{},
		},
	}

	if err := validateKernelCollectionSpec(spec); err != nil {
		t.Fatalf("validateKernelCollectionSpec() error = %v, want nil", err)
	}
}

func TestValidateKernelCollectionSpecRejectsIncompleteIPv6MapSet(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelForwardProgramName: &ebpf.ProgramSpec{},
			kernelReplyProgramName:   &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:              &ebpf.MapSpec{},
			kernelFlowsMapNameV4:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:           &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV4:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV6:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.MapSpec{},
			kernelTCFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelIfParentMapName:             &ebpf.MapSpec{},
			kernelLocalIPv4MapName:            &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName:   &ebpf.MapSpec{},
			kernelNATConfigMapName:            &ebpf.MapSpec{},
			kernelStatsMapName:                &ebpf.MapSpec{},
			kernelOccupancyMapName:            &ebpf.MapSpec{},
			kernelRulesMapNameV6:              &ebpf.MapSpec{},
			kernelFlowsMapNameV6:              &ebpf.MapSpec{},
		},
	}

	if err := validateKernelCollectionSpec(spec); err == nil {
		t.Fatal("validateKernelCollectionSpec() error = nil, want incomplete IPv6 map set error")
	}
}

func TestLookupKernelCollectionPiecesAllowsOptionalIPv6Maps(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:   &ebpf.Program{},
			kernelReplyProgramName:     &ebpf.Program{},
			kernelForwardProgramNameV6: &ebpf.Program{},
			kernelReplyProgramNameV6:   &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelRulesMapNameV6:              &ebpf.Map{},
			kernelFlowsMapNameV6:              &ebpf.Map{},
			kernelNatPortsMapNameV6:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
		},
	}

	pieces, err := lookupKernelCollectionPieces(coll)
	if err != nil {
		t.Fatalf("lookupKernelCollectionPieces() error = %v", err)
	}
	if pieces.rulesV4 == nil || pieces.rulesV6 == nil || pieces.flowsV6 == nil || pieces.natV6 == nil {
		t.Fatalf("lookupKernelCollectionPieces() = %+v, want both IPv4 and IPv6 maps", pieces)
	}
	if pieces.forwardProgV6 == nil || pieces.replyProgV6 == nil {
		t.Fatalf("lookupKernelCollectionPieces() = %+v, want both IPv6 programs", pieces)
	}
}

func TestLookupKernelCollectionPiecesRejectsIncompleteIPv6Maps(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName: &ebpf.Program{},
			kernelReplyProgramName:   &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelRulesMapNameV6:              &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
		},
	}

	if _, err := lookupKernelCollectionPieces(coll); err == nil {
		t.Fatal("lookupKernelCollectionPieces() error = nil, want incomplete IPv6 map set error")
	}
}

func TestValidateKernelCollectionSpecRejectsMissingIPv6Programs(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelForwardProgramName: &ebpf.ProgramSpec{},
			kernelReplyProgramName:   &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:              &ebpf.MapSpec{},
			kernelFlowsMapNameV4:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:           &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV4:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV6:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.MapSpec{},
			kernelTCFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelIfParentMapName:             &ebpf.MapSpec{},
			kernelLocalIPv4MapName:            &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName:   &ebpf.MapSpec{},
			kernelNATConfigMapName:            &ebpf.MapSpec{},
			kernelStatsMapName:                &ebpf.MapSpec{},
			kernelOccupancyMapName:            &ebpf.MapSpec{},
			kernelRulesMapNameV6:              &ebpf.MapSpec{},
			kernelFlowsMapNameV6:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV6:           &ebpf.MapSpec{},
		},
	}

	if err := validateKernelCollectionSpec(spec); err == nil {
		t.Fatal("validateKernelCollectionSpec() error = nil, want missing IPv6 program error")
	}
}

func TestLookupKernelCollectionPiecesRejectsIncompleteIPv6Programs(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:   &ebpf.Program{},
			kernelReplyProgramName:     &ebpf.Program{},
			kernelForwardProgramNameV6: &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelRulesMapNameV6:              &ebpf.Map{},
			kernelFlowsMapNameV6:              &ebpf.Map{},
			kernelNatPortsMapNameV6:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
		},
	}

	if _, err := lookupKernelCollectionPieces(coll); err == nil {
		t.Fatal("lookupKernelCollectionPieces() error = nil, want incomplete IPv6 program set error")
	}
}

func TestValidateKernelCollectionSpecRejectsIncompleteIPv4DispatcherSet(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelForwardProgramName:         &ebpf.ProgramSpec{},
			kernelReplyProgramName:           &ebpf.ProgramSpec{},
			kernelForwardDispatchProgramName: &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:              &ebpf.MapSpec{},
			kernelFlowsMapNameV4:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:           &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV4:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV6:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.MapSpec{},
			kernelTCFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelIfParentMapName:             &ebpf.MapSpec{},
			kernelLocalIPv4MapName:            &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName:   &ebpf.MapSpec{},
			kernelNATConfigMapName:            &ebpf.MapSpec{},
			kernelStatsMapName:                &ebpf.MapSpec{},
			kernelOccupancyMapName:            &ebpf.MapSpec{},
			kernelTCProgramChainMapName:       &ebpf.MapSpec{},
		},
	}

	if err := validateKernelCollectionSpec(spec); err == nil {
		t.Fatal("validateKernelCollectionSpec() error = nil, want incomplete IPv4 dispatcher set error")
	}
}

func TestLookupKernelCollectionPiecesRejectsIncompleteIPv4DispatcherSet(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:         &ebpf.Program{},
			kernelReplyProgramName:           &ebpf.Program{},
			kernelForwardDispatchProgramName: &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
			kernelTCProgramChainMapName:       &ebpf.Map{},
		},
	}

	if _, err := lookupKernelCollectionPieces(coll); err == nil {
		t.Fatal("lookupKernelCollectionPieces() error = nil, want incomplete IPv4 dispatcher set error")
	}
}

func TestValidateKernelCollectionSpecRejectsIncompleteIPv4FullNATSplitSet(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelForwardProgramName:                &ebpf.ProgramSpec{},
			kernelReplyProgramName:                  &ebpf.ProgramSpec{},
			kernelForwardDispatchProgramName:        &ebpf.ProgramSpec{},
			kernelForwardTransparentProgramName:     &ebpf.ProgramSpec{},
			kernelForwardFullNATProgramName:         &ebpf.ProgramSpec{},
			kernelForwardFullNATExistingProgramName: &ebpf.ProgramSpec{},
			kernelForwardEgressNATProgramName:       &ebpf.ProgramSpec{},
			kernelReplyDispatchProgramName:          &ebpf.ProgramSpec{},
			kernelReplyTransparentProgramName:       &ebpf.ProgramSpec{},
			kernelReplyFullNATProgramName:           &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:              &ebpf.MapSpec{},
			kernelFlowsMapNameV4:              &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:           &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV4:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.MapSpec{},
			kernelTCFlowsOldMapNameV6:         &ebpf.MapSpec{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.MapSpec{},
			kernelTCFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelIfParentMapName:             &ebpf.MapSpec{},
			kernelLocalIPv4MapName:            &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName:   &ebpf.MapSpec{},
			kernelNATConfigMapName:            &ebpf.MapSpec{},
			kernelStatsMapName:                &ebpf.MapSpec{},
			kernelOccupancyMapName:            &ebpf.MapSpec{},
			kernelTCProgramChainMapName:       &ebpf.MapSpec{},
		},
	}

	if err := validateKernelCollectionSpec(spec); err == nil {
		t.Fatal("validateKernelCollectionSpec() error = nil, want incomplete IPv4 full-nat split set error")
	}
}

func TestKernelAttachmentProgramsForPreparedRulesSkipsIPv6ProgramsForIPv4PreparedRules(t *testing.T) {
	forwardV4 := &ebpf.Program{}
	replyV4 := &ebpf.Program{}
	forwardV6 := &ebpf.Program{}
	replyV6 := &ebpf.Program{}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:   forwardV4,
			kernelReplyProgramName:     replyV4,
			kernelForwardProgramNameV6: forwardV6,
			kernelReplyProgramNameV6:   replyV6,
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
		},
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "198.51.100.10", OutIP: "203.0.113.10"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
	}}

	got := kernelAttachmentProgramsForPreparedRules(coll, prepared, kernelTCAttachmentProgramModeLegacy)
	if got.forwardProg != forwardV4 || got.replyProg != replyV4 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv4 programs")
	}
	if got.forwardProgV6 != nil || got.replyProgV6 != nil {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() returned IPv6 programs for IPv4-only prepared rules")
	}
}

func TestKernelAttachmentProgramsForPreparedRulesIncludesIPv6ProgramsWhenNeeded(t *testing.T) {
	forwardV4 := &ebpf.Program{}
	replyV4 := &ebpf.Program{}
	forwardV6 := &ebpf.Program{}
	replyV6 := &ebpf.Program{}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:   forwardV4,
			kernelReplyProgramName:     replyV4,
			kernelForwardProgramNameV6: forwardV6,
			kernelReplyProgramNameV6:   replyV6,
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelRulesMapNameV6:              &ebpf.Map{},
			kernelFlowsMapNameV6:              &ebpf.Map{},
			kernelNatPortsMapNameV6:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
		},
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "2001:db8::10", OutIP: "2001:db8::20"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv6},
	}}

	got := kernelAttachmentProgramsForPreparedRules(coll, prepared, kernelTCAttachmentProgramModeLegacy)
	if got.forwardProg != forwardV4 || got.replyProg != replyV4 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv4 programs")
	}
	if got.forwardProgV6 != forwardV6 || got.replyProgV6 != replyV6 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv6 programs for IPv6 prepared rules")
	}
}

func TestKernelAttachmentProgramsForPreparedRulesUsesIPv4DispatcherWhenEnabled(t *testing.T) {
	forwardV4 := &ebpf.Program{}
	replyV4 := &ebpf.Program{}
	forwardDispatch := &ebpf.Program{}
	replyDispatch := &ebpf.Program{}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:            forwardV4,
			kernelReplyProgramName:              replyV4,
			kernelForwardDispatchProgramName:    forwardDispatch,
			kernelForwardTransparentProgramName: &ebpf.Program{},
			kernelForwardFullNATProgramName:     &ebpf.Program{},
			kernelForwardEgressNATProgramName:   &ebpf.Program{},
			kernelReplyDispatchProgramName:      replyDispatch,
			kernelReplyTransparentProgramName:   &ebpf.Program{},
			kernelReplyFullNATProgramName:       &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
			kernelTCProgramChainMapName:       &ebpf.Map{},
		},
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "198.51.100.10", OutIP: "203.0.113.10"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		value: tcRuleValueV4{
			Flags: kernelRuleFlagFullNAT,
		},
	}}

	got := kernelAttachmentProgramsForPreparedRules(coll, prepared, kernelTCAttachmentProgramModeDispatchV4)
	if got.forwardProg != forwardDispatch || got.replyProg != replyDispatch {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not select IPv4 dispatcher programs")
	}
	if got.mode != kernelTCAttachmentProgramModeDispatchV4 {
		t.Fatalf("kernelAttachmentProgramsForPreparedRules() mode = %q, want %q", got.mode, kernelTCAttachmentProgramModeDispatchV4)
	}
}

func TestKernelAttachmentProgramsForPreparedRulesKeepsTransparentIPv4OnLegacyPrograms(t *testing.T) {
	forwardV4 := &ebpf.Program{}
	replyV4 := &ebpf.Program{}
	forwardDispatch := &ebpf.Program{}
	replyDispatch := &ebpf.Program{}

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelForwardProgramName:            forwardV4,
			kernelReplyProgramName:              replyV4,
			kernelForwardDispatchProgramName:    forwardDispatch,
			kernelForwardTransparentProgramName: &ebpf.Program{},
			kernelForwardFullNATProgramName:     &ebpf.Program{},
			kernelForwardEgressNATProgramName:   &ebpf.Program{},
			kernelReplyDispatchProgramName:      replyDispatch,
			kernelReplyTransparentProgramName:   &ebpf.Program{},
			kernelReplyFullNATProgramName:       &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:              &ebpf.Map{},
			kernelFlowsMapNameV4:              &ebpf.Map{},
			kernelNatPortsMapNameV4:           &ebpf.Map{},
			kernelTCFlowsOldMapNameV4:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV4:      &ebpf.Map{},
			kernelTCFlowsOldMapNameV6:         &ebpf.Map{},
			kernelTCNatPortsOldMapNameV6:      &ebpf.Map{},
			kernelTCFlowMigrationStateMapName: &ebpf.Map{},
			kernelTCProgramChainMapName:       &ebpf.Map{},
		},
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "198.51.100.10", OutIP: "203.0.113.10", Transparent: true},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
	}}

	got := kernelAttachmentProgramsForPreparedRules(coll, prepared, kernelTCAttachmentProgramModeDispatchV4)
	if got.forwardProg != forwardV4 || got.replyProg != replyV4 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() selected dispatcher programs for transparent-only IPv4 rules")
	}
	if got.mode != kernelTCAttachmentProgramModeLegacy {
		t.Fatalf("kernelAttachmentProgramsForPreparedRules() mode = %q, want %q for transparent-only IPv4 rules", got.mode, kernelTCAttachmentProgramModeLegacy)
	}
}

func TestKernelCollectionSpecSupportsIPv6(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV6:    &ebpf.MapSpec{},
			kernelFlowsMapNameV6:    &ebpf.MapSpec{},
			kernelNatPortsMapNameV6: &ebpf.MapSpec{},
		},
	}
	if !kernelCollectionSpecSupportsIPv6(spec) {
		t.Fatal("kernelCollectionSpecSupportsIPv6() = false, want true")
	}
	delete(spec.Maps, kernelNatPortsMapNameV6)
	if kernelCollectionSpecSupportsIPv6(spec) {
		t.Fatal("kernelCollectionSpecSupportsIPv6() = true, want false when IPv6 map set is incomplete")
	}
}
