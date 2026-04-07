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
			kernelRulesMapNameV4:            &ebpf.MapSpec{},
			kernelFlowsMapNameV4:            &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:         &ebpf.MapSpec{},
			kernelIfParentMapName:           &ebpf.MapSpec{},
			kernelLocalIPv4MapName:          &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName: &ebpf.MapSpec{},
			kernelNATConfigMapName:          &ebpf.MapSpec{},
			kernelStatsMapName:              &ebpf.MapSpec{},
			kernelOccupancyMapName:          &ebpf.MapSpec{},
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
			kernelRulesMapNameV4:            &ebpf.MapSpec{},
			kernelFlowsMapNameV4:            &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:         &ebpf.MapSpec{},
			kernelIfParentMapName:           &ebpf.MapSpec{},
			kernelLocalIPv4MapName:          &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName: &ebpf.MapSpec{},
			kernelNATConfigMapName:          &ebpf.MapSpec{},
			kernelStatsMapName:              &ebpf.MapSpec{},
			kernelOccupancyMapName:          &ebpf.MapSpec{},
			kernelRulesMapNameV6:            &ebpf.MapSpec{},
			kernelFlowsMapNameV6:            &ebpf.MapSpec{},
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
			kernelRulesMapNameV4:    &ebpf.Map{},
			kernelFlowsMapNameV4:    &ebpf.Map{},
			kernelNatPortsMapNameV4: &ebpf.Map{},
			kernelRulesMapNameV6:    &ebpf.Map{},
			kernelFlowsMapNameV6:    &ebpf.Map{},
			kernelNatPortsMapNameV6: &ebpf.Map{},
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
			kernelRulesMapNameV4:    &ebpf.Map{},
			kernelFlowsMapNameV4:    &ebpf.Map{},
			kernelNatPortsMapNameV4: &ebpf.Map{},
			kernelRulesMapNameV6:    &ebpf.Map{},
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
			kernelRulesMapNameV4:            &ebpf.MapSpec{},
			kernelFlowsMapNameV4:            &ebpf.MapSpec{},
			kernelNatPortsMapNameV4:         &ebpf.MapSpec{},
			kernelIfParentMapName:           &ebpf.MapSpec{},
			kernelLocalIPv4MapName:          &ebpf.MapSpec{},
			kernelEgressWildcardFastMapName: &ebpf.MapSpec{},
			kernelNATConfigMapName:          &ebpf.MapSpec{},
			kernelStatsMapName:              &ebpf.MapSpec{},
			kernelOccupancyMapName:          &ebpf.MapSpec{},
			kernelRulesMapNameV6:            &ebpf.MapSpec{},
			kernelFlowsMapNameV6:            &ebpf.MapSpec{},
			kernelNatPortsMapNameV6:         &ebpf.MapSpec{},
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
			kernelRulesMapNameV4:    &ebpf.Map{},
			kernelFlowsMapNameV4:    &ebpf.Map{},
			kernelNatPortsMapNameV4: &ebpf.Map{},
			kernelRulesMapNameV6:    &ebpf.Map{},
			kernelFlowsMapNameV6:    &ebpf.Map{},
			kernelNatPortsMapNameV6: &ebpf.Map{},
		},
	}

	if _, err := lookupKernelCollectionPieces(coll); err == nil {
		t.Fatal("lookupKernelCollectionPieces() error = nil, want incomplete IPv6 program set error")
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
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "198.51.100.10", OutIP: "203.0.113.10"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
	}}

	gotForwardV4, gotReplyV4, gotForwardV6, gotReplyV6 := kernelAttachmentProgramsForPreparedRules(coll, prepared)
	if gotForwardV4 != forwardV4 || gotReplyV4 != replyV4 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv4 programs")
	}
	if gotForwardV6 != nil || gotReplyV6 != nil {
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
	}
	prepared := []preparedKernelRule{{
		rule: Rule{ID: 1, InIP: "2001:db8::10", OutIP: "2001:db8::20"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv6},
	}}

	gotForwardV4, gotReplyV4, gotForwardV6, gotReplyV6 := kernelAttachmentProgramsForPreparedRules(coll, prepared)
	if gotForwardV4 != forwardV4 || gotReplyV4 != replyV4 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv4 programs")
	}
	if gotForwardV6 != forwardV6 || gotReplyV6 != replyV6 {
		t.Fatal("kernelAttachmentProgramsForPreparedRules() did not return IPv6 programs for IPv6 prepared rules")
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
