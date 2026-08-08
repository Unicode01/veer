//go:build linux

package app

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestTCHotRestartTransparentFlowParents(t *testing.T) {
	prepared := []preparedKernelRule{
		{
			rule:           Rule{ID: 44, Transparent: true},
			outIfIndex:     3,
			replyIfParents: []kernelIfParentMapping{{ifindex: 55, parentIfIndex: 3}, {ifindex: 66, parentIfIndex: 3}},
			spec:           kernelPreparedRuleSpec{Family: ipFamilyIPv4},
			value:          tcRuleValueV4{RuleID: 44, OutIfIndex: 3},
		},
		{
			rule:           Rule{ID: 45, Transparent: false},
			replyIfParents: []kernelIfParentMapping{{ifindex: 77, parentIfIndex: 3}},
			spec:           kernelPreparedRuleSpec{Family: ipFamilyIPv4},
			value:          tcRuleValueV4{RuleID: 45, OutIfIndex: 3},
		},
	}

	parents := tcHotRestartTransparentFlowParents(prepared)
	if len(parents) != 2 {
		t.Fatalf("parents = %#v, want two transparent bridge members", parents)
	}
	for _, child := range []uint32{55, 66} {
		if got := parents[tcHotRestartTransparentFlowPath{ruleID: 44, childIfIndex: child}]; got != 3 {
			t.Fatalf("parent for rule 44 child %d = %d, want 3", child, got)
		}
	}
}

func TestMergeTCHotRestartTransparentFlowValues(t *testing.T) {
	canonical := tcFlowValueV4{
		RuleID:           44,
		Flags:            kernelFlowFlagFrontClosing,
		LastSeenNS:       100,
		FrontCloseSeenNS: 90,
		SessionID:        9001,
	}
	source := canonical
	source.Flags = kernelFlowFlagReplySeen | kernelFlowFlagReplyClosing
	source.LastSeenNS = 120
	source.FrontCloseSeenNS = 80

	merged := mergeTCHotRestartTransparentFlowValues(canonical, source)
	wantFlags := uint16(kernelFlowFlagFrontClosing | kernelFlowFlagReplySeen | kernelFlowFlagReplyClosing)
	if merged.Flags != wantFlags || merged.LastSeenNS != 120 || merged.FrontCloseSeenNS != 90 || merged.SessionID != 9001 {
		t.Fatalf("merged = %+v, want flags=%#x last_seen=120 front_close=90 session=9001", merged, wantFlags)
	}
}

func TestStageTCHotRestartTransparentFlowAliasesCanonicalizesLegacyMemberKey(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "tc_flow_alias_test",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	defer flows.Close()

	sourceKey := tcFlowKeyV4{IfIndex: 55, SrcAddr: 2, DstAddr: 3, SrcPort: 22, DstPort: 40000, Proto: 6}
	sourceValue := tcFlowValueV4{RuleID: 44, Flags: kernelFlowFlagReplySeen, LastSeenNS: 100, SessionID: 9001}
	if err := flows.Put(sourceKey, sourceValue); err != nil {
		t.Fatalf("put legacy member flow: %v", err)
	}
	prepared := []preparedKernelRule{{
		rule:           Rule{ID: 44, Transparent: true},
		outIfIndex:     3,
		replyIfParents: []kernelIfParentMapping{{ifindex: 55, parentIfIndex: 3}},
		spec:           kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		value:          tcRuleValueV4{RuleID: 44, OutIfIndex: 3},
	}}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{kernelTCFlowsOldMapNameV4: flows}}

	aliases, err := stageTCHotRestartTransparentFlowAliases(coll, prepared, nil)
	if err != nil {
		t.Fatalf("stageTCHotRestartTransparentFlowAliases() error = %v", err)
	}
	if len(aliases.items) != 1 {
		t.Fatalf("staged aliases = %d, want 1", len(aliases.items))
	}
	canonicalKey := sourceKey
	canonicalKey.IfIndex = 3
	var canonical tcFlowValueV4
	if err := flows.Lookup(canonicalKey, &canonical); err != nil {
		t.Fatalf("lookup staged canonical flow: %v", err)
	}
	if canonical.SessionID != sourceValue.SessionID {
		t.Fatalf("staged canonical session = %d, want %d", canonical.SessionID, sourceValue.SessionID)
	}

	sourceValue.Flags |= kernelFlowFlagReplyClosing
	sourceValue.LastSeenNS = 120
	if err := flows.Put(sourceKey, sourceValue); err != nil {
		t.Fatalf("refresh legacy member flow: %v", err)
	}
	canonical.Flags |= kernelFlowFlagFrontClosing
	canonical.FrontCloseSeenNS = 110
	if err := flows.Put(canonicalKey, canonical); err != nil {
		t.Fatalf("refresh canonical flow: %v", err)
	}

	finalized, err := aliases.finalize()
	if err != nil {
		t.Fatalf("aliases.finalize() error = %v", err)
	}
	if finalized != 1 {
		t.Fatalf("finalized aliases = %d, want 1", finalized)
	}
	if err := flows.Lookup(sourceKey, &sourceValue); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("legacy source lookup error = %v, want key not exist", err)
	}
	if err := flows.Lookup(canonicalKey, &canonical); err != nil {
		t.Fatalf("lookup finalized canonical flow: %v", err)
	}
	wantFlags := uint16(kernelFlowFlagReplySeen | kernelFlowFlagReplyClosing | kernelFlowFlagFrontClosing)
	if canonical.Flags != wantFlags || canonical.LastSeenNS != 120 || canonical.FrontCloseSeenNS != 110 {
		t.Fatalf("finalized canonical = %+v, want flags=%#x last_seen=120 front_close=110", canonical, wantFlags)
	}
}

func TestFinalizeTCHotRestartTransparentFlowAliasesDoesNotReviveClosedSource(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "tc_closed_alias_test",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	defer flows.Close()

	sourceKey := tcFlowKeyV4{IfIndex: 55, SrcAddr: 2, DstAddr: 3, SrcPort: 22, DstPort: 40000, Proto: 6}
	if err := flows.Put(sourceKey, tcFlowValueV4{RuleID: 44, LastSeenNS: 100, SessionID: 9001}); err != nil {
		t.Fatalf("put legacy member flow: %v", err)
	}
	prepared := []preparedKernelRule{{
		rule:           Rule{ID: 44, Transparent: true},
		outIfIndex:     3,
		replyIfParents: []kernelIfParentMapping{{ifindex: 55, parentIfIndex: 3}},
		spec:           kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		value:          tcRuleValueV4{RuleID: 44, OutIfIndex: 3},
	}}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{kernelTCFlowsOldMapNameV4: flows}}
	aliases, err := stageTCHotRestartTransparentFlowAliases(coll, prepared, nil)
	if err != nil {
		t.Fatalf("stageTCHotRestartTransparentFlowAliases() error = %v", err)
	}
	if err := flows.Delete(sourceKey); err != nil {
		t.Fatalf("close legacy member flow: %v", err)
	}

	finalized, err := aliases.finalize()
	if err != nil {
		t.Fatalf("aliases.finalize() error = %v", err)
	}
	if finalized != 1 {
		t.Fatalf("finalized aliases = %d, want 1", finalized)
	}
	canonicalKey := sourceKey
	canonicalKey.IfIndex = 3
	var value tcFlowValueV4
	if err := flows.Lookup(canonicalKey, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("closed canonical alias lookup error = %v, want key not exist", err)
	}
}
