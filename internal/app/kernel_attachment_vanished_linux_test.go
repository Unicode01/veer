//go:build linux

package app

import (
	"net"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestKernelAttachmentRuleSetsWithoutGoneLinksMovesTargetsToVanished(t *testing.T) {
	sets := kernelAttachmentRuleSets{
		ForwardIngress:      map[int][]int64{5: {1}, 7: {2}},
		ReplyIngress:        map[int][]int64{9: {1, 2}, 7: {3}},
		ForwardEgress:       map[int][]int64{},
		ReplyEgress:         nil,
		PluginIngressHooked: map[int]struct{}{7: {}, 9: {}},
	}
	lookups := map[int]int{}
	pruned := sets.withoutGoneLinks(func(ifindex int) bool {
		lookups[ifindex]++
		return ifindex == 7
	})

	if want := map[int]int{5: 1, 7: 1, 9: 1}; !reflect.DeepEqual(lookups, want) {
		t.Fatalf("link lookups = %v, want one per interface %v", lookups, want)
	}
	if want := map[int][]int64{5: {1}}; !reflect.DeepEqual(pruned.ForwardIngress, want) {
		t.Fatalf("ForwardIngress = %v, want %v", pruned.ForwardIngress, want)
	}
	if want := map[int][]int64{9: {1, 2}}; !reflect.DeepEqual(pruned.ReplyIngress, want) {
		t.Fatalf("ReplyIngress = %v, want %v", pruned.ReplyIngress, want)
	}
	// Later code adds plugin targets into the maps it finds non-nil.
	if pruned.ForwardEgress == nil || len(pruned.ForwardEgress) != 0 {
		t.Fatalf("ForwardEgress = %#v, want an empty non-nil map", pruned.ForwardEgress)
	}
	if pruned.ReplyEgress != nil {
		t.Fatalf("ReplyEgress = %#v, want nil as before", pruned.ReplyEgress)
	}
	if want := map[int]struct{}{9: {}}; !reflect.DeepEqual(pruned.PluginIngressHooked, want) {
		t.Fatalf("PluginIngressHooked = %v, want %v", pruned.PluginIngressHooked, want)
	}
	if want := map[int]struct{}{7: {}}; !reflect.DeepEqual(pruned.Vanished, want) {
		t.Fatalf("Vanished = %v, want %v", pruned.Vanished, want)
	}
	if got := pruned.vanishedSummary(); got != "[7]" {
		t.Fatalf("vanishedSummary() = %q, want [7]", got)
	}
	if _, ok := sets.ForwardIngress[7]; !ok || sets.Vanished != nil {
		t.Fatal("withoutGoneLinks changed the sets it was called on")
	}

	// The next reconcile names the same interfaces and prunes them again:
	// the targets compare equal, so nothing is reattached.
	again := sets.withoutGoneLinks(func(ifindex int) bool { return ifindex == 7 })
	if !pruned.sameTargets(again) {
		t.Fatal("two prunings of the same sets have different targets")
	}

	forwardReady := map[int]bool{5: true}
	replyReady := map[int]bool{9: true}
	pruned.markVanishedReady(forwardReady, replyReady)
	if !forwardReady[7] || !replyReady[7] {
		t.Fatalf("vanished interface not counted as attached: forward=%v reply=%v", forwardReady, replyReady)
	}

	if kept := sets.withoutGoneLinks(func(int) bool { return false }); !reflect.DeepEqual(kept, sets) {
		t.Fatalf("withoutGoneLinks with every interface present = %+v, want the sets unchanged", kept)
	}
}

func TestEffectiveKernelAttachmentRuleSetsKeepsSetsWhoseTargetsAllVanished(t *testing.T) {
	stored := kernelAttachmentRuleSets{
		ForwardIngress: map[int][]int64{7: {1}},
		ReplyIngress:   map[int][]int64{7: {1}},
	}.withoutGoneLinks(func(int) bool { return true })
	prepared := []preparedKernelRule{{rule: Rule{ID: 1}, inIfIndex: 7, outIfIndex: 7}}

	got := effectiveKernelAttachmentRuleSets(prepared, stored)
	if got.hasTargets() {
		t.Fatalf("effective sets = %+v, want the stored sets without targets, not the prepared interfaces", got)
	}
}

func TestWithoutGoneXDPLinksSplitsInterfaces(t *testing.T) {
	kept, vanished := withoutGoneXDPLinks([]int{3, 4, 8}, func(ifindex int) bool { return ifindex == 4 })
	if !reflect.DeepEqual(kept, []int{3, 8}) || !reflect.DeepEqual(vanished, []int{4}) {
		t.Fatalf("withoutGoneXDPLinks() = %v, %v; want [3 8], [4]", kept, vanished)
	}
}

func TestKernelLinkIndexGoneOnlyForMissingInterfaces(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	if kernelLinkIndexGone(lo.Index) {
		t.Fatal("loopback reported gone")
	}
	if kernelLinkIndexGone(0) || kernelLinkIndexGone(-1) {
		t.Fatal("an unset ifindex reported gone")
	}
	if !kernelLinkIndexGone(1 << 30) {
		t.Fatal("an ifindex no interface has was not reported gone")
	}
}

// TestEgressNATTCHeldRuleSurvivesChildInterfaceRemoval covers a guest being
// destroyed: its tap is gone, but the interface inventory keeps the egress NAT
// rule for a grace period, so the next reconcile still names the tap. That
// reconcile must keep the rule running in place instead of failing to attach
// on the old ifindex and falling back to a full rebuild.
func TestEgressNATTCHeldRuleSurvivesChildInterfaceRemoval(t *testing.T) {
	if os.Getenv(egressNATTestEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Linux egress NAT integration test", egressNATTestEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command is required")
	}

	topology := setupEgressNATIntegrationTopology(t)
	rt := newTCKernelRuleRuntime(&Config{})
	defer rt.Close()
	rule := buildEgressNATSyntheticRule(EgressNAT{
		ID:              1,
		ParentInterface: topology.BridgeIF,
		OutInterface:    topology.UplinkHostIF,
		OutSourceIP:     egressNATUplinkAddr,
		Protocol:        "tcp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}, topology.ChildHostIF, 1, "tcp")
	results, err := rt.Reconcile([]Rule{rule})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := results[rule.ID]; !result.Running || result.Error != "" {
		t.Fatalf("egress NAT result = %+v, want running", result)
	}
	child, err := net.InterfaceByName(topology.ChildHostIF)
	if err != nil {
		t.Fatalf("look up %s: %v", topology.ChildHostIF, err)
	}
	coll := rt.coll

	mustRunDataplanePerfCmd(t, "ip", "link", "del", topology.ChildHostIF)

	for _, phase := range []string{"first reconcile after removal", "second reconcile after removal"} {
		results, err = rt.Reconcile([]Rule{rule})
		if err != nil {
			t.Fatalf("%s: Reconcile() error = %v", phase, err)
		}
		if result := results[rule.ID]; !result.Running || result.Error != "" {
			t.Fatalf("%s: egress NAT result = %+v, want the held rule running", phase, result)
		}
		if rt.coll != coll {
			t.Fatalf("%s: the tc collection was rebuilt (mode %q), want an in-place update", phase, rt.lastReconcileMode)
		}
		if _, ok := rt.attachmentRuleSets.Vanished[child.Index]; !ok {
			t.Fatalf("%s: attachment sets %+v do not record ifindex %d as vanished", phase, rt.attachmentRuleSets, child.Index)
		}
		for _, health := range rt.attachmentHealthSnapshot() {
			if !health.Healthy {
				t.Fatalf("%s: attachment health = %+v, want healthy", phase, health)
			}
		}
	}
	if rt.lastReconcileMode != "steady" {
		t.Fatalf("reconcile mode after the second pass = %q, want steady", rt.lastReconcileMode)
	}
}
