//go:build linux

package app

import "testing"

func TestActiveOwnerRulesMatchEgressNATRejectsConfigurationChanges(t *testing.T) {
	item := EgressNAT{
		ID:              10,
		ParentInterface: "vmbr1",
		OutInterface:    "eno1",
		OutSourceIP:     "203.0.113.60",
		Protocol:        "tcp+udp",
		NATType:         egressNATTypeSymmetric,
		RedirectMode:    egressNATRedirectModePreparedL2,
		Enabled:         true,
	}
	rules := []Rule{
		buildEgressNATSyntheticRule(item, "tap100i0", 5601, "tcp"),
		buildEgressNATSyntheticRule(item, "tap100i0", 5602, "udp"),
	}
	if !activeOwnerRulesMatchEgressNAT(rules, item) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() = false for unchanged configuration")
	}

	changedSource := item
	changedSource.OutSourceIP = "203.0.113.61"
	if activeOwnerRulesMatchEgressNAT(rules, changedSource) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() retained rules after source IP change")
	}
	changedType := item
	changedType.NATType = egressNATTypeFullCone
	if activeOwnerRulesMatchEgressNAT(rules, changedType) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() retained rules after NAT type change")
	}
	changedProtocol := item
	changedProtocol.Protocol = "tcp"
	if activeOwnerRulesMatchEgressNAT(rules, changedProtocol) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() retained rules after protocol change")
	}
	duplicate := []Rule{rules[0], rules[0]}
	if activeOwnerRulesMatchEgressNAT(duplicate, item) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() accepted duplicate target/protocol rules")
	}
	mismatchedTargets := []Rule{
		buildEgressNATSyntheticRule(item, "tap100i0", 5603, "tcp"),
		buildEgressNATSyntheticRule(item, "tap100i1", 5604, "udp"),
	}
	if activeOwnerRulesMatchEgressNAT(mismatchedTargets, item) {
		t.Fatal("activeOwnerRulesMatchEgressNAT() accepted incomplete protocol sets across targets")
	}
}
